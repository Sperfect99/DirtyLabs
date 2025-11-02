# File: main.py
# Version: 3.4
# Author: [Stylianos Tanellari]
# Description:
#   Main entrypoint for the Crypto-Steganography tool.
#   Handles CLI, user interaction, and orchestrates the crypto and steganography modules.
#   Maintains backwards-compatibility with older helper APIs.

import argparse
import getpass
import logging
import os
import zlib
import shutil
import tempfile
from typing import Optional, Tuple

from PIL import Image, UnidentifiedImageError
import numpy as np
from scipy.stats import chisquare

import crypto
import steganography

# -------------------------
# Custom exceptions
# -------------------------
class StegoError(Exception):
    """Raised for steganography-related high-level errors."""
    pass

class CryptoError(Exception):
    """Raised for crypto-related high-level errors."""
    pass

# -------------------------
# Logging configuration
# -------------------------
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("stego_main")

# -------------------------
# Small utility helpers
# -------------------------
def format_bytes(size: int) -> str:
    """Return human-friendly byte size."""
    if size < 1024:
        return f"{size} Bytes"
    elif size < 1024**2:
        return f"{size/1024:.2f} KB"
    elif size < 1024**3:
        return f"{size/1024**2:.2f} MB"
    else:
        return f"{size/1024**3:.2f} GB"

def get_password(prompt: str, confirm: bool = True) -> str:
    """
    Gets and confirms a password from the user. Loops until they match.
    """
    while True:
        pwd = getpass.getpass(f"{prompt}: ")
        if not confirm:
            return pwd
        pwd2 = getpass.getpass(f"Confirm {prompt}: ")
        if pwd == pwd2:
            return pwd
        logger.warning("Passwords do not match. Try again.")

def _ensure_backup(output_file: str) -> Optional[str]:
    """
    Prevents overwriting. If 'output_file' exists, renames it to '..._backup1.png'.
    """
    if os.path.exists(output_file):
        base, ext = os.path.splitext(output_file)
        i = 1
        while True:
            candidate = f"{base}_backup{i}{ext}"
            if not os.path.exists(candidate):
                break
            i += 1
        logger.warning(f"Output '{output_file}' exists. Backing up as '{candidate}'.")
        os.rename(output_file, candidate)
        return candidate
    return None

def _prepare_carrier_image(path: str) -> str:
    """
    Converts lossy JPEGs to a temp PNG for safe LSB embedding. Caller must clean up.
    """
    lower = path.lower()
    if lower.endswith((".jpg", ".jpeg")):
        logger.warning("Carrier appears to be JPEG (lossy). Converting to PNG for safer embedding...")
        img = Image.open(path).convert("RGB")
        fd, tmp = tempfile.mkstemp(suffix=".png")
        os.close(fd)
        img.save(tmp, "PNG")
        logger.info(f"Converted JPEG -> PNG at temporary path: {tmp}")
        return tmp
    return path

def _prepare_payload_archive(path: str) -> Tuple[str, Optional[str]]:
    """
    Zips a directory into a temp archive. Returns (archive_path, temp_dir) for cleanup.
    """
    if os.path.isdir(path):
        tmpdir = tempfile.mkdtemp()
        base = os.path.join(tmpdir, "archive")
        archive_path = shutil.make_archive(base, "zip", path)
        logger.info(f"Zipped folder '{path}' -> '{archive_path}' (temporary)")
        return archive_path, tmpdir
    return path, None


# -------------------------
# Compatibility helpers
# -------------------------
def _get_stego_seed(password: str) -> bytes:
    """
    Gets the stego_seed. Tries new API (derive_stego_seed) but falls back to older methods for compatibility.
    """
    # Prefer explicit API derive_stego_seed
    if hasattr(crypto, "derive_stego_seed"):
        try:
            seed = crypto.derive_stego_seed(password)
            if isinstance(seed, (bytes, bytearray)):
                return bytes(seed)
        except Exception as e:
            logger.debug(f"crypto.derive_stego_seed failed: {e}")

    # Try derive_all (enc_key, mac_key, stego_seed)
    if hasattr(crypto, "derive_all"):
        try:
            # IMPORTANT: pass deterministic salt for the stego seed so seed is reproducible.
            deterministic_salt = b"stego-derive-all-fixed-salt-v1"
            result = crypto.derive_all(password, deterministic_salt)
            if isinstance(result, tuple) and len(result) == 3:
                seed = result[2]
                if isinstance(seed, (bytes, bytearray)):
                    return bytes(seed)
        except TypeError:
            # try without salt param if function expects only password (older variant)
            try:
                result = crypto.derive_all(password)
                if isinstance(result, tuple) and len(result) == 3:
                    seed = result[2]
                    if isinstance(seed, (bytes, bytearray)):
                        return bytes(seed)
            except Exception as e:
                logger.debug(f"derive_all variant failed: {e}")
        except Exception as e:
            logger.debug(f"crypto.derive_all failed: {e}")

    # Last-resort legacy: sha256(password)
    import hashlib
    logger.debug("Falling back to legacy stego seed derivation (sha256(password)) — consider updating crypto.py with derive_stego_seed.")
    return hashlib.sha256(password.encode("utf-8")).digest()


def _encrypt_payload(password: Optional[str], data: bytes, algo: str) -> Optional[bytes]:
    """
    Encrypts data using crypto.encrypt_data.
    Handles API variations gracefully.
    """
    if password is None:
        logger.error("Encryption requires a password; received None.")
        return None
    if not hasattr(crypto, "encrypt_data"):
        logger.error("crypto.encrypt_data not found.")
        return None
    try:
        return crypto.encrypt_data(password, data, algo=algo)
    except TypeError:
        # Some older variants may accept different args order, try without algo
        try:
            return crypto.encrypt_data(password, data)
        except Exception as e:
            logger.error(f"Encryption failed (fallback attempts): {e}")
            return None
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        return None

def _decrypt_payload(password: str, blob: bytes, algo: str) -> Optional[bytes]:
    """
    Decrypts data using crypto.decrypt_data.
    Handles API variations gracefully.
    """
    if not hasattr(crypto, "decrypt_data"):
        logger.error("crypto.decrypt_data not found.")
        return None
    try:
        return crypto.decrypt_data(password, blob, algo=algo)
    except TypeError:
        try:
            return crypto.decrypt_data(password, blob)
        except Exception as e:
            logger.error(f"Decrypt fallback failed: {e}")
            return None
    except Exception as e:
        logger.error(f"Decrypt failed: {e}")
        return None

# -------------------------
# Core tool functions
# -------------------------
def check_capacity(input_file: Optional[str] = None, bits_per_channel: int = 1) -> None:
    """
    Show carrier capacity using specific bits_per_channel.
    """
    try:
        if not input_file:
            input_file = input("Enter carrier file (e.g., photo.png): ").strip().strip('"')
        if not os.path.exists(input_file):
            logger.error(f"File '{input_file}' not found.")
            return

        cap = steganography.get_carrier_capacity(input_file,
                                                 bits_per_channel=bits_per_channel,
                                                 logger_in=logger)
        if not cap:
            logger.error("Capacity information not available for this file.")
            return

        logger.info(f"--- Capacity for '{input_file}' ---")
        logger.info(f"Bits per channel: {bits_per_channel}")
        logger.info(f"Standard Mode (100%): {format_bytes(cap['full_mode_bytes'])}")
        logger.info(f"Decoy Mode (50% each): {format_bytes(cap['decoy_mode_bytes_A'])}")
        logger.info("(Capacity values are BEFORE compression.)")

    except Exception as e:
        logger.error(f"[Capacity Error] {e}")


def hide_message_interactive() -> None:
    """
    Interactive flow for hiding. Guides user through choices,
    including bits-per-channel selection with explanation.
    """
    print("\n--- Hide Message or File (Interactive Mode) ---")
    infile = input("Carrier file (e.g., photo.png): ").strip().strip('"')
    outfile = input("Output file (e.g., secret.png): ").strip().strip('"')
    algo = input("Encryption algorithm [AES / ChaCha20] (default=AES): ").strip().lower() or "aes"
    double = input("Use double encryption? (y/N): ").strip().lower() == "y"

    # payload type
    txt = None
    secret_path = None
    while True:
        choice = input("Hide [T]ext or [F]ile?: ").strip().lower()
        if choice == "t":
            txt = input("Type your REAL secret message: ")
            break
        elif choice == "f":
            secret_path = input("Path to real secret file or folder: ").strip().strip('"')
            break
        else:
            logger.warning("Invalid choice. Enter 'T' or 'F'.")

    # optional decoy
    decoy_text = None
    if input("Add DECOY message? (y/N): ").strip().lower() == "y":
        decoy_text = input("Type DECOY message: ")

    # bits-per-channel selection (stealth vs capacity)
    print("\nChoose security / capacity tradeoff:")
    print("  1 — Maximum security (1 bit per channel) — most stealthy")
    print("  2 — Balanced (2 bits per channel) — good compromise (default)")
    print("  3 — Maximum capacity (3 bits per channel) — higher throughput, easier to detect")
    bits_choice = input("Choose [1/2/3] (default=1): ").strip() or "1"
    bits_per_channel = {"1": 1, "2": 2, "3": 3}.get(bits_choice, 1)

    # run core hide
    hide_message(
        infile, outfile,
        text=txt,
        secret_file=secret_path,
        decoy_text=decoy_text,
        algo=algo,
        double=double,
        bits_per_channel=bits_per_channel
    )

def hide_message(input_file: str,
                 output_file: str,
                 text: Optional[str] = None,
                 secret_file: Optional[str] = None,
                 decoy_text: Optional[str] = None,
                 algo: str = "aes",
                 double: bool = False,
                 bits_per_channel: int = 1) -> None:
    """
    The main 'hide' logic. Takes all args, zips, compresses, encrypts, and calls steganography.hide_data().
    """
    tmp_files = []
    tmp_dirs = []
    try:
        # Validate carrier
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"Carrier '{input_file}' not found.")
        carrier = _prepare_carrier_image(input_file)
        if carrier != input_file:
            tmp_files.append(carrier)  # mark temp png to remove later

        # capacity check — use the user's bits_per_channel selection
        cap = steganography.get_carrier_capacity(carrier, bits_per_channel=bits_per_channel)
        if not cap:
            raise StegoError("Could not read carrier capacity.")


        logger.info(f"Carrier capacity (baseline): {format_bytes(cap['full_mode_bytes'])}")

        # build payload bytes
        if text:
            real_payload = b"TEXT::" + text.encode("utf-8")
            payload_desc = "Message"
        elif secret_file:
            if not os.path.exists(secret_file):
                raise FileNotFoundError(f"Secret path '{secret_file}' not found.")
            secret_to_hide, tmpdir = _prepare_payload_archive(secret_file)
            if tmpdir:
                tmp_dirs.append(tmpdir)
            with open(secret_to_hide, "rb") as fh:
                data = fh.read()
            filename = os.path.basename(secret_to_hide)
            real_payload = f"FILE::{filename}".encode("utf-8") + b"::" + data
            payload_desc = f"File ({filename})"
        else:
            raise StegoError("No text or file provided for hiding.")

        # decoy payload (optional)
        decoy_payload = b"TEXT::" + decoy_text.encode("utf-8") if decoy_text else None

        # backup existing output if any
        _ensure_backup(output_file)

        # Normalize algorithm name
        algo_norm = "aes" if algo in ("aes", "") else "chacha20" if algo in ("chacha20", "chacha") else None
        if algo_norm is None:
            logger.warning("Unknown algorithm selection; defaulting to AES.")
            algo_norm = "aes"

        # conservative pre-check capacity (rough: raw before compression)
        max_capacity = cap["full_mode_bytes"] if not decoy_payload else cap["decoy_mode_bytes_B"]
        if len(real_payload) > max_capacity:
            logger.error(f"Payload raw size {format_bytes(len(real_payload))} exceeds available {format_bytes(max_capacity)}. Aborting.")
            return

        # compress payloads
        logger.info("Compressing payloads (zlib level=9)...")
        comp_real = zlib.compress(real_payload, level=9)
        logger.info(f"Real {payload_desc}: {format_bytes(len(real_payload))} -> compressed {format_bytes(len(comp_real))}")
        comp_decoy = zlib.compress(decoy_payload, level=9) if decoy_payload else None
        if comp_decoy:
            logger.info(f"Decoy compressed: {format_bytes(len(decoy_payload))} -> {format_bytes(len(comp_decoy))}")

        # get user passwords
        real_pwd = get_password("Enter REAL password", confirm=True)
        decoy_pwd = get_password("Enter DECOY password", confirm=True) if decoy_payload else None

        # derive stego seed(s) using crypto (preferred) 
        logger.debug("Deriving stego seeds using compatibility helper...")
        stego_seed = _get_stego_seed(real_pwd)
        decoy_seed = _get_stego_seed(decoy_pwd) if decoy_pwd else None


        # Encrypt payloads (single-layer)
        logger.info(f"Encrypting payload(s) using {algo_norm.upper()} + HMAC integrity...")
        enc_real = _encrypt_payload(real_pwd, comp_real, algo_norm)
        if not enc_real:
            raise CryptoError("Real payload encryption failed.")
        enc_decoy = _encrypt_payload(decoy_pwd, comp_decoy, algo_norm) if comp_decoy else None
        if comp_decoy and not enc_decoy:
            raise CryptoError("Decoy payload encryption failed.")

        # Optional double encryption (nested)
        if double:
            sec_pwd = get_password("Enter SECOND password for double encryption", confirm=True)
            logger.info("Applying second-level encryption (double)...")
            enc_real = _encrypt_payload(sec_pwd, enc_real, algo_norm)
            if comp_decoy:
                enc_decoy = _encrypt_payload(sec_pwd, enc_decoy, algo_norm)

        # At this point: enc_real (bytes) is ready to embed; enc_decoy maybe None
        # Call steganography.hide_data.
        logger.info("Embedding encrypted data into carrier (this may take a while)...")
        # Try to prefer new API: hide_data(input, output, real_blob, stego_seed, decoy_blob, decoy_seed, bits_per_channel)
        hide_success = False
        try:
            # If stego_seed is bytes, pass it through; otherwise pass password (legacy)
            if hasattr(steganography, "hide_data"):
                # attempt modern signature
                try:
                    hide_success = steganography.hide_data(
                        input_file=carrier,
                        output_file=output_file,
                        real_data=enc_real,
                        real_seed=stego_seed,
                        decoy_data=enc_decoy,
                        decoy_seed=decoy_seed,
                        bits_per_channel=bits_per_channel,
                        logger_in=logger  
                    )
                except TypeError:
                    # older signature: hide_data(input, output, real_blob, real_password, decoy_blob, decoy_password)
                    logger.debug("hide_data signature mismatch; trying legacy call (password strings).")
                    hide_success = steganography.hide_data(
                        carrier,
                        output_file,
                        enc_real,
                        real_pwd,
                        enc_decoy,
                        decoy_pwd
                    )
            else:
                raise StegoError("steganography.hide_data function not found.")
        except Exception as e:
            logger.error(f"Embedding failed: {e}")
            hide_success = False

        if hide_success:
            logger.info(f"✅ Success: hidden data written to '{output_file}'")
        else:
            raise StegoError("Embedding returned failure.")

    except (FileNotFoundError, StegoError, CryptoError) as e:
        logger.error(f"[Hide Error] {e}")
    except Exception as e:
        logger.error(f"[Hide Unexpected] {e}")
    finally:
        # cleanup temporary files & dirs
        for f in tmp_files:
            try:
                os.remove(f)
            except Exception:
                pass
        for d in tmp_dirs:
            try:
                shutil.rmtree(d)
            except Exception:
                pass

def retrieve_message_interactive() -> None:
    print("\n--- Extract Message or File (Interactive) ---")
    infile = input("Hidden file (e.g., secret.png): ").strip().strip('"')
    algo = input("Algorithm used [AES / ChaCha20] (default=AES): ").strip().lower() or "aes"
    double = input("Was data double-encrypted? (y/N): ").strip().lower() == "y"

    print("\nChoose bits per channel used during hiding:")
    print("  1 — Maximum stealth (default)")
    print("  2 — Balanced")
    print("  3 — High capacity")
    b = input("Bits per channel [1/2/3] (default=1): ").strip() or "1"
    bits = {"1":1,"2":2,"3":3}.get(b,"1")
    retrieve_message(infile, algo=algo, double=double, bits_per_channel=bits)

def retrieve_message(input_file: str, algo: str = "aes", double: bool = False, bits_per_channel: int = 1) -> None:

    """
    The main 'retrieve' logic. Calls steganography.retrieve_data(), decrypts, decompresses, and saves the result.
    """
    try:
        if not os.path.exists(input_file):
            logger.error(f"File '{input_file}' not found.")
            return

        algo_norm = "aes" if algo in ("aes", "") else "chacha20" if algo in ("chacha20", "chacha") else "aes"

        # Ask for password (first-level)
        password = getpass.getpass("Enter the secret password to decrypt: ")

        # Derive stego seed (try crypto API)
        stego_seed = None
        try:
            stego_seed = _get_stego_seed(password)
        except Exception as e:
            logger.debug(f"derive_stego_seed fallback failed: {e}")
            stego_seed = None

        # Attempt to retrieve encrypted payload and partition info.
        # Many steganography versions: retrieve_data(input, password) OR retrieve_data(input, seed)
        encrypted_blob = None
        partition_label = None
        try:
            # Try modern: retrieve_data(input, seed, bits_per_channel?) -> returns (payload, partition)
            if hasattr(steganography, "retrieve_data"):
                # prefer calling with seed bytes
                try:
                    # Pass logger for progress bars / output
                    result = steganography.retrieve_data(input_file, stego_seed,
                                     bits_per_channel=bits_per_channel,
                                     logger_in=logger)

                    if isinstance(result, tuple) and len(result) >= 1:
                        encrypted_blob, partition_label = result[0], result[1] if len(result) > 1 else None
                except TypeError:
                    # maybe legacy: retrieve_data(input, password)
                    logger.debug("steganography.retrieve_data signature mismatch; trying legacy password call.")
                    result = steganography.retrieve_data(input_file, password)
                    if isinstance(result, tuple):
                        encrypted_blob, partition_label = result[0], result[1] if len(result) > 1 else None
                    else:
                        encrypted_blob = result
                except Exception as e:
                    logger.debug(f"retrieve_data( seed ) failed: {e}")
                    # fallback next
            else:
                raise StegoError("steganography.retrieve_data not found.")
        except Exception as e:
            logger.debug(f"retrieve_data attempts raised: {e}")

        if not encrypted_blob:
            logger.error("No hidden data found for that password/seed.")
            return

        # If partition indicates decoy, warn user
        if partition_label and str(partition_label).upper().startswith("A"):
            logger.warning("[!] Warning: Partition A (decoy) unlocked. Try another password for the real payload.")
        else:
            logger.info(f"Found data in partition: {partition_label or 'unknown/Full'}")

        # If double encryption requested, collect second password
        second_pwd = None
        if double:
            second_pwd = getpass.getpass("Enter SECOND password for double encryption: ")

        # Decrypt first (outer) layer
        # FIXED order
        if double:
            if not second_pwd:
                logger.error("Double encryption flagged but no second password provided.")
                return
            # first decrypt outer layer
            decrypted = _decrypt_payload(second_pwd, encrypted_blob, algo_norm)
            if decrypted is None:
                logger.error("First-stage (outer) decryption failed (wrong second password or integrity failure).")
                return
            # then decrypt inner layer
            decrypted = _decrypt_payload(password, decrypted, algo_norm)
            if decrypted is None:
                logger.error("Second-stage (inner) decryption failed (wrong real password or integrity failure).")
                return
        else:
            decrypted = _decrypt_payload(password, encrypted_blob, algo_norm)
            if decrypted is None:
                logger.error("Decryption failed (wrong password or integrity check failed).")
                return



        # Decompress
        try:
            decompressed = zlib.decompress(decrypted)
        except zlib.error:
            logger.error("Decompression failed: data corrupted or wrong decryption.")
            return

        # Parse payload: either FILE::<name>::<bytes> or TEXT::<message>
        try:
            header_parts = decompressed.split(b"::", 2)
            if header_parts[0] == b"FILE" and len(header_parts) == 3:
                filename = header_parts[1].decode("utf-8")
                file_data = header_parts[2]
                with open(filename, "wb") as fh:
                    fh.write(file_data)
                logger.info(f"🎉 Extracted file saved as '{filename}' ({format_bytes(len(file_data))})")
                if filename.lower().endswith(".zip"):
                    logger.info("Note: extracted file is a ZIP — unzip to inspect contents.")
            elif header_parts[0] == b"TEXT" and len(header_parts) >= 2:
                message = header_parts[1].split(b"::", 1)[0].decode("utf-8")
                logger.info("🎉 SECRET MESSAGE:")
                logger.info(message)
            else:
                # Legacy fallback: treat entire decompressed as text
                try:
                    text = decompressed.decode("utf-8")
                    logger.info("🎉 SECRET (legacy format):")
                    logger.info(text)
                except Exception:
                    logger.warning("Unknown payload format; could not parse data.")
        except Exception as e:
            logger.error(f"Failed to parse payload: {e}")

    except Exception as e:
        logger.error(f"[Retrieve Error] {e}")

# -------------------------
# Steganalysis helper (Chi-squared on LSBs)
# -------------------------
def analyze_image(path: str) -> None:
    """
    Runs a simple Chi-Squared test on the LSBs. Not foolproof, but a good quick check for randomness.
    """
    try:
        if not os.path.exists(path):
            logger.error(f"File '{path}' not found.")
            return
        img = Image.open(path)
        arr = np.array(img)
        # flatten and take LSB of each channel value
        lsb = (arr & 1).flatten()
        ones = int(lsb.sum())
        zeros = int(lsb.size - ones)
        chi, p = chisquare([ones, zeros])
        logger.info(f"Chi-squared = {chi:.2f}, p-value = {p:.4f}")
        if p < 0.05:
            logger.warning("⚠ Possible non-random LSB distribution — embedding suspected.")
        else:
            logger.info("✅ LSBs appear statistically random (no obvious embedding).")
    except Exception as e:
        logger.error(f"[Analyze Error] {e}")

# -------------------------
# CLI parser & interactive menu
# -------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Advanced Crypto-Steganography Tool (v3.4)")
    sub = parser.add_subparsers(dest="command", help="commands")

    # hide
    hide_p = sub.add_parser("hide", help="Hide a message or file")
    hide_p.add_argument("-i", "--input", required=True, help="Carrier file (PNG/WAV/JPG/BMP/FLAC)")
    hide_p.add_argument("-o", "--output", required=True, help="Output file")
    hide_p.add_argument("-t", "--text", help="Text to hide (optional)")
    hide_p.add_argument("-f", "--file", help="Secret file or folder to hide (optional)")
    hide_p.add_argument("--decoy", help="Optional decoy text")
    hide_p.add_argument("--algo", choices=["aes", "chacha20"], default="aes", help="Encryption algorithm")
    hide_p.add_argument("--double", action="store_true", help="Apply double encryption")
    hide_p.add_argument("--bits", type=int, choices=[1,2,3], default=1,
                        help="LSB bits per channel (1=secure,2=balanced,3=capacity)")

    # extract
    extract_p = sub.add_parser("extract", help="Extract hidden data")
    extract_p.add_argument("-i", "--input", required=True, help="Hidden file")
    extract_p.add_argument("--algo", choices=["aes", "chacha20"], default="aes")
    extract_p.add_argument("--double", action="store_true")
    extract_p.add_argument("--bits", type=int, choices=[1,2,3], default=1,
                        help="LSB bits per channel used during hiding (1=secure,2=balanced,3=capacity)")


    # capacity
    cap_p = sub.add_parser("capacity", help="Check carrier capacity")
    cap_p.add_argument("-i", "--input", required=True, help="Carrier file")
    cap_p.add_argument("--bits", type=int, choices=[1,2,3], default=1,
                    help="LSB bits per channel (1/2/3)")


    # analyze
    an_p = sub.add_parser("analyze", help="Analyze image LSBs (chi-squared)")
    an_p.add_argument("-i", "--input", required=True, help="Image file to analyze")

    return parser.parse_args()

def main_menu() -> str:
    print("\n--- Advanced Crypto-Steganography (v3.4) ---")
    print("1. 🔐 Hide message or file")
    print("2. 🔍 Extract message or file")
    print("3. 📊 Check capacity")
    print("4. 🔬 Analyze carrier (LSB chi²)")
    print("5. ❌ Exit")
    return input("Select an option (1–5): ").strip()

# -------------------------
# Entry point
# -------------------------
if __name__ == "__main__":
    args = parse_args()
    if not args.command:
        # Interactive fallback menu
        while True:
            sel = main_menu()
            if sel == "1":
                hide_message_interactive()
            elif sel == "2":
                retrieve_message_interactive()
            elif sel == "3":
                f = input("Carrier file (e.g., photo.png): ").strip().strip('"')
                print("\nBits per channel to analyze capacity:")
                print("  1 — Secure (default)")
                print("  2 — Balanced (recommended)")
                print("  3 — High capacity")
                b = input("Choose [1/2/3] (default=1): ").strip() or "1"
                bits = {"1":1,"2":2,"3":3}.get(b,1)
                check_capacity(f, bits_per_channel=bits)

            elif sel == "4":
                f = input("Image to analyze: ").strip().strip('"')
                analyze_image(f)
            elif sel == "5":
                logger.info("Goodbye!")
                break
            else:
                logger.warning("Invalid selection; try again.")
    else:
        # CLI-mode
        try:
            if args.command == "hide":
                hide_message(
                    input_file=args.input,
                    output_file=args.output,
                    text=args.text,
                    secret_file=args.file,
                    decoy_text=args.decoy,
                    algo=args.algo,
                    double=args.double,
                    bits_per_channel=args.bits
                )
            elif args.command == "extract":
                retrieve_message(args.input, algo=args.algo, double=args.double, bits_per_channel=args.bits)

            elif args.command == "capacity":
                check_capacity(args.input, bits_per_channel=args.bits)
            elif args.command == "analyze":
                analyze_image(args.input)
            else:
                logger.error("Unknown command.")
        except Exception as e:
            logger.error(f"[Main Error] {e}")
