# File: steganography.py
# Version: 3.6 (FIX: Implemented true Alpha Channel skipping)
#
# Description:
#   - Fixes a bug where the Alpha (Transparency) channel was being modified.
#   - Now explicitly ignores the Alpha channel during capacity calculation,
#     hiding, and retrieval, preventing visual artifacts.
#   - Retains all v3.5 upgrades (Numpy, TQDM, Audio, bits-per-channel).

import logging
import os
import random
import hashlib
from typing import Tuple, Optional
from PIL import Image
import numpy as np
from tqdm import tqdm

# Requires: pip install pysoundfile numpy Pillow tqdm
try:
    import soundfile as sf
except ImportError:
    sf = None
    print("[Warning] 'pysoundfile' not installed. Audio formats (.wav, .flac) will not work.")

# Logger instance inherited from main
logger = logging.getLogger("stego_main")

# --- Bit/Byte Utility Functions ---

def _str_to_binary(data: bytes) -> str:
    """Converts bytes to a string of bits (e.g., b'A' -> '01000001')"""
    return ''.join(format(byte, '08b') for byte in data)

def _binary_to_bytes(binary_data: str) -> bytes:
    """Converts a string from bits to bytes"""
    byte_list = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    return bytes(int(b, 2) for b in byte_list if len(b) == 8)

def _get_data_header(data: bytes) -> str:
    """Creates a 4-byte (32-bit) length header containing the data length."""
    data_len_header = len(data).to_bytes(4, byteorder='big')
    return _str_to_binary(data_len_header)

def _read_header_from_bits(bit_stream: list) -> int:
    """Reads the first 32 bits and returns them as an integer (length)."""
    header_bits = "".join(bit_stream[:32])
    if len(header_bits) < 32:
        raise ValueError("Not enough bits for 32-bit header.")
    return int.from_bytes(_binary_to_bytes(header_bits), byteorder='big')

def _seed_to_int(seed: bytes | str) -> int:
    """
    Converts the seed (bytes or str) to an int for 'random.seed()'.
    If it's a str, uses the old SHA256 method (legacy fallback).
    """
    if isinstance(seed, str):
        logger.warning("Seed is a string (legacy). Using SHA256(password).")
        seed_bytes = hashlib.sha256(seed.encode()).digest()
    else:
        seed_bytes = seed
    return int.from_bytes(seed_bytes, "big")

# --- Core Embedding/Reading Logic (v3.5 logic) ---

def _embed_payload(flat_arr: np.ndarray, 
                   indices: list[int], 
                   payload_bytes: bytes, 
                   seed_int: int, 
                   bits_per_channel: int, 
                   desc: str):
    """
    Internal worker. Embeds payload bits into the carrier array (flat_arr) at the specified 'indices', shuffled by the 'seed_int'.
    """
    pbar = None
    bit_idx = 0
    try:
        payload_bits = list(map(int, _get_data_header(payload_bytes) + _str_to_binary(payload_bytes)))
        total_capacity_bits = len(indices) * bits_per_channel
        if len(payload_bits) > total_capacity_bits:
            raise ValueError(f"Payload ({desc}) too big: {len(payload_bits)} bits > {total_capacity_bits} available.")

        # shuffle once
        shuffled_indices = indices[:]
        rng = random.Random(seed_int)
        rng.shuffle(shuffled_indices)

        # create mapping from bit index -> flat_arr index and slot
        # Instead of computing ch_idx_in_partition every loop, expand indices per bits_per_channel
        # mapping[i] = (flat_index, bit_slot)
        mapping_len = len(shuffled_indices) * bits_per_channel
        # preallocate mapping arrays (faster than tuple list)
        flat_idx_map = [0] * mapping_len
        bit_slot_map = [0] * mapping_len
        pos = 0
        for idx in shuffled_indices:
            for slot in range(bits_per_channel):
                flat_idx_map[pos] = idx
                bit_slot_map[pos] = slot
                pos += 1

        # 4. LSB masking (independent of 8/16/24-bit type)
        mask = ~((1 << bits_per_channel) - 1)


        disable_pbar = not logger.isEnabledFor(logging.DEBUG) or len(payload_bits) > 2_000_000
        pbar = tqdm(payload_bits, desc=f"Embedding ({desc})", unit="bit", leave=False, disable=disable_pbar)

        for bit_to_write in pbar:
            # mapping direct lookup (no division/modulo)
            ch_idx = flat_idx_map[bit_idx]
            bit_slot = bit_slot_map[bit_idx]

            current_val = int(flat_arr[ch_idx])
            lower_group = current_val & ((1 << bits_per_channel) - 1)

            if bit_to_write == 1:
                lower_group |= (1 << bit_slot)
            else:
                lower_group &= ~(1 << bit_slot)

            flat_arr[ch_idx] = (current_val & mask) | lower_group
            bit_idx += 1

    except Exception as e:
        logger.error(f"❌ Error embedding ({desc}) at bit #{bit_idx}: {type(e).__name__} – {e}")
        if logger.isEnabledFor(logging.DEBUG):
            import traceback
            logger.debug(traceback.format_exc())
        raise
    finally:
        if pbar:
            pbar.close()



def _read_payload_from_indices(flat_arr: np.ndarray, 
                               indices: list[int], 
                               seed_int: int, 
                               bits_per_channel: int, 
                               desc: str) -> Optional[bytes]:
    """
    Internal worker. Tries to extract a payload from the carrier (flat_arr)
    using the provided 'indices' and 'seed_int'. Returns bytes or None on failure.
    """
    pbar_header = None
    pbar_data = None
    try:
        total_capacity_bits = len(indices) * bits_per_channel
        if total_capacity_bits < 32:
            return None

        disable_pbar = not logger.isEnabledFor(logging.DEBUG) or total_capacity_bits > 2_000_000

        shuffled_indices = indices[:]
        rng = random.Random(seed_int)
        rng.shuffle(shuffled_indices)

        # build mapping once
        mapping_len = len(shuffled_indices) * bits_per_channel
        flat_idx_map = [0] * mapping_len
        bit_slot_map = [0] * mapping_len
        pos = 0
        for idx in shuffled_indices:
            for slot in range(bits_per_channel):
                flat_idx_map[pos] = idx
                bit_slot_map[pos] = slot
                pos += 1

        # read header (32 bits)
        header_bits = []
        pbar_header = tqdm(total=32, desc=f"Reading Header ({desc})", unit="bit", leave=False, disable=disable_pbar)
        for i in range(32):
            ch_idx = flat_idx_map[i]
            bit_slot = bit_slot_map[i]
            val = int(flat_arr[ch_idx])
            lower_group = val & ((1 << bits_per_channel) - 1)
            bit = (lower_group >> bit_slot) & 1
            header_bits.append(str(bit))
            pbar_header.update(1)
        pbar_header.close()

        data_len_bytes = _read_header_from_bits(header_bits)
        total_bits_to_read = 32 + (data_len_bytes * 8)
        if total_bits_to_read > total_capacity_bits:
            return None

        # read data
        data_bits = []
        pbar_data = tqdm(total=data_len_bytes * 8, desc=f"Reading Data ({desc})", unit="bit", leave=False, disable=disable_pbar)
        for i in range(32, total_bits_to_read):
            ch_idx = flat_idx_map[i]
            bit_slot = bit_slot_map[i]
            val = int(flat_arr[ch_idx])
            lower_group = val & ((1 << bits_per_channel) - 1)
            bit = (lower_group >> bit_slot) & 1
            data_bits.append(str(bit))
            pbar_data.update(1)
        pbar_data.close()

        return _binary_to_bytes("".join(data_bits))

    except (ValueError, IndexError, TypeError):
        return None
    except Exception as e:
        logger.debug(f"Read payload ({desc}) failed: {e}")
        return None
    finally:
        if pbar_header: pbar_header.close()
        if pbar_data: pbar_data.close()



# --- Public API Functions ---

def get_carrier_capacity(filepath: str, bits_per_channel: int = 1, logger_in=None) -> Optional[dict]:
    """
    Calculates the capacity (in bytes) for a carrier file.
    bits_per_channel: 1, 2, or 3 (how many bits to use per channel/sample)
    Returns dict with available bytes per mode.
    NOTE: By default we ignore the alpha channel to avoid artifacts.
    """
    global logger
    if logger_in:
        logger = logger_in  # Use logger from main.py

    try:
        ext = os.path.splitext(filepath)[1].lower()
        if ext in (".png", ".bmp"):
            img = Image.open(filepath)
            bands = img.getbands()
            pixels = img.width * img.height

            # --- FIX: ALPHA CHANNEL HANDLING ---
            # Ignore Alpha channel to prevent visual artifacts
            if "A" in bands:
                channels = 3 # R, G, B (ignore A)
                logger.debug("Capacity: RGBA image detected, ignoring A channel.")
            else:
                channels = len(bands) # 1 (L) or 3 (RGB)
            
            total_slots = pixels * channels
            # --- END FIX ---
            
            total_bits = total_slots * bits_per_channel
            total_bytes = total_bits // 8
            header = 4  # bytes for data length

            return {
                "full_mode_bytes": max(total_bytes - header, 0),
                "decoy_mode_bytes_A": max((total_bytes // 2) - header, 0),
                "decoy_mode_bytes_B": max((total_bytes // 2) - header, 0),
                "bits_per_channel": bits_per_channel
            }

        elif ext in (".wav", ".flac"):
            if sf is None:
                logger.error("pysoundfile' library is not installed.")
                return None

            info = sf.info(filepath)
            total_slots = info.frames * info.channels
            total_bits = total_slots * bits_per_channel
            total_bytes = total_bits // 8
            header = 4

            return {
                "full_mode_bytes": max(total_bytes - header, 0),
                "decoy_mode_bytes_A": max((total_bytes // 2) - header, 0),
                "decoy_mode_bytes_B": max((total_bytes // 2) - header, 0),
                "bits_per_channel": bits_per_channel
            }

        else:
            logger.error(f"Unsupported file type: {ext}")
            return None

    except Exception as e:
        logger.error(f"[Capacity Error] {e}")
        return None




def hide_data(input_file: str, 
              output_file: str,
              real_data: bytes, 
              real_seed: bytes | str,
              decoy_data: Optional[bytes] = None, 
              decoy_seed: Optional[bytes | str] = None,
              bits_per_channel: int = 1,
              logger_in=None) -> bool:
    """
    Main 'hide' entrypoint for the stego module.
    Handles carrier loading (Image/Audio), index generation (skipping alpha),
    partitioning (for decoy mode), and calls _embed_payload to do the work.
    """
    global logger
    if logger_in: logger = logger_in

    try:
        # 0. Convert seeds to integers
        real_seed_int = _seed_to_int(real_seed)
        decoy_seed_int = _seed_to_int(decoy_seed) if decoy_seed else None

        # 1. Load the carrier into a flat numpy array
        ext = os.path.splitext(input_file)[1].lower()
        arr = None
        orig_shape = None
        
        if ext in (".png", ".bmp"):
            img = Image.open(input_file)
            
            # --- FIX: ALPHA CHANNEL HANDLING ---
            # Convert to RGBA only if transparency exists (P mode) or is already RGBA
            # to standardize the layout. Otherwise, convert to RGB.
            if "A" in img.getbands() or img.mode == "P":
                img = img.convert("RGBA")
                logger.debug("Image converted to RGBA (standardizing layout).")
            elif img.mode != "RGB":
                img = img.convert("RGB")
                logger.debug("Image converted to RGB.")
            # --- END FIX ---

            arr = np.array(img)
            orig_shape = arr.shape
            flat_arr = arr.flatten()
        
        elif ext in (".wav", ".flac"):
            if sf is None:
                raise ImportError("pysoundfile library required for audio.")
            data, sr = sf.read(input_file, always_2d=False)

            if data.dtype.kind == "f":
                data = (data * 32767).astype(np.int16)# Convert float audio to int16 for LSB manipulation

            orig_shape = data.shape
            arr = data # Store arr for dtype check later
            flat_arr = data.flatten()

        else:
            logger.error(f"Unsupported file type: {ext}")
            return False

        # 2. Create list of embeddable indices
        
        # --- FIX: ALPHA CHANNEL HANDLING ---
        # If image is (H, W, 4), create indices that skip the Alpha channel (every 4th)
        if ext in (".png", ".bmp") and arr is not None and arr.ndim == 3 and arr.shape[2] == 4:
            logger.info("RGBA image detected. Ignoring Alpha channel for embedding.")
            # Create a mask: True for R, G, B. False for A.
            # (H, W, 4) -> (H*W*4,)
            mask = np.ones(flat_arr.shape, dtype=bool)
            mask[3::4] = False # Ignore Alpha (index 3, 7, 11, ...)
            indices_full = np.where(mask)[0].tolist()
        else:
            # For RGB (H,W,3), L (H,W), or Audio (F,)
            indices_full = list(range(flat_arr.size))
        # --- END FIX ---

        # 3. Embed data
        if decoy_data and decoy_seed_int is not None:
            # A/B (Decoy) Mode Logic
            logger.info("Decoy mode: Splitting into Partition A (Decoy) and B (Real)...")
            mid = len(indices_full) // 2
            indices_A = indices_full[:mid]
            indices_B = indices_full[mid:]
            
            _embed_payload(flat_arr, indices_A, decoy_data, decoy_seed_int, bits_per_channel, "Decoy (A)")
            _embed_payload(flat_arr, indices_B, real_data, real_seed_int, bits_per_channel, "Real (B)")
        else:
            # Full (Real-Only) Mode Logic
            logger.info("Standard mode: Using Full Partition...")
            _embed_payload(flat_arr, indices_full, real_data, real_seed_int, bits_per_channel, "Real (Full)")

        # 4. Save the modified carrier
        logger.info(f"Saving file to {output_file}...")
        # IMPORTANT: flat_arr was modified in-place. Reshape it to the original shape.
        new_arr = flat_arr.reshape(orig_shape).astype(arr.dtype)
        
        if ext in (".png", ".bmp"):
            # new_arr has the correct shape (H,W,4) or (H,W,3)
            # The Alpha channel (if present) was never touched.
            out_img = Image.fromarray(new_arr, mode=img.mode)
            out_img.save(output_file)
        elif ext in (".wav", ".flac"):
            sf.write(output_file, new_arr, sr)
            
        logger.info("Embedding complete.")
        return True

    except Exception as e:
        logger.error(f"[Hide Error] {e}")
        return False


def retrieve_data(input_file: str, 
                  seed: bytes | str, 
                  bits_per_channel: int = 1,
                  logger_in=None) -> Tuple[Optional[bytes], Optional[str]]:
    """
    Main 'retrieve' entrypoint. Tries to find a valid payload using the seed.
    It intelligently scans partitions in the correct order (B -> Full -> A)
    to find the real data first. Returns (data, partition_label) or (None, None).
    """
    global logger
    if logger_in:
        logger = logger_in

    try:
        seed_int = _seed_to_int(seed)

        # 1. Load carrier
        ext = os.path.splitext(input_file)[1].lower()
        arr = None
        
        if ext in (".png", ".bmp"):
            img = Image.open(input_file)
            arr = np.array(img)
            flat_arr = arr.flatten()
            
        elif ext in (".wav", ".flac"):
            if sf is None:
                raise ImportError("pysoundfile library required for audio.")
            data, sr = sf.read(input_file, always_2d=False)

            if data.dtype.kind == "f":
                data = (data * 32767).astype(np.int16)

            arr = data # Store for dtype check
            flat_arr = data.flatten()

        else:
            logger.error(f"Unsupported file type: {ext}")
            return None, None

        # 2. Create list of embeddable indices
        
        # --- FIX: ALPHA CHANNEL HANDLING ---
        # (Must match hide_data logic)
        if ext in (".png", ".bmp") and arr is not None and arr.ndim == 3 and arr.shape[2] == 4:
            logger.debug("RGBA image detected. Ignoring Alpha channel for retrieval.")
            mask = np.ones(flat_arr.shape, dtype=bool)
            mask[3::4] = False # Ignore Alpha (index 3, 7, 11, ...)
            indices_full = np.where(mask)[0].tolist()
        else:
            indices_full = list(range(flat_arr.size))
        # --- END FIX ---

        mid = len(indices_full) // 2
        indices_A = indices_full[:mid]
        indices_B = indices_full[mid:]

        logger.info("Scanning partitions with provided seed...")

        # --- Try Partition B (Real) ---
        logger.debug("Attempting read from Partition B (Real)...")
        data_B = _read_payload_from_indices(flat_arr, indices_B, seed_int, bits_per_channel, "B")
        if data_B is not None:
            logger.info("✅ Valid payload found in Partition B (Real).")
            return data_B, "B (Real)"
        else:
            logger.debug("⛔ No data found in Partition B.")

        # --- Try Partition Full (Real-Only) ---
        logger.debug("Attempting read from Partition Full (Real-Only)...")
        data_Full = _read_payload_from_indices(flat_arr, indices_full, seed_int, bits_per_channel, "Full")
        if data_Full is not None:
            logger.info("✅ Payload found in Partition Full (Real-Only).")
            return data_Full, "Full (Real-Only)"
        else:
            logger.debug("⛔ No data found in Partition Full.")

        # --- Try Partition A (Decoy) ---
        logger.debug("Attempting read from Partition A (Decoy)...")
        data_A = _read_payload_from_indices(flat_arr, indices_A, seed_int, bits_per_channel, "A")
        if data_A is not None:
            logger.warning("⚠ Payload found in Partition A (Decoy).")
            return data_A, "A (Decoy)"
        else:
            logger.debug("⛔ No data found in Partition A.")

        # --- No success ---
        logger.warning("No valid payload found for the given seed.")
        return None, None

    except Exception as e:
        logger.error(f"[Retrieve Error] {e}")
        return None, None