# File: crypto.py
# Version: 3.4
# - Argon2id KDF for encryption keys (enc_key, mac_key)
# - deterministic derive_stego_seed(password) (Argon2id with domain salt)
# - AES-GCM & ChaCha20-Poly1305 support
# - HMAC-SHA256 appended for integrity (MAC computed over nonce+ciphertext)
# - encrypt_data/decrypt_data accept 'algo' param
# - encrypt_data returns: salt(16) + nonce(12) + ciphertext + mac(32)

import os
import hmac as py_hmac
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from argon2.low_level import hash_secret_raw, Type

# Argon2 parameters (tunable)
_ARGON_TIME = 3
_ARGON_MEMORY_KB = 64 * 1024  # 64 MB
_ARGON_PARALLELISM = 2

# Domain salt for deterministic stego seed derivation (fixed constant for domain separation)
_STEGO_DOMAIN_SALT = b"stego-stable-seed-v1"

def _derive_enc_mac_keys(password: str, salt: bytes) -> Tuple[bytes, bytes]:
    """
    Derive encryption key and MAC key (each 32 bytes) from password and random salt, using Argon2id.
    """
    key_material = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=_ARGON_TIME,
        memory_cost=_ARGON_MEMORY_KB,
        parallelism=_ARGON_PARALLELISM,
        hash_len=64,
        type=Type.ID
    )
    return key_material[:32], key_material[32:64]

def derive_stego_seed(password: str) -> bytes:
    """
    Deterministically derives the 32-byte stego_seed from a password.
    Uses Argon2id with a *fixed* domain salt (_STEGO_DOMAIN_SALT) to ensurethe same password *always* produces the same seed for placement.
    """
    seed = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=_STEGO_DOMAIN_SALT,
        time_cost=_ARGON_TIME,
        memory_cost=_ARGON_MEMORY_KB,
        parallelism=1,
        hash_len=32,
        type=Type.ID
    )
    return seed  # 32 bytes

# prepend a version marker so we can change format later safely
_CRYPTO_HEADER = b"CS01"  # CryptoStego v0.1 header

def encrypt_data(password: str, data: bytes, algo: str = "aes", include_hmac: bool = True) -> bytes | None:
    """
    Encrypts data using AES-GCM or ChaCha20. Prepends salt/nonce and appends HMAC.
    Returns: HEADER || salt(16) || nonce(12) || ciphertext || mac(32)
    """
    try:
        salt = os.urandom(16)
        enc_key, mac_key = _derive_enc_mac_keys(password, salt)

        nonce = os.urandom(12)
        algo_norm = (algo or "aes").lower()
        if algo_norm == "aes":
            aead = AESGCM(enc_key)
        elif algo_norm in ("chacha20", "chacha"):
            aead = ChaCha20Poly1305(enc_key)
        else:
            raise ValueError(f"Unsupported algorithm: {algo}")

        ciphertext = aead.encrypt(nonce, data, None)

        result = _CRYPTO_HEADER + salt + nonce + ciphertext
        if include_hmac:
            mac = py_hmac.new(mac_key, nonce + ciphertext, digestmod="sha256").digest()
            result += mac

        return result
    except Exception as e:
        print(f"[Crypto Error] Encryption failed: {e}")
        return None

def decrypt_data(password: str, encrypted_blob: bytes, algo: str = "aes") -> bytes | None:
    """
    Decrypt blob created by encrypt_data. Accepts both formats with/without HMAC.
    """
    try:
        if not encrypted_blob or len(encrypted_blob) < (len(_CRYPTO_HEADER) + 16 + 12 + 1):
            return None

        # check header
        if not encrypted_blob.startswith(_CRYPTO_HEADER):
            # Not our format
            return None

        # strip header
        blob = encrypted_blob[len(_CRYPTO_HEADER):]

        salt = blob[:16]
        nonce = blob[16:28]
        # mac MAY be present; detect by size: if len(blob) >= 16+12+32+1 then mac present at end
        possible_mac = None
        if len(blob) >= (16 + 12 + 32 + 1):
            possible_mac = blob[-32:]
            ciphertext = blob[28:-32]
        else:
            ciphertext = blob[28:]
            possible_mac = None

        enc_key, mac_key = _derive_enc_mac_keys(password, salt)

        if possible_mac is not None:
            mac_calc = py_hmac.new(mac_key, nonce + ciphertext, digestmod="sha256").digest()
            if not py_hmac.compare_digest(mac_calc, possible_mac):
                return None

        algo_norm = (algo or "aes").lower()
        if algo_norm == "aes":
            aead = AESGCM(enc_key)
        elif algo_norm in ("chacha20", "chacha"):
            aead = ChaCha20Poly1305(enc_key)
        else:
            raise ValueError(f"Unsupported algorithm: {algo}")

        plaintext = aead.decrypt(nonce, ciphertext, None)
        return plaintext
    except InvalidTag:
        return None
    except Exception as e:
        print(f"[Crypto Error] Decryption failed: {e}")
        return None


def derive_all(password: str, salt: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Legacy helper for old main.py versions that expected one function for all keys.
      Returns (enc_key, mac_key, stego_seed).
    """
    enc_key, mac_key = _derive_enc_mac_keys(password, salt)
    stego_seed = derive_stego_seed(password)
    return enc_key, mac_key, stego_seed
