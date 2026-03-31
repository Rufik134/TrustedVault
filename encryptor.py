"""
encryptor.py — AES-GCM encryption and key derivation for TrustedVault.

Files are encrypted with a key derived solely from the hardware fingerprint,
binding the ciphertext to a specific machine. The AES key is NEVER written
to disk — it exists only in memory during the encryption/decryption call.
"""

import os
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ── Vault file format constants ───────────────────────────────────────────────
MAGIC_BYTES = b"TVAULT01"          # 8-byte magic identifier
RESERVED_BYTES = b"\x00" * 8      # 8 reserved bytes (future use)
HEADER_SIZE = 16                   # 16 bytes total header
SALT_SIZE = 16                     # 16 bytes of per-file KDF salt
NONCE_SIZE = 12                    # AES-GCM standard 96-bit nonce

# ── KDF constants ─────────────────────────────────────────────────────────────
KDF_SALT = b"trustedvault_salt_v1"
KDF_ITERATIONS = 100_000
KEY_LENGTH = 32                    # 256-bit AES key


from config import ALLOW_WHITELIST_WIDE_DECRYPTION, FIREBASE_PROJECT_ID, FIREBASE_PROJECT_NUMBER


def _derive_shared_key(salt: bytes) -> bytes:
    """Derive a shared AES key used by all whitelist devices.

    This mode is intentionally weaker than the default, since it does not bind
    ciphertext to a specific hardware fingerprint. Use it only when you want
    every authorized (whitelisted) device to be able to decrypt the same vault
    files.
    """
    shared_secret = f"{FIREBASE_PROJECT_ID}:{FIREBASE_PROJECT_NUMBER}"

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(shared_secret.encode())


def derive_key_from_fingerprint(fingerprint: str, salt: bytes = KDF_SALT) -> bytes:
    """Derive the AES key based strictly on the hardware fingerprint.

    This is the original behavior (machine-locking)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(fingerprint.encode())


def derive_key(fingerprint: str, salt: bytes | None = None) -> bytes:
    """Derive a 256-bit AES key.

    By default, the key is derived from the hardware fingerprint. When
    ALLOW_WHITELIST_WIDE_DECRYPTION is enabled, a shared project key is used
    instead, allowing any whitelisted device to decrypt the same file.

    Args:
        fingerprint (str): SHA-256 hardware fingerprint string.

    Returns:
        bytes: 32-byte AES-256 key (exists only in memory).
    """
    if salt is None:
        salt = KDF_SALT

    if ALLOW_WHITELIST_WIDE_DECRYPTION:
        return _derive_shared_key(salt)

    return derive_key_from_fingerprint(fingerprint, salt)


def encrypt_file(input_path: str, output_path: str, fingerprint: str) -> None:
    """
    Encrypt a file with AES-GCM and lock it to the given hardware fingerprint.

    Output format (.vault):
        [MAGIC_BYTES (8)] [RESERVED (8)] [SALT (16)] [NONCE (12)] [CIPHERTEXT+TAG]

    The nonce is randomly generated per encryption — never reused.

    Args:
        input_path  (str): Path to the plaintext file (PDF or TXT supported).
        output_path (str): Destination path for the encrypted .vault file.
        fingerprint (str): Hardware fingerprint used to derive the AES key.

    Raises:
        FileNotFoundError: If input_path does not exist.
        Exception: On any encryption or I/O error.
    """
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")

    try:
        with open(input_path, "rb") as fh:
            plaintext = fh.read()

        salt = os.urandom(SALT_SIZE)
        key = derive_key(fingerprint, salt)
        nonce = os.urandom(NONCE_SIZE)

        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        with open(output_path, "wb") as fh:
            fh.write(MAGIC_BYTES)       # 8-byte magic
            fh.write(RESERVED_BYTES)    # 8 reserved bytes
            fh.write(salt)              # 16-byte per-file salt
            fh.write(nonce)             # 12-byte nonce
            fh.write(ciphertext)        # ciphertext + 16-byte GCM auth tag

        print(f"🔒 File encrypted and machine-locked successfully → {output_path}")

    except Exception as e:
        print(f"❌ Encryption failed: {e}")
        raise


def encrypt_file_for_device(input_path: str, target_fingerprint: str) -> str:
    """
    Encrypt a file for a DIFFERENT device using that device's hardware fingerprint.

    This allows a sender to lock a file so that only the recipient's machine
    can decrypt it — the sender never needs physical access to the target device.

    Args:
        input_path         (str): Path to the plaintext file to encrypt.
        target_fingerprint (str): Hardware fingerprint of the RECIPIENT's machine.

    Returns:
        str: Path to the generated .vault file.

    Raises:
        FileNotFoundError: If input_path does not exist.
    """
    base = os.path.splitext(os.path.basename(input_path))[0]
    output_path = os.path.join(
        os.path.dirname(input_path) or ".",
        f"{base}_for_{target_fingerprint[:8]}.vault",
    )

    print(f"🔑 Encrypting '{input_path}' for remote device fingerprint: {target_fingerprint[:16]}...")
    encrypt_file(input_path, output_path, target_fingerprint)
    return output_path


def _validate_header(data: bytes) -> bool:
    """
    Check that a vault file begins with the expected magic bytes.

    Args:
        data (bytes): Raw bytes of the vault file.

    Returns:
        bool: True if the header is valid, False otherwise.
    """
    if len(data) < HEADER_SIZE + NONCE_SIZE:
        return False
    return data[:8] == MAGIC_BYTES
