"""
decryptor.py — AES-GCM decryption and invisible folder watcher for TrustedVault.

Decryption enforces a strict two-factor check:
  1. Cloud authorization via Firebase Firestore whitelist.
  2. Hardware fingerprint match — wrong machine → cryptographic failure.

The watch_folder() function acts as an "invisible decryptor" service,
automatically decrypting any .vault file dropped into the watched directory.
"""

import os
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from cloud_auth import check_authorization
from encryptor import HEADER_SIZE, MAGIC_BYTES, NONCE_SIZE, derive_key
from identity_module import get_hardware_fingerprint

# Where decrypted files are temporarily written
DEFAULT_OUTPUT_DIR = "./temp_view"


def decrypt_file(vault_path: str, output_dir: str = DEFAULT_OUTPUT_DIR) -> bool:
    """
    Decrypt a .vault file to a temporary output directory.

    Two-factor enforcement:
        Factor 1 — Cloud authorization: if the current machine's fingerprint
                   is not in the Firebase whitelist, decryption is aborted.
        Factor 2 — Hardware match: if the vault was encrypted for a different
                   machine the AES-GCM authentication tag will not verify,
                   causing a cryptographic failure (hardware mismatch).

    Args:
        vault_path (str): Path to the .vault file to decrypt.
        output_dir (str): Directory to write the decrypted file into.
                          Created automatically if it does not exist.

    Returns:
        bool: True on successful decryption, False on any failure.
    """
    # ── Step 1: Extract hardware fingerprint ──────────────────────────────────
    try:
        hw = get_hardware_fingerprint()
        fingerprint = hw["fingerprint"]
        print(f"🔑 Hardware fingerprint: {fingerprint[:16]}...")
    except Exception as e:
        print(f"❌ Failed to read hardware identity: {e}")
        return False

    # ── Step 2: Cloud authorization ───────────────────────────────────────────
    print("☁️  Checking cloud authorization...")
    if not check_authorization(fingerprint):
        print("🚫 Decryption aborted — cloud authorization denied.")
        return False

    # ── Step 3: Read and validate vault file ──────────────────────────────────
    try:
        with open(vault_path, "rb") as fh:
            vault_data = fh.read()
    except FileNotFoundError:
        print(f"❌ Vault file not found: {vault_path}")
        return False
    except Exception as e:
        print(f"❌ Failed to read vault file: {e}")
        return False

    if len(vault_data) < HEADER_SIZE + NONCE_SIZE:
        print("❌ Vault file is too small or corrupt.")
        return False

    if vault_data[:8] != MAGIC_BYTES:
        print("❌ Invalid vault file — missing magic header (TVAULT01).")
        return False

    # ── Step 3: Derive AES key from fingerprint ───────────────────────────────
    try:
        key = derive_key(fingerprint)
    except Exception as e:
        print(f"❌ Key derivation failed: {e}")
        return False

    # ── Step 4: Attempt AES-GCM decryption ───────────────────────────────────
    nonce_start = HEADER_SIZE
    nonce_end = HEADER_SIZE + NONCE_SIZE
    nonce = vault_data[nonce_start:nonce_end]
    ciphertext = vault_data[nonce_end:]

    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        print("🚫 Hardware mismatch: This file is not authorized for this device.")
        return False
    except Exception as e:
        print(f"❌ Decryption error: {e}")
        return False

    # ── Step 5: Write decrypted file to output directory ──────────────────────
    try:
        os.makedirs(output_dir, exist_ok=True)
        _ensure_temp_readme(output_dir)

        base_name = os.path.basename(vault_path)
        # Strip .vault extension to restore original filename
        if base_name.endswith(".vault"):
            base_name = base_name[: -len(".vault")]

        out_path = os.path.join(output_dir, base_name)

        with open(out_path, "wb") as fh:
            fh.write(plaintext)

    except Exception as e:
        print(f"❌ Failed to write decrypted file: {e}")
        return False

    # ── Step 6: Report success ────────────────────────────────────────────────
    print(f"✅ File decrypted into secure temp folder: {os.path.abspath(out_path)}")
    return True


def watch_folder(watch_dir: str) -> None:
    """
    Monitor a folder for new .vault files and auto-decrypt them.

    This is the "Invisible Decryptor" service. It starts a watchdog observer
    that listens for file creation events. Any new .vault file triggers an
    immediate decrypt_file() call.

    Press Ctrl+C to stop the service.

    Args:
        watch_dir (str): Directory path to monitor.
    """
    if not os.path.isdir(watch_dir):
        print(f"❌ Watch directory does not exist: {watch_dir}")
        return

    print(f"👁️  Invisible Decryptor watching: {os.path.abspath(watch_dir)}")
    print("    Drop .vault files into this folder to auto-decrypt them.")
    print("    Press Ctrl+C to stop.\n")

    handler = _VaultFileHandler()
    observer = Observer()
    observer.schedule(handler, watch_dir, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Invisible Decryptor stopped.")
    finally:
        observer.stop()
        observer.join()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

class _VaultFileHandler(FileSystemEventHandler):
    """Watchdog event handler that decrypts newly created .vault files."""

    def on_created(self, event):
        """
        Triggered when a new file appears in the watched directory.

        Args:
            event: watchdog FileCreatedEvent object.
        """
        if not event.is_directory and event.src_path.endswith(".vault"):
            print(f"\n📥 New vault file detected: {event.src_path}")
            decrypt_file(event.src_path)


def _ensure_temp_readme(output_dir: str) -> None:
    """
    Write a warning README inside the temp_view directory if absent.

    Args:
        output_dir (str): Path to the temporary decryption output folder.
    """
    readme_path = os.path.join(output_dir, "README.txt")
    if not os.path.exists(readme_path):
        content = (
            "⚠️  TEMPORARY DECRYPTION FOLDER — TrustedVault\n"
            "=" * 50 + "\n\n"
            "Files in this folder were AUTO-DECRYPTED by TrustedVault.\n\n"
            "IMPORTANT:\n"
            "  - These files are NOT permanently stored or backed up.\n"
            "  - Do NOT leave sensitive files here after viewing.\n"
            "  - Delete files when finished to prevent data exposure.\n"
            "  - This folder should never be shared or committed to source control.\n\n"
            "Generated by TrustedVault — Trusted Execution Framework\n"
        )
        try:
            with open(readme_path, "w") as fh:
                fh.write(content)
        except Exception:
            pass  # Non-critical — don't fail decryption over a missing README
