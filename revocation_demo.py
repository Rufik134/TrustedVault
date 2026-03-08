"""
revocation_demo.py — Live revocation demonstration for TrustedVault.

Walks the user through the full authorization lifecycle:
  1. Shows the machine's hardware fingerprint.
  2. Attempts decryption (should succeed while authorized).
  3. Prompts the user to revoke access in Firebase.
  4. Re-attempts decryption (should fail at cloud auth after revocation).

This demo illustrates that access can be revoked instantly and remotely —
no file modification, no re-encryption, no physical device access required.
"""

from decryptor import decrypt_file
from identity_module import display_fingerprint, get_hardware_fingerprint


def run_revocation_demo(vault_file: str) -> None:
    """
    Run an interactive revocation lifecycle demonstration.

    Demonstrates that removing a device from the Firebase whitelist
    immediately prevents decryption — even for files the device could
    previously open — without touching the encrypted file itself.

    Args:
        vault_file (str): Path to an existing .vault file to use in the demo.
    """
    print("\n" + "=" * 60)
    print("  🔐 TrustedVault — Access Revocation Demo")
    print("=" * 60)

    # ── Step 1: Display hardware fingerprint ──────────────────────────────────
    print("\n📍 Step 1: Current Machine Hardware Identity")
    print("-" * 60)
    display_fingerprint()

    hw = get_hardware_fingerprint()
    fingerprint = hw["fingerprint"]

    # ── Step 2: First decryption attempt (authorized) ─────────────────────────
    print("\n📍 Step 2: Initial Decryption Attempt")
    print("-" * 60)
    print(f"Attempting to decrypt: {vault_file}")
    print()

    success = decrypt_file(vault_file)

    if success:
        print("\n✅ Decryption SUCCEEDED — device is currently authorized.")
    else:
        print(
            "\n⚠️  Initial decryption FAILED.\n"
            "   Make sure this device is registered in Firebase before running the demo.\n"
            f"   Fingerprint: {fingerprint}"
        )
        print("=" * 60)
        return

    # ── Step 3: Prompt user to revoke access ──────────────────────────────────
    print("\n" + "=" * 60)
    print("📍 Step 3: Revoke Access in Firebase")
    print("-" * 60)
    print(
        "\nNow go to your Firebase Firestore console and remove or\n"
        "set 'authorized' to false for the document with ID:\n\n"
        f"   {fingerprint}\n\n"
        "Firebase Console → Firestore Database → authorized_devices\n"
        "→ find the document → delete it or set authorized = false\n"
    )
    input("Press Enter once you have revoked access to continue the demo...")

    # ── Step 4: Second decryption attempt (revoked) ───────────────────────────
    print("\n📍 Step 4: Post-Revocation Decryption Attempt")
    print("-" * 60)
    print(f"Re-attempting decryption of: {vault_file}")
    print()

    success_after_revoke = decrypt_file(vault_file)

    # ── Result summary ────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  📊 Demo Result Summary")
    print("=" * 60)

    if not success_after_revoke:
        print("✅ Revocation WORKED — decryption was denied after whitelist removal.")
        print("   The file is unchanged. No re-encryption was needed.")
        print("   Access was revoked instantly via the cloud whitelist.")
    else:
        print("⚠️  Decryption still succeeded after revocation attempt.")
        print("   Verify that you deleted/disabled the correct Firestore document.")
        print(f"   Expected document ID: {fingerprint}")

    print("=" * 60)
    print("\n🔐 Demo complete.\n")
