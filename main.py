"""
main.py — CLI entry point for TrustedVault.

TrustedVault: Trusted Execution Framework for Machine-Locked File Exchange.

Encrypts files to a specific hardware fingerprint and enforces two-factor
decryption: cloud whitelist authorization + cryptographic hardware binding.

Usage:
    python main.py identity              Show this machine's hardware fingerprint
    python main.py encrypt <file>        Encrypt a file locked to THIS machine
    python main.py decrypt <file.vault>  Decrypt a vault file
    python main.py watch <folder>        Start the invisible decryptor service
    python main.py demo <file.vault>     Run the access revocation demo
    python main.py register              Show Firebase device registration steps
"""

import argparse
import os
import sys


def cmd_identity(_args) -> None:
    """Display the current machine's hardware fingerprint."""
    from identity_module import display_fingerprint
    display_fingerprint()


def cmd_encrypt(args) -> None:
    """
    Encrypt a file and lock it to the current machine's hardware fingerprint.

    The output file is saved alongside the input file with a .vault extension.
    """
    from encryptor import encrypt_file
    from identity_module import get_hardware_fingerprint

    input_path = args.file
    if not os.path.isfile(input_path):
        print(f"❌ File not found: {input_path}")
        sys.exit(1)

    # Derive output path: same directory, same stem, .vault extension
    base = os.path.splitext(input_path)[0]
    output_path = f"{base}.vault"

    print(f"🔑 Reading hardware fingerprint...")
    hw = get_hardware_fingerprint()
    fingerprint = hw["fingerprint"]
    print(f"   Fingerprint: {fingerprint[:16]}...")

    encrypt_file(input_path, output_path, fingerprint)


def cmd_decrypt(args) -> None:
    """Decrypt a .vault file to the temp_view directory."""
    from decryptor import decrypt_file

    vault_path = args.file
    if not os.path.isfile(vault_path):
        print(f"❌ Vault file not found: {vault_path}")
        sys.exit(1)

    success = decrypt_file(vault_path)
    if not success:
        sys.exit(1)


def cmd_watch(args) -> None:
    """Start the invisible decryptor service on the given folder."""
    from decryptor import watch_folder

    folder = args.folder
    if not os.path.isdir(folder):
        print(f"❌ Directory not found: {folder}")
        sys.exit(1)

    watch_folder(folder)


def cmd_demo(args) -> None:
    """Run the interactive access revocation demonstration."""
    from revocation_demo import run_revocation_demo

    vault_file = args.file
    if not os.path.isfile(vault_file):
        print(f"❌ Vault file not found: {vault_file}")
        sys.exit(1)

    run_revocation_demo(vault_file)


def cmd_register(_args) -> None:
    """Display Firebase device registration instructions for this machine."""
    from cloud_auth import register_device
    from identity_module import get_hardware_fingerprint

    hw = get_hardware_fingerprint()
    register_device(hw["fingerprint"])


def build_parser() -> argparse.ArgumentParser:
    """
    Build and return the CLI argument parser.

    Returns:
        argparse.ArgumentParser: Configured parser with all subcommands.
    """
    parser = argparse.ArgumentParser(
        prog="trustedvault",
        description=(
            "TrustedVault — Trusted Execution Framework for Machine-Locked File Exchange.\n\n"
            "Encrypts files to a specific hardware fingerprint and enforces two-factor\n"
            "decryption: cloud whitelist authorization + cryptographic hardware binding."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py identity\n"
            "  python main.py encrypt report.pdf\n"
            "  python main.py decrypt report.vault\n"
            "  python main.py watch ./incoming\n"
            "  python main.py demo report.vault\n"
            "  python main.py register\n"
        ),
    )

    subparsers = parser.add_subparsers(title="commands", dest="command")
    subparsers.required = True

    # identity
    subparsers.add_parser(
        "identity",
        help="Show this machine's hardware fingerprint (UUID + MAC + SHA-256 hash).",
    ).set_defaults(func=cmd_identity)

    # encrypt
    enc_parser = subparsers.add_parser(
        "encrypt",
        help="Encrypt a file and lock it to THIS machine's hardware fingerprint.",
    )
    enc_parser.add_argument("file", help="Path to the plaintext file (PDF or TXT).")
    enc_parser.set_defaults(func=cmd_encrypt)

    # decrypt
    dec_parser = subparsers.add_parser(
        "decrypt",
        help=(
            "Decrypt a .vault file. Requires cloud authorization AND matching hardware. "
            "Output goes to ./temp_view/."
        ),
    )
    dec_parser.add_argument("file", help="Path to the .vault file to decrypt.")
    dec_parser.set_defaults(func=cmd_decrypt)

    # watch
    watch_parser = subparsers.add_parser(
        "watch",
        help=(
            "Start the invisible decryptor service. "
            "Auto-decrypts any .vault file dropped into the folder."
        ),
    )
    watch_parser.add_argument("folder", help="Directory to monitor for .vault files.")
    watch_parser.set_defaults(func=cmd_watch)

    # demo
    demo_parser = subparsers.add_parser(
        "demo",
        help=(
            "Run the interactive revocation demo: decrypt → revoke in Firebase → "
            "retry to confirm denial."
        ),
    )
    demo_parser.add_argument("file", help="Path to an existing .vault file for the demo.")
    demo_parser.set_defaults(func=cmd_demo)

    # register
    subparsers.add_parser(
        "register",
        help="Show step-by-step instructions to register this device in Firebase.",
    ).set_defaults(func=cmd_register)

    return parser


def main() -> None:
    """Parse CLI arguments and dispatch to the appropriate command handler."""
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
