"""
identity_module.py — Hardware fingerprint extraction for TrustedVault.

Extracts a unique, machine-locked identity by combining the system UUID
and primary MAC address, then hashing them into a single fingerprint.
"""

import hashlib
import platform
import subprocess
import uuid


def get_hardware_fingerprint() -> dict:
    """
    Extract hardware identity from the current machine.

    Collects the system UUID (via OS-specific commands) and the primary
    MAC address, then derives a SHA-256 fingerprint from their combination.

    Returns:
        dict with keys:
            - 'uuid'        (str): Platform-specific system UUID.
            - 'mac'         (str): MAC address as a hex string.
            - 'fingerprint' (str): SHA-256 hash of uuid+mac (cryptographic anchor).
    """
    system_uuid = _get_system_uuid()
    mac_address = _get_mac_address()

    combined = f"{system_uuid}{mac_address}"
    fingerprint = hashlib.sha256(combined.encode()).hexdigest()

    return {
        "uuid": system_uuid,
        "mac": mac_address,
        "fingerprint": fingerprint,
    }


def display_fingerprint() -> None:
    """
    Print a formatted summary of the current machine's hardware identity.

    Calls get_hardware_fingerprint() and displays each field with labels.
    """
    try:
        info = get_hardware_fingerprint()
        print("\n🔑 Hardware Identity Summary")
        print("=" * 50)
        print(f"  System UUID  : {info['uuid']}")
        print(f"  MAC Address  : {info['mac']}")
        print(f"  Fingerprint  : {info['fingerprint']}")
        print("=" * 50)
    except Exception as e:
        print(f"❌ Failed to retrieve hardware fingerprint: {e}")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_system_uuid() -> str:
    """
    Return a platform-specific system UUID string.

    - Windows : parsed from `wmic csproduct get uuid`
    - Linux   : contents of /etc/machine-id
    - macOS   : parsed from `ioreg -rd1 -c IOPlatformExpertDevice`

    Falls back to the MAC-based UUID node if all OS methods fail.
    """
    os_name = platform.system()

    try:
        if os_name == "Windows":
            result = subprocess.check_output(
                ["wmic", "csproduct", "get", "uuid"],
                stderr=subprocess.DEVNULL,
                timeout=5,
            ).decode().strip()
            lines = [ln.strip() for ln in result.splitlines() if ln.strip()]
            # Output format: header line "UUID" then the value
            if len(lines) >= 2:
                return lines[1]

        elif os_name == "Linux":
            with open("/etc/machine-id", "r") as fh:
                return fh.read().strip()

        elif os_name == "Darwin":  # macOS
            result = subprocess.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                stderr=subprocess.DEVNULL,
                timeout=5,
            ).decode()
            for line in result.splitlines():
                if "IOPlatformUUID" in line:
                    # Line example: "IOPlatformUUID" = "XXXXXXXX-..."
                    parts = line.split("=")
                    if len(parts) == 2:
                        return parts[1].strip().strip('"')

    except Exception:
        pass  # Fall through to fallback

    # Fallback: derive a UUID from the network node
    return str(uuid.UUID(int=uuid.getnode()))


def _get_mac_address() -> str:
    """
    Return the primary MAC address as a colon-separated hex string.

    Uses uuid.getnode() which reads the hardware address exposed by the OS.
    """
    node = uuid.getnode()
    # Format as 6 colon-separated hex pairs (e.g. "aa:bb:cc:dd:ee:ff")
    mac_hex = f"{node:012x}"
    return ":".join(mac_hex[i:i+2] for i in range(0, 12, 2))
