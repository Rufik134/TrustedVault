"""
cloud_auth.py — Firebase Firestore cloud authorization for TrustedVault.

Checks whether a hardware fingerprint is listed as an authorized device
in the Firebase Firestore whitelist. Fails securely on any network error.
"""

import requests

from config import FIREBASE_COLLECTION, FIREBASE_PROJECT_ID, WHITELIST_ENDPOINT


def check_authorization(fingerprint: str) -> bool:
    """
    Verify whether the given hardware fingerprint is cloud-authorized.

    Makes a GET request to the Firebase Firestore REST API and checks for
    a document whose ID matches the fingerprint and contains `authorized: true`.

    Fails securely: any network error, timeout, or unexpected response
    is treated as DENIED.

    Args:
        fingerprint (str): SHA-256 hardware fingerprint to look up.

    Returns:
        bool: True if authorized, False otherwise.
    """
    url = WHITELIST_ENDPOINT.format(
        project_id=FIREBASE_PROJECT_ID,
        collection=FIREBASE_COLLECTION,
        fingerprint=fingerprint,
    )

    try:
        response = requests.get(url, timeout=10)

        if response.status_code == 404:
            print("❌ Cloud Authorization: DENIED — device not found in whitelist.")
            return False

        if response.status_code != 200:
            print(
                f"❌ Cloud Authorization: DENIED — unexpected HTTP {response.status_code}."
            )
            return False

        data = response.json()
        fields = data.get("fields", {})

        # Firestore REST API encodes booleans as {"booleanValue": true}
        authorized_field = fields.get("authorized", {})
        is_authorized = authorized_field.get("booleanValue", False)

        if is_authorized:
            print("✅ Cloud Authorization: GRANTED")
            return True
        else:
            print("❌ Cloud Authorization: DENIED — 'authorized' field is not true.")
            return False

    except requests.exceptions.ConnectionError:
        print("❌ Cloud Authorization: DENIED — no network connection (fail-secure).")
        return False
    except requests.exceptions.Timeout:
        print("❌ Cloud Authorization: DENIED — request timed out (fail-secure).")
        return False
    except Exception as e:
        print(f"❌ Cloud Authorization: DENIED — unexpected error: {e}")
        return False


def register_device(fingerprint: str) -> None:
    """
    Print step-by-step instructions for manually registering a device in Firebase.

    Auto-registration is intentionally not supported to keep the whitelist
    under administrator control.

    Args:
        fingerprint (str): The hardware fingerprint to register.
    """
    print("\n🔑 Device Registration Instructions")
    print("=" * 55)
    print("To authorize this machine, add it to your Firebase console:\n")
    print("  1. Go to https://console.firebase.google.com/")
    print(f"     and open project: '{FIREBASE_PROJECT_ID}'")
    print("  2. Navigate to Firestore Database → Data tab.")
    print(f"  3. Open (or create) the collection: '{FIREBASE_COLLECTION}'")
    print("  4. Click '+ Add document'.")
    print(f"  5. Set the Document ID to:\n\n        {fingerprint}\n")
    print("  6. Add a field:")
    print("        Field name : authorized")
    print("        Field type : boolean")
    print("        Field value: true")
    print("  7. Click Save.")
    print("\n  The device will be authorized on the next decryption attempt.")
    print("=" * 55)
