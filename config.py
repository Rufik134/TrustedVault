"""
config.py — Firebase configuration constants for TrustedVault.

Stores Firebase project credentials and endpoint templates.
Replace placeholder values with real Firebase credentials before use.
"""

# Firebase project credentials
FIREBASE_API_KEY = "YOUR_API_KEY"
FIREBASE_PROJECT_ID = "cybersec-ddd85"
FIREBASE_PROJECT_NUMBER = "1088924217709"

# If True, encryption/decryption uses a shared project key rather than a per-device
# key derived from the hardware fingerprint. This allows any device that is
# whitelisted in Firebase to decrypt any .vault file (at the cost of losing the
# “machine lock” property).
ALLOW_WHITELIST_WIDE_DECRYPTION = True

FIREBASE_AUTH_DOMAIN = f"{FIREBASE_PROJECT_ID}.firebaseapp.com"
FIREBASE_STORAGE_BUCKET = f"{FIREBASE_PROJECT_ID}.appspot.com"

# Firestore collection that holds authorized device documents
FIREBASE_COLLECTION = "authorized_devices"

# Firestore REST API base URL
FIRESTORE_BASE_URL = "https://firestore.googleapis.com/v1"

# Whitelist endpoint template — format with PROJECT_ID, COLLECTION, and fingerprint
WHITELIST_ENDPOINT = (
    f"{FIRESTORE_BASE_URL}/projects/{{project_id}}"
    f"/databases/(default)/documents/{{collection}}/{{fingerprint}}"
)
