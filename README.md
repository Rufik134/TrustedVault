# TrustedVault — Trusted Execution Framework for Machine-Locked File Exchange

TrustedVault is a hybrid MFA file encryption system that cryptographically binds encrypted files to specific hardware. Unlike traditional password-based encryption, TrustedVault derives its encryption key directly from the machine's hardware identity — meaning a file encrypted on one device cannot be decrypted on any other device, even if an attacker possesses the file. This machine-locking approach eliminates credential sharing, key management overhead, and the risk of stolen passwords enabling unauthorized access.

The system enforces a strict two-factor authorization model at every decryption attempt. Factor one is a cloud-based whitelist check against Firebase Firestore — an administrator must explicitly register a device before it can decrypt any vault file. Factor two is the cryptographic hardware binding itself — the AES-256 key is derived in memory from the machine's SHA-256 hardware fingerprint (UUID + MAC address) using PBKDF2, so a wrong machine produces the wrong key and AES-GCM authentication fails. Revoking access is instant: remove the device from Firebase and no further decryption is possible, without touching or re-encrypting any files.

---

## Setup Instructions

### 1. Install Dependencies

```bash
cd trusted_vault
pip install -r requirements.txt
```

### 2. Firebase Project Setup

1. Go to [https://console.firebase.google.com/](https://console.firebase.google.com/) and create or open a project.
2. Navigate to **Firestore Database** → **Create database** (start in production mode).
3. Open `config.py` and update the following constants with your project's values:

```python
FIREBASE_API_KEY   = "your-real-api-key"
FIREBASE_PROJECT_ID = "your-project-id"
```

### 3. Firestore Collection & Document Structure

TrustedVault stores authorized device fingerprints as Firestore document IDs.

**Collection name:** `authorized_devices`

**Document structure:**
```
Document ID : <sha256-hardware-fingerprint>
Fields      : { authorized: true }   ← boolean field
```

To authorize a device, add a document where the ID is the device's fingerprint and set `authorized = true` (boolean). To revoke, delete the document or set `authorized = false`.

---

## Usage Walkthrough

### Show this machine's hardware identity
```bash
python main.py identity
```
Output includes the system UUID, MAC address, and the SHA-256 fingerprint used as the cryptographic anchor.

### Register this device in Firebase
```bash
python main.py register
```
Prints step-by-step instructions for adding this device to the Firebase whitelist.

### Encrypt a file (locked to THIS machine)
```bash
python main.py encrypt report.pdf
```
Creates `report.vault` alongside the original file. Only this machine (when cloud-authorized) can decrypt it.

### Encrypt a file for a DIFFERENT machine (programmatic)
```python
from encryptor import encrypt_file_for_device
encrypt_file_for_device("report.pdf", "<recipient-fingerprint>")
```

### Decrypt a vault file
```bash
python main.py decrypt report.vault
```
Decryption requires:
1. This machine's fingerprint must be in the Firebase whitelist.
2. The vault file must have been encrypted for this machine's fingerprint.

Decrypted output is written to `./temp_view/`.

### Start the Invisible Decryptor service
```bash
python main.py watch ./incoming
```
Monitors `./incoming/` for new `.vault` files and auto-decrypts them on arrival.

### Run the Revocation Demo
```bash
python main.py demo report.vault
```
Interactive walkthrough — see **Revocation Demo** section below.

---

## Security Architecture

### Factor 1 — Cloud Authorization (Firebase Firestore Whitelist)

Every decryption attempt makes a live REST call to Firebase Firestore to check whether the current machine's fingerprint exists as an authorized device. If the document is absent or `authorized` is not `true`, decryption is immediately aborted. This check happens **before** any cryptographic operation.

- **Fail-secure:** network errors, timeouts, and unexpected responses all default to DENIED.
- **Instant revocation:** deleting or disabling a Firestore document revokes access immediately, globally, without modifying any encrypted files.
- **Centralized control:** administrators manage the whitelist from the Firebase console with no software deployment required.

### Factor 2 — Hardware Fingerprint Binding (Cryptographic Lock)

The AES-256 encryption key is derived entirely in memory from the machine's hardware fingerprint:

```
fingerprint = SHA-256(system_UUID + MAC_address)
aes_key     = PBKDF2-HMAC-SHA256(fingerprint, salt="trustedvault_salt_v1", iterations=100000)
```

This key is **never stored to disk** — it is derived at runtime and discarded after use. Encrypting with one machine's fingerprint means only that machine produces the correct key; any other machine produces a different key, causing AES-GCM authentication tag verification to fail with an `InvalidTag` error.

### Vault File Format

```
Bytes 0–7   : Magic header "TVAULT01"
Bytes 8–15  : Reserved (8 zero bytes)
Bytes 16–27 : AES-GCM nonce (12 bytes, random per file)
Bytes 28+   : AES-GCM ciphertext + 16-byte authentication tag
```

---

## Revocation Demo

The revocation demo (`python main.py demo <file.vault>`) walks through the full lifecycle:

1. **Show hardware identity** — displays this machine's fingerprint.
2. **Decrypt (should succeed)** — confirms the device is currently authorized.
3. **Pause for manual revocation** — prompts you to go to Firebase and remove or disable the device's document.
4. **Re-attempt decryption (should fail)** — demonstrates that cloud denial is immediate and absolute.

This proves that the encrypted file is unchanged, no re-encryption was needed, and access revocation is purely administrative — enforced at runtime by the cloud check.

---

## Security Notes

- The `temp_view/` folder is a **temporary decryption output directory**. A `README.txt` is automatically placed inside it warning that files should not be stored there permanently.
- Never commit `.vault` files or `temp_view/` contents to version control.
- Rotate hardware fingerprints by updating the Firestore document ID when replacing hardware components.
- For production use, secure Firestore with proper security rules requiring server-side authentication rather than open REST API access.
