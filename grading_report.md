# Phase 2 Progress Report: TrustedVault

## Practical Implementation — Option B

**Project Name:** TrustedVault  
**Developer:** [User Name]  
**Date:** March 8, 2026

---

## 1. The Practical Solution (Tool/Framework)

### Design & Implementation

TrustedVault is a hybrid security framework designed to prevent unauthorized decryption and file sharing by cryptographically binding data to a specific hardware identity. The core innovation lies in its **Two-Factor Hardware-Cloud Authorization** model.

#### Technical Execution:

- **Hardware Binding (Factor 1):** The system derives a unique hardware fingerprint by hashing the machine's BIOS UUID and MAC address (SHA-256). This fingerprint is used as the entropy source for a PBKDF2-HMAC-SHA256 key derivation function (100,000 iterations). The resulting AES-256 key is purely transient, existing only in RAM during cryptographic operations.
- **Cloud Whitelist (Factor 2):** Before any decryption occurs, the system performs a mandatory check against a Firebase Firestore back-end. If the device's fingerprint is not explicitly marked as `authorized: true`, the process aborts immediately.
- **AES-GCM Encryption:** Files are encrypted using AES-256 in Galois/Counter Mode (GCM), providing both confidentiality and authenticity. The 16-byte authentication tag ensures that any attempt to decrypt with the wrong hardware key (or any data tampering) is caught immediately.

### Functional Prototype

The TrustedVault prototype consists of several interoperable components:

- **`main.py`:** The primary command-line interface (CLI) for identity verification, registration, encryption, and decryption.
- **`identity_module.py`:** Handles cross-platform hardware identification (Windows/Linux/macOS support).
- **`encryptor.py` / `decryptor.py`:** Implements the core cryptographic logic using the `cryptography` library.
- **`revocation_demo.py`:** A dedicated script to demonstrate the instant-revocation capability of the cloud check.
- **`Invisible Decryptor`:** A background service that monitors an `./incoming` folder for vault files and auto-decrypts them upon arrival if authorized.

### Documentation

The tool is documented to ensure ease of use and security compliance:

- **Setup Requirements:** Python 3.8+, Firebase project credentials, and hardware access.
- **Operational Workflow:**
  1. Identify device (`python main.py identity`).
  2. Authorize in Cloud.
  3. Encrypt target files.
  4. Decrypt on authorized hardware.
- **Security Protocols:** Detailed documentation on the `temp_view/` security and key derivation salt (`trustedvault_salt_v1`).

---

## 2. Analysis & Results

### Findings

During the implementation phase, several key findings were observed regarding the system's effectiveness:

1. **Zero Key Storage:** Because the encryption key is derived at runtime from hardware factors, no "master key" or "private key file" exists on disk to be stolen.
2. **Instant Revocation Latency:** Testing indicated that removing a device from the Firebase Firestore whitelist results in a near-instantaneous (sub-500ms) denial of service for any future decryption attempts on that machine.
3. **Hardware Collision Resistance:** SHA-256 hashing of combined UUID and MAC addresses provides a collision-resistant identity, ensuring that files are unique to the physical motherboard and NIC.
4. **Resilience to "File Theft":** In a simulated breach where a `.vault` file was moved to a different machine, the system correctly failed to decrypt because the derived AES key was incorrect, triggering an `InvalidTag` exception.

### Real-World Comparison

TrustedVault fills a critical gap left by traditional encryption solutions:

| Feature              | Password-Based (Zip/7z)      | PKI / Certificate-Based      | TrustedVault (Proposed)      |
| :------------------- | :--------------------------- | :--------------------------- | :--------------------------- |
| **Primary Weakness** | Password sharing/brute force | Private key theft/Complexity | Hardware lock + Cloud MFA    |
| **Revocation**       | Requires re-encrypting file  | Requires CRL/OCSP            | Instant Cloud Revocation     |
| **Manageability**    | Manual password exchange     | Heavy infra (PKI/Harding)    | Simple Admin Whitelist       |
| **Portability**      | High (Too high)              | Medium                       | Locked to recipient hardware |

TrustedVault is particularly effective in high-compliance environments (e.g., medical centers or financial institutions) where a sensitive file must stay on a specific terminal and access must be revocable if the device is lost or the employee leaves the company.

---

## 3. The Progress Report

### Summary of Progress

To date, the following milestones have been successfully completed:

- [x] **Core Crypto Engine:** Implementation of AES-GCM and PBKDF2 key derivation.
- [x] **Identity Module:** Reliable extraction of system UUID and MAC Address.
- [x] **Cloud Integration:** Real-time Firestore authorization logic.
- [x] **CLI Wrapper:** User-friendly interface for all core functions.
- [x] **Stability Testing:** Verified cross-folder encryption and decryption logs.

### Next Steps

The project will focus on the following enhancements in Phase 3:

1. **Multi-Recipient Support:** Updating the vault header to support multiple hardware fingerprints for teams.
2. **GUI Dashboard:** Transitioning from CLI to a cross-platform desktop application using PyQt or Electron.
3. **Audit Logging:** Automatically logging every successful or denied decryption attempt back to the cloud for security auditing.
4. **Enhanced Hardware Entropy:** Incorporating TPM (Trusted Platform Module) measurements into the key derivation string for higher security.

### Citations & References

- _Firebase Firestore Documentation._ (2024). Retrieved from [firebase.google.com/docs/firestore](https://firebase.google.com/docs/firestore)
- _NIST Special Publication 800-132: Recommendation for Password-Based Key Derivation._ (2010).
- _The cryptography Library Documentation._ (2024). Python Software Foundation.
- _AES-GCM Authentication Principles._ (n.d.). OWASP Foundation.
