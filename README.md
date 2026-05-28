# secure-backup-system
Secure Backup System using AES-256-GCM Encryption | CNS Project
# 🔐 Secure Backup System using AES-256-GCM

> Cryptography and Network Security (22CS62) | LA2 Project
> NITTE (Deemed to be University) | AY 2025-2026

## 📌 Project Overview

A secure file backup system that encrypts any file using AES-256-GCM 
symmetric encryption, stores versioned backups in a dedicated vault, 
and restores files with SHA-256 integrity verification.

Built with Python + Tkinter, it handles wrong passwords and corrupted 
files safely, passing 10 automated security tests.

## 🔑 CNS Concepts Used

| Concept | Purpose |
|---------|---------|
| AES-256-GCM | Authenticated file encryption |
| PBKDF2-HMAC-SHA256 | Password to key derivation (390,000 iterations) |
| Cryptographic Salting | Rainbow table attack prevention |
| SHA-256 Hashing | File integrity verification |
| CSPRNG (os.urandom) | Secure salt and IV generation |
| Initialization Vectors | Semantic security per encryption |

## 🚀 How to Run

### Install dependencies
pip install -r requirements.txt

### Run the application
python main.py

### Run all tests
pytest tests/ -v

## 📁 Project Structure

secure_backup/
├── main.py              # Entry point — launches GUI
├── encryption.py        # AES-256-GCM file encryption
├── decryption.py        # AES-256-GCM file decryption
├── key_manager.py       # PBKDF2 key derivation + salt
├── integrity.py         # SHA-256 hashing + verification
├── backup_manager.py    # Vault storage + backup registry
├── ui.py                # Tkinter GUI (3 tabs)
├── utils.py             # File helpers + validators
├── constants.py         # Security constants
├── exceptions.py        # Custom exception classes
├── requirements.txt     # Project dependencies
└── tests/
    ├── conftest.py          # pytest path fix
    ├── test_encryption.py   # 5 encryption tests
    └── test_decryption.py   # 5 decryption tests

## 🛡️ Security Design

| Feature | Implementation |
|---------|---------------|
| Encryption | AES-256-GCM (AEAD) |
| Key Derivation | PBKDF2-HMAC-SHA256 |
| Iterations | 390,000 (OWASP 2023) |
| Salt Size | 16 bytes (os.urandom) |
| IV Size | 12 bytes (os.urandom) |
| Integrity Check | SHA-256 pre/post encryption |
| Wrong Password | GCM InvalidTag detection |
| Header Size | 92 bytes (salt + IV + hash) |

## 📦 Encrypted File Format

| Bytes | Size | Content |
|-------|------|---------|
| 0 – 15 | 16 bytes | PBKDF2 Salt |
| 16 – 27 | 12 bytes | AES-GCM IV |
| 28 – 91 | 64 bytes | SHA-256 hash of original |
| 92 + | Variable | AES-256-GCM Ciphertext + Auth Tag |

## ✅ Test Results

All 10 tests passing:

| Test | Result |
|------|--------|
| test_decrypt_restores_original_content | ✅ Pass |
| test_wrong_password_raises_WrongPasswordError | ✅ Pass |
| test_decrypt_returns_integrity_verified | ✅ Pass |
| test_hash_matches_after_decrypt | ✅ Pass |
| test_corrupted_file_raises_error | ✅ Pass |
| test_encrypt_creates_output_file | ✅ Pass |
| test_encrypted_file_has_correct_header | ✅ Pass |
| test_encrypt_returns_correct_dict_keys | ✅ Pass |
| test_encrypt_nonexistent_file_raises_error | ✅ Pass |
| test_same_file_different_salt_each_time | ✅ Pass |

## 🔧 Requirements

- Python 3.12+
- cryptography >= 41.0.0
- pytest >= 7.0.0
- tkinter (Python standard library)

## 👥 Team Members

| Name | Roll Number |
|------|-------------|
| Shivangi Singh | 1NT23CS223 |
| Shreyansh Singh | 1NT23CS229 |
| Ujjwal Raj | 1NT23CS260 |

## 🌍 Real World Applications

Same cryptographic stack used in:
- **WhatsApp** — AES-GCM end-to-end encryption
- **TLS 1.3** — AEAD cipher suites
- **Apple FileVault** — AES disk encryption
- **AWS S3** — Server-side encryption