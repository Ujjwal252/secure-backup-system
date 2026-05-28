# Secure Backup System — AES-256 Encryption

## Project Overview
A Python application to encrypt and decrypt files using AES-256-GCM with PBKDF2 key derivation and SHA-256 integrity verification.

## Features
- AES-256-GCM encryption (authenticated encryption)
- PBKDF2-HMAC-SHA256 key derivation (390,000 iterations)
- SHA-256 file integrity verification
- Wrong password detection without crash
- Tkinter GUI with Encrypt and Restore tabs

## Project Structure
- `main.py` — Application entry point that launches the Tkinter GUI
- `ui.py` — Tkinter-based interface for encryption and restoration
- `encryption.py` — AES-256-GCM file encryption module
- `decryption.py` — AES-256-GCM file decryption and integrity verification module
- `key_manager.py` — PBKDF2 key derivation and salt generation
- `integrity.py` — SHA-256 hashing and file verification helpers
- `utils.py` — File path helpers, password validation, and formatting utilities
- `exceptions.py` — Custom exceptions for encryption, decryption, and file validation
- `constants.py` — Shared project constants for sizes and formats
- `tests/` — Pytest test suite covering encryption and decryption flows

## Setup & Installation
1. Install Python 3.9 or newer.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the application:
   ```bash
   python main.py
   ```

## How to Use
1. Launch the GUI with `python main.py`.
2. On the **Encrypt** tab:
   - Browse for a file to encrypt.
   - Enter a password and confirm it.
   - Click **Encrypt & Backup**.
3. On the **Restore** tab:
   - Browse for an encrypted `.enc` file.
   - Enter the original password.
   - Optionally choose an output folder.
   - Click **Restore File**.

## Encrypted File Format
The encrypted `.enc` file uses this binary layout:

- Bytes 0–15: salt (16 bytes)
- Bytes 16–27: IV (12 bytes)
- Bytes 28–91: original_hash (64 bytes, UTF-8 encoded SHA-256 hex string)
- Bytes 92+: ciphertext + 16-byte GCM authentication tag

## Security Design
- AES-256-GCM provides authenticated encryption.
- PBKDF2-HMAC-SHA256 with a 16-byte random salt protects the password.
- A fresh random salt is generated per file and stored in the header.
- A unique 12-byte IV is generated per encryption operation.
- GCM authentication detects wrong passwords or tampering.
- SHA-256 post-decryption verification ensures restored data matches the original.

## Running Tests
From the project root:
```bash
pytest tests/ -v
```
