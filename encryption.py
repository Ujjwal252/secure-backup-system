"""File encryption using AES-256-GCM for the Secure Backup System."""

import os
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from constants import IV_SIZE, SALT_SIZE, HASH_HEX_LENGTH, HEADER_SIZE
from key_manager import generate_salt, derive_key
from integrity import compute_hash
from exceptions import BackupFileNotFoundError
from utils import validate_file_exists, get_encrypted_output_path


def encrypt_file(input_path: str, password: str, output_path: str = None) -> dict:
    """Encrypt a file using AES-256-GCM with a password-derived key.

    The encrypted output contains a binary header storing the salt, IV,
    and the SHA-256 hash of the original file. The hash is used later
    during decryption to verify the restored file is identical to the original.

    Binary layout of the output .enc file:
        Bytes 0–15   : salt (16 bytes)         — PBKDF2 salt
        Bytes 16–27  : iv (12 bytes)           — AES-GCM nonce
        Bytes 28–91  : original_hash (64 bytes)— SHA-256 hex digest (UTF-8)
        Bytes 92+    : ciphertext              — AES-GCM encrypted data + 16-byte auth tag

    Parameters:
        input_path  (str): Absolute or relative path to the file to encrypt.
        password    (str): Plaintext password used to derive the AES key.
        output_path (str): Optional. If None, appends ".enc" to input_path.

    Returns:
        dict with keys:
            "status"        : "success"
            "output_path"   : path to the .enc file
            "original_hash" : SHA-256 hex digest of the original file
            "file_size"     : size of the encrypted output file in bytes

    Raises:
        BackupFileNotFoundError : if input_path does not exist.
        OSError                 : if the output file cannot be written.
    """
    try:
        # Step 1: Validate the source file exists before attempting encryption.
        validate_file_exists(input_path)

        # Step 2: Hash computed BEFORE encryption to capture the original
        # file fingerprint. Stored in the header for post-decryption verification.
        original_hash = compute_hash(input_path)

        # Step 3: A new salt is generated for every encryption operation.
        # This ensures the same password produces a different key each time,
        # preventing precomputed dictionary attacks.
        # generate_salt() calls os.urandom() internally — always fresh bytes.
        salt = generate_salt()

        # Step 4: Derive a 32-byte AES-256 key from the password and fresh salt.
        key = derive_key(password, salt)

        # Step 5: Generate a fresh 12-byte IV (nonce) for AES-GCM.
        # IV must be unique per encryption. Reusing IV with the same key
        # completely breaks GCM confidentiality.
        iv = os.urandom(IV_SIZE)

        # Step 6: Read the entire source file into memory as plaintext bytes.
        with open(input_path, "rb") as source_file:
            plaintext = source_file.read()

        # Step 7: Encrypt using AES-256-GCM.
        # AESGCM.encrypt() appends a 16-byte authentication tag to the
        # ciphertext automatically. This tag is verified during decryption —
        # a wrong password causes InvalidTag to be raised, not garbage output.
        # The third argument (None) means no additional authenticated data (AAD).
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(iv, plaintext, None)

        # Step 8: Determine output path.
        if output_path is None:
            output_path = get_encrypted_output_path(input_path)

        # Step 9: Write the .enc file in the exact binary layout defined above.
        with open(output_path, "wb") as output_file:
            output_file.write(salt)                         # 16 bytes
            output_file.write(iv)                           # 12 bytes
            output_file.write(original_hash.encode("utf-8"))# 64 bytes
            output_file.write(ciphertext)                   # variable

        # Step 10: Return result metadata.
        file_size = os.path.getsize(output_path)
        return {
            "status": "success",
            "output_path": output_path,
            "original_hash": original_hash,
            "file_size": file_size,
        }

    except BackupFileNotFoundError:
        raise
    except Exception as e:
        print(f"[ERROR] Encryption failed: {e}", file=sys.stderr)
        raise