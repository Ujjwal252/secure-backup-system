"""File decryption for AES-256-GCM encrypted backups in the Secure Backup System."""

import os
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from constants import IV_SIZE, HEADER_SIZE, SALT_SIZE, HASH_HEX_LENGTH
from key_manager import derive_key
from integrity import verify_integrity, compute_hash
from exceptions import (
    WrongPasswordError,
    FileIntegrityError,
    CorruptedFileError,
    BackupFileNotFoundError,
)
from utils import validate_file_exists, get_decrypted_output_path


def decrypt_file(input_path: str, password: str, output_folder: str = None) -> dict:
    """Decrypt an AES-256-GCM encrypted .enc file using a password.

    Parses the binary header to extract the salt, IV, and original SHA-256 hash,
    re-derives the AES key from the password and salt, decrypts the ciphertext,
    writes the restored file, and verifies its integrity against the stored hash.

    Parameters:
        input_path: Path to the .enc file to decrypt.
        password: Plaintext password (must match the one used tofile encrypt).
        output_folder: Optional folder for the restored file.
            If None, uses the same folder as input_path.

    Returns:
        A dictionary with keys:
            "status": "success"
            "output_path": path to the restored (decrypted) 
            "integrity": "verified"
            "original_hash": the hash read from the file header
            "restored_hash": the hash computed from the restored file

    Raises:
        BackupFileNotFoundError: if input_path does not exist.
        CorruptedFileError: if file is too small or header is malformed.
        WrongPasswordError: if the AES-GCM tag verification fails.
        FileIntegrityError: if SHA-256 of restored file doesn't match header.
    """
    try:
        validate_file_exists(input_path)

        with open(input_path, "rb") as encrypted_file:
            raw_data = encrypted_file.read()

        if len(raw_data) <= HEADER_SIZE:
            raise CorruptedFileError(
                f"File is too small to be a valid encrypted backup. "
                f"Expected > {HEADER_SIZE} bytes, got {len(raw_data)} bytes."
            )

        salt = raw_data[0:SALT_SIZE]
        iv = raw_data[SALT_SIZE:SALT_SIZE + IV_SIZE]
        original_hash = raw_data[SALT_SIZE + IV_SIZE : HEADER_SIZE].decode("utf-8")
        ciphertext = raw_data[HEADER_SIZE:]
        # Header parsed per the fixed layout defined in encryption.py.
        # Salt and IV are stored unencrypted — they are not secret. Only the
        # password (and thus the derived key) must remain secret.

        if len(original_hash) != HASH_HEX_LENGTH:
            raise CorruptedFileError(
                "Encrypted file header contains an invalid hash length."
            )

        key = derive_key(password, salt)
        # PBKDF2 with the same password and salt always produces
        # the same key. If the wrong password is given, a different key is
        # produced, and GCM authentication will fail in the next step.

        try:
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(iv, ciphertext, None)
        except InvalidTag:
            raise WrongPasswordError(
                "Incorrect password or corrupted file. "
                "The encrypted data could not be authenticated. "
                "Please check your password and try again."
            )
        # InvalidTag means either the password is wrong (producing
        # a different key) or the ciphertext was tampered with. Either way,
        # decryption must be aborted to prevent returning garbage data.

        if output_folder is None:
            output_folder = os.path.dirname(os.path.abspath(input_path))

        output_path = get_decrypted_output_path(input_path, output_folder)

        with open(output_path, "wb") as restored_file:
            restored_file.write(plaintext)

        # Post-decryption integrity check confirms the restored
        # file is bit-for-bit identical to the original file before encryption.
        verify_integrity(output_path, original_hash)

        restored_hash = compute_hash(output_path)

        return {
            "status": "success",
            "output_path": output_path,
            "integrity": "verified",
            "original_hash": original_hash,
            "restored_hash": restored_hash,
        }
    except (
        WrongPasswordError,
        FileIntegrityError,
        CorruptedFileError,
        BackupFileNotFoundError,
    ):
        raise
    except Exception as e:
        print(f"Decryption failed: {e}", file=sys.stderr)
        raise
