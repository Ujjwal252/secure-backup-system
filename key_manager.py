"""Password-based key derivation for the Secure Backup System."""

import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from constants import SALT_SIZE, KEY_SIZE, PBKDF2_ITERATIONS


def generate_salt() -> bytes:
    """Generate a cryptographically secure random salt for PBKDF2.

    Returns:
        A raw bytes salt of length SALT_SIZE.
    """
    return os.urandom(SALT_SIZE)


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES-256 key from a password and salt using PBKDF2.

    The same password and salt always produce the same key, allowing
    decryption to reconstruct the key without storing it directly.

    Parameters:
        password: The plaintext password.
        salt: The salt bytes used for PBKDF2.

    Returns:
        A 32-byte AES-256 key.
    """
    password_bytes = password.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    # PBKDF2 deliberately slows down brute-force attacks by running the hash
    # function 390,000 times per attempt.
    return kdf.derive(password_bytes)
