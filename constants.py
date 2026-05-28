"""Project-wide constants for the Secure Backup System."""

SALT_SIZE = 16  # bytes, used for PBKDF2 salt
IV_SIZE = 12  # bytes, recommended nonce size for AES-GCM (NIST SP 800-38D)
KEY_SIZE = 32  # bytes, gives AES-256
PBKDF2_ITERATIONS = 390000  # OWASP 2023 minimum for PBKDF2-HMAC-SHA256
HASH_HEX_LENGTH = 64  # SHA-256 hex digest is always 64 hex characters
HEADER_SIZE = 92  # SALT_SIZE + IV_SIZE + HASH_HEX_LENGTH = 16 + 12 + 64
CHUNK_SIZE = 65536  # 64 KB chunks for reading large files in integrity.py
FILE_EXTENSION = ".enc"  # extension appended to encrypted backup files
