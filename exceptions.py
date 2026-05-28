"""Custom exceptions for the Secure Backup System using AES-256 Encryption."""


class WrongPasswordError(Exception):
    """Raised when AES-GCM decryption fails due to an incorrect password
    or a corrupted authentication tag.
    """


class FileIntegrityError(Exception):
    """Raised when the SHA-256 hash of the restored file does not match the
    hash stored inside the encrypted file header.
    """


class CorruptedFileError(Exception):
    """Raised when the encrypted file is too small to contain a valid header
    (minimum 92 bytes) or when the header format is invalid.
    """


class BackupFileNotFoundError(Exception):
    """Raised when a specified input file path does not exist on disk.
    Named BackupFileNotFoundError to avoid shadowing Python's built-in.
    """
