"""File hashing and integrity verification for the Secure Backup System."""

import hashlib
import hmac

from constants import CHUNK_SIZE
from exceptions import FileIntegrityError


def compute_hash(file_path: str) -> str:
    """Compute the SHA-256 hash of a file and return it as a hex string.

    Reads the file in 64KB chunks for memory efficiency when processing
    large files.

    Parameters:
        file_path: The path to the file to hash.

    Returns:
        The 64-character SHA-256 hex digest.
    """
    sha256_obj = hashlib.sha256()
    with open(file_path, "rb") as file_handle:
        while True:
            chunk = file_handle.read(CHUNK_SIZE)
            if chunk == b"":
                break
            sha256_obj.update(chunk)
    return sha256_obj.hexdigest()


def verify_integrity(file_path: str, expected_hash: str) -> bool:
    """Verify that a file's SHA-256 hash matches the expected hash.

    Used after decryption to confirm the restored file is identical to the
    original source data.

    Parameters:
        file_path: The path to the file to verify.
        expected_hash: The expected SHA-256 hash in hex form.

    Returns:
        True when the integrity check passes.

    Raises:
        FileIntegrityError: When the actual hash does not match expected_hash.
    """
    actual_hash = compute_hash(file_path)
    # hmac.compare_digest prevents timing attacks during comparison.
    if hmac.compare_digest(actual_hash, expected_hash):
        return True

    raise FileIntegrityError(
        f"Integrity check FAILED. The restored file does not match the original. "
        f"Expected: {expected_hash[:16]}... Got: {actual_hash[:16]}..."
    )


def compute_hash_from_bytes(data: bytes) -> str:
    """Compute SHA-256 hash directly from a bytes object.

    Parameters:
        data: The bytes to hash.

    Returns:
        The SHA-256 hex digest of the input bytes.
    """
    return hashlib.sha256(data).hexdigest()
