"""Utility helpers for the Secure Backup System."""

import os
from pathlib import Path

from exceptions import BackupFileNotFoundError


def ensure_directory(path: str) -> None:
    """Create a directory and all intermediate parent directories.

    Parameters:
        path: The directory path to create.

    Raises:
        BackupFileNotFoundError: If the path is empty or None.
    """
    if not path:
        raise BackupFileNotFoundError("Path must not be empty.")

    os.makedirs(path, exist_ok=True)


def get_encrypted_output_path(input_path: str) -> str:
    """Return the encrypted output path by appending the .enc extension.

    Parameters:
        input_path: The original file path.

    Returns:
        The encrypted output file path.
    """
    return f"{input_path}.enc"


def get_decrypted_output_path(encrypted_path: str, output_folder: str) -> str:
    """Return the restored file path for a decrypted output.

    Parameters:
        encrypted_path: The encrypted file path, typically ending in .enc.
        output_folder: The folder where the restored file should be placed.

    Returns:
        The decrypted output file path with restored_ prefixed to the filename.
    """
    encrypted_name = Path(encrypted_path).name
    if encrypted_name.endswith(".enc"):
        decrypted_name = encrypted_name[:-len(".enc")]
    else:
        decrypted_name = encrypted_name

    restored_name = f"restored_{decrypted_name}"
    return str(Path(output_folder) / restored_name)


def format_file_size(byte_count: int) -> str:
    """Convert a byte count to a human-readable size string.

    Parameters:
        byte_count: The number of bytes.

    Returns:
        A formatted string in bytes, KB, MB, or GB.
    """
    if byte_count < 1024:
        return f"{byte_count} bytes"
    if byte_count < 1024 * 1024:
        return f"{byte_count / 1024:.2f} KB"
    if byte_count < 1024 * 1024 * 1024:
        return f"{byte_count / (1024 * 1024):.2f} MB"
    return f"{byte_count / (1024 * 1024 * 1024):.2f} GB"


def validate_file_exists(path: str) -> None:
    """Verify that a file exists at the provided path.

    Parameters:
        path: The file path to validate.

    Raises:
        BackupFileNotFoundError: If the file does not exist.
    """
    if not os.path.isfile(path):
        raise BackupFileNotFoundError(f"File not found: {path}")


def validate_password_strength(password: str) -> list[str]:
    """Validate password strength and return warnings for failed rules.

    Parameters:
        password: The password string to evaluate.

    Returns:
        A list of warning messages for each failed password rule.
    """
    warnings: list[str] = []
    special_characters = set("!@#$%^&*")

    if len(password) < 8:
        warnings.append("Password should be at least 8 characters.")
    if not any(char.isdigit() for char in password):
        warnings.append("Password should contain a number.")
    if not any(char in special_characters for char in password):
        warnings.append("Password should contain a special character.")

    return warnings
