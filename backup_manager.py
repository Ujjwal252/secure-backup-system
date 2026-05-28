"""Backup registry manager for the Secure Backup System.

Maintains a JSON registry of all encrypted backups stored in the vault.
Each entry records the original filename, backup path, timestamp, file
size, and SHA-256 hash for identification and restore purposes.
"""

import os
import json
from datetime import datetime

# Backup vault stored in user's home directory
VAULT_DIR = os.path.join(os.getcwd(), "SecureBackupVault")
REGISTRY_FILE = os.path.join(VAULT_DIR, "backup_registry.json")


def ensure_vault_exists() -> None:
    """Create the backup vault directory if it does not exist."""
    os.makedirs(VAULT_DIR, exist_ok=True)


def get_vault_dir() -> str:
    """Return the absolute path to the backup vault directory."""
    ensure_vault_exists()
    return VAULT_DIR


def generate_backup_filename(original_path: str) -> str:
    """Generate a timestamped backup filename for a given original file.

    Format: originalname_YYYY-MM-DD_HH-MM-SS.enc
    Example: report.pdf_2026-05-06_14-32-10.enc

    Parameters:
        original_path (str): Path to the original file.

    Returns:
        str: Full path inside the vault with timestamp.
    """
    ensure_vault_exists()
    original_name = os.path.basename(original_path)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    backup_filename = f"{original_name}_{timestamp}.enc"
    return os.path.join(VAULT_DIR, backup_filename)


def load_registry() -> list:
    """Load the backup registry from the JSON file.

    Returns:
        list: List of backup entry dicts. Empty list if no registry exists.
    """
    ensure_vault_exists()
    if not os.path.isfile(REGISTRY_FILE):
        return []
    with open(REGISTRY_FILE, "r") as f:
        return json.load(f)


def save_registry(entries: list) -> None:
    """Save the backup registry list to the JSON file.

    Parameters:
        entries (list): List of backup entry dicts to persist.
    """
    ensure_vault_exists()
    with open(REGISTRY_FILE, "w") as f:
        json.dump(entries, f, indent=4)


def register_backup(original_path: str, backup_path: str,
                    original_hash: str, file_size: int) -> dict:
    """Add a new backup entry to the registry.

    Parameters:
        original_path (str): Path to the original file that was encrypted.
        backup_path   (str): Path to the .enc file inside the vault.
        original_hash (str): SHA-256 hex digest of the original file.
        file_size     (int): Size of the encrypted backup file in bytes.

    Returns:
        dict: The newly created registry entry.
    """
    entries = load_registry()

    entry = {
        "id": len(entries) + 1,
        "original_name": os.path.basename(original_path),
        "original_path": original_path,
        "backup_path": backup_path,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "original_hash": original_hash,
        "encrypted_size": file_size,
    }

    entries.append(entry)
    save_registry(entries)
    return entry


def get_all_backups() -> list:
    """Return all backup entries from the registry, newest first.

    Returns:
        list: Backup entries sorted by timestamp descending.
    """
    entries = load_registry()
    # Sort newest first so the backup manager shows recent backups at top
    return sorted(entries, key=lambda x: x["timestamp"], reverse=True)


def delete_backup_entry(backup_path: str) -> None:
    """Remove a backup entry from the registry and delete the .enc file.

    Parameters:
        backup_path (str): Path to the .enc file to delete.
    """
    entries = load_registry()
    entries = [e for e in entries if e["backup_path"] != backup_path]
    save_registry(entries)

    if os.path.isfile(backup_path):
        os.remove(backup_path)