import sys
import os
from pathlib import Path

import pytest

# Add parent directory to path so modules can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from encryption import encrypt_file
from exceptions import BackupFileNotFoundError
from constants import HEADER_SIZE


def test_encrypt_creates_output_file(tmp_path):
    """Test that encrypting a file creates the .enc output file on disk."""
    temp_file = tmp_path / "secure.txt"
    temp_file.write_bytes(b"Hello, secure world!")

    result = encrypt_file(str(temp_file), "TestPass@1")

    output_path = Path(result["output_path"])
    assert output_path.exists()


def test_encrypted_file_has_correct_header(tmp_path):
    """Test that the .enc file contains the correct binary header layout."""
    temp_file = tmp_path / "secure.txt"
    temp_file.write_bytes(b"Hello, secure world!")

    result = encrypt_file(str(temp_file), "TestPass@1")
    output_path = Path(result["output_path"])

    data = output_path.read_bytes()
    assert len(data) > HEADER_SIZE        # file must be larger than header alone
    assert len(data[0:16]) == 16          # salt must be 16 bytes
    assert len(data[16:28]) == 12         # IV must be 12 bytes

    header_hash = data[28:92].decode("utf-8")
    assert len(header_hash) == 64         # SHA-256 hex digest is always 64 chars
    int(header_hash, 16)                  # must be a valid hex string


def test_encrypt_returns_correct_dict_keys(tmp_path):
    """Test that encrypt_file returns a dict with all required keys and values."""
    temp_file = tmp_path / "secure.txt"
    temp_file.write_bytes(b"Hello, secure world!")

    result = encrypt_file(str(temp_file), "TestPass@1")

    assert set(result.keys()) == {"status", "output_path", "original_hash", "file_size"}
    assert result["status"] == "success"
    assert isinstance(result["original_hash"], str)
    assert len(result["original_hash"]) == 64


def test_encrypt_nonexistent_file_raises_error():
    """Test that encrypting a non-existent file raises BackupFileNotFoundError."""
    with pytest.raises(BackupFileNotFoundError):
        encrypt_file("/nonexistent/path/file.txt", "pass")


def test_same_file_different_salt_each_time(tmp_path):
    """Test that encrypting the same file twice produces different salts.
    
    Fix: explicit output paths prevent the second call from overwriting
    the first .enc file, which caused both results to point to the same
    file and read the same salt bytes.
    """
    temp_file = tmp_path / "secure.txt"
    temp_file.write_bytes(b"Hello, secure world!")

    # Use different output paths so the two .enc files do not overwrite each other.
    # Without this, encrypt_file() generates the same default output path for
    # both calls (input_path + ".enc"), the second call overwrites the first,
    # and both result dicts point to the same file — so we read the same salt twice.
    output_one = str(tmp_path / "output_one.enc")
    output_two = str(tmp_path / "output_two.enc")

    result_one = encrypt_file(str(temp_file), "TestPass@1", output_one)
    result_two = encrypt_file(str(temp_file), "TestPass@1", output_two)

    # Read first 16 bytes (salt) from each separate encrypted file
    salt_one = open(result_one["output_path"], "rb").read(16)
    salt_two = open(result_two["output_path"], "rb").read(16)

    # os.urandom() must produce fresh bytes every call — salts must differ
    assert salt_one != salt_two, (
        "Salt must be unique per encryption operation. "
        "generate_salt() must call os.urandom() fresh each time."
    )