import sys
import os
from pathlib import Path

import pytest

sys.path.insert(0, "..")

from encryption import encrypt_file
from decryption import decrypt_file
from exceptions import WrongPasswordError, FileIntegrityError, CorruptedFileError, BackupFileNotFoundError


def test_decrypt_restores_original_content(tmp_path):
    temp_file = tmp_path / "secret.txt"
    temp_file.write_bytes(b"Secret data 12345")

    encrypt_result = encrypt_file(str(temp_file), "GoodPass@9")
    decrypted_result = decrypt_file(encrypt_result["output_path"], "GoodPass@9")

    restored_path = Path(decrypted_result["output_path"])
    assert restored_path.read_bytes() == b"Secret data 12345"


def test_wrong_password_raises_WrongPasswordError(tmp_path):
    temp_file = tmp_path / "secret.txt"
    temp_file.write_bytes(b"Secret data 12345")

    encrypt_result = encrypt_file(str(temp_file), "CorrectPass@1")

    with pytest.raises(WrongPasswordError):
        decrypt_file(encrypt_result["output_path"], "WrongPass@999")


def test_decrypt_returns_integrity_verified(tmp_path):
    temp_file = tmp_path / "secret.txt"
    temp_file.write_bytes(b"Secret data 12345")

    encrypt_result = encrypt_file(str(temp_file), "GoodPass@9")
    decrypt_result = decrypt_file(encrypt_result["output_path"], "GoodPass@9")

    assert decrypt_result["integrity"] == "verified"
    assert decrypt_result["status"] == "success"


def test_hash_matches_after_decrypt(tmp_path):
    temp_file = tmp_path / "secret.txt"
    temp_file.write_bytes(b"Secret data 12345")

    encrypt_result = encrypt_file(str(temp_file), "GoodPass@9")
    decrypt_result = decrypt_file(encrypt_result["output_path"], "GoodPass@9")

    assert encrypt_result["original_hash"] == decrypt_result["restored_hash"]


def test_corrupted_file_raises_error(tmp_path):
    corrupted_file = tmp_path / "broken.enc"
    corrupted_file.write_bytes(os.urandom(50))

    with pytest.raises(CorruptedFileError):
        decrypt_file(str(corrupted_file), "AnyPass@1")
