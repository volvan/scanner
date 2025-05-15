import sys
from utils.crypto import encrypt_ip, decrypt_ip
from config import crypto_config
import pyffx  # type: ignore
import utils.crypto as crypto_mod
import pytest
import importlib


def test_encrypt_decrypt_ip_roundtrip(monkeypatch):
    """Ensure IPs are encrypted/decrypted correctly and format is preserved."""
    monkeypatch.setattr(crypto_config, "FPE_KEY", "testfpekey12345")
    monkeypatch.setattr(crypto_config, "FPE_ALPHABET", "0123456789")
    monkeypatch.setattr(crypto_config, "FPE_LENGTH", 3)

    crypto_mod.cipher = pyffx.String(
        crypto_config.FPE_KEY.encode(),
        alphabet=crypto_config.FPE_ALPHABET,
        length=crypto_config.FPE_LENGTH
    )

    original_ip = "192.0.2.1"
    encrypted = encrypt_ip(original_ip)
    decrypted = decrypt_ip(encrypted)

    # Expect padded format from decrypt_ip since encrypt_ip uses zfill
    assert decrypted == "192.000.002.001"
    assert encrypted != original_ip
    assert all(part.isdigit() and len(part) == 3 for part in encrypted.split("."))


def test_raises_if_fpe_key_is_none(monkeypatch):
    """Ensure crypto module raises an error if FPE_KEY is not set."""
    # Force FPE_KEY to None to trigger the ValueError
    monkeypatch.setattr(crypto_config, "FPE_KEY", None)

    # Unload crypto so it re-imports with FPE_KEY = None
    if "utils.crypto" in sys.modules:
        del sys.modules["utils.crypto"]

    with pytest.raises(ValueError, match="FPE_KEY not found in environment variables"):
        importlib.import_module("utils.crypto")
