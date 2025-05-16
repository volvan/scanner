# Services
import pyffx  # type: ignore

# Configuration
try:
    from config import crypto_config
except ImportError:
    from ..config import crypto_config


if crypto_config.FPE_KEY is None:
    raise ValueError("FPE_KEY not found in environment variables")

# Create FPE cipher from environment
key = crypto_config.FPE_KEY.encode()
cipher = pyffx.String(key, alphabet=crypto_config.FPE_ALPHABET, length=crypto_config.FPE_LENGTH)


def encrypt_ip(ip_addr: str) -> str:
    """Encrypt an IPv4 address using format-preserving encryption (FPE).

    Args:
        ip_addr (str): The plaintext IPv4 address (e.g., "192.168.0.1").

    Returns:
        str: The encrypted IPv4 address.
    """
    octets = ip_addr.split('.')
    return '.'.join(cipher.encrypt(o.zfill(crypto_config.FPE_LENGTH)) for o in octets)


def decrypt_ip(encrypted_ip: str) -> str:
    """Decrypt an FPE-encrypted IPv4 address back to plaintext.

    Args:
        encrypted_ip (str): The encrypted IPv4 address.

    Returns:
        str: The original plaintext IPv4 address.
    """
    octets = encrypted_ip.split('.')
    return '.'.join(cipher.decrypt(o) for o in octets)
