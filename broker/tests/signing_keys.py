"""RSA key helpers for tests that sign or publish broker identity tokens."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def make_rsa_key() -> rsa.RSAPrivateKey:
    """Generate a fresh 2048-bit key, for tests that need keys distinct from the session-shared ``broker_signing_key`` (e.g. rotation)."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def private_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def public_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
