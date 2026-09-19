"""ChaCha20-Poly1305 AEAD (RFC 8439 section 2.8).

Pure Python, standard library only. The one-time Poly1305 key is the first
half of the ChaCha20 block with counter zero; the ciphertext uses counter
one, exactly as the RFC prescribes.
"""

from __future__ import annotations

from crypto_gu.constant_time import equal as constant_time_equal
from crypto_gu.encoding import to_bytes
from crypto_gu.errors import InvalidIVError, InvalidKeyError, InvalidTagError
from crypto_gu.symmetric.chacha20 import NONCE_SIZE, _block
from crypto_gu.symmetric.chacha20 import encrypt as chacha20_encrypt
from crypto_gu.symmetric.poly1305 import KEY_SIZE as POLY1305_KEY_SIZE
from crypto_gu.symmetric.poly1305 import TAG_SIZE, poly1305

KEY_SIZE = 32


def _pad16(data: bytes) -> bytes:
    remainder = len(data) % 16
    return b"" if remainder == 0 else b"\x00" * (16 - remainder)


def _mac_data(aad: bytes, ciphertext: bytes) -> bytes:
    return (
        aad
        + _pad16(aad)
        + ciphertext
        + _pad16(ciphertext)
        + len(aad).to_bytes(8, "little")
        + len(ciphertext).to_bytes(8, "little")
    )


def _validate(key: bytes, nonce: bytes) -> None:
    if len(key) != KEY_SIZE:
        raise InvalidKeyError("ChaCha20-Poly1305 key must be %d bytes, got %d" % (KEY_SIZE, len(key)))
    if len(nonce) != NONCE_SIZE:
        raise InvalidIVError("ChaCha20-Poly1305 nonce must be %d bytes, got %d" % (NONCE_SIZE, len(nonce)))


def encrypt(key, nonce, plaintext, aad=b"") -> bytes:
    """Return ``ciphertext || tag`` for the given plaintext and associated data."""
    key = to_bytes(key)
    nonce = to_bytes(nonce)
    plaintext = to_bytes(plaintext)
    aad = to_bytes(aad)
    _validate(key, nonce)
    one_time_key = _block(key, 0, nonce)[:POLY1305_KEY_SIZE]
    ciphertext = chacha20_encrypt(key, nonce, plaintext, start_counter=1)
    tag = poly1305(one_time_key, _mac_data(aad, ciphertext))
    return ciphertext + tag


def decrypt(key, nonce, data, aad=b"") -> bytes:
    """Verify the tag and return the plaintext, or raise InvalidTagError."""
    key = to_bytes(key)
    nonce = to_bytes(nonce)
    data = to_bytes(data)
    aad = to_bytes(aad)
    _validate(key, nonce)
    if len(data) < TAG_SIZE:
        raise InvalidTagError("ciphertext shorter than the authentication tag")
    ciphertext, tag = data[:-TAG_SIZE], data[-TAG_SIZE:]
    one_time_key = _block(key, 0, nonce)[:POLY1305_KEY_SIZE]
    expected = poly1305(one_time_key, _mac_data(aad, ciphertext))
    if not constant_time_equal(tag, expected):
        raise InvalidTagError("authentication tag mismatch")
    return chacha20_encrypt(key, nonce, ciphertext, start_counter=1)


__all__ = ["KEY_SIZE", "encrypt", "decrypt"]
