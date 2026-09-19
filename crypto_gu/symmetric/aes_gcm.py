"""AES-GCM AEAD (NIST SP 800-38D).

Pure Python, standard library only. GHASH multiplication runs in
GF(2^128) using the reflected bit order mandated by the specification and
the reduction polynomial x^128 + x^7 + x^2 + x + 1.
"""

from __future__ import annotations

from crypto_gu.constant_time import equal as constant_time_equal
from crypto_gu.encoding import to_bytes
from crypto_gu.errors import InvalidIVError, InvalidKeyError, InvalidTagError
from crypto_gu.symmetric.aes import block_encrypt

KEY_SIZE = 16
BLOCK_SIZE = 16
TAG_SIZE = 16

_R = 0xE1000000000000000000000000000000


def _validate(key: bytes, nonce: bytes) -> None:
    if len(key) not in (16, 24, 32):
        raise InvalidKeyError("AES key must be 16, 24 or 32 bytes, got %d" % len(key))
    if not nonce:
        raise InvalidIVError("AES-GCM nonce must not be empty")


def _gf_mul(x: int, y: int) -> int:
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _R
        else:
            v >>= 1
    return z


def _pad16(data: bytes) -> bytes:
    remainder = len(data) % BLOCK_SIZE
    return b"" if remainder == 0 else b"\x00" * (BLOCK_SIZE - remainder)


def _ghash(h: int, data: bytes) -> bytes:
    y = 0
    for offset in range(0, len(data), BLOCK_SIZE):
        y = _gf_mul(y ^ int.from_bytes(data[offset:offset + BLOCK_SIZE], "big"), h)
    return y.to_bytes(BLOCK_SIZE, "big")


def _inc32(value: int) -> int:
    return (value & ~0xFFFFFFFF) | ((value + 1) & 0xFFFFFFFF)


def _gctr(key: bytes, icb: int, data: bytes) -> bytes:
    if not data:
        return b""
    out = bytearray()
    counter = icb
    for offset in range(0, len(data), BLOCK_SIZE):
        keystream = block_encrypt(key, counter.to_bytes(BLOCK_SIZE, "big"))
        chunk = data[offset:offset + BLOCK_SIZE]
        out += bytes(a ^ b for a, b in zip(keystream, chunk))
        counter = _inc32(counter)
    return bytes(out)


def _initial_counter(h: int, nonce: bytes) -> int:
    if len(nonce) == 12:
        return int.from_bytes(nonce + b"\x00\x00\x00\x01", "big")
    block = nonce + _pad16(nonce) + (0).to_bytes(8, "big") + (len(nonce) * 8).to_bytes(8, "big")
    return int.from_bytes(_ghash(h, block), "big")


def _authentication_block(h: int, aad: bytes, ciphertext: bytes) -> bytes:
    block = (
        aad
        + _pad16(aad)
        + ciphertext
        + _pad16(ciphertext)
        + (len(aad) * 8).to_bytes(8, "big")
        + (len(ciphertext) * 8).to_bytes(8, "big")
    )
    return _ghash(h, block)


def _prepare(key, nonce):
    key = to_bytes(key)
    nonce = to_bytes(nonce)
    _validate(key, nonce)
    h = int.from_bytes(block_encrypt(key, b"\x00" * BLOCK_SIZE), "big")
    return key, nonce, h, _initial_counter(h, nonce)


def encrypt(key, nonce, plaintext, aad=b"", tag_length: int = TAG_SIZE) -> bytes:
    """Return ``ciphertext || tag`` (tag truncated to ``tag_length`` bytes)."""
    key, nonce, h, j0 = _prepare(key, nonce)
    plaintext = to_bytes(plaintext)
    aad = to_bytes(aad)
    if not 4 <= tag_length <= 16:
        raise ValueError("tag_length must be in 4..16")
    ciphertext = _gctr(key, _inc32(j0), plaintext)
    block = _authentication_block(h, aad, ciphertext)
    tag = _gctr(key, j0, block)[:tag_length]
    return ciphertext + tag


def decrypt(key, nonce, data, aad=b"", tag_length: int = TAG_SIZE) -> bytes:
    """Verify the tag and return the plaintext, or raise InvalidTagError."""
    key, nonce, h, j0 = _prepare(key, nonce)
    data = to_bytes(data)
    aad = to_bytes(aad)
    if len(data) < tag_length:
        raise InvalidTagError("ciphertext shorter than the authentication tag")
    ciphertext, tag = data[:-tag_length], data[-tag_length:]
    block = _authentication_block(h, aad, ciphertext)
    expected = _gctr(key, j0, block)[:tag_length]
    if not constant_time_equal(tag, expected):
        raise InvalidTagError("authentication tag mismatch")
    return _gctr(key, _inc32(j0), ciphertext)


__all__ = ["KEY_SIZE", "BLOCK_SIZE", "TAG_SIZE", "encrypt", "decrypt"]
