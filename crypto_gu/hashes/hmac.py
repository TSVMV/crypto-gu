"""HMAC plus Merkle-Damgard length-extension for MD5 and SHA-256."""

from __future__ import annotations

from typing import Callable

from crypto_gu.encoding import to_bytes
from crypto_gu.hashes.md5 import _compress as _md5_compress
from crypto_gu.hashes.md5 import md5, md5_hex
from crypto_gu.hashes.sha256 import _compress as _sha256_compress
from crypto_gu.hashes.sha256 import sha256, sha256_hex


def _key_schedule(key: bytes, block_size: int, digestmod: Callable) -> tuple:
    if len(key) > block_size:
        key = digestmod(key)
    key = key.ljust(block_size, b"\x00")
    return (bytes(x ^ 0x36 for x in key), bytes(x ^ 0x5c for x in key))


def hmac(key, message, digestmod: Callable = sha256, block_size: int = 64) -> bytes:
    """RFC 2104 HMAC."""
    inner, outer = _key_schedule(to_bytes(key), block_size, digestmod)
    return digestmod(outer + digestmod(inner + to_bytes(message)))


def hmac_hex(key, message, digestmod: Callable = sha256, block_size: int = 64) -> str:
    return hmac(key, message, digestmod, block_size).hex()


def hmac_md5(key, message) -> bytes:
    return hmac(key, message, md5, 64)


def hmac_sha256(key, message) -> bytes:
    return hmac(key, message, sha256, 64)


# --------------------------------------------------------------------------- #
# Merkle-Damgard length extension
# --------------------------------------------------------------------------- #


def padded_length(msg_len: int) -> int:
    """Length in bytes of a Merkle-Damgard padded message of *msg_len* bytes."""
    return ((msg_len + 9 + 63) // 64) * 64


def length_extend_md5(total_prefix_len: int, mac: bytes, suffix: bytes) -> bytes:
    """Forge ``MD5(prefix || suffix)`` from ``MD5(prefix)``.

    ``total_prefix_len`` is ``len(secret) + len(message)`` -- the attacker must
    know it. ``mac`` is the raw 16-byte digest of ``prefix``.
    """
    if len(mac) != 16:
        raise ValueError("mac must be 16 bytes")
    prefix_padded = padded_length(total_prefix_len)
    new_len = prefix_padded + len(suffix)
    pad = b"\x80" + b"\x00" * ((64 - ((new_len + 9) % 64)) % 64)
    pad += (new_len * 8).to_bytes(8, "little")
    state = tuple(int.from_bytes(mac[i * 4 : (i + 1) * 4], "little") for i in range(4))
    data = to_bytes(suffix) + pad
    for i in range(0, len(data), 64):
        state = _md5_compress(state, data[i : i + 64])
    return b"".join(v.to_bytes(4, "little") for v in state)


def length_extend_sha256(total_prefix_len: int, mac: bytes, suffix: bytes) -> bytes:
    """Forge ``SHA256(prefix || suffix)`` from ``SHA256(prefix)``."""
    if len(mac) != 32:
        raise ValueError("mac must be 32 bytes")
    prefix_padded = padded_length(total_prefix_len)
    new_len = prefix_padded + len(suffix)
    pad = b"\x80" + b"\x00" * ((64 - ((new_len + 9) % 64)) % 64)
    pad += (new_len * 8).to_bytes(8, "big")
    state = tuple(int.from_bytes(mac[i * 4 : (i + 1) * 4], "big") for i in range(8))
    data = to_bytes(suffix) + pad
    for i in range(0, len(data), 64):
        state = _sha256_compress(state, data[i : i + 64])
    return b"".join(v.to_bytes(4, "big") for v in state)


def length_extend(algorithm: str, total_prefix_len: int, mac: bytes, suffix: bytes) -> bytes:
    table = {"md5": length_extend_md5, "sha256": length_extend_sha256}
    key = algorithm.lower()
    if key not in table:
        raise ValueError("length extension is only supported for %s" % sorted(table))
    return table[key](total_prefix_len, mac, suffix)


__all__ = [
    "hmac",
    "hmac_hex",
    "hmac_md5",
    "hmac_sha256",
    "padded_length",
    "length_extend_md5",
    "length_extend_sha256",
    "length_extend",
    "sha256",
    "sha256_hex",
    "md5",
    "md5_hex",
]
