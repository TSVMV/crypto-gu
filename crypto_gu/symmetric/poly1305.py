"""Poly1305 one-time authenticator (RFC 8439 section 2.5).

Pure Python, standard library only. The accumulator works with Python
integers, so the 130-bit modular reduction is exact without limb tricks.
"""

from __future__ import annotations

from crypto_gu.encoding import to_bytes
from crypto_gu.errors import InvalidKeyError

KEY_SIZE = 32
TAG_SIZE = 16
_BLOCK_SIZE = 16
_P = (1 << 130) - 5


def _clamp(r: int) -> int:
    return r & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF


def poly1305(key, message) -> bytes:
    """Return the 16-octet Poly1305 tag of ``message`` under ``key``."""
    key = to_bytes(key)
    if len(key) != KEY_SIZE:
        raise InvalidKeyError("Poly1305 key must be %d bytes, got %d" % (KEY_SIZE, len(key)))
    message = to_bytes(message)
    r = _clamp(int.from_bytes(key[:16], "little"))
    s = int.from_bytes(key[16:], "little")
    acc = 0
    for offset in range(0, len(message), _BLOCK_SIZE):
        chunk = message[offset:offset + _BLOCK_SIZE]
        block = int.from_bytes(chunk + b"\x01", "little")
        acc = ((acc + block) * r) % _P
    return ((acc + s) % (1 << 128)).to_bytes(TAG_SIZE, "little")


__all__ = ["KEY_SIZE", "TAG_SIZE", "poly1305"]
