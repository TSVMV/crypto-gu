"""Padding schemes.

All padders expose ``pad`` and ``unpad`` with a matching ``block_size`` and
raise :class:`InvalidPaddingError` on malformed input.
"""

from __future__ import annotations

from typing import Optional

from crypto_gu.encoding import to_bytes
from crypto_gu.errors import InvalidPaddingError


class Padder:
    """Pad *data* to a multiple of ``block_size``."""

    block_size: int = 16

    def __init__(self, block_size: Optional[int] = None):
        if block_size is not None:
            self.block_size = int(block_size)
        if self.block_size <= 0:
            raise ValueError("block_size must be positive")

    def pad(self, data: bytes) -> bytes:
        raise NotImplementedError

    def unpad(self, data: bytes) -> bytes:
        raise NotImplementedError


class PKCS7(Padder):
    """RFC 2315 style padding. Padding length is never zero."""

    def pad(self, data: bytes) -> bytes:
        data = to_bytes(data)
        n = self.block_size - (len(data) % self.block_size)
        return data + bytes([n]) * n

    def unpad(self, data: bytes) -> bytes:
        data = to_bytes(data)
        if not data or len(data) % self.block_size:
            raise InvalidPaddingError("not block-aligned")
        n = data[-1]
        if n == 0 or n > self.block_size:
            raise InvalidPaddingError("padding byte out of range: %d" % n)
        if data[-n:] != bytes([n]) * n:
            raise InvalidPaddingError("invalid padding bytes")
        return data[:-n]


class ZeroPad(Padder):
    """Pad with zero bytes. Cannot unpad unambiguously; strips all trailing zeros."""

    def pad(self, data: bytes) -> bytes:
        data = to_bytes(data)
        n = self.block_size - (len(data) % self.block_size)
        if n == self.block_size:
            return data
        return data + b"\x00" * n

    def unpad(self, data: bytes) -> bytes:
        return to_bytes(data).rstrip(b"\x00")


class XxPad(Padder):
    """Pad with 'x' (0x78) bytes."""

    def pad(self, data: bytes) -> bytes:
        data = to_bytes(data)
        n = self.block_size - (len(data) % self.block_size)
        return data + b"x" * n

    def unpad(self, data: bytes) -> bytes:
        return to_bytes(data).rstrip(b"x")


class Ansix923(Padder):
    """ANSI X9.23: zero bytes then a final length byte."""

    def pad(self, data: bytes) -> bytes:
        data = to_bytes(data)
        n = self.block_size - (len(data) % self.block_size)
        return data + b"\x00" * (n - 1) + bytes([n])

    def unpad(self, data: bytes) -> bytes:
        data = to_bytes(data)
        if not data or len(data) % self.block_size:
            raise InvalidPaddingError("not block-aligned")
        n = data[-1]
        if n == 0 or n > self.block_size:
            raise InvalidPaddingError("padding byte out of range: %d" % n)
        if len(data) >= n and data[-n:-1] != b"\x00" * (n - 1):
            raise InvalidPaddingError("invalid ANSI X9.23 padding")
        return data[:-n]


class OneAndZerosPad(Padder):
    """One byte then zeros, until the block is full."""

    def pad(self, data: bytes) -> bytes:
        data = to_bytes(data)
        n = self.block_size - (len(data) % self.block_size)
        return data + b"\x01" + b"\x00" * (n - 1)

    def unpad(self, data: bytes) -> bytes:
        data = to_bytes(data)
        if not data or len(data) % self.block_size:
            raise InvalidPaddingError("not block-aligned")
        return data[: -self.block_size + 1]


class NoPad(Padder):
    """Rejects data that is not already block-aligned."""

    def pad(self, data: bytes) -> bytes:
        data = to_bytes(data)
        if len(data) % self.block_size:
            raise InvalidPaddingError("data is not block-aligned")
        return data

    def unpad(self, data: bytes) -> bytes:
        data = to_bytes(data)
        if len(data) % self.block_size:
            raise InvalidPaddingError("data is not block-aligned")
        return data


# --------------------------------------------------------------------------- #
# Module level helpers
# --------------------------------------------------------------------------- #


def pad(data: bytes, block_size: int = 16, scheme: str = "pkcs7") -> bytes:
    return make_padder(scheme, block_size).pad(data)


def unpad(data: bytes, block_size: int = 16, scheme: str = "pkcs7") -> bytes:
    return make_padder(scheme, block_size).unpad(data)


def make_padder(scheme: str, block_size: int = 16) -> Padder:
    table = {
        "pkcs7": PKCS7,
        "zero": ZeroPad,
        "x": XxPad,
        "xx": XxPad,
        "x923": Ansix923,
        "ansi": Ansix923,
        "10": OneAndZerosPad,
        "1z": OneAndZerosPad,
        "none": NoPad,
        "nopad": NoPad,
    }
    key = scheme.lower()
    if key not in table:
        raise ValueError("unknown padding scheme: %r (known: %s)" % (scheme, sorted(table)))
    return table[key](block_size)


__all__ = [
    "Padder",
    "PKCS7",
    "ZeroPad",
    "XxPad",
    "Ansix923",
    "OneAndZerosPad",
    "NoPad",
    "pad",
    "unpad",
    "make_padder",
]
