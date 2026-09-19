"""Pure-Python SHA-1 (FIPS 180-4).

SHA-1 is retained for verification of legacy data and for teaching; it is
collision-broken and must not be used for new commitments or signatures.
"""

from __future__ import annotations

from crypto_gu.encoding import to_bytes

_MASK = 0xFFFFFFFF
_BLOCK = 64
_ROUNDS = 80

_INIT = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)

_K = (
    0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6,
)


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _MASK


def _compress(state, block):
    a, b, c, d, e = state
    w = [int.from_bytes(block[i * 4 : i * 4 + 4], "big") for i in range(16)]
    for t in range(16, _ROUNDS):
        w.append(_rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1))

    for t in range(_ROUNDS):
        if t < 20:
            f = (b & c) ^ (~b & d & _MASK)
        elif t < 40:
            f = b ^ c ^ d
        elif t < 60:
            f = (b & c) | (b & d) | (c & d)
        else:
            f = b ^ c ^ d
        k = _K[t // 20]
        temp = (_rotl(a, 5) + f + e + w[t] + k) & _MASK
        e, d, c, b = d, c, _rotl(b, 30), a
        a = temp

    return (
        (state[0] + a) & _MASK,
        (state[1] + b) & _MASK,
        (state[2] + c) & _MASK,
        (state[3] + d) & _MASK,
        (state[4] + e) & _MASK,
    )


def _pad(message: bytes) -> bytes:
    length = len(message) * 8
    padded = message + b"\x80"
    padded += b"\x00" * ((56 - len(padded)) % _BLOCK)
    padded += length.to_bytes(8, "big")
    return padded


def sha1(data) -> bytes:
    """Return the 20-byte SHA-1 digest of *data*."""
    padded = _pad(to_bytes(data))
    state = _INIT
    for i in range(0, len(padded), _BLOCK):
        state = _compress(state, padded[i : i + _BLOCK])
    return b"".join(v.to_bytes(4, "big") for v in state)


def sha1_hex(data) -> str:
    return sha1(data).hex()


__all__ = ["sha1", "sha1_hex"]
