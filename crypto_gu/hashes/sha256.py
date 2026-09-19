"""Pure-Python SHA-256 (FIPS 180-4)."""

from __future__ import annotations

from crypto_gu.encoding import to_bytes

_MASK = 0xFFFFFFFF

_INIT = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)

_K = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
)


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & _MASK


def _compress(state, block):
    h0, h1, h2, h3, h4, h5, h6, h7 = state
    w = list(int.from_bytes(block[i * 4 : i * 4 + 4], "big") for i in range(16))
    for t in range(16, 64):
        s0 = _rotr(w[t - 15], 7) ^ _rotr(w[t - 15], 18) ^ (w[t - 15] >> 3)
        s1 = _rotr(w[t - 2], 17) ^ _rotr(w[t - 2], 19) ^ (w[t - 2] >> 10)
        w.append((w[t - 16] + s0 + w[t - 7] + s1) & _MASK)

    a, b, c, d = h0, h1, h2, h3
    e, f, g, h = h4, h5, h6, h7
    for t in range(64):
        ch = (e & f) ^ (~e & g & _MASK)
        maj = (a & b) ^ (a & c) ^ (b & c)
        s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        t1 = (h + s1 + ch + _K[t] + w[t]) & _MASK
        t2 = (s0 + maj) & _MASK
        h, g, f, e = g, f, e, (d + t1) & _MASK
        d, c, b, a = c, b, a, (t1 + t2) & _MASK

    return (
        (h0 + a) & _MASK, (h1 + b) & _MASK, (h2 + c) & _MASK, (h3 + d) & _MASK,
        (h4 + e) & _MASK, (h5 + f) & _MASK, (h6 + g) & _MASK, (h7 + h) & _MASK,
    )


def _pad(message: bytes) -> bytes:
    length = len(message) * 8
    padded = message + b"\x80"
    padded += b"\x00" * ((56 - len(padded)) % 64)
    padded += length.to_bytes(8, "big")
    return padded


def sha256(data) -> bytes:
    """Return the 32-byte SHA-256 digest of *data*."""
    message = to_bytes(data)
    padded = _pad(message)
    state = _INIT
    for i in range(0, len(padded), 64):
        state = _compress(state, padded[i : i + 64])
    return b"".join(v.to_bytes(4, "big") for v in state)


def sha256_hex(data) -> str:
    return sha256(data).hex()


__all__ = ["sha256", "sha256_hex"]
