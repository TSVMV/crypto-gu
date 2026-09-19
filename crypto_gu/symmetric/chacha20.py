"""ChaCha20 (RFC 8439) stream cipher.

Pure Python, standard library only. Implements the ChaCha20 quarter round,
the 20-round block function, the 12-octet nonce construction, and a
byte-stream that can also be used as a deterministic keystream generator
for keystream-reuse attacks.
"""

from __future__ import annotations

from crypto_gu.errors import InvalidIVError, InvalidKeyError

KEY_SIZE = 32
BLOCK_SIZE = 64
NONCE_SIZE = 12
COUNTER_SIZE = 4

_ROUNDS = 20

_CONST = b"expand 32-byte k"


def _rotl(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def _quarter_round(x, a: int, b: int, c: int, d: int) -> None:
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] = _rotl(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] = _rotl(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] = _rotl(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] = _rotl(x[b] ^ x[c], 7)


def _block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """Run 20 ChaCha rounds on one 64-byte block, returning the keystream."""
    if len(key) != KEY_SIZE:
        raise InvalidKeyError("ChaCha20 key must be %d bytes, got %d" % (KEY_SIZE, len(key)))
    if len(nonce) != NONCE_SIZE:
        raise InvalidIVError("ChaCha20 nonce must be %d bytes, got %d" % (NONCE_SIZE, len(nonce)))
    state = [
        int.from_bytes(_CONST[0:4], "little"),
        int.from_bytes(_CONST[4:8], "little"),
        int.from_bytes(_CONST[8:12], "little"),
        int.from_bytes(_CONST[12:16], "little"),
    ] + [int.from_bytes(key[i:i + 4], "little") for i in range(0, KEY_SIZE, 4)]
    state.append(counter & 0xFFFFFFFF)
    state.extend(int.from_bytes(nonce[i:i + 4], "little") for i in range(0, NONCE_SIZE, 4))
    work = list(state)
    for _ in range(_ROUNDS // 2):
        _quarter_round(work, 0, 4, 8, 12)
        _quarter_round(work, 1, 5, 9, 13)
        _quarter_round(work, 2, 6, 10, 14)
        _quarter_round(work, 3, 7, 11, 15)
        _quarter_round(work, 0, 5, 10, 15)
        _quarter_round(work, 1, 6, 11, 12)
        _quarter_round(work, 2, 7, 8, 13)
        _quarter_round(work, 3, 4, 9, 14)
    added = [((work[i] + state[i]) & 0xFFFFFFFF) for i in range(16)]
    return b"".join(word.to_bytes(4, "little") for word in added)


def keystream(key: bytes, nonce: bytes, length: int, start_counter: int = 0) -> bytes:
    """Generate ``length`` bytes of ChaCha20 keystream.

    ``start_counter`` lets callers offset the block counter, which is the
    primitive behind keystream-reuse attacks.
    """
    if length < 0:
        raise ValueError("keystream length must be non-negative")
    chunks = []
    counter = start_counter
    remaining = length
    while remaining:
        ks = _block(key, counter, nonce)
        take = min(BLOCK_SIZE, remaining)
        chunks.append(ks[:take])
        remaining -= take
        counter += 1
    return b"".join(chunks)


def encrypt(key: bytes, nonce: bytes, data: bytes, start_counter: int = 0) -> bytes:
    """Encrypt (XOR) arbitrary-length data with ChaCha20."""
    ks = keystream(key, nonce, len(data), start_counter)
    return bytes(a ^ b for a, b in zip(ks, data))


def decrypt(key: bytes, nonce: bytes, data: bytes, start_counter: int = 0) -> bytes:
    return encrypt(key, nonce, data, start_counter)


__all__ = [
    "KEY_SIZE",
    "BLOCK_SIZE",
    "NONCE_SIZE",
    "COUNTER_SIZE",
    "_block",
    "keystream",
    "encrypt",
    "decrypt",
]
