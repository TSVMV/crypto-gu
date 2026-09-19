"""Key derivation: PBKDF2 (RFC 8018), HKDF (RFC 5869) and scrypt (RFC 7914)."""

from __future__ import annotations

from typing import Callable

from crypto_gu.encoding import to_bytes
from crypto_gu.hashes.hmac import hmac
from crypto_gu.hashes.md5 import md5
from crypto_gu.hashes.sha1 import sha1
from crypto_gu.hashes.sha256 import sha256
from crypto_gu.hashes.sha512 import sha512

_WORD = 0xFFFFFFFF
_DIGEST_BLOCK_SIZE = {md5: 64, sha1: 64, sha256: 64, sha512: 128}


def _digest_len(digestmod: Callable) -> int:
    return len(digestmod(b""))


def _block_size(digestmod: Callable) -> int:
    return _DIGEST_BLOCK_SIZE.get(digestmod, 64)


def _mac(key: bytes, message: bytes, digestmod: Callable) -> bytes:
    return hmac(key, message, digestmod, _block_size(digestmod))


def _xor(*blocks: bytes) -> bytes:
    value = 0
    for block in blocks:
        value ^= int.from_bytes(block, "big")
    return value.to_bytes(len(blocks[0]), "big")


def _int_be(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


# --------------------------------------------------------------------------- #
# PBKDF2
# --------------------------------------------------------------------------- #


def pbkdf2(password, salt, iterations: int, dklen: int, digestmod: Callable = sha256) -> bytes:
    """RFC 8018 section 5.2 pseudorandom function."""
    password = to_bytes(password)
    salt = to_bytes(salt)
    iterations = int(iterations)
    dklen = int(dklen)
    if iterations < 1:
        raise ValueError("iterations must be >= 1, got %r" % (iterations,))
    if dklen < 1:
        raise ValueError("dklen must be >= 1, got %r" % (dklen,))
    if iterations > 0xFFFFFFFF:
        raise ValueError("iterations must fit in 32 bits")
    digest_len = _digest_len(digestmod)
    if dklen > 0xFFFFFFFF * digest_len:
        raise ValueError("dklen too large for %d-byte digests" % digest_len)

    output = b""
    for counter in range(1, -(-dklen // digest_len) + 1):
        block = _mac(password, salt + _int_be(counter, 4), digestmod)
        accum = block
        for _ in range(iterations - 1):
            block = _mac(password, block, digestmod)
            accum = _xor(accum, block)
        output += accum
    return output[:dklen]


# --------------------------------------------------------------------------- #
# HKDF
# --------------------------------------------------------------------------- #


def hkdf_extract(salt, ikm, digestmod: Callable = sha256) -> bytes:
    """RFC 5869 section 2.2."""
    salt = to_bytes(salt) if salt is not None else b""
    if not salt:
        salt = b"\x00" * _digest_len(digestmod)
    return _mac(salt, to_bytes(ikm), digestmod)


def hkdf_expand(prk, info: bytes = b"", length: int = 0, digestmod: Callable = sha256) -> bytes:
    """RFC 5869 section 2.3."""
    prk = to_bytes(prk)
    digest_len = _digest_len(digestmod)
    length = int(length)
    if length < 0:
        raise ValueError("length must be >= 0, got %r" % (length,))
    if length > 255 * digest_len:
        raise ValueError("length exceeds 255 * HashLen = %d" % (255 * digest_len,))
    if not prk:
        raise ValueError("prk must not be empty")
    info = to_bytes(info)

    okm = b""
    previous = b""
    counter = 1
    while len(okm) < length:
        previous = _mac(prk, previous + info + bytes([counter]), digestmod)
        okm += previous
        counter += 1
    return okm[:length]


def hkdf(ikm, length: int, salt=None, info: bytes = b"", digestmod: Callable = sha256) -> bytes:
    """RFC 5869 two-step construct: Extract-then-Expand."""
    return hkdf_expand(hkdf_extract(salt, ikm, digestmod), info, length, digestmod)


# --------------------------------------------------------------------------- #
# scrypt
# --------------------------------------------------------------------------- #


def _rotl32(x: int, n: int) -> int:
    x &= _WORD
    return ((x << n) | (x >> (32 - n))) & _WORD


def _salsa20_8_core(block: list) -> list:
    t = list(block)
    for _ in range(4):
        t[4] ^= _rotl32(t[0] + t[12], 7)
        t[8] ^= _rotl32(t[4] + t[0], 9)
        t[12] ^= _rotl32(t[8] + t[4], 13)
        t[0] ^= _rotl32(t[12] + t[8], 18)
        t[9] ^= _rotl32(t[5] + t[1], 7)
        t[13] ^= _rotl32(t[9] + t[5], 9)
        t[1] ^= _rotl32(t[13] + t[9], 13)
        t[5] ^= _rotl32(t[1] + t[13], 18)
        t[14] ^= _rotl32(t[10] + t[6], 7)
        t[2] ^= _rotl32(t[14] + t[10], 9)
        t[6] ^= _rotl32(t[2] + t[14], 13)
        t[10] ^= _rotl32(t[6] + t[2], 18)
        t[3] ^= _rotl32(t[15] + t[11], 7)
        t[7] ^= _rotl32(t[3] + t[15], 9)
        t[11] ^= _rotl32(t[7] + t[3], 13)
        t[15] ^= _rotl32(t[11] + t[7], 18)

        t[1] ^= _rotl32(t[0] + t[3], 7)
        t[2] ^= _rotl32(t[1] + t[0], 9)
        t[3] ^= _rotl32(t[2] + t[1], 13)
        t[0] ^= _rotl32(t[3] + t[2], 18)
        t[6] ^= _rotl32(t[5] + t[4], 7)
        t[7] ^= _rotl32(t[6] + t[5], 9)
        t[4] ^= _rotl32(t[7] + t[6], 13)
        t[5] ^= _rotl32(t[4] + t[7], 18)
        t[11] ^= _rotl32(t[10] + t[9], 7)
        t[8] ^= _rotl32(t[11] + t[10], 9)
        t[9] ^= _rotl32(t[8] + t[11], 13)
        t[10] ^= _rotl32(t[9] + t[8], 18)
        t[12] ^= _rotl32(t[15] + t[14], 7)
        t[13] ^= _rotl32(t[12] + t[15], 9)
        t[14] ^= _rotl32(t[13] + t[12], 13)
        t[15] ^= _rotl32(t[14] + t[13], 18)

    return [(t[i] + block[i]) & _WORD for i in range(16)]


def _words(block: bytes) -> list:
    return [int.from_bytes(block[i * 4 : i * 4 + 4], "little") for i in range(len(block) // 4)]


def _unwords(words: list) -> bytes:
    return b"".join(w.to_bytes(4, "little") for w in words)


def _block_mix(block: bytes, r: int) -> bytes:
    chunk_size = 64
    x = _words(block[(2 * r - 1) * chunk_size : 2 * r * chunk_size])
    mixed = []
    for i in range(2 * r):
        x = _salsa20_8_core([a ^ b for a, b in zip(x, _words(block[i * chunk_size : (i + 1) * chunk_size]))])
        mixed.append(x)
    evens = b"".join(_unwords(chunk) for chunk in mixed[0::2])
    odds = b"".join(_unwords(chunk) for chunk in mixed[1::2])
    return evens + odds


def _integerify(block: bytes) -> int:
    return int.from_bytes(block[-64:], "little")


def _romix(block: bytes, r: int, n: int) -> bytes:
    if n < 2 or n & (n - 1):
        raise ValueError("n must be a power of two >= 2, got %r" % (n,))
    sequence = []
    current = block
    for _ in range(n):
        sequence.append(current)
        current = _block_mix(current, r)
    for _ in range(n):
        offset = _integerify(current) % n
        current = _block_mix(_xor(current, sequence[offset]), r)
    return current


def scrypt(password, salt, n: int, r: int, p: int, dklen: int) -> bytes:
    """RFC 7914 scrypt using HMAC-SHA-256."""
    password = to_bytes(password)
    salt = to_bytes(salt)
    n, r, p, dklen = int(n), int(r), int(p), int(dklen)
    if r < 1 or p < 1 or dklen < 1:
        raise ValueError("r, p and dklen must be >= 1")
    if n < 2 or n & (n - 1):
        raise ValueError("n must be a power of two >= 2, got %r" % (n,))
    if n > 1 << (16 * r):
        raise ValueError("n must be less than 2^(16r)")
    if p > (0xFFFFFFFF * 32) // (128 * r):
        raise ValueError("p exceeds (2^32-1) * 32 / (128r)")
    if dklen > 0xFFFFFFFF * 32:
        raise ValueError("dklen exceeds (2^32-1) * 32")
    block_size = 128 * r
    derived = pbkdf2(password, salt, 1, block_size * p, sha256)
    blocks = [_romix(derived[i * block_size : (i + 1) * block_size], r, n) for i in range(p)]
    return pbkdf2(password, b"".join(blocks), 1, dklen, sha256)


__all__ = [
    "pbkdf2",
    "hkdf_extract",
    "hkdf_expand",
    "hkdf",
    "scrypt",
]
