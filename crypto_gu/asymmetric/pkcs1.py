"""RSA encryption and signature schemes from PKCS #1 v2.2 (RFC 8017).

Provides MGF1, RSAES-OAEP (section 7.1) and RSASSA-PSS (section 8.1). The
underlying trapdoor is the textbook :class:`~crypto_gu.asymmetric.rsa.RSAKey`
already in this package; these helpers add the randomised, provably related
padding that turns it into a real-world scheme.

Pure Python, standard library only (``os.urandom`` supplies the randomness).
"""

from __future__ import annotations

import os

from crypto_gu.errors import DecryptionError, InvalidSignatureError
from crypto_gu.hashes import HASH_TABLE


def _hash_length(hash_name: str) -> int:
    key = hash_name.lower()
    if key not in HASH_TABLE:
        raise ValueError("unknown hash algorithm: %r" % hash_name)
    return len(HASH_TABLE[key](b""))


def _digest(hash_name: str, data: bytes) -> bytes:
    return HASH_TABLE[hash_name.lower()](data)


def _i2osp(value: int, length: int) -> bytes:
    if value < 0 or value >> (8 * length):
        raise ValueError("integer too large")
    return value.to_bytes(length, "big")


def _os2ip(data: bytes) -> int:
    return int.from_bytes(data, "big")


def mgf1(seed: bytes, length: int, hash_name: str = "sha256") -> bytes:
    """Mask generation function MGF1 (RFC 8017 appendix B.2.1)."""
    if length < 0:
        raise ValueError("mask length must be non-negative")
    hlen = _hash_length(hash_name)
    if length > (1 << 32) * hlen:
        raise ValueError("mask too long")
    output = b""
    counter = 0
    while len(output) < length:
        output += _digest(hash_name, seed + counter.to_bytes(4, "big"))
        counter += 1
    return output[:length]


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _modulus_size(n: int) -> int:
    return (n.bit_length() + 7) // 8


# --------------------------------------------------------------------------- #
# RSAES-OAEP
# --------------------------------------------------------------------------- #


def oaep_encode(message: bytes, k: int, hash_name: str = "sha256", label: bytes = b"") -> bytes:
    """EME-OAEP encoding (RFC 8017 section 7.1.1)."""
    hlen = _hash_length(hash_name)
    if len(message) > k - 2 * hlen - 2:
        raise ValueError("message too long for OAEP")
    lhash = _digest(hash_name, label)
    ps = b"\x00" * (k - len(message) - 2 * hlen - 2)
    db = lhash + ps + b"\x01" + message
    seed = os.urandom(hlen)
    db_mask = mgf1(seed, k - hlen - 1, hash_name)
    masked_db = _xor(db, db_mask)
    seed_mask = mgf1(masked_db, hlen, hash_name)
    masked_seed = _xor(seed, seed_mask)
    return b"\x00" + masked_seed + masked_db


def oaep_decode(encoded: bytes, k: int, hash_name: str = "sha256", label: bytes = b"") -> bytes:
    """EME-OAEP decoding; raises :class:`DecryptionError` on malformed input."""
    hlen = _hash_length(hash_name)
    if len(encoded) != k or k < 2 * hlen + 2:
        raise DecryptionError("decryption error")
    if encoded[0] != 0:
        raise DecryptionError("decryption error")
    masked_seed = encoded[1 : 1 + hlen]
    masked_db = encoded[1 + hlen :]
    seed = _xor(masked_seed, mgf1(masked_db, hlen, hash_name))
    db = _xor(masked_db, mgf1(seed, k - hlen - 1, hash_name))
    if db[:hlen] != _digest(hash_name, label):
        raise DecryptionError("decryption error")
    index = hlen
    while index < len(db) and db[index] == 0:
        index += 1
    if index >= len(db) or db[index] != 1:
        raise DecryptionError("decryption error")
    return db[index + 1 :]


def oaep_encrypt(key, message: bytes, hash_name: str = "sha256", label: bytes = b"") -> bytes:
    """RSAES-OAEP encrypt with a public (or full) :class:`RSAKey`."""
    k = _modulus_size(key.n)
    encoded = oaep_encode(message, k, hash_name, label)
    m = _os2ip(encoded)
    if m >= key.n:
        raise ValueError("encoded message representative out of range")
    return _i2osp(pow(m, key.e, key.n), k)


def oaep_decrypt(key, ciphertext: bytes, hash_name: str = "sha256", label: bytes = b"") -> bytes:
    """RSAES-OAEP decrypt; requires the private exponent."""
    if key.d is None:
        raise DecryptionError("decryption error")
    k = _modulus_size(key.n)
    if len(ciphertext) != k:
        raise DecryptionError("decryption error")
    c = _os2ip(ciphertext)
    if c >= key.n:
        raise DecryptionError("decryption error")
    m = pow(c, key.d, key.n)
    return oaep_decode(_i2osp(m, k), k, hash_name, label)


# --------------------------------------------------------------------------- #
# RSASSA-PSS
# --------------------------------------------------------------------------- #


def pss_encode(message: bytes, em_bits: int, hash_name: str = "sha256", salt_length: int = 32) -> bytes:
    """EMSA-PSS encoding (RFC 8017 section 9.1.1)."""
    hlen = _hash_length(hash_name)
    em_len = (em_bits + 7) // 8
    if em_len < hlen + salt_length + 2:
        raise ValueError("encoding error")
    m_hash = _digest(hash_name, message)
    salt = os.urandom(salt_length)
    h = _digest(hash_name, b"\x00" * 8 + m_hash + salt)
    ps = b"\x00" * (em_len - salt_length - hlen - 2)
    db = ps + b"\x01" + salt
    db_mask = mgf1(h, em_len - hlen - 1, hash_name)
    masked_db = bytearray(_xor(db, db_mask))
    masked_db[0] &= 0xFF >> (8 * em_len - em_bits)
    return bytes(masked_db) + h + b"\xbc"


def pss_verify(message: bytes, encoded: bytes, em_bits: int, hash_name: str = "sha256",
               salt_length: int = 32) -> bool:
    """EMSA-PSS verification (RFC 8017 section 9.1.2). Returns a bool."""
    hlen = _hash_length(hash_name)
    em_len = (em_bits + 7) // 8
    if len(encoded) != em_len or em_len < hlen + salt_length + 2:
        return False
    if encoded[-1] != 0xBC:
        return False
    masked_db = bytearray(encoded[: em_len - hlen - 1])
    h = encoded[em_len - hlen - 1 : em_len - 1]
    if masked_db[0] & ~(0xFF >> (8 * em_len - em_bits)):
        return False
    masked_db[0] &= 0xFF >> (8 * em_len - em_bits)
    db = bytearray(_xor(bytes(masked_db), mgf1(h, em_len - hlen - 1, hash_name)))
    db[0] &= 0xFF >> (8 * em_len - em_bits)
    ps_len = em_len - hlen - salt_length - 2
    if db[:ps_len] != b"\x00" * ps_len or db[ps_len] != 0x01:
        return False
    salt = bytes(db[-salt_length:]) if salt_length else b""
    m_hash = _digest(hash_name, message)
    return h == _digest(hash_name, b"\x00" * 8 + m_hash + salt)


def pss_sign(key, message: bytes, hash_name: str = "sha256", salt_length: int = 32) -> bytes:
    """RSASSA-PSS sign; requires the private exponent."""
    if key.d is None:
        raise InvalidSignatureError("signing requires a private key")
    k = _modulus_size(key.n)
    em_bits = key.n.bit_length() - 1
    encoded = pss_encode(message, em_bits, hash_name, salt_length)
    m = _os2ip(encoded)
    if m >= key.n:
        raise ValueError("encoded message representative out of range")
    return _i2osp(pow(m, key.d, key.n), k)


def pss_verify_signature(key, message: bytes, signature: bytes, hash_name: str = "sha256",
                         salt_length: int = 32) -> bool:
    """RSASSA-PSS verify with a public (or full) :class:`RSAKey`."""
    k = _modulus_size(key.n)
    if len(signature) != k:
        return False
    s = _os2ip(signature)
    if s >= key.n:
        return False
    m = pow(s, key.e, key.n)
    em_bits = key.n.bit_length() - 1
    return pss_verify(message, _i2osp(m, k), em_bits, hash_name, salt_length)


__all__ = [
    "mgf1",
    "oaep_encode",
    "oaep_decode",
    "oaep_encrypt",
    "oaep_decrypt",
    "pss_encode",
    "pss_verify",
    "pss_sign",
    "pss_verify_signature",
]
