"""AES-128/192/256 (FIPS-197) with ECB, CBC, CFB, OFB and CTR modes.

Pure Python, standard library only. The S-box is generated at import time from
the GF(2^8) multiplicative inverse plus the FIPS-197 affine transformation.
"""

from __future__ import annotations

from crypto_gu.errors import InvalidIVError, InvalidKeyError, InvalidPaddingError

BLOCK = 16
_KEY_SIZES = (16, 24, 32)
_ROUNDS = {16: 10, 24: 12, 32: 14}

_POLY = 0x11b


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= _POLY
    return a & 0xFF


def _gf_mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        b >>= 1
        a = _xtime(a)
    return p & 0xFF


def _gf_pow(a: int, n: int) -> int:
    r = 1
    while n:
        if n & 1:
            r = _gf_mul(r, a)
        a = _gf_mul(a, a)
        n >>= 1
    return r & 0xFF


def _gf_inv(a: int) -> int:
    return 0 if a == 0 else _gf_pow(a, 254)


def _affine(x: int) -> int:
    """FIPS-197 section 5.1.1 affine transformation."""
    out = 0
    for b in range(8):
        bit = 0
        for k in (0, 4, 5, 6, 7):
            bit ^= (x >> ((b + k) % 8)) & 1
        out |= (bit ^ ((0x63 >> b) & 1)) << b
    return out


SBOX = bytes(_affine(_gf_inv(i)) for i in range(256))
_inv = [0] * 256
for _i, _v in enumerate(SBOX):
    _inv[_v] = _i
INV_SBOX = bytes(_inv)

_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
         0x6C, 0xD8, 0xB2, 0x7C)


def _expand_key(key: bytes) -> list:
    """Return the key schedule as a flat list of round words (bytes)."""
    if len(key) not in _KEY_SIZES:
        raise InvalidKeyError("AES key must be %d, %d, or %d bytes, got %d"
                              % (_KEY_SIZES[0], _KEY_SIZES[1], _KEY_SIZES[2], len(key)))
    nk = len(key) // 4
    nr = _ROUNDS[len(key)]
    w = [list(key[i:i + 4]) for i in range(0, len(key), 4)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
    return w


def _add_round_key(state: bytearray, w: list, round_no: int) -> None:
    for i in range(16):
        state[i] ^= w[(round_no * 4 + i // 4)][i % 4]


def _sub_bytes(state: bytearray, box: bytes) -> None:
    for i in range(16):
        state[i] = box[state[i]]


def _shift_rows(state: bytearray) -> None:
    for r in range(1, 4):
        row = [state[r + 4 * c] for c in range(4)]
        for c in range(4):
            state[r + 4 * c] = row[(c + r) % 4]


def _inv_shift_rows(state: bytearray) -> None:
    for r in range(1, 4):
        row = [state[r + 4 * c] for c in range(4)]
        for c in range(4):
            state[r + 4 * c] = row[(c - r) % 4]


def _mix_columns(state: bytearray) -> None:
    for c in range(4):
        s = [state[r + 4 * c] for r in range(4)]
        out = [
            _gf_mul(s[0], 2) ^ _gf_mul(s[1], 3) ^ s[2] ^ s[3],
            s[0] ^ _gf_mul(s[1], 2) ^ _gf_mul(s[2], 3) ^ s[3],
            s[0] ^ s[1] ^ _gf_mul(s[2], 2) ^ _gf_mul(s[3], 3),
            _gf_mul(s[0], 3) ^ s[1] ^ s[2] ^ _gf_mul(s[3], 2),
        ]
        for r in range(4):
            state[r + 4 * c] = out[r]


def _inv_mix_columns(state: bytearray) -> None:
    for c in range(4):
        s = [state[r + 4 * c] for r in range(4)]
        out = [
            _gf_mul(s[0], 14) ^ _gf_mul(s[1], 11) ^ _gf_mul(s[2], 13) ^ _gf_mul(s[3], 9),
            _gf_mul(s[0], 9) ^ _gf_mul(s[1], 14) ^ _gf_mul(s[2], 11) ^ _gf_mul(s[3], 13),
            _gf_mul(s[0], 13) ^ _gf_mul(s[1], 9) ^ _gf_mul(s[2], 14) ^ _gf_mul(s[3], 11),
            _gf_mul(s[0], 11) ^ _gf_mul(s[1], 13) ^ _gf_mul(s[2], 9) ^ _gf_mul(s[3], 14),
        ]
        for r in range(4):
            state[r + 4 * c] = out[r]


def block_encrypt(key: bytes, data: bytes) -> bytes:
    """Encrypt exactly one 16-byte block."""
    if len(data) != BLOCK:
        raise InvalidPaddingError("AES block must be %d bytes, got %d" % (BLOCK, len(data)))
    w = _expand_key(key)
    nr = _ROUNDS[len(key)]
    state = bytearray(data)
    _add_round_key(state, w, 0)
    for r in range(1, nr + 1):
        _sub_bytes(state, SBOX)
        _shift_rows(state)
        if r != nr:
            _mix_columns(state)
        _add_round_key(state, w, r)
    return bytes(state)


def block_decrypt(key: bytes, data: bytes) -> bytes:
    """Decrypt exactly one 16-byte block."""
    if len(data) != BLOCK:
        raise InvalidPaddingError("AES block must be %d bytes, got %d" % (BLOCK, len(data)))
    w = _expand_key(key)
    nr = _ROUNDS[len(key)]
    state = bytearray(data)
    _add_round_key(state, w, nr)
    for r in range(nr - 1, 0, -1):
        _inv_shift_rows(state)
        _sub_bytes(state, INV_SBOX)
        _add_round_key(state, w, r)
        _inv_mix_columns(state)
    _inv_shift_rows(state)
    _sub_bytes(state, INV_SBOX)
    _add_round_key(state, w, 0)
    return bytes(state)


# --------------------------------------------------------------------------- #
# Modes of operation
# --------------------------------------------------------------------------- #


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _require_blocks(data: bytes, mode: str) -> None:
    if len(data) % BLOCK:
        raise InvalidPaddingError(
            "%s needs a multiple of %d bytes, got %d" % (mode, BLOCK, len(data))
        )


def _require_iv(iv: bytes) -> bytes:
    if len(iv) != BLOCK:
        raise InvalidIVError("AES IV must be %d bytes, got %d" % (BLOCK, len(iv)))
    return iv


def ecb_encrypt(key: bytes, data: bytes) -> bytes:
    _require_blocks(data, "ECB")
    return b"".join(block_encrypt(key, data[i:i + BLOCK]) for i in range(0, len(data), BLOCK))


def ecb_decrypt(key: bytes, data: bytes) -> bytes:
    _require_blocks(data, "ECB")
    return b"".join(block_decrypt(key, data[i:i + BLOCK]) for i in range(0, len(data), BLOCK))


def cbc_encrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    iv = _require_iv(iv)
    _require_blocks(data, "CBC")
    out, prev = bytearray(), iv
    for i in range(0, len(data), BLOCK):
        block = _xor(data[i:i + BLOCK], prev)
        prev = block_encrypt(key, block)
        out += prev
    return bytes(out)


def cbc_decrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    iv = _require_iv(iv)
    _require_blocks(data, "CBC")
    out, prev = bytearray(), iv
    for i in range(0, len(data), BLOCK):
        block = data[i:i + BLOCK]
        out += _xor(block_decrypt(key, block), prev)
        prev = block
    return bytes(out)


def cfb_encrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    """CFB full-block mode; any input length."""
    iv = _require_iv(iv)
    prev = iv
    out = bytearray()
    for i in range(0, len(data), BLOCK):
        chunk = data[i:i + BLOCK]
        out += _xor(chunk, block_encrypt(key, prev))
        prev = bytes(out[i:i + len(chunk)])
    return bytes(out)


def cfb_decrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    iv = _require_iv(iv)
    prev = iv
    out = bytearray()
    for i in range(0, len(data), BLOCK):
        chunk = data[i:i + BLOCK]
        plain = _xor(chunk, block_encrypt(key, prev))
        prev = chunk
        out += plain
    return bytes(out)


def ofb_encrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    """OFB mode; any input length. Encryption and decryption are identical."""
    iv = _require_iv(iv)
    prev = iv
    out = bytearray()
    for i in range(0, len(data), BLOCK):
        keystream = block_encrypt(key, prev)
        out += _xor(data[i:i + BLOCK], keystream)
        prev = keystream
    return bytes(out)


def ofb_decrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    return ofb_encrypt(key, data, iv)


def _ctr_block(nonce: bytes, counter: int) -> bytes:
    """Build a CTR counter block from a nonce and an integer counter."""
    n = len(nonce)
    if n == BLOCK:
        return (int.from_bytes(nonce, "big") + counter).to_bytes(BLOCK, "big")
    if n == 0:
        return counter.to_bytes(BLOCK, "big")
    return nonce.ljust(BLOCK - n, b"\x00") + counter.to_bytes(n, "big")


def ctr_encrypt(key: bytes, data: bytes, nonce: bytes, initial: int = 0) -> bytes:
    """CTR mode. A short nonce is zero-padded to the left of the counter."""
    if len(nonce) > BLOCK:
        raise InvalidIVError("CTR nonce must be at most %d bytes, got %d" % (BLOCK, len(nonce)))
    out = bytearray()
    counter = initial
    for i in range(0, len(data), BLOCK):
        out += _xor(data[i:i + BLOCK], block_encrypt(key, _ctr_block(nonce, counter)))
        counter += 1
    return bytes(out)


def ctr_decrypt(key: bytes, data: bytes, nonce: bytes, initial: int = 0) -> bytes:
    return ctr_encrypt(key, data, nonce, initial)


_MODES = {
    "ecb": (ecb_encrypt, ecb_decrypt),
    "cbc": (cbc_encrypt, cbc_decrypt),
    "cfb": (cfb_encrypt, cfb_decrypt),
    "ofb": (ofb_encrypt, ofb_decrypt),
    "ctr": (ctr_encrypt, ctr_decrypt),
}


def encrypt(key: bytes, data: bytes, mode: str = "cbc", iv: bytes = b"", nonce: bytes = b"") -> bytes:
    fn = _MODES.get(mode.lower())
    if fn is None:
        raise InvalidKeyError("unknown AES mode %r" % mode)
    encrypt_fn, _ = fn
    if mode.lower() == "ecb":
        return encrypt_fn(key, data)
    if mode.lower() == "ctr":
        return encrypt_fn(key, data, nonce)
    return encrypt_fn(key, data, iv)


def decrypt(key: bytes, data: bytes, mode: str = "cbc", iv: bytes = b"", nonce: bytes = b"") -> bytes:
    fn = _MODES.get(mode.lower())
    if fn is None:
        raise InvalidKeyError("unknown AES mode %r" % mode)
    _, decrypt_fn = fn
    if mode.lower() == "ecb":
        return decrypt_fn(key, data)
    if mode.lower() == "ctr":
        return decrypt_fn(key, data, nonce)
    return decrypt_fn(key, data, iv)


def cipher(key: bytes, data: bytes, mode: str = "cbc", iv: bytes | None = None,
           nonce: bytes = b"", operation: str = "encrypt") -> tuple:
    """Convenience: returns ``(output, iv_or_nonce)`` for transport.

    ``operation`` is ``"encrypt"`` or ``"decrypt"``.
    """
    mode = mode.lower()
    fn = _MODES.get(mode)
    if fn is None:
        raise InvalidKeyError("unknown AES mode %r" % mode)
    is_enc = operation.lower() == "encrypt"
    run = fn[0] if is_enc else fn[1]
    if mode == "ctr":
        return run(key, data, nonce), nonce
    if mode == "ecb":
        return run(key, data), b""
    if iv is None:
        raise InvalidIVError("%s mode needs an IV" % mode.upper())
    return run(key, data, iv), iv


__all__ = [
    "BLOCK",
    "SBOX",
    "INV_SBOX",
    "block_encrypt",
    "block_decrypt",
    "ecb_encrypt",
    "ecb_decrypt",
    "cbc_encrypt",
    "cbc_decrypt",
    "cfb_encrypt",
    "cfb_decrypt",
    "ofb_encrypt",
    "ofb_decrypt",
    "ctr_encrypt",
    "ctr_decrypt",
    "encrypt",
    "decrypt",
    "cipher",
]
