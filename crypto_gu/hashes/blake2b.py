"""BLAKE2b (RFC 7693) pure-Python implementation, verified against hashlib."""

_WORD = 0xFFFFFFFFFFFFFFFF
_ROUNDS = 12
_BLOCK = 128

_IV = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
]

_SIGMA = [
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
]


def _rotr64(v, n):
    return ((v >> n) | (v << (64 - n))) & _WORD


def _g(v, a, b, c, d, x, y):
    v[a] = (v[a] + v[b] + x) & _WORD
    v[d] = _rotr64(v[d] ^ v[a], 32)
    v[c] = (v[c] + v[d]) & _WORD
    v[b] = _rotr64(v[b] ^ v[c], 24)
    v[a] = (v[a] + v[b] + y) & _WORD
    v[d] = _rotr64(v[d] ^ v[a], 16)
    v[c] = (v[c] + v[d]) & _WORD
    v[b] = _rotr64(v[b] ^ v[c], 63)


def _compress(state, block, t0, t1, last):
    v = list(state) + list(_IV)
    v[12] ^= t0
    v[13] ^= t1
    if last:
        v[14] ^= _WORD
    m = [int.from_bytes(block[i * 8 : i * 8 + 8], "little") for i in range(16)]
    for r in range(_ROUNDS):
        s = _SIGMA[r % 10]
        _g(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
        _g(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
        _g(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
        _g(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
        _g(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
        _g(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
        _g(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
        _g(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
    return [(state[i] ^ v[i] ^ v[i + 8]) & _WORD for i in range(8)]


class Blake2b:
    def __init__(self, data=b"", key=b"", salt=b"", personal=b"", digest_size=64):
        if not 1 <= digest_size <= 64:
            raise ValueError("digest_size must be in 1..64")
        if len(key) > 64:
            raise ValueError("key too long")
        if len(salt) > 16:
            raise ValueError("salt too long")
        if len(personal) > 16:
            raise ValueError("personal too long")
        self._digest_size = digest_size
        self._buf = b""
        self._t = 0
        self._state = list(_IV)
        self._state[0] ^= 0x01010000 ^ (len(key) << 8) ^ digest_size
        salt16 = salt.ljust(16, b"\x00")
        personal16 = personal.ljust(16, b"\x00")
        self._state[4] ^= int.from_bytes(salt16[0:8], "little")
        self._state[5] ^= int.from_bytes(salt16[8:16], "little")
        self._state[6] ^= int.from_bytes(personal16[0:8], "little")
        self._state[7] ^= int.from_bytes(personal16[8:16], "little")
        if key:
            self._buf = key.ljust(_BLOCK, b"\x00")
        if data:
            self.update(data)

    def update(self, data):
        self._buf += data
        while len(self._buf) > _BLOCK:
            block = self._buf[:_BLOCK]
            self._buf = self._buf[_BLOCK:]
            self._t += _BLOCK
            self._state = _compress(self._state, block, self._t & _WORD, (self._t >> 64) & _WORD, False)
        return self

    def digest(self):
        self._t += len(self._buf)
        pad = self._buf.ljust(_BLOCK, b"\x00")
        state = _compress(self._state, pad, self._t & _WORD, (self._t >> 64) & _WORD, True)
        return b"".join(w.to_bytes(8, "little") for w in state)[: self._digest_size]

    def hexdigest(self):
        return self.digest().hex()


def blake2b(data=b"", key=b"", salt=b"", personal=b"", digest_size=64):
    return Blake2b(key=key, salt=salt, personal=personal, digest_size=digest_size).update(data).digest()
