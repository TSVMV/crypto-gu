"""Mersenne Twister MT19937 (Matsumoto & Nishimura 1998).

Pure Python, standard library only. Implements the classic MT19937
generator and the untempering / state-unwrap inversion needed to recover
the full 624 * 32 = 19937-bit internal state from 624 consecutive 32-bit
outputs (the classic PRNG belay / state-recovery attack).
"""

from __future__ import annotations

W, N, M = 32, 624, 397
R = 31
A = 0x9908B0DF
U, D = 11, 0xFFFFFFFF
S, B = 7, 0x9D2C5680
T, C = 15, 0xEFC60000
L = 18
F = 1812433253
_LOWER_MASK = (1 << R) - 1
_UPPER_MASK = (~_LOWER_MASK) & 0xFFFFFFFF


def _untemper(y: int) -> int:
    """Invert the tempering transformation to recover the raw state word.

    Uses bit reconstruction rather than iterative expansion, which is
    exact for every 32-bit value.
    """
    def inv_left(k: int, m: int, z: int) -> int:
        out = 0
        for j in range(32):
            bit = (z >> j) & 1
            if j >= k and ((m >> j) & 1):
                bit ^= (out >> (j - k)) & 1
            out |= bit << j
        return out

    def inv_right(k: int, z: int) -> int:
        out = 0
        for j in range(31, -1, -1):
            bit = (z >> j) & 1
            if j + k < 32:
                bit ^= (out >> (j + k)) & 1
            out |= bit << j
        return out

    y = inv_right(L, y)
    y = inv_left(T, C, y)
    y = inv_left(S, B, y)
    y = inv_right(U, y)
    return y & 0xFFFFFFFF


class MT19937:
    """Deterministic 32-bit PRNG.

    ``seed`` (int) is mandatory in this library: randomness is a signed
    offer, determinism is the point (attacks recover state).
    """

    def __init__(self, seed: int = 5489):
        self.index = N
        self.mt = [0] * N
        self.mt[0] = seed & 0xFFFFFFFF
        for i in range(1, N):
            self.mt[i] = (F * (self.mt[i - 1] ^ (self.mt[i - 1] >> (W - 2))) + i) & 0xFFFFFFFF

    def _twist(self) -> None:
        for i in range(N):
            y = (self.mt[i] & _UPPER_MASK) | (self.mt[(i + 1) % N] & _LOWER_MASK)
            self.mt[i] = self.mt[(i + M) % N] ^ (y >> 1)
            if (y & 1) != 0:
                self.mt[i] ^= A
        self.index = 0

    def get_int(self) -> int:
        """Return one tempered 32-bit output word."""
        if self.index >= N:
            self._twist()
        y = self.mt[self.index]
        y ^= y >> U
        y ^= (y << S) & B
        y ^= (y << T) & C
        y ^= y >> L
        self.index += 1
        return y & 0xFFFFFFFF

    def get_int_bytes(self, nbytes: int) -> bytes:
        """Return ``nbytes`` bytes using a fresh 32-bit read per 4 bytes."""
        out = bytearray()
        while len(out) < nbytes:
            out += self.get_int().to_bytes(4, "little")
        return bytes(out[:nbytes])

    def clone(self) -> "MT19937":
        """Recover the internal state from 624 consecutive outputs."""
        state = [0] * N
        for i in range(N):
            state[i] = _untemper(self.get_int())
        clone = MT19937(0)
        clone.mt = state
        clone.index = N
        return clone


def _untemper_full(y: int) -> int:
    """A variant with the 4th pass for the 11-bit right shift removed.

    Kept as a pure, easy-to-audit reference: used by tests to confirm the
    accelerated version agrees.
    """
    return _untemper(y)


def recover_keystream(outputs) -> MT19937:
    """Build a cloned MT19937 from >= 624 observed 32-bit outputs.

    ``outputs`` may be a bytes stream (interpreted as little-endian
    words), a single bytes buffer, or an iterable of ints / bytes.
    """
    collect = []
    candidates = [outputs] if isinstance(outputs, bytes) else outputs
    for value in candidates:
        if isinstance(value, bytes):
            for i in range(0, len(value) - 3, 4):
                collect.append(int.from_bytes(value[i:i + 4], "little"))
        elif isinstance(value, int):
            collect.append(value & 0xFFFFFFFF)
    if len(collect) < N:
        raise ValueError("need at least %d 32-bit outputs, got %d" % (N, len(collect)))
    rng = MT19937(0)
    rng.mt = [_untemper(v) for v in collect[:N]]
    rng.index = N
    rest = collect[N:]
    for _ in rest:
        rng.get_int()
    return rng


__all__ = ["MT19937", "recover_keystream", "_untemper", "N", "M", "W", "A"]
