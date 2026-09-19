"""RSA public-key primitives.

Pure Python, standard library only. Key generation uses the Miller-Rabin
based :mod:`crypto_gu.number_theory` primes. Textbook RSA helpers are
provided, plus :func:`construct_private` to build a private key from an
explicit factorisation (the output of the attacks in
:mod:`crypto_gu.attacks.rsa`).
"""

from __future__ import annotations

from dataclasses import dataclass

from crypto_gu import number_theory as nt


def _i2b(value: int, size: int) -> bytes:
    return value.to_bytes(size, "big")


def _b2i(data: bytes) -> int:
    return int.from_bytes(data, "big")


@dataclass
class RSAKey:
    """A minimal RSA public/private key pair. ``d`` may be ``None``."""

    n: int
    e: int = 65537
    d: int | None = None
    p: int | None = None
    q: int | None = None

    @classmethod
    def generate(cls, bits: int = 1024, e: int = 65537) -> "RSAKey":
        half = bits // 2
        p = nt.rand_prime(half)
        q = nt.rand_prime(bits - half)
        while q == p:
            q = nt.rand_prime(bits - half)
        return cls._from_pq(p, q, e)

    @classmethod
    def _from_pq(cls, p: int, q: int, e: int) -> "RSAKey":
        n = p * q
        phi = (p - 1) * (q - 1)
        d = nt.modinv(e, phi)
        return cls(n=n, e=e, d=d, p=p, q=q)

    @classmethod
    def from_pq(cls, p: int, q: int, e: int = 65537) -> "RSAKey":
        return cls._from_pq(p, q, e)

    @classmethod
    def from_ned(cls, n: int, e: int, d: int) -> "RSAKey":
        return cls(n=n, e=e, d=d)

    def public(self) -> "RSAKey":
        return RSAKey(n=self.n, e=self.e)

    def _size(self) -> int:
        return (self.n.bit_length() + 7) // 8

    def encrypt(self, message: bytes) -> bytes:
        m = _b2i(message)
        if m >= self.n:
            raise ValueError("message too long for this RSA modulus")
        return _i2b(pow(m, self.e, self.n), self._size())

    def decrypt(self, ciphertext: bytes) -> bytes:
        if self.d is None:
            raise ValueError("cannot decrypt with a public-only key")
        c = _b2i(ciphertext)
        m = _i2b(pow(c, self.d, self.n), self._size()).lstrip(b"\x00")
        return m or b"\x00"

    def sign(self, message: bytes) -> bytes:
        return self.decrypt(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        return _b2i(self.encrypt(signature)) == _b2i(message)

    def max_bytes(self) -> int:
        return (self.n.bit_length() - 1) // 8


def generate_keypair(bits: int = 1024, e: int = 65537) -> RSAKey:
    return RSAKey.generate(bits, e)


def public_encrypt(n: int, e: int, message: bytes) -> bytes:
    return RSAKey(n=n, e=e).encrypt(message)


def private_decrypt(n: int, e: int, d: int, ciphertext: bytes) -> bytes:
    return RSAKey(n=n, e=e, d=d).decrypt(ciphertext)


def construct_private(n: int, p: int, q: int, e: int = 65537) -> RSAKey:
    """Build the private key from a recovered factorisation."""
    if p * q != n:
        raise ValueError("p * q does not equal n")
    return RSAKey._from_pq(p, q, e)


__all__ = ["RSAKey", "generate_keypair", "public_encrypt", "private_decrypt",
           "construct_private"]
