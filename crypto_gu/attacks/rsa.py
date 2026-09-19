"""Deterministic RSA attack recipes.

These recover factors or plaintext from a *misconfigured* RSA setup
without brute-forcing the key space. Every attack here either succeeds on
its precondition or returns ``None``; nothing here tries random exponents.

Implemented:
- :func:`wiener`           — recovers ``d`` from a small private exponent.
- :func:`fermat`           — factorial for close primes ``p``, ``q``.
- :func:`pollard_p_minus_1`— smooth ``p-1``.
- :func:`common_modulus`   — two ciphertexts of the same message, public
                             exponents coprime.
- :func:`broadcast`        — Håstad, low exponent + many receivers.
- :func:`plaintext_encrypt` — no-op composition helper.
"""

from __future__ import annotations

from crypto_gu import number_theory as nt


def _cf_frac(num: int, den: int) -> list:
    """Continued fraction expansion of the rational num/den as ints."""
    terms = []
    while den:
        terms.append(num // den)
        num, den = den, num % den
    return terms


def _convergents(terms: list) -> list:
    out = []
    n0, d0 = 0, 1
    n1, d1 = 1, 0
    for a in terms:
        n0, n1 = n1, a * n1 + n0
        d0, d1 = d1, a * d1 + d0
        out.append((n1, d1))
    return out


def wiener(n: int, e: int):
    """Recover ``d`` (as an int) when it is smaller than ``n^0.25 / 3``.

    Standard Wiener attack: the continued fraction of ``e/n`` contains
    ``k/d``; test each convergent for a valid factorisation.
    Returns the private exponent, or ``None``.
    """
    for k, d in _convergents(_cf_frac(e, n)):
        if k == 0 or d == 0:
            continue
        if (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        r = nt.isqrt(disc)
        if r * r != disc:
            continue
        p = (s + r) // 2
        q = (s - r) // 2
        if p * q == n:
            return d
    return None


def fermat(n: int, limit: int = 1000000):
    """Recover factors when ``p`` and ``q`` are close (difference of squares)."""
    return nt.fermat_factor(n, limit)


def pollard_p_minus_1(n: int, bound: int = 100000, rng=None):
    """Recover a factor when ``p-1`` is bound-smooth."""
    return nt.pollard_p_minus_1(n, bound, rng)


def common_modulus(n: int, e1: int, c1: int, e2: int, c2: int):
    """Recover plaintext ``m`` (int) from two ciphertexts sharing modulus.

    Precondition: ``gcd(e1, e2) == 1``.  Returns the message int, or
    ``None`` if the ciphertexts are inconsistent.
    """
    g, x, y = nt.extended_gcd(e1, e2)
    if g != 1:
        return None
    if x < 0:
        c1 = nt.modinv(c1, n)
        x = -x
    if y < 0:
        c2 = nt.modinv(c2, n)
        y = -y
    return (pow(c1, x, n) * pow(c2, y, n)) % n


def broadcast(ciphertexts, exponent: int = 3):
    """Håstad's broadcast attack.

    ``ciphertexts`` is an iterable of ``(n, c)`` pairs for the same
    plaintext encrypted to ``len(ciphertexts)`` >= ``exponent`` receivers.
    Returns the message int, or ``None`` when precondition is unmet.
    """
    pairs = list(ciphertexts)
    if len(pairs) < exponent:
        return None
    res = nt.crt([(c % n, n) for n, c in pairs])
    return _iroot(res, exponent)


def _iroot(num: int, root: int) -> int:
    """Integer ``root``-th root (floor) via Newton iterations."""
    if root == 1:
        return num
    if num < 0:
        return -_iroot(-num, root)
    if num == 0:
        return 0
    high = 1 << ((num.bit_length() + root - 1) // root)
    while True:
        low = ((root - 1) * high + num // pow(high, root - 1)) // root
        if low >= high:
            break
        high = low
    return high


def plaintext_encrypt(key, message: bytes) -> bytes:
    """Helper to compute a ciphertext from :class:`RSAKey` without padding."""
    return key.encrypt(message)


__all__ = ["wiener", "fermat", "pollard_p_minus_1", "common_modulus",
           "broadcast"]
