"""Integer arithmetic used by the asymmetric ciphers and their solvers.

Everything here works on Python arbitrary precision ints, so there is no
overflow to worry about.  ``is_prime`` uses a fixed witness set that is
proven correct for every ``n`` below 3.3e24, which covers every key size
this library can reasonably handle.
"""

from __future__ import annotations

import itertools
import random
from typing import Dict, List, Optional, Sequence, Tuple

from .errors import NotPrimitiveError

__all__ = [
    "gcd",
    "extended_gcd",
    "modinv",
    "crt",
    "is_prime",
    "next_prime",
    "rand_prime",
    "legendre_symbol",
    "jacobi_symbol",
    "tonelli_shanks",
    "modular_sqrt",
    "pollard_rho",
    "pollard_p_minus_1",
    "fermat_factor",
    "factorize",
    "continued_fraction",
    "continued_fraction_bounds",
    "discrete_log_bsgs",
    "square_free_decomp",
    "power_mod",
]

_PRIMES_2_100 = (
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97,
)

# Deterministic witness set valid for all n < 3.317e24.
_MR_WITNESSES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def gcd(*values: int) -> int:
    """Greatest common divisor of every value in *values*.

    ``gcd(0, 0)`` is ``0``; ``gcd(0, n)`` is ``abs(n)``.
    """
    result = 0
    for v in values:
        v = abs(int(v))
        while v:
            result, v = v, result % v
    return result


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Return ``(g, x, y)`` with ``g = gcd(a, b)`` and ``a*x + b*y == g``."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def modinv(a: int, modulus: int) -> int:
    """Multiplicative inverse of *a* mod *modulus*.

    Raises :class:`NotPrimitiveError` when *a* and *modulus* are not coprime.
    """
    modulus = abs(modulus)
    if modulus == 0:
        raise ValueError("modulus must be non-zero")
    g, x, _ = extended_gcd(a % modulus, modulus)
    if g != 1:
        raise NotPrimitiveError("no inverse: gcd(%d, %d) == %d" % (a, modulus, g))
    return x % modulus


def crt(congruences: Sequence[Tuple[int, int]]) -> int:
    """Chinese Remainder Theorem.

    ``congruences`` is a sequence of ``(remainder, modulus)`` pairs and the
    moduli must be pairwise coprime.  Returns the unique solution below the
    product of the moduli.
    """
    if not congruences:
        raise ValueError("no congruences given")
    solution, modulus = 0, 1
    for remainder, m in congruences:
        m = abs(m)
        if m <= 1:
            continue
        if gcd(modulus, m) != 1:
            raise NotPrimitiveError("moduli %d and %d are not coprime" % (modulus, m))
        inv = modinv(modulus, m)
        solution = (solution + modulus * (((remainder - solution) * inv) % m)) % (modulus * m)
        modulus *= m
    return solution % modulus


def is_prime(n: int, witnesses: Optional[Sequence[int]] = None) -> bool:
    """Miller-Rabin primality test.

    With the default witness set this is a decision procedure, not a
    probabilistic one: every ``n < 3.317e24`` is classified correctly.
    """
    n = abs(int(n))
    if n < 2:
        return False
    for p in _PRIMES_2_100:
        if n == p:
            return True
        if n % p == 0:
            return False

    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for a in (_MR_WITNESSES if witnesses is None else witnesses):
        if a >= n:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def next_prime(n: int) -> int:
    """Smallest prime strictly greater than *n*."""
    candidate = max(int(n) + 1, 2)
    if candidate == 2:
        return 2
    if candidate % 2 == 0:
        candidate += 1
    while not is_prime(candidate):
        candidate += 2
    return candidate


def rand_prime(bits: int, rng: Optional[random.Random] = None) -> int:
    """Random prime with exactly *bits* bits, top and bottom bits set."""
    if bits < 2:
        raise ValueError("bits must be >= 2")
    if bits == 2:
        return 3
    rng = rng or random.Random()
    while True:
        candidate = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(candidate):
            return candidate


def legendre_symbol(a: int, p: int) -> int:
    """Legendre symbol ``(a | p)`` for an odd prime *p*.

    Returns ``0`` if ``p | a``, ``1`` for a quadratic residue, ``-1`` otherwise.
    """
    p = abs(p)
    if p % 2 == 0 or not is_prime(p):
        raise ValueError("p must be an odd prime")
    a %= p
    if a == 0:
        return 0
    return 1 if pow(a, (p - 1) // 2, p) == 1 else -1


def jacobi_symbol(a: int, n: int) -> int:
    """Jacobi symbol ``(a | n)`` for an odd positive *n*."""
    n = abs(n)
    if n <= 0 or n % 2 == 0:
        raise ValueError("n must be a positive odd integer")
    a %= n
    result = 1
    while a != 0:
        while a % 2 == 0:
            a //= 2
            if n % 8 in (3, 5):
                result = -result
        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            result = -result
        a %= n
    return result if n == 1 else 0


def tonelli_shanks(n: int, p: int) -> int:
    """Square root of *n* mod odd prime *p*, Tonelli-Shanks algorithm.

    Raises :class:`NotPrimitiveError` when *n* is not a quadratic residue.
    """
    p = abs(p)
    if p == 2:
        return n % 2
    if p % 2 == 0:
        raise ValueError("p must be odd")
    n %= p
    if n == 0:
        return 0
    if legendre_symbol(n, p) != 1:
        raise NotPrimitiveError("%d is not a quadratic residue mod %d" % (n, p))
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)

    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while legendre_symbol(z, p) != -1:
        z += 1
    m, c, t, r = s, pow(z, q, p), pow(n, q, p), pow(n, (q + 1) // 2, p)
    while t != 1:
        i, tt = 0, t
        while tt != 1:
            tt = tt * tt % p
            i += 1
        b = pow(c, 1 << (m - i - 1), p)
        m, c = i, b * b % p
        t = t * c % p
        r = r * b % p
    return r


def modular_sqrt(n: int, modulus: int) -> Optional[int]:
    """A square root of *n* mod *modulus*, or ``None`` when it does not exist.

    Handles prime, prime square, and Blum-integer moduli.  General composite
    moduli fall back to Tonelli-Shanks on each prime factor.
    """
    n %= modulus
    if modulus <= 1 or n == 0:
        return 0
    if modulus == 2:
        return n % 2
    if modulus % 2 == 0:
        return None
    if is_prime(modulus):
        try:
            return tonelli_shanks(n, modulus)
        except NotPrimitiveError:
            return None
    # Jacobi of -1 rules out a root. A value of 0 only means gcd(n, modulus)
    # is non-trivial, which is compatible with having a root (e.g. n = 14
    # mod 35, since 14**2 == 21 mod 35), so it must not be rejected here.
    if jacobi_symbol(n, modulus) == -1:
        return None

    per_prime: List[Tuple[int, int]] = []
    seen: Dict[int, int] = {}
    for f in factorize(modulus):
        seen[f] = seen.get(f, 0) + 1
    for p in sorted(seen):
        try:
            rp = tonelli_shanks(n, p)
        except NotPrimitiveError:
            return None
        per_prime.append((rp % p, p))

    for combo in itertools.product(*[[(r, p), ((p - r) % p, p)] for r, p in per_prime]):
        candidate = crt(combo)
        if candidate * candidate % modulus == n:
            return candidate
    return None


def pollard_rho(n: int, x0: Optional[int] = None, c: Optional[int] = None) -> Optional[int]:
    """Pollard's rho factor, Brent variant.  Returns a non-trivial factor or ``None``."""
    n = abs(n)
    if n <= 1 or is_prime(n):
        return None
    if n % 2 == 0:
        return 2
    rng = random.Random(n ^ 0x5DEECE66D)
    x0 = x0 if x0 is not None else rng.randrange(2, n)
    c = c if c is not None else rng.randrange(1, n - 1)

    def f(v: int) -> int:
        return (v * v + c) % n

    y, r, q, m = x0, 1, 1, 32
    g, x, ys = 1, 0, 0
    while g == 1:
        x = y
        for _ in range(r):
            y = f(y)
        k = 0
        while k < r and g == 1:
            ys = y
            for _ in range(min(m, r - k)):
                y = f(y)
                q = q * abs(x - y) % n
            g = gcd(q, n)
            k += m
        r *= 2
    if g == n:
        while True:
            ys = f(ys)
            g = gcd(abs(x - ys), n)
            if g > 1:
                break
    return None if g == n else g


def pollard_p_minus_1(n: int, bound: int = 100000, rng: Optional[random.Random] = None) -> Optional[int]:
    """Pollard's p-1 factor.  Succeeds when some prime factor ``p`` of *n* has
    ``p-1`` smooth below *bound*.  Returns ``None`` when it fails."""
    n = abs(n)
    if n <= 1 or is_prime(n):
        return None
    rng = rng or random.Random()
    a = rng.randrange(2, n)
    exponent = 1
    p = 2
    while p <= bound:
        step = p
        while step <= bound:
            exponent *= step
            step *= p
        a = pow(a, exponent, n)
        g = gcd(a - 1, n)
        if 1 < g < n:
            return g
        a = pow(a, p, n)
        p = next_prime(p)
    return None


def fermat_factor(n: int, limit: int = 100000) -> Optional[int]:
    """Fermat's difference of squares.  Fast when the two primes are close."""
    n = abs(n)
    if n <= 1 or is_prime(n):
        return None
    a = isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(limit):
        d2 = a * a - n
        if d2 >= 0:
            d = isqrt(d2)
            if d * d == d2:
                b = a - d
                if b > 1 and n % b == 0:
                    return b
        a += 1
    return None


def isqrt(n: int) -> int:
    """Integer square root, floor."""
    if n < 0:
        raise ValueError("negative")
    if n == 0:
        return 0
    x = int(n ** 0.5)
    while x * x > n:
        x -= 1
    while (x + 1) * (x + 1) <= n:
        x += 1
    return x


def factorize(n: int) -> List[int]:
    """Full factorisation into primes, sorted, smallest first.

    Uses trial division up to 10^5, then Pollard rho with retries.
    """
    n = abs(n)
    if n <= 1:
        return []
    out: List[int] = []
    for p in _PRIMES_2_100:
        while n % p == 0:
            out.append(p)
            n //= p
    if n == 1:
        return out
    stack = [n]
    while stack:
        x = stack.pop()
        if x == 1:
            continue
        if is_prime(x):
            out.append(x)
            continue
        found: Optional[int] = None
        for c in range(1, 12):
            f = pollard_rho(x, x0=2 + c, c=c)
            if f:
                found = f
                break
        if found is None:
            f2 = pollard_p_minus_1(x, bound=1000000)
            if f2:
                found = f2
        if found is None:
            raise NotPrimitiveError("failed to factor %d" % x)
        stack.append(found)
        stack.append(x // found)
    out.sort()
    return out


def square_free_decomp(n: int) -> Tuple[int, int]:
    """Return ``(b, c)`` with ``n == b * c^2`` and *b* squarefree."""
    b, c = 1, 1
    counts: Dict[int, int] = {}
    for p in factorize(abs(int(n))):
        counts[p] = counts.get(p, 0) + 1
    for p, e in counts.items():
        b *= p ** (e % 2)
        c *= p ** (e // 2)
    return b, c


def continued_fraction(x: float, max_terms: int = 100) -> List[int]:
    """Simple continued fraction expansion of *x* as ints."""
    out: List[int] = []
    for _ in range(max_terms):
        if x != int(x):
            out.append(int(x))
            x = 1.0 / (x - int(x))
        else:
            out.append(int(x))
            break
    return out


def continued_fraction_bounds(cf: Sequence[int]) -> List[Tuple[int, int]]:
    """Convergents ``(numerator, denominator)`` of a continued fraction."""
    out: List[Tuple[int, int]] = []
    p_prev2, p_prev = 0, 1
    q_prev2, q_prev = 1, 0
    for a in cf:
        p = a * p_prev + p_prev2
        q = a * q_prev + q_prev2
        p_prev2, p_prev = p_prev, p
        q_prev2, q_prev = q_prev, q
        out.append((p, q))
    return out


def discrete_log_bsgs(base: int, target: int, modulus: int, order: Optional[int] = None) -> Optional[int]:
    """Baby-step giant-step discrete logarithm, ``base**k == target (mod modulus)``.

    Returns ``k`` in ``[0, order)`` or ``None`` when no solution exists.
    """
    modulus = abs(modulus)
    target %= modulus
    n = order if order is not None else modulus - 1
    if n <= 0 or modulus <= 1:
        return None
    if gcd(base, modulus) != 1:
        return None

    m = isqrt(n)
    if m * m < n:
        m += 1

    babies: Dict[int, int] = {}
    e = 1
    for i in range(m):
        babies.setdefault(e, i)
        e = e * base % modulus

    giant_step = modinv(pow(base, m, modulus), modulus)
    gamma = target
    for j in range(m + 1):
        i = babies.get(gamma)
        if i is not None:
            k = j * m + i
            if k < n and pow(base, k, modulus) == target:
                return k
        gamma = gamma * giant_step % modulus
    return None


def power_mod(base: int, exp: int, modulus: int) -> int:
    """``base**exp % modulus`` (alias of the builtin, kept for readability)."""
    if modulus == 1:
        return 0
    return pow(base, exp, modulus)
