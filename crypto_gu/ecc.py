"""Short Weierstrass elliptic curves: y^2 = x^3 + a*x + b (mod p).

Pure Python, standard library only. Points are ``(x, y)`` tuples; the point
at infinity is ``None``. The addition formula uses only the coefficient
``a`` — ``b`` matters exclusively for membership checks via
:func:`on_curve`. That asymmetry is exactly what the invalid-curve attack
(:mod:`crypto_gu.attacks.ecc`) exploits, so the primitives deliberately
mirror it: they never validate curve membership themselves.

All functions take the field prime ``p`` and curve coefficient ``a``
explicitly; nothing here caches curve state.
"""

from __future__ import annotations

from crypto_gu import number_theory as nt

Point = tuple  # (x, y) or None

__all__ = [
    "on_curve",
    "point_neg",
    "point_add",
    "point_mul",
    "point_order",
    "curve_order_bruteforce",
    "ec_bsgs",
]


def on_curve(p: int, a: int, b: int, P: Point) -> bool:
    """Return True if ``P`` satisfies y^2 = x^3 + a*x + b (mod p)."""
    if P is None:
        return True
    x, y = P
    return (y * y - (x * x * x + a * x + b)) % p == 0


def point_neg(p: int, P: Point) -> Point:
    """Negate a point: -(x, y) = (x, -y); -infinity = infinity."""
    if P is None:
        return None
    return (P[0], (-P[1]) % p)


def point_add(p: int, a: int, P: Point, Q: Point) -> Point:
    """Add two points on y^2 = x^3 + a*x + b (mod p).

    The chord/tangent formulas depend on ``a`` alone; ``b`` never enters,
    which is why callers may mix points from different curves sharing the
    same ``a`` — the precondition of the invalid-curve attack.
    """
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        if y1 % p == 0:
            return None
        lam = (3 * x1 * x1 + a) * nt.modinv(2 * y1, p) % p
    else:
        lam = (y2 - y1) * nt.modinv((x2 - x1) % p, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def point_mul(p: int, a: int, k: int, P: Point) -> Point:
    """Scalar multiplication ``k * P`` by double-and-add."""
    if k < 0:
        return point_mul(p, a, -k, point_neg(p, P))
    R = None
    Q = P
    while k:
        if k & 1:
            R = point_add(p, a, R, Q)
        Q = point_add(p, a, Q, Q)
        k >>= 1
    return R


def point_order(p: int, a: int, P: Point, max_order: int) -> int:
    """Smallest ``k`` with ``k * P = infinity``, searching up to ``max_order``.

    Returns 0 when the order exceeds ``max_order``. Intended for small
    subgroups (teaching vectors, invalid-curve generators); never run this
    on a cryptographic-size group.
    """
    if P is None:
        return 1
    R = P
    k = 1
    while k <= max_order:
        if R is None:
            return k
        R = point_add(p, a, R, P)
        k += 1
    return 0


def curve_order_bruteforce(p: int, a: int, b: int) -> int:
    """Count points on y^2 = x^3 + a*x + b over F_p by enumerating x.

    O(p) — teaching-scale primes only (say p < 10^7). Uses Legendre
    symbols to count quadratic residues and adds the point at infinity.
    """
    count = 1  # point at infinity
    for x in range(p):
        rhs = (x * x * x + a * x + b) % p
        if rhs == 0:
            count += 1
        elif nt.legendre_symbol(rhs, p) == 1:
            count += 2
    return count


def ec_bsgs(p: int, a: int, G: Point, Q: Point, order: int) -> int:
    """Baby-step giant-step ECDLP: find ``d`` with ``Q = d * G``.

    ``order`` is the (known) order of ``G``. Returns the discrete log in
    ``[0, order)``, or ``None`` when no solution exists. Works on any
    prime-order or small composite-order subgroup; the caller is expected
    to have projected the problem onto such a subgroup first (see
    :func:`crypto_gu.attacks.ecc.pohlig_hellman`).
    """
    m = nt.isqrt(order) + 1
    table = {}
    cur = None
    for j in range(m):
        if cur not in table:  # keep the smallest j for each point
            table[cur] = j
        cur = point_add(p, a, cur, G)
    mG = point_mul(p, a, m, G)
    neg = point_neg(p, mG)
    cur = Q
    for i in range(m):
        if cur in table:
            d = (i * m + table[cur]) % order
            if point_mul(p, a, d, G) == Q:
                return d
        cur = point_add(p, a, cur, neg)
    return None
