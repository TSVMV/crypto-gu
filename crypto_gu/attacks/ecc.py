"""Deterministic ECDLP attacks.

Both attacks recover the secret scalar ``d`` from a *misconfigured* ECC
setup without ever brute-forcing the full key space:

- :func:`pohlig_hellman` — the group order is smooth (all prime factors
  small). The DLP is projected onto each prime-power subgroup, solved
  there with BSGS, and stitched back with CRT.

- :func:`invalid_curve` — the server multiplies attacker-supplied points
  without checking curve membership. Points submitted on a *different*
  curve that shares the same ``a`` coefficient travel through the same
  addition formulas; choosing curves whose order factors into small
  primes leaks ``d`` modulo each small factor, and CRT reassembles ``d``.
"""

from __future__ import annotations

from crypto_gu import ecc
from crypto_gu import number_theory as nt

__all__ = ["pohlig_hellman", "invalid_curve"]


def pohlig_hellman(p: int, a: int, P, Q, group_order: int, factorization: dict):
    """Recover ``d`` with ``Q = d * P`` on a smooth-order curve.

    ``group_order`` is the order of P (the curve subgroup order) and
    ``factorization`` maps each prime ``q`` to its exponent ``e`` so that
    ``prod(q**e) == group_order``. Every prime power ``q**e`` must be
    small enough for a BSGS table (about ``sqrt(q**e)`` entries).

    Returns ``(d, residues)`` where ``residues`` is the list of
    ``(residue, modulus)`` pairs that were combined, or ``(None, [])``
    when any subgroup DLP has no solution.
    """
    residues = []
    for q, e in factorization.items():
        mod = q ** e
        cofactor = group_order // mod
        G = ecc.point_mul(p, a, cofactor, P)
        H = ecc.point_mul(p, a, cofactor, Q)
        x = ecc.ec_bsgs(p, a, G, H, mod)
        if x is None:
            return None, []
        residues.append((x, mod))
    d = nt.crt(residues)
    return d, residues


def invalid_curve(p: int, a: int, oracle, generators):
    """Recover ``d`` from an oracle that multiplies unvalidated points.

    ``oracle(P) -> R`` must return the server's answer for ``d * P``. The
    server is assumed to run the standard addition formulas (which only
    use ``a``) with no membership check, so points from a different curve
    ``y^2 = x^3 + a*x + b'`` are processed happily.

    ``generators`` is a sequence of ``(G_i, r_i)`` pairs where ``G_i``
    lies on such an invalid curve and has small order exactly ``r_i``
    (build these with :func:`ecc.point_order` on your candidate curves).
    For each generator the local BSGS recovers ``d mod r_i``; residues
    are combined with CRT.

    Returns ``(d, residues)`` with ``d`` determined modulo
    ``prod(r_i)`` — enough to pin the scalar once the product exceeds the
    true order — or ``(None, [])`` if any oracle call is rejected
    (``None`` answer) or any subgroup DLP fails. A rejected point usually
    means the server validated curve membership after all. Note that
    ``d mod r_i == 0`` makes the true answer the point at infinity; this
    API treats such a response as a rejection, so pick generators whose
    orders divide the scalar if that case matters.
    """
    residues = []
    for G, r in generators:
        R = oracle(G)
        if R is None:
            return None, []
        d_i = ecc.ec_bsgs(p, a, G, R, r)
        if d_i is None:
            return None, []
        residues.append((d_i, r))
    d = nt.crt(residues)
    return d, residues
