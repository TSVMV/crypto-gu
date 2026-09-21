"""Tests for ECDLP attacks (Pohlig-Hellman, invalid curve)."""

import sys
import unittest

sys.path.insert(0, "/workspace/crypto-gu")

from crypto_gu import ecc
from crypto_gu import number_theory as nt
from crypto_gu.attacks import ecc as attacks


def find_smooth_curve(p, max_ab=12, max_prime=64):
    """Find (a, b, generator) with a smooth, cyclic full group over F_p.

    Returns ``(a, b, order, factors, P)`` where ``P`` generates the whole
    curve group (needed for the projection math). The group over F_p is
    cyclic for elliptic curves, but a smooth order costs nothing to check
    directly by hunting for a point of full order.
    """
    for a in range(max_ab):
        for b in range(max_ab):
            order = ecc.curve_order_bruteforce(p, a, b)
            if order < 4:
                continue
            factors = {}
            for q in nt.factorize(order):
                factors[q] = factors.get(q, 0) + 1
            if not factors or max(factors) > max_prime:
                continue
            P = find_point_of_order(p, a, b, order)
            if P is not None:
                return a, b, order, factors, P
    raise AssertionError("no smooth cyclic curve found under the search bounds")


def find_point_of_order(p, a, b, order):
    for x in range(p):
        for y in range(p):
            if not ecc.on_curve(p, a, b, (x, y)):
                continue
            if ecc.point_order(p, a, (x, y), order) == order:
                return (x, y)
    return None


def find_large_prime_order_point(p, a, b, min_order=100):
    """A point of prime order >= min_order on y^2 = x^3 + a*x + b.

    The curve group over F_p is cyclic; factor its order, take a large
    prime factor q, and project any non-infinity point through (N/q)*.
    """
    n = ecc.curve_order_bruteforce(p, a, b)
    primes = sorted({q for q in nt.factorize(n) if q >= min_order},
                    reverse=True)
    for q in primes:
        for x in range(p):
            for y in range(p):
                if not ecc.on_curve(p, a, b, (x, y)):
                    continue
                proj = ecc.point_mul(p, a, n // q, (x, y))
                if proj is not None:
                    return proj, q
    return None, 0


class TestInvalidCurve(unittest.TestCase):
    def test_recovers_secret_mod_product(self):
        p = 10007
        a = 1
        # Server key on the real curve y^2 = x^3 + x + 3.
        real_b = 3
        d = 4242
        oracle = lambda P: ecc.point_mul(p, a, d, P)  # noqa: E731 - test stub

        # Find two invalid curves (same a, different b) whose groups have
        # coprime large prime factors; the oracle processes their points
        # because a alone drives the addition formulas.
        generators = []
        used = set()
        for b_prime in range(1, 60):
            if b_prime == real_b:
                continue
            G, r = find_large_prime_order_point(p, a, b_prime)
            if G is None or r in used:
                continue
            # The point must be rejected by the REAL curve's membership.
            if ecc.on_curve(p, a, real_b, G):
                continue
            if any(nt.gcd(r, r0) != 1 for r0 in used):
                continue
            used.add(r)
            generators.append((G, r))
            if len(generators) == 2:
                break
        self.assertEqual(len(generators), 2, "need two small-subgroup generators")
        (G1, r1), (G2, r2) = generators
        self.assertEqual(nt.gcd(r1, r2), 1, "residue moduli must be coprime")

        recovered, residues = attacks.invalid_curve(p, a, oracle, generators)
        self.assertEqual(len(residues), 2)
        m = r1 * r2
        self.assertGreater(m, d, "test setup must make the CRT modulus exceed d")
        self.assertEqual(recovered, d % m)
        self.assertEqual(recovered % r1, d % r1)
        self.assertEqual(recovered % r2, d % r2)

    def test_validating_oracle_returns_none(self):
        p = 10007
        a, real_b = 1, 3
        d = 4242
        real_curve_members = lambda P: ecc.on_curve(p, a, real_b, P)  # noqa: E731

        def strict_oracle(P):
            if not real_curve_members(P):
                return None  # server rejects non-members
            return ecc.point_mul(p, a, d, P)

        G, r = find_large_prime_order_point(p, a, 7, min_order=2)
        self.assertIsNotNone(G)
        recovered, residues = attacks.invalid_curve(
            p, a, strict_oracle, [(G, r)])
        self.assertIsNone(recovered)
        self.assertEqual(residues, [])


if __name__ == "__main__":
    unittest.main()
