"""Tests for elliptic curve primitives (crypto_gu.ecc)."""

import sys
import unittest

sys.path.insert(0, "/workspace/crypto-gu")

from crypto_gu import ecc

# Classic teaching curve (Paar & Pelzl): y^2 = x^3 + 2x + 2 over F_17.
# Its order is 19 and P = (5, 1) is a generator.
P17, A17, B17 = 17, 2, 2
G17 = (5, 1)
ORDER17 = 19


class TestCurvePrimitives(unittest.TestCase):
    def test_generator_on_curve(self):
        self.assertTrue(ecc.on_curve(P17, A17, B17, G17))

    def test_known_order(self):
        self.assertEqual(ecc.curve_order_bruteforce(P17, A17, B17), ORDER17)
        self.assertEqual(ecc.point_order(P17, A17, G17, ORDER17), ORDER17)

    def test_negation(self):
        neg = ecc.point_neg(P17, G17)
        self.assertEqual(neg, (5, 16))
        self.assertTrue(ecc.on_curve(P17, A17, B17, neg))
        self.assertIsNone(ecc.point_add(P17, A17, G17, neg))
        self.assertIsNone(ecc.point_neg(P17, None))

    def test_lagrange(self):
        # k * (order) * G must be the point at infinity for any k.
        R = ecc.point_mul(P17, A17, 7 * ORDER17, G17)
        self.assertIsNone(R)

    def test_scalar_distributivity(self):
        # k*(G + G) == (k + k)*G
        P2 = ecc.point_add(P17, A17, G17, G17)
        lhs = ecc.point_mul(P17, A17, 9, P2)
        rhs = ecc.point_mul(P17, A17, 18, G17)
        self.assertEqual(lhs, rhs)

    def test_associativity(self):
        P2 = ecc.point_mul(P17, A17, 2, G17)
        P5 = ecc.point_mul(P17, A17, 5, G17)
        lhs = ecc.point_add(P17, A17, ecc.point_add(P17, A17, G17, P2), P5)
        rhs = ecc.point_add(P17, A17, G17, ecc.point_add(P17, A17, P2, P5))
        self.assertEqual(lhs, rhs)

    def test_identity_elements(self):
        self.assertEqual(ecc.point_add(P17, A17, None, G17), G17)
        self.assertEqual(ecc.point_add(P17, A17, G17, None), G17)
        self.assertEqual(ecc.point_mul(P17, A17, 0, G17), None)
        self.assertEqual(ecc.point_mul(P17, A17, 1, G17), G17)

    def test_negative_scalar(self):
        # (-3)*G == 16*G on an order-19 group
        self.assertEqual(ecc.point_mul(P17, A17, -3, G17),
                         ecc.point_mul(P17, A17, 16, G17))

    def test_ec_bsgs_recovers_scalar(self):
        for d in (1, 5, 11, 18):
            Q = ecc.point_mul(P17, A17, d, G17)
            self.assertEqual(ecc.ec_bsgs(P17, A17, G17, Q, ORDER17), d)

    def test_ec_bsgs_infinity_target(self):
        self.assertEqual(ecc.ec_bsgs(P17, A17, G17, None, ORDER17), 0)

    def test_curve_order_matches_enumeration(self):
        # Cross-check the Legendre-counting on a tiny curve by direct search.
        p, a, b = 7, 1, 3
        direct = 1  # point at infinity
        for x in range(p):
            for y in range(p):
                if ecc.on_curve(p, a, b, (x, y)):
                    direct += 1
        self.assertEqual(ecc.curve_order_bruteforce(p, a, b), direct)


if __name__ == "__main__":
    unittest.main()
