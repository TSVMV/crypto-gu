"""Tests for crypto_gu.number_theory.

``is_prime`` is validated against a textbook sieve rather than against
hand-remembered constants, so a regression cannot hide behind a bad fixture.
"""

import random
import unittest

from crypto_gu.errors import NotPrimitiveError
from crypto_gu.number_theory import (
    continued_fraction_bounds,
    crt,
    discrete_log_bsgs,
    extended_gcd,
    factorize,
    fermat_factor,
    gcd,
    is_prime,
    jacobi_symbol,
    legendre_symbol,
    modinv,
    modular_sqrt,
    next_prime,
    pollard_p_minus_1,
    pollard_rho,
    rand_prime,
    square_free_decomp,
    tonelli_shanks,
)


def sieve(n: int) -> list:
    table = [True] * (n + 1)
    table[0] = table[1] = False
    i = 2
    while i * i <= n:
        if table[i]:
            for j in range(i * i, n + 1, i):
                table[j] = False
        i += 1
    return table


SMALL_PRIMES = [i for i, ok in enumerate(sieve(2000)) if ok]


class TestGcd(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(gcd(12, 18), 6)
        self.assertEqual(gcd(12, 18, 24), 6)
        self.assertEqual(gcd(0, 0), 0)
        self.assertEqual(gcd(0, 7), 7)
        self.assertEqual(gcd(-6, 10), 2)

    def test_extended(self):
        g, x, y = extended_gcd(240, 46)
        self.assertEqual(g, 2)
        self.assertEqual(240 * x + 46 * y, 2)

    def test_modinv(self):
        self.assertEqual(modinv(3, 7), 5)
        self.assertEqual((3 * modinv(3, 100)) % 100, 1)
        with self.assertRaises(NotPrimitiveError):
            modinv(4, 8)


class TestCrt(unittest.TestCase):
    def test_textbook(self):
        x = crt([(2, 3), (3, 5), (2, 7)])
        self.assertEqual((x % 3, x % 5, x % 7), (2, 3, 2))

    def test_coprime_required(self):
        with self.assertRaises(NotPrimitiveError):
            crt([(1, 6), (1, 4)])

    def test_single(self):
        self.assertEqual(crt([(5, 11)]), 5)


class TestIsPrime(unittest.TestCase):
    def test_matches_sieve(self):
        table = sieve(50000)
        for n in range(2, 50000):
            self.assertEqual(is_prime(n), table[n], "n=%d" % n)

    def test_edges(self):
        self.assertFalse(is_prime(0))
        self.assertFalse(is_prime(1))
        self.assertTrue(is_prime(2))
        self.assertTrue(is_prime(3))
        self.assertFalse(is_prime(4))
        self.assertFalse(is_prime(561))  # Carmichael number

    def test_next_prime(self):
        for p in SMALL_PRIMES[:-1]:
            self.assertEqual(next_prime(p - 1), p)
        self.assertEqual(next_prime(2), 3)
        self.assertEqual(next_prime(0), 2)


class TestRandPrime(unittest.TestCase):
    def test_bits_and_primality(self):
        rng = random.Random(1234)
        for _ in range(200):
            bits = random.randint(2, 72)
            p = rand_prime(bits, rng)
            self.assertTrue(is_prime(p))
            self.assertEqual(p.bit_length(), bits)
        with self.assertRaises(ValueError):
            rand_prime(1)


class TestSymbols(unittest.TestCase):
    def test_legendre(self):
        self.assertEqual(legendre_symbol(2, 7), 1)   # 3^2 == 2 mod 7
        self.assertEqual(legendre_symbol(3, 7), -1)
        self.assertEqual(legendre_symbol(0, 7), 0)
        with self.assertRaises(ValueError):
            legendre_symbol(2, 4)

    def test_jacobi(self):
        self.assertEqual(jacobi_symbol(2, 7), 1)
        self.assertEqual(jacobi_symbol(2, 15), 1)
        self.assertEqual(jacobi_symbol(7, 15), -1)
        self.assertEqual(jacobi_symbol(3, 15), 0)   # 3 divides 15
        self.assertEqual(jacobi_symbol(0, 9), 0)
        with self.assertRaises(ValueError):
            jacobi_symbol(2, 8)

    def test_jacobi_multiplicative(self):
        # jacobi(a, p*q) == legendre(a, p) * legendre(a, q)
        for p, q in [(3, 5), (5, 7), (3, 11), (7, 13)]:
            for a in range(p * q):
                self.assertEqual(
                    jacobi_symbol(a, p * q),
                    legendre_symbol(a, p) * legendre_symbol(a, q),
                    (a, p, q),
                )

    def test_exhaustive(self):
        # Legendre must agree with brute-force squaring for small primes.
        for p in SMALL_PRIMES:
            if p % 2 == 0:
                continue
            squares = {(x * x) % p for x in range(p)}
            for a in range(p):
                expected = 0 if a == 0 else 1 if a in squares else -1
                self.assertEqual(legendre_symbol(a, p), expected, (a, p))


class TestSquareRoots(unittest.TestCase):
    def test_prime_modulus(self):
        for p in (7, 11, 23, 104729):
            for x in range(p):
                a = (x * x) % p
                r = modular_sqrt(a, p)
                self.assertIsNotNone(r)
                self.assertEqual((r * r) % p, a)

    def test_non_residue(self):
        self.assertIsNone(modular_sqrt(3, 7))
        with self.assertRaises(NotPrimitiveError):
            tonelli_shanks(3, 7)

    def test_tonelli_shanks(self):
        for p in (5, 7, 11, 23, 104729):
            for x in range(0, p, 3):
                a = (x * x) % p
                r = tonelli_shanks(a, p)
                self.assertEqual((r * r) % p, a)

    def test_composite_modulus(self):
        for a in range(35):
            if any((x * x) % 35 == a for x in range(35)):
                r = modular_sqrt(a, 35)
                self.assertIsNotNone(r)
                self.assertEqual((r * r) % 35, a)
        self.assertIsNone(modular_sqrt(3, 35))


class TestFactorization(unittest.TestCase):
    def test_known(self):
        self.assertEqual(factorize(1), [])
        self.assertEqual(factorize(2), [2])
        self.assertEqual(factorize(12), [2, 2, 3])
        self.assertEqual(factorize(613300581), [3, 3, 181, 383, 983])
        self.assertEqual(factorize(104729 * 104731), [11, 9521, 104729])

    def test_random_semiprimes(self):
        rng = random.Random(99)
        for _ in range(15):
            a = rand_prime(40, rng)
            b = rand_prime(40, rng)
            n = a * b
            self.assertEqual(sorted(factorize(n)), sorted([a, b]))

    def test_pollard_rho(self):
        rng = random.Random(555)
        for _ in range(15):
            a = rand_prime(32, rng)
            b = rand_prime(32, rng)
            n = a * b
            f = pollard_rho(n)
            self.assertIn(f, (a, b))

    def test_pollard_p_minus_1(self):
        p = 1009  # p-1 = 2^4 * 3^2 * 7, very smooth
        q = rand_prime(64, random.Random(7))
        n = p * q
        f = pollard_p_minus_1(n, bound=200)
        self.assertIn(f, (p, q))

    def test_fermat_close_primes(self):
        for _ in range(30):
            a = rand_prime(60, random.Random(1))
            b = next_prime(a + 2)
            n = a * b
            f = fermat_factor(n)
            self.assertIn(f, (a, b))
        self.assertIsNone(fermat_factor(2))


class TestCrtAndDiscreteLog(unittest.TestCase):
    def test_convergents(self):
        self.assertEqual(
            continued_fraction_bounds([2, 2, 3]),
            [(2, 1), (5, 2), (17, 7)],
        )
        self.assertEqual(continued_fraction_bounds([3, 1, 4]), [(3, 1), (4, 1), (19, 5)])

    def test_discrete_log(self):
        self.assertEqual(discrete_log_bsgs(3, 27, 101), 3)
        p = 104729
        g, k = 5, 1234
        self.assertEqual(discrete_log_bsgs(g, pow(g, k, p), p), k)
        self.assertIsNone(discrete_log_bsgs(6, 7, 9))

    def test_square_free_decomp(self):
        self.assertEqual(square_free_decomp(72), (2, 6))   # 72 = 2 * 6^2
        self.assertEqual(square_free_decomp(12), (3, 2))   # 12 = 3 * 2^2
        self.assertEqual(square_free_decomp(7), (7, 1))


if __name__ == "__main__":
    unittest.main()
