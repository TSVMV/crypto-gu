"""Tests for deterministic RSA attack recipes."""

import random
import unittest

from crypto_gu import number_theory as nt
from crypto_gu.asymmetric import rsa as asym
from crypto_gu.attacks import rsa


def _close_prime_pair(bits=40):
    p = nt.next_prime(random.randrange(2**bits, 2**bits + 2**20))
    q = nt.next_prime(random.randrange(p + 10, p + 2**12))
    return p, q


def _smooth_prime(bound=100):
    base = 1
    for pr in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
               31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
               73, 79, 83, 89, 97):
        if pr > bound:
            break
        base *= pr
    k = 2
    while True:
        cand = k * base + 1
        if nt.is_prime(cand):
            return cand
        k += 1


class TestWiener(unittest.TestCase):
    def test_recovers_small_d(self):
        random.seed(11)
        for _ in range(3):
            while True:
                p = nt.next_prime(random.randrange(2**40, 2**41))
                q = nt.next_prime(random.randrange(2**40, 2**41))
                n = p * q
                phi = (p - 1) * (q - 1)
                d = random.randrange(5, int(n**0.25) // 3)
                try:
                    e = nt.modinv(d, phi)
                except Exception:
                    continue
                break
            with self.subTest(bits=n.bit_length()):
                self.assertEqual(rsa.wiener(n, e), d)

    def test_fails_on_large_d(self):
        random.seed(12)
        p = nt.next_prime(random.randrange(2**40, 2**41))
        q = nt.next_prime(random.randrange(2**40, 2**41))
        n = p * q
        e = 65537
        self.assertIsNone(rsa.wiener(n, e))


class TestFermat(unittest.TestCase):
    def test_close_primes(self):
        random.seed(13)
        p, q = _close_prime_pair()
        n = p * q
        factor = rsa.fermat(n)
        self.assertIsNotNone(factor)
        self.assertEqual(factor * (n // factor), n)

    def test_far_primes_returns_none_or_wrong(self):
        random.seed(14)
        p = nt.next_prime(random.randrange(2**40, 2**41))
        q = nt.next_prime(random.randrange(2**62, 2**63))
        n = p * q
        self.assertIsNone(rsa.fermat(n, limit=10000))


class TestPollardPMinusOne(unittest.TestCase):
    def test_smooth_p_minus_one(self):
        random.seed(15)
        p = _smooth_prime(bound=50)
        q = nt.next_prime(2**40)
        n = p * q
        factor = rsa.pollard_p_minus_1(n, bound=100)
        self.assertEqual(factor, p)


class TestCommonModulus(unittest.TestCase):
    def test_recover_message(self):
        random.seed(16)
        key = asym.RSAKey.generate(512)
        msg = random.randrange(2, key.n // 2)
        e1, e2 = 17, 19
        c1 = pow(msg, e1, key.n)
        c2 = pow(msg, e2, key.n)
        recovered = rsa.common_modulus(key.n, e1, c1, e2, c2)
        self.assertEqual(recovered, msg)

    def test_returns_none_when_e_not_coprime(self):
        random.seed(17)
        key = asym.RSAKey.generate(512)
        self.assertIsNone(rsa.common_modulus(key.n, 10, 1, 15, 1))


class TestBroadcast(unittest.TestCase):
    def test_hastad_e3(self):
        random.seed(18)
        msg = 123456789
        keys = [asym.RSAKey.generate(256) for _ in range(3)]
        cts = [pow(msg, 3, k.n) for k in keys]
        recovered = rsa.broadcast([(k.n, c) for k, c in zip(keys, cts)], 3)
        self.assertEqual(recovered, msg)

    def test_hastad_e5(self):
        random.seed(19)
        msg = 987654321
        keys = [asym.RSAKey.generate(256) for _ in range(5)]
        cts = [pow(msg, 5, k.n) for k in keys]
        recovered = rsa.broadcast([(k.n, c) for k, c in zip(keys, cts)], 5)
        self.assertEqual(recovered, msg)

    def test_insufficient_receivers(self):
        random.seed(20)
        keys = [asym.RSAKey.generate(256) for _ in range(2)]
        cts = [pow(5, 3, k.n) for k in keys]
        recovered = rsa.broadcast([(k.n, c) for k, c in zip(keys, cts)], 3)
        self.assertIsNone(recovered)


class TestConstructedKeyEndToEnd(unittest.TestCase):
    def test_wiener_to_decrypt(self):
        random.seed(21)
        while True:
            p = nt.next_prime(random.randrange(2**40, 2**41))
            q = nt.next_prime(random.randrange(2**40, 2**41))
            n = p * q
            phi = (p - 1) * (q - 1)
            d = random.randrange(5, int(n**0.25) // 3)
            try:
                e = nt.modinv(d, phi)
            except Exception:
                continue
            break
        public = asym.RSAKey(n=n, e=e)
        msg = b"recover me"
        c = public.encrypt(msg)
        recovered_d = rsa.wiener(n, e)
        private = asym.RSAKey(n=n, e=e, d=recovered_d)
        self.assertEqual(private.decrypt(c), msg)


if __name__ == "__main__":
    unittest.main()
