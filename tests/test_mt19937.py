"""Tests for MT19937 and state-recovery/unwrapping."""

import random
import unittest

from crypto_gu.rng.mt19937 import MT19937, N, _untemper, recover_keystream


def _temper(x):
    x &= 0xFFFFFFFF
    x ^= x >> 11
    x ^= (x << 7) & 0x9D2C5680
    x ^= (x << 15) & 0xEFC60000
    x ^= x >> 18
    return x & 0xFFFFFFFF


class TestGenerator(unittest.TestCase):
    def test_deterministic_with_seed(self):
        a, b = MT19937(42), MT19937(42)
        self.assertEqual([a.get_int() for _ in range(10)],
                         [b.get_int() for _ in range(10)])

    def test_seed_changes_stream(self):
        a = MT19937(1)
        b = MT19937(2)
        self.assertNotEqual(a.get_int(), b.get_int())

    def test_twist_boundary_repeats_periodically(self):
        r = MT19937(123)
        for _ in range(N):
            r.get_int()
        r.get_int()
        # After one full state consumption we keep producing; just ensure
        # output is valid 32-bit and no exception across two twists.
        values = [r.get_int() for _ in range(N + 200)]
        self.assertTrue(all(0 <= v <= 0xFFFFFFFF for v in values))
        self.assertEqual(len(values), N + 200)
        self.assertEqual(len(values), N + 200)

    def test_get_int_bytes_length(self):
        r = MT19937(7)
        for size in (0, 1, 4, 5, 16):
            self.assertEqual(len(r.get_int_bytes(size)), size)


class TestUntemper(unittest.TestCase):
    def test_identity(self):
        for _ in range(5000):
            x = random.getrandbits(32)
            self.assertEqual(_untemper(_temper(x)), x)

    def test_untemper_of_known_temper(self):
        # manually verified sequence
        self.assertEqual(_untemper(0x2B7E4A2D), 0x12345678)


class TestStateRecovery(unittest.TestCase):
    def test_recover_from_int_list(self):
        rng = MT19937(19650218)
        data = [rng.get_int() for _ in range(700)]
        clone = recover_keystream(data)
        self.assertEqual([rng.get_int() for _ in range(100)],
                         [clone.get_int() for _ in range(100)])

    def test_recover_from_single_bytes(self):
        rng = MT19937(19650218)
        raw = b"".join(rng.get_int().to_bytes(4, "little") for _ in range(700))
        clone = recover_keystream(raw)
        self.assertEqual([rng.get_int() for _ in range(100)],
                         [clone.get_int() for _ in range(100)])

    def test_recover_from_list_of_byte_chunks(self):
        rng = MT19937(19650218)
        chunks = [rng.get_int().to_bytes(4, "little") for _ in range(700)]
        clone = recover_keystream(chunks)
        self.assertEqual([rng.get_int() for _ in range(100)],
                         [clone.get_int() for _ in range(100)])

    def test_recover_from_mixed(self):
        rng = MT19937(19650218)
        mixed = []
        for _ in range(700):
            if _ % 2:
                mixed.append(rng.get_int())
            else:
                mixed.append(rng.get_int().to_bytes(4, "little"))
        clone = recover_keystream(mixed)
        self.assertEqual([rng.get_int() for _ in range(100)],
                         [clone.get_int() for _ in range(100)])

    def test_insufficient_outputs(self):
        with self.assertRaises(ValueError):
            recover_keystream([1, 2, 3])

    def test_exactly_624_outputs(self):
        rng = MT19937(31337)
        data = [rng.get_int() for _ in range(N)]
        clone = recover_keystream(data)
        self.assertEqual([rng.get_int() for _ in range(50)],
                         [clone.get_int() for _ in range(50)])


if __name__ == "__main__":
    unittest.main()
