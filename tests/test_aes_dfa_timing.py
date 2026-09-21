"""Tests for AES differential fault analysis and timing side channels."""

import random
import sys
import unittest

sys.path.insert(0, "/workspace/crypto-gu")

from crypto_gu.attacks import aes as attacks
from crypto_gu.attacks import timing
from crypto_gu.symmetric import aes as aes_sym


def inject_fault_and_finish(key, plaintext, pos, delta):
    """Encrypt with ``key`` but XOR ``delta`` into state byte ``pos`` of the
    state entering the final round; return the faulty ciphertext block."""
    words = aes_sym._expand_key(key)
    rounds = aes_sym._ROUNDS[len(key)]
    state = bytearray(plaintext)
    aes_sym._add_round_key(state, words, 0)
    for rnd in range(1, rounds):
        aes_sym._sub_bytes(state, aes_sym.SBOX)
        aes_sym._shift_rows(state)
        aes_sym._mix_columns(state)
        aes_sym._add_round_key(state, words, rnd)
    # Final round (no MixColumns): disturb one byte of its input state.
    state[pos] ^= delta
    aes_sym._sub_bytes(state, aes_sym.SBOX)
    aes_sym._shift_rows(state)
    aes_sym._add_round_key(state, words, rounds)
    return bytes(state)


def last_round_key(key):
    words = aes_sym._expand_key(key)
    flat = [b for w in words[len(words) - 4:] for b in w]
    return bytes(flat)


class TestInvertKeySchedule(unittest.TestCase):
    def test_roundtrip_known_vector(self):
        # FIPS-197 appendix A.1: key 2b7e151628aed2a6abf7158809cf4f3c,
        # final round key d014f9a8c9ee2589e13f0cc8b6630ca6.
        master = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        k10 = bytes.fromhex("d014f9a8c9ee2589e13f0cc8b6630ca6")
        self.assertEqual(attacks.invert_key_schedule(k10), master)

    def test_roundtrip_random_keys(self):
        rng = random.Random(2024)
        for _ in range(8):
            master = bytes(rng.randrange(256) for _ in range(16))
            self.assertEqual(attacks.invert_key_schedule(last_round_key(master)),
                             master)


class TestDfaLastRound(unittest.TestCase):
    KEY = bytes.fromhex("10a58869d74be5a374cf867cfb473859")
    PT = b"DFA fault attack"

    def test_with_known_plaintext_check(self):
        ct = aes_sym.block_encrypt(self.KEY, self.PT)
        faults = [(pos, inject_fault_and_finish(self.KEY, self.PT, pos, 1))
                  for pos in range(16)]
        check = lambda k: aes_sym.block_encrypt(k, self.PT) == ct  # noqa: E731
        master = attacks.dfa_last_round(ct, faults, delta=1, check=check)
        self.assertEqual(master, self.KEY)

    def test_with_repeated_faults_no_check(self):
        # Two deltas per position make every candidate unique; the second
        # fault overrides the global delta via a 3-tuple.
        ct = aes_sym.block_encrypt(self.KEY, self.PT)
        faults = []
        for pos in range(16):
            faults.append((pos, inject_fault_and_finish(self.KEY, self.PT, pos, 1),
                           1))
            faults.append((pos, inject_fault_and_finish(self.KEY, self.PT, pos, 2),
                           2))
        master = attacks.dfa_last_round(ct, faults)
        self.assertEqual(master, self.KEY)

    def test_ambiguous_without_check_returns_none(self):
        ct = aes_sym.block_encrypt(self.KEY, self.PT)
        faults = [(pos, inject_fault_and_finish(self.KEY, self.PT, pos, 1))
                  for pos in range(16)]
        self.assertIsNone(attacks.dfa_last_round(ct, faults, delta=1, check=None))

    def test_rejects_missing_positions(self):
        ct = aes_sym.block_encrypt(self.KEY, self.PT)
        faults = [(pos, inject_fault_and_finish(self.KEY, self.PT, pos, 1))
                  for pos in range(15)]  # position 15 missing
        with self.assertRaises(ValueError):
            attacks.dfa_last_round(ct, faults)

    def test_rejects_unchanged_output(self):
        ct = aes_sym.block_encrypt(self.KEY, self.PT)
        with self.assertRaises(ValueError):
            attacks.dfa_last_round(ct, [(0, ct)], delta=1)


class TestTimingRecovery(unittest.TestCase):
    def test_recovers_exponent_with_noise(self):
        rng = random.Random(7)
        d = rng.getrandbits(64)
        base, penalty = 100.0, 3.0
        samples = {}
        for i in range(64):
            bit = (d >> (63 - i)) & 1  # index 0 = MSB
            samples[i] = [base + bit * penalty + rng.uniform(-0.4, 0.4)
                          for _ in range(10)]
        self.assertEqual(timing.recover_exponent(samples), d)

    def test_dict_and_pair_inputs_agree(self):
        samples = {0: [1.0, 1.1], 1: [2.0, 2.1], 2: [1.05]}
        pairs = list(samples.items())
        self.assertEqual(timing.classify_bits(samples),
                         timing.classify_bits(pairs))

    def test_explicit_threshold(self):
        samples = [(0, [10.0]), (1, [20.0])]
        self.assertEqual(timing.classify_bits(samples, threshold=15.0),
                         {0: 0, 1: 1})

    def test_lsb_first_order(self):
        samples = [(0, [20.0]), (1, [10.0])]
        self.assertEqual(timing.recover_exponent(samples, msb_first=True), 0b10)
        self.assertEqual(timing.recover_exponent(samples, msb_first=False), 0b01)

    def test_rejects_degenerate_input(self):
        with self.assertRaises(ValueError):
            timing.classify_bits([(0, [])])
        with self.assertRaises(ValueError):
            timing.classify_bits([(0, [5.0]), (1, [5.0])])  # one cluster only


if __name__ == "__main__":
    unittest.main()
