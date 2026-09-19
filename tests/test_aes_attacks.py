"""Tests for symmetric attacks (ECB oracle, CBC padding oracle)."""

import sys
import unittest

sys.path.insert(0, "/workspace/crypto-gu")

from crypto_gu.attacks import aes as attacks
from crypto_gu.symmetric import aes as aes_sym

KEY = b"\x01" * 16
IV = b"\x02" * 16
PREFIX = b"SECRET-FIXED-"
SECRET = b"flag{congrats-ecb-oracle}"


def build_ecb_oracle(prefix, secret, key):
    def oracle(data):
        body = prefix + data + secret
        need = 16 - len(body) % 16
        if need == 0:
            need = 16
        return aes_sym.ecb_encrypt(key, body + bytes([need]) * need)

    return oracle


def pkcs7_pad(data):
    need = 16 - len(data) % 16
    return data + bytes([need]) * need


def pkcs7_unpad(data):
    n = data[-1]
    return 1 <= n <= 16 and data[-n:] == bytes([n]) * n


class TestEcbByteAtATime(unittest.TestCase):
    def test_no_prefix(self):
        oracle = build_ecb_oracle(b"", SECRET, KEY)
        self.assertEqual(attacks.ecb_byte_at_a_time(oracle), SECRET)

    def test_short_prefix(self):
        oracle = build_ecb_oracle(b"pre", SECRET, KEY)
        self.assertEqual(attacks.ecb_byte_at_a_time(oracle), SECRET)

    def test_block_aligned_prefix(self):
        oracle = build_ecb_oracle(b"A" * 16, SECRET, KEY)
        self.assertEqual(attacks.ecb_byte_at_a_time(oracle), SECRET)

    def test_two_block_prefix(self):
        oracle = build_ecb_oracle(b"B" * 37, SECRET, KEY)
        self.assertEqual(attacks.ecb_byte_at_a_time(oracle), SECRET)

    def test_multiblock_secret(self):
        secret = b"x" * 32
        oracle = build_ecb_oracle(PREFIX, secret, KEY)
        self.assertEqual(attacks.ecb_byte_at_a_time(oracle), secret)

    def test_two_byte_repeated_prefix(self):
        secret = b"y" * 17
        oracle = build_ecb_oracle(b"AB" * 20, secret, KEY)
        self.assertEqual(attacks.ecb_byte_at_a_time(oracle), secret)

    def test_short_mixed_prefix(self):
        secret = b"z" * 24
        oracle = build_ecb_oracle(b"MMn" * 2, secret, KEY)
        self.assertEqual(attacks.ecb_byte_at_a_time(oracle), secret)

    def test_empty_secret(self):
        oracle = build_ecb_oracle(b"Q" * 10, b"", KEY)
        self.assertEqual(attacks.ecb_byte_at_a_time(oracle), b"")

    def test_given_secret_len(self):
        oracle = build_ecb_oracle(PREFIX, SECRET, KEY)
        got = attacks.ecb_byte_at_a_time(oracle, secret_len=len(SECRET))
        self.assertEqual(got, SECRET)

    def test_cbc_oracle_rejected(self):
        def oracle(data):
            body = PREFIX + data + SECRET
            return aes_sym.cbc_encrypt(KEY, pkcs7_pad(body), IV)

        with self.assertRaises(ValueError):
            attacks.ecb_byte_at_a_time(oracle)


class TestCbcPaddingOracle(unittest.TestCase):
    def _oracle(self, key, iv):
        def block_decrypt(blob):
            prev, block = blob[:16], blob[16:]
            return pkcs7_unpad(aes_sym.cbc_decrypt(key, block, prev))

        return block_decrypt

    def test_single_block(self):
        plaintext = pkcs7_pad(b"hello world!!!!")
        ct = aes_sym.cbc_encrypt(KEY, plaintext, IV)
        blk = self._oracle(KEY, IV)
        got = attacks.cbc_padding_oracle(blk, IV, ct)
        self.assertEqual(got, plaintext)

    def test_multi_block_text(self):
        plaintext = pkcs7_pad(b"The quick brown fox jumps" + b" over the lazy!")
        ct = aes_sym.cbc_encrypt(KEY, plaintext, IV)
        got = attacks.cbc_padding_oracle(self._oracle(KEY, IV), IV, ct)
        self.assertEqual(got, plaintext)

    def test_three_blocks(self):
        plaintext = pkcs7_pad(b"A" * 47)
        ct = aes_sym.cbc_encrypt(KEY, plaintext, IV)
        got = attacks.cbc_padding_oracle(self._oracle(KEY, IV), IV, ct)
        self.assertEqual(got, plaintext)

    def test_non_block_ciphertext_rejected(self):
        with self.assertRaises(ValueError):
            attacks.cbc_padding_oracle(self._oracle(KEY, IV), IV, b"\x00" * 17)

    def test_oracle_exhausted(self):
        ct = aes_sym.cbc_encrypt(KEY, pkcs7_pad(b"A" * 16), IV)
        with self.assertRaises(ValueError):
            attacks.cbc_padding_oracle(lambda blob: False, IV, ct)


if __name__ == "__main__":
    unittest.main(verbosity=2)
