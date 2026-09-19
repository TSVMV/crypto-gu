"""Tests for ChaCha20 (RFC 8439)."""

import unittest

from crypto_gu.errors import InvalidIVError, InvalidKeyError
from crypto_gu.symmetric import chacha20

KEY = bytes.fromhex("".join("%02x" % i for i in range(32)))

NONCE_A1 = bytes.fromhex("00000009" + "0000004a" + "00000000")
NONCE_242 = bytes.fromhex("00000000" + "0000004a" + "00000000")

PLAINTEXT = bytes.fromhex(
    "4c616469657320616e642047656e746c"
    "656d656e206f662074686520636c6173"
    "73206f66202739393a20496620492063"
    "6f756c64206f6666657220796f75206f"
    "6e6c79206f6e652074697020666f7220"
    "746865206675747572652c2073756e73"
    "637265656e20776f756c642062652069"
    "742e"
)


class TestBlockFunction(unittest.TestCase):
    def test_rfc8439_a1_serialized_block(self):
        # RFC 8439 A.1: key 00..1f, nonce 00000009-0000004a-00000000,
        # counter=1.
        blk = chacha20._block(KEY, 1, NONCE_A1)
        expected = (
            "10f1e7e4" "d13b5915" "500fdd1f" "a32071c4"
            "c7d1f4c7" "33c06803" "0422aa9a" "c3d46c4e"
            "d2826446" "079faa09" "14c2d705" "d98b02a2"
            "b5129cd1" "de164eb9" "cbd083e8" "a2503c4e"
        )
        self.assertEqual(blk.hex(), expected)


class TestKeystreamAndCipher(unittest.TestCase):
    def test_rfc8439_242_keystream(self):
        ks = chacha20.keystream(KEY, NONCE_242, len(PLAINTEXT), 1)
        expected = (
            "224f51f3401bd9e12fde276fb8631ded"
            "8c131f823d2c06e27e4fcaec9ef3cf78"
            "8a3b0aa372600a92b57974cded2b9334"
            "794cba40c63e34cdea212c4cf07d41b7"
            "69a6749f3f630f4122cafe28ec4dc47e"
            "26d4346d70b98c73f3e9c53ac40c5945"
            "398b6eda1a832c89c167eacd901d7e2b"
            "f363"
        )
        self.assertEqual(ks.hex(), expected)

    def test_rfc8439_242_ciphertext(self):
        ct = chacha20.encrypt(KEY, NONCE_242, PLAINTEXT, 1)
        expected = (
            "6e2e359a2568f98041ba0728dd0d6981"
            "e97e7aec1d4360c20a27afccfd9fae0b"
            "f91b65c5524733ab8f593dabcd62b357"
            "1639d624e65152ab8f530c359f0861d8"
            "07ca0dbf500d6a6156a38e088a22b65e"
            "52bc514d16ccf806818ce91ab7793736"
            "5af90bbf74a35be6b40b8eedf2785e42"
            "874d"
        )
        self.assertEqual(ct.hex(), expected)

    def test_decrypt_is_encrypt(self):
        ct = chacha20.encrypt(KEY, NONCE_242, PLAINTEXT, 1)
        self.assertEqual(chacha20.decrypt(KEY, NONCE_242, ct, 1), PLAINTEXT)

    def test_keystream_offsets(self):
        full = chacha20.keystream(KEY, NONCE_242, 128, 1)
        part = chacha20.keystream(KEY, NONCE_242, 32, 1)
        self.assertEqual(full[:32], part)

    def test_counter_offset_changes_stream(self):
        a = chacha20.keystream(KEY, NONCE_242, 64, 0)
        b = chacha20.keystream(KEY, NONCE_242, 64, 1)
        self.assertNotEqual(a, b)

    def test_short_data_roundtrip(self):
        for size in (0, 1, 15, 16, 30, 63, 64, 129):
            msg = bytes(range(size))
            ct = chacha20.encrypt(KEY, NONCE_242, msg)
            self.assertEqual(chacha20.decrypt(KEY, NONCE_242, ct), msg)


class TestArguments(unittest.TestCase):
    def test_short_key(self):
        with self.assertRaises(InvalidKeyError):
            chacha20._block(b"short", 0, NONCE_242)

    def test_bad_nonce(self):
        with self.assertRaises(InvalidIVError):
            chacha20._block(KEY, 0, b"\x00" * 4)

    def test_negative_length(self):
        with self.assertRaises(ValueError):
            chacha20.keystream(KEY, NONCE_242, -1)

    def test_keystream_zero_length(self):
        self.assertEqual(chacha20.keystream(KEY, NONCE_242, 0), b"")


class ReuseAttackSmoke(unittest.TestCase):
    def test_keystream_reuse_recovers_plaintext(self):
        # Two ciphertexts sharing key+nonce: xor recovers pt1^pt2.
        m1 = b"The first secret message streams."
        m2 = b"Second message for the stream.."
        c1 = chacha20.encrypt(KEY, NONCE_242, m1)
        c2 = chacha20.encrypt(KEY, NONCE_242, m2)
        m1_xor_m2 = bytes(a ^ b for a, b in zip(m1, m2))
        c1_xor_c2 = bytes(a ^ b for a, b in zip(c1, c2))
        self.assertEqual(c1_xor_c2, m1_xor_m2)


if __name__ == "__main__":
    unittest.main()
