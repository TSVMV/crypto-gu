import hashlib
import unittest

from crypto_gu.hashes.sha1 import sha1
from crypto_gu.hashes.sha512 import sha512


class TestSHA1RFC6234(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(sha1(b""), bytes.fromhex("da39a3ee5e6b4b0d3255bfef95601890afd80709"))

    def test_abc(self):
        self.assertEqual(sha1(b"abc"), bytes.fromhex("a9993e364706816aba3e25717850c26c9cd0d89d"))

    def test_448_bit_two_blocks(self):
        msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        self.assertEqual(sha1(msg), bytes.fromhex("84983e441c3bd26ebaae4aa1f95129e5e54670f1"))

    def test_896_bit(self):
        msg = (
            b"abcdefghbcdefghicdefghijdefghijkefghijkl"
            b"fghijklmghijklmnhijklmnoijklmnopjklmnopq"
            b"klmnopqrlmnopqrsmnopqrstnopqrstu"
        )
        self.assertEqual(
            sha1(msg),
            bytes.fromhex("a49b2446a02c645bf419f995b67091253a04a259"),
        )

    def test_tofu_utf8(self):
        msg = "💩".encode()
        self.assertEqual(sha1(msg), hashlib.sha1(msg).digest())


class TestSHA1BlockBoundaries(unittest.TestCase):
    def test_length_around_padding_edge(self):
        for size in (0, 1, 55, 56, 57, 63, 64, 65, 79, 80, 127, 128):
            with self.subTest(size=size):
                msg = (b"sha1 boundary payload material " * 16)[:size]
                self.assertEqual(sha1(msg), hashlib.sha1(msg).digest())


class TestSHA512RFC6234(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(
            sha512(b""),
            bytes.fromhex(
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc"
                "83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f"
                "63b931bd47417a81a538327af927da3e"
            ),
        )

    def test_abc(self):
        self.assertEqual(
            sha512(b"abc"),
            bytes.fromhex(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea2"
                "0a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd"
                "454d4423643ce80e2a9ac94fa54ca49f"
            ),
        )

    def test_896_bit_one_block(self):
        msg = (
            b"abcdefghbcdefghicdefghijdefghijkefghijkl"
            b"fghijklmghijklmnhijklmnoijklmnopjklmnopq"
            b"klmnopqrlmnopqrsmnopqrstnopqrstu"
        )
        self.assertEqual(
            sha512(msg),
            bytes.fromhex(
                "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa172"
                "99aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d3"
                "29eeb6dd26545e96e55b874be909"
            ),
        )

    def test_two_blocks(self):
        msg = b"0123456789abcdef" * 14  # 224 bytes -> two padded blocks
        self.assertEqual(sha512(msg), hashlib.sha512(msg).digest())


class TestSHA512AgainstHashlib(unittest.TestCase):
    def test_length_around_padding_edge(self):
        for size in (0, 1, 119, 120, 121, 127, 128, 129, 2047, 2048, 4095, 4096):
            with self.subTest(size=size):
                msg = (b"0123456789abcdef" * ((size // 16) + 1))[:size]
                self.assertEqual(sha512(msg), hashlib.sha512(msg).digest())

    def test_two_million_a_rfc6234(self):
        msg = b"a" * (2000000)
        self.assertEqual(
            sha512(msg).hex(),
            "9bc68759247e3332bec1c79d128d28a8931d0c9f96c8aa975731b563475fdddddf"
            "7f873c25086908effe270e23c5a01e5dfb3289bf5d091d8fb454b1bcf98dda",
        )

    def test_accepts_str_and_bytes_equal(self):
        self.assertEqual(sha512("same input"), sha512(b"same input"))

    def test_digest_length(self):
        self.assertEqual(len(sha512(b"x")), 64)
        self.assertEqual(len(sha1(b"x")), 20)


if __name__ == "__main__":
    unittest.main()
