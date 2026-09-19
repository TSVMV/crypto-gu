"""Tests for crypto_gu.encoding and crypto_gu.padding."""

import random
import unittest

from crypto_gu.encoding import (
    b32_decode,
    b32_encode,
    b58_decode,
    b58_encode,
    b64_decode,
    b64_encode,
    b85_decode,
    b85_encode,
    bcd_encode,
    from_bytes,
    hex_decode,
    hex_encode,
    int_to_bytes,
    morse_decode,
    morse_encode,
    printable,
    to_bytes,
    unpack_bits,
    unpack_bytes,
    xor_bytes,
    xor_crypt,
)
from crypto_gu.errors import InvalidPaddingError
from crypto_gu.padding import (
    PKCS7,
    ZeroPad,
    make_padder,
    pad,
    unpad,
)


class TestToIntBytes(unittest.TestCase):
    def test_roundtrip(self):
        for n in (0, 1, 255, 256, 65535, 0xDEADBEEF):
            self.assertEqual(from_bytes(to_bytes(n)), n)

    def test_zero(self):
        self.assertEqual(to_bytes(0), b"\x00")

    def test_str(self):
        self.assertEqual(to_bytes("hi"), b"hi")

    def test_negative(self):
        with self.assertRaises(ValueError):
            to_bytes(-1)

    def test_bad_type(self):
        with self.assertRaises(TypeError):
            to_bytes(1.5)

    def test_int_to_bytes_width(self):
        self.assertEqual(int_to_bytes(1, 4), b"\x00\x00\x00\x01")
        with self.assertRaises(ValueError):
            int_to_bytes(256, 1)


class TestHex(unittest.TestCase):
    def test_known(self):
        self.assertEqual(hex_encode(b"\x00\xff\x10"), "00ff10")
        self.assertEqual(hex_decode("00FF10"), b"\x00\xff\x10")

    def test_odd_length(self):
        self.assertEqual(hex_decode("f"), b"\x0f")

    def test_roundtrip(self):
        rng = random.Random(3)
        for _ in range(50):
            data = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 40)))
            self.assertEqual(hex_decode(hex_encode(data)), data)

    def test_invalid(self):
        with self.assertRaises(ValueError):
            hex_decode("zz")


class TestBaseEncodings(unittest.TestCase):
    def test_base64(self):
        self.assertEqual(b64_encode(b"hello world"), "aGVsbG8gd29ybGQ=")
        self.assertEqual(b64_decode("aGVsbG8gd29ybGQ="), b"hello world")

    def test_base32(self):
        self.assertEqual(b32_encode(b"hello"), "NBSWY3DP")
        self.assertEqual(b32_decode("NBSWY3DP"), b"hello")

    def test_base58(self):
        self.assertEqual(b58_encode(b"\x00\x01"), "12")
        rng = random.Random(7)
        for _ in range(30):
            data = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 60)))
            dec = b58_decode(b58_encode(data))
            self.assertEqual(dec, data)

    def test_base58_invalid(self):
        for c in "0OIl":
            with self.assertRaises(ValueError):
                b58_decode(c)

    def test_base85(self):
        rng = random.Random(11)
        for _ in range(20):
            data = bytes(rng.randrange(1, 256) for _ in range(rng.randrange(1, 40)))
            self.assertEqual(b85_decode(b85_encode(data)), data)


class TestXor(unittest.TestCase):
    def test_xor_crypt_symmetric(self):
        data = b"attack at dawn"
        key = b"key"
        self.assertEqual(xor_crypt(xor_crypt(data, key), key), data)

    def test_xor_crypt_known(self):
        self.assertEqual(xor_crypt(b"\x01\x02\x03", b"\xff"), b"\xfe\xfd\xfc")

    def test_xor_bytes_length(self):
        with self.assertRaises(ValueError):
            xor_bytes(b"\x00", b"\x00\x00")

    def test_xor_empty_key(self):
        with self.assertRaises(ValueError):
            xor_crypt(b"abc", b"")


class TestMorse(unittest.TestCase):
    def test_known(self):
        self.assertEqual(morse_encode("SOS"), "... --- ...")
        self.assertEqual(morse_encode("SOS. 1"), "... --- ... .-.-.- / .----")
        self.assertEqual(morse_decode("... --- ..."), "SOS")
        self.assertEqual(morse_decode(morse_encode("HELLO WORLD")), "HELLO WORLD")

    def test_invalid(self):
        with self.assertRaises(ValueError):
            morse_decode("/?")


class TestMisc(unittest.TestCase):
    def test_bcd(self):
        self.assertEqual(bcd_encode(b"12"), b"\x12")
        self.assertEqual(bcd_encode(b"998"), b"\x99\x80")
        with self.assertRaises(ValueError):
            bcd_encode(b"a")

    def test_bits(self):
        self.assertEqual(unpack_bits(b"\x81"), [1, 0, 0, 0, 0, 0, 0, 1])
        self.assertEqual(unpack_bytes([1, 0, 0, 0, 0, 0, 0, 1]), b"\x81")
        self.assertEqual(unpack_bytes(unpack_bits(b"\xab\xcd")), b"\xab\xcd")

    def test_printable(self):
        self.assertEqual(printable(b"a\x00b\xff\x09"), b"ab\t")
        self.assertIn(b"\n", printable(b"line\nnext"))
        self.assertEqual(printable(b"\x80\x81"), b"")


class TestPadding(unittest.TestCase):
    def test_pkcs7_roundtrip(self):
        p = PKCS7(16)
        rng = random.Random(5)
        for _ in range(30):
            data = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 60)))
            self.assertEqual(p.unpad(p.pad(data)), data)
            self.assertEqual(len(p.pad(data)) % 16, 0)

    def test_pkcs7_full_block(self):
        p = PKCS7(16)
        self.assertEqual(len(p.pad(b"A" * 16)), 32)
        self.assertEqual(p.unpad(p.pad(b"A" * 16)), b"A" * 16)

    def test_pkcs7_single_block(self):
        self.assertEqual(PKCS7(4).pad(b"abc"), b"abc\x01")
        self.assertEqual(PKCS7(4).pad(b"ab"), b"ab\x02\x02")

    def test_pkcs7_rejects(self):
        p = PKCS7(4)
        for bad in (b"", b"\x00" * 4, b"abcd" * 2 + b"ab", b"\xff\xff\xff\xff"):
            with self.assertRaises(InvalidPaddingError):
                p.unpad(bad)

    def test_zero_pad(self):
        p = ZeroPad(8)
        self.assertEqual(len(p.pad(b"abc")) % 8, 0)
        self.assertEqual(p.unpad(p.pad(b"abc")), b"abc")

    def test_make_padder(self):
        self.assertIsInstance(make_padder("pkcs7"), PKCS7)
        self.assertIsInstance(make_padder("ANSI", 8), type(make_padder("ansi", 8)))
        with self.assertRaises(ValueError):
            make_padder("nope")

    def test_module_helpers(self):
        self.assertEqual(unpad(pad(b"hello", 8), 8), b"hello")
        self.assertEqual(unpad(pad(b"hello", 8, "zero"), 8, "zero"), b"hello")

    def test_x923(self):
        p = make_padder("x923", 8)
        data = b"hello"
        self.assertEqual(p.unpad(p.pad(data)), data)
        padded = p.pad(data)
        n = len(padded) - len(data)
        self.assertEqual(padded[-1], n)
        self.assertEqual(padded[-n:-1], b"\x00" * (n - 1))


if __name__ == "__main__":
    unittest.main()
