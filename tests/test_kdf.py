import hashlib
import unittest

from crypto_gu.hashes.md5 import md5
from crypto_gu.hashes.sha1 import sha1
from crypto_gu.hashes.sha512 import sha512
from crypto_gu.kdf import hkdf, hkdf_expand, hkdf_extract, pbkdf2, scrypt


class TestPBKDF2RFC7914(unittest.TestCase):
    def test_pbkdf2_hmac_sha256_passwd_salt_c1(self):
        self.assertEqual(
            pbkdf2(b"passwd", b"salt", 1, 64),
            bytes.fromhex(
                "55ac046e56e3089fec1691c22544b605"
                "f94185216dde0465e68b9d57c20dacbc"
                "49ca9cccf179b645991664b39d77ef31"
                "7c71b845b1e30bd509112041d3a19783"
            ),
        )


class TestPBKDF2Oracles(unittest.TestCase):
    def test_sha256_matrix(self):
        for iterations in (1, 2, 1000, 4096):
            for dklen in (1, 16, 32, 64, 100):
                with self.subTest(iterations=iterations, dklen=dklen):
                    self.assertEqual(
                        pbkdf2(b"password", b"salt", iterations, dklen),
                        hashlib.pbkdf2_hmac("sha256", b"password", b"salt", iterations, dklen),
                    )

    def test_other_digests(self):
        for name, digestmod in (("sha1", sha1), ("sha512", sha512), ("md5", md5)):
            with self.subTest(digest=name):
                self.assertEqual(
                    pbkdf2(b"password", b"salt", 1000, 64, digestmod),
                    hashlib.pbkdf2_hmac(name, b"password", b"salt", 1000, 64),
                )

    def test_empty_password_and_salt(self):
        self.assertEqual(
            pbkdf2(b"", b"", 1, 32),
            hashlib.pbkdf2_hmac("sha256", b"", b"", 1, 32),
        )

    def test_rejects_bad_iterations(self):
        with self.assertRaises(ValueError):
            pbkdf2(b"p", b"s", 0, 16)
        with self.assertRaises(ValueError):
            pbkdf2(b"p", b"s", 1, 0)


class TestHKDFRFC5869(unittest.TestCase):
    def test_case_1_sha256(self):
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        prk = hkdf_extract(salt, ikm)
        self.assertEqual(prk, bytes.fromhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"))
        self.assertEqual(
            hkdf_expand(prk, info, 42),
            bytes.fromhex(
                "3cb25f25faacd57a90434f64d0362f2a"
                "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                "34007208d5b887185865"
            ),
        )
        self.assertEqual(hkdf(ikm, 42, salt, info), hkdf_expand(prk, info, 42))

    def test_case_2_sha256_long(self):
        ikm = bytes(range(0x00, 0x50))
        salt = bytes(range(0x60, 0xB0))
        info = bytes(range(0xB0, 0x100))
        self.assertEqual(
            hkdf_extract(salt, ikm),
            bytes.fromhex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"),
        )
        self.assertEqual(
            hkdf(ikm, 82, salt, info),
            bytes.fromhex(
                "b11e398dc80327a1c8e7f78c596a4934"
                "4f012eda2d4efad8a050cc4c19afa97c"
                "59045a99cac7827271cb41c65e590e09"
                "da3275600c2f09b8367793a9aca3db71"
                "cc30c58179ec3e87c14c01d5c1f3434f"
                "1d87"
            ),
        )

    def test_case_3_sha256_zero_salt_info(self):
        ikm = bytes.fromhex("0b" * 22)
        self.assertEqual(
            hkdf_extract(b"", ikm),
            bytes.fromhex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"),
        )
        self.assertEqual(
            hkdf(ikm, 42, b""),
            bytes.fromhex(
                "8da4e775a563c18f715f802a063c5a31"
                "b8a11f5c5ee1879ec3454e5f3c738d2d"
                "9d201395faa4b61a96c8"
            ),
        )

    def test_extract_none_salt_equals_all_zero(self):
        ikm = b"input key material"
        self.assertEqual(hkdf_extract(None, ikm), hkdf_extract(b"\x00" * 32, ikm))

    def test_expand_zero_length(self):
        self.assertEqual(hkdf_expand(b"prk", b"", 0), b"")

    def test_expand_length_limit(self):
        with self.assertRaises(ValueError):
            hkdf_expand(b"prk", b"", 255 * 32 + 1)

    def test_expand_various_lengths(self):
        prk = hkdf_extract(b"salt", b"ikm")
        for length in (1, 31, 32, 33, 64, 255, 256, 512):
            with self.subTest(length=length):
                self.assertEqual(len(hkdf_expand(prk, b"info", length)), length)


class TestScryptRFC7914(unittest.TestCase):
    def test_vector_1(self):
        self.assertEqual(
            scrypt(b"", b"", 16, 1, 1, 64),
            bytes.fromhex(
                "77d6576238657b203b19ca42c18a0497"
                "f16b4844e3074ae8dfdffa3fede21442"
                "fcd0069ded0948f8326a753a0fc81f17"
                "e8d3e0fb2e0d3628cf35e20c38d18906"
            ),
        )

    def test_vector_2(self):
        self.assertEqual(
            scrypt(b"password", b"NaCl", 1024, 8, 16, 64),
            bytes.fromhex(
                "fdbabe1c9d3472007856e7190d01e9fe"
                "7c6ad7cbc8237830e77376634b373162"
                "2eaf30d92e22a3886ff109279d9830da"
                "c727afb94a83ee6d8360cbdfa2cc0640"
            ),
        )

    def test_oracle_matrix(self):
        for n, r, p, dklen in (
            (16, 1, 1, 16),
            (16, 2, 1, 32),
            (32, 1, 1, 16),
            (16, 1, 2, 32),
            (64, 2, 3, 24),
        ):
            with self.subTest(n=n, r=r, p=p, dklen=dklen):
                self.assertEqual(
                    scrypt(b"password", b"salt", n, r, p, dklen),
                    hashlib.scrypt(b"password", salt=b"salt", n=n, r=r, p=p, dklen=dklen),
                )

    def test_rejects_bad_parameters(self):
        with self.assertRaises(ValueError):
            scrypt(b"p", b"s", 15, 1, 1, 16)
        with self.assertRaises(ValueError):
            scrypt(b"p", b"s", 1, 1, 1, 16)
        with self.assertRaises(ValueError):
            scrypt(b"p", b"s", 16, 0, 1, 16)


if __name__ == "__main__":
    unittest.main()
