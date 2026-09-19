import unittest

from crypto_gu.errors import InvalidKeyError, InvalidTagError
from crypto_gu.symmetric import aes_gcm, chacha20poly1305, poly1305


class TestPoly1305RFC8439(unittest.TestCase):
    def test_section_2_5_2(self):
        key = bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
        self.assertEqual(
            poly1305.poly1305(key, b"Cryptographic Forum Research Group"),
            bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9"),
        )

    def test_empty_message(self):
        key = bytes(range(32))
        self.assertEqual(poly1305.poly1305(key, b""), key[16:])

    def test_block_boundaries(self):
        key = bytes(range(32))
        tags = {size: poly1305.poly1305(key, b"\xaa" * size) for size in (1, 15, 16, 17, 31, 32, 33)}
        self.assertEqual(len(set(tags.values())), len(tags))

    def test_rejects_bad_key(self):
        with self.assertRaises(InvalidKeyError):
            poly1305.poly1305(b"short", b"msg")


class TestChaCha20Poly1305RFC8439(unittest.TestCase):
    KEY = bytes(range(0x80, 0xA0))
    NONCE = bytes.fromhex("070000004041424344454647")
    AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    PLAINTEXT = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you "
        b"only one tip for the future, sunscreen would be it."
    )
    CIPHERTEXT = bytes.fromhex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116"
    )
    TAG = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")

    def test_section_2_8_2(self):
        out = chacha20poly1305.encrypt(self.KEY, self.NONCE, self.PLAINTEXT, self.AAD)
        self.assertEqual(out, self.CIPHERTEXT + self.TAG)

    def test_roundtrip(self):
        out = chacha20poly1305.encrypt(self.KEY, self.NONCE, self.PLAINTEXT, self.AAD)
        self.assertEqual(chacha20poly1305.decrypt(self.KEY, self.NONCE, out, self.AAD), self.PLAINTEXT)

    def test_empty_plaintext_and_aad(self):
        out = chacha20poly1305.encrypt(self.KEY, self.NONCE, b"", b"")
        self.assertEqual(len(out), 16)
        self.assertEqual(chacha20poly1305.decrypt(self.KEY, self.NONCE, out, b""), b"")

    def test_tampered_tag_rejected(self):
        out = chacha20poly1305.encrypt(self.KEY, self.NONCE, self.PLAINTEXT, self.AAD)
        with self.assertRaises(InvalidTagError):
            chacha20poly1305.decrypt(self.KEY, self.NONCE, out[:-1] + bytes([out[-1] ^ 1]), self.AAD)

    def test_wrong_aad_rejected(self):
        out = chacha20poly1305.encrypt(self.KEY, self.NONCE, self.PLAINTEXT, self.AAD)
        with self.assertRaises(InvalidTagError):
            chacha20poly1305.decrypt(self.KEY, self.NONCE, out, self.AAD + b"x")


class TestAESGCMNIST(unittest.TestCase):
    def test_case_1_empty(self):
        out = aes_gcm.encrypt(bytes(16), bytes(12), b"")
        self.assertEqual(out, bytes.fromhex("58e2fccefa7e3061367f1d57a4e7455a"))

    def test_case_2_single_block(self):
        out = aes_gcm.encrypt(bytes(16), bytes(12), bytes(16))
        self.assertEqual(out, bytes.fromhex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"))

    def test_case_3_multi_block(self):
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
        nonce = bytes.fromhex("cafebabefacedbaddecaf888")
        plaintext = bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
        )
        out = aes_gcm.encrypt(key, nonce, plaintext)
        self.assertEqual(
            out,
            bytes.fromhex(
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
                "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"
                "4d5c2af327cd64a62cf35abd2ba6fab4"
            ),
        )

    def test_case_4_with_aad(self):
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
        nonce = bytes.fromhex("cafebabefacedbaddecaf888")
        plaintext = bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
        )
        aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        out = aes_gcm.encrypt(key, nonce, plaintext, aad)
        self.assertEqual(
            out,
            bytes.fromhex(
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
                "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
                "5bc94fbc3221a5db94fae95ae7121a47"
            ),
        )

    def test_case_5_non_96_bit_iv(self):
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
        nonce = bytes.fromhex("cafebabefacedbad")
        plaintext = bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
        )
        aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        out = aes_gcm.encrypt(key, nonce, plaintext, aad)
        self.assertEqual(
            out,
            bytes.fromhex(
                "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c74"
                "2373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598"
                "3612d2e79e3b0785561be14aaca2fccb"
            ),
        )

    def test_aes_192_and_256_keys(self):
        for key_size in (24, 32):
            with self.subTest(key_size=key_size):
                key = bytes(range(1, key_size + 1))
                out = aes_gcm.encrypt(key, bytes(12), b"payload")
                self.assertEqual(aes_gcm.decrypt(key, bytes(12), out), b"payload")

    def test_tag_truncation_roundtrip(self):
        key = bytes(range(16))
        out = aes_gcm.encrypt(key, bytes(12), b"payload", b"aad", tag_length=8)
        self.assertEqual(len(out), 7 + 8)
        self.assertEqual(aes_gcm.decrypt(key, bytes(12), out, b"aad", tag_length=8), b"payload")

    def test_tamper_and_wrong_aad_rejected(self):
        key = bytes(range(16))
        out = aes_gcm.encrypt(key, bytes(12), b"payload", b"aad")
        with self.assertRaises(InvalidTagError):
            aes_gcm.decrypt(key, bytes(12), out[:-1] + bytes([out[-1] ^ 1]), b"aad")
        with self.assertRaises(InvalidTagError):
            aes_gcm.decrypt(key, bytes(12), out, b"aad2")

    def test_various_message_lengths(self):
        key = bytes(range(16))
        for size in (0, 1, 15, 16, 17, 31, 32, 33, 64, 100):
            with self.subTest(size=size):
                msg = (b"aes-gcm payload material " * 8)[:size]
                out = aes_gcm.encrypt(key, bytes(12), msg, b"header")
                self.assertEqual(aes_gcm.decrypt(key, bytes(12), out, b"header"), msg)


if __name__ == "__main__":
    unittest.main()
