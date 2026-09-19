"""Tests for crypto_gu.hashes, verified against RFC 1321, RFC 6234, RFC 2202 and RFC 4231."""

import hashlib
import hmac as _hmac_stdlib
import os
import unittest

from crypto_gu.hashes import hash_algorithm, md5, md5_hex, sha256, sha256_hex
from crypto_gu.hashes.hmac import (
    hmac,
    hmac_md5,
    hmac_sha256,
    length_extend,
    length_extend_md5,
    length_extend_sha256,
    padded_length,
)

# RFC 1321 Appendix A.5 -- MD5 test suite
MD5_RFC1321 = {
    b"": "d41d8cd98f00b204e9800998ecf8427e",
    b"a": "0cc175b9c0f1b6a831c399e269772661",
    b"abc": "900150983cd24fb0d6963f7d28e17f72",
    b"message digest": "f96b697d7cb7938d525a2f31aaf161d0",
    b"abcdefghijklmnopqrstuvwxyz": "c3fcd3d76192e4007dfb496cca67e13b",
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789":
        "d174ab98d277d9f5a5611c2c9f419d9f",
    b"1234567890" * 8: "57edf4a22be3c955ac49da2e2107b67a",
}

# RFC 6234 (FIPS 180-2) SHA-256 test vectors
TEST2_1 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
TEST4 = (b"01234567012345670123456701234567" * 2) * 10
TEST8_256 = bytes.fromhex("e3d72570dcdd787ce3887ab2cd684652")
TEST10_256 = bytes.fromhex(
    "8326754e2277372f4fc12b20527afef04d8a056971b11ad57123a7c137760000"
    "d7bef6f3c1f7a9083aa39d810db310777dab8b1e7f02b84a26c773325f8b2374d"
    "e7a4b5a58cb5c5cf35bcee6fb946e5bd694fa593a8beb3f9d6592ecedaa66ca82"
    "a29d0c51bcf9336230e5d784e4c0a43f8d79a30a165cbabe452b774b9c7109a97"
    "d138f129228966f6c0adc106aad5a9fdd30825769b2c671af6759df28eb393d54d6"
)

SHA256_RFC6234 = {
    b"": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    b"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    TEST2_1: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    b"a" * 1_000_000: "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    TEST4: "594847328451bdfa85056225462cc1d867d877fb388df0ce35f25ab5562bfbb5",
    TEST8_256: "175ee69b02ba9b58e2b0a5fd13819cea573f3940a94f825128cf4209beabb4e8",
    TEST10_256: "97dbca7df46d62c8a422c941dd7e835b8ad3361763f7e9b2d95f4f0da6e1ccbc",
}

# RFC 2202 section 2 -- HMAC-MD5 test cases
HMAC_MD5_RFC2202 = [
    (b"\x0b" * 16, b"Hi There", "9294727a3638bb1c13f48ef8158bfc9d"),
    (b"Jefe", b"what do ya want for nothing?", "750c783e6ab0b503eaa86e310a5db738"),
    (b"\xaa" * 16, b"\xdd" * 50, "56be34521d144c88dbb8c733f0e8b3f6"),
    (bytes(range(1, 26)), b"\xcd" * 50, "697eaf0aca3a3aea3a75164746ffaa79"),
    (b"\x0c" * 16, b"Test With Truncation", "56461ef2342edc00f9bab995690efd4c"),
    (b"\xaa" * 80, b"Test Using Larger Than Block-Size Key - Hash Key First",
     "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd"),
    (b"\xaa" * 80,
     b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
     "6f630fad67cda0ee1fb1f562db3aa53e"),
]

# RFC 4231 sections 4.1-4.8 -- HMAC-SHA-256 test cases
HMAC_SHA256_RFC4231 = [
    (b"\x0b" * 20, b"Hi There",
     "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
    (b"Jefe", b"what do ya want for nothing?",
     "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
    (b"\xaa" * 20, b"\xdd" * 50,
     "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
    (bytes(range(1, 26)), b"\xcd" * 50,
     "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
    (b"\xaa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First",
     "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
    (b"\xaa" * 131,
     b"This is a test using a larger than block-size key and a larger than "
     b"block-size data. The key needs to be hashed before being used by the "
     b"HMAC algorithm.",
     "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
]


class TestMd5(unittest.TestCase):
    def test_rfc1321_vectors(self):
        for msg, expected in MD5_RFC1321.items():
            self.assertEqual(md5(msg).hex(), expected, msg[:24])
            self.assertEqual(md5_hex(msg), expected)

    def test_matches_hashlib(self):
        for size in range(0, 300):
            data = os.urandom(size)
            self.assertEqual(md5(data), hashlib.md5(data).digest(), size)


class TestSha256(unittest.TestCase):
    def test_rfc6234_vectors(self):
        for msg, expected in SHA256_RFC6234.items():
            self.assertEqual(sha256(msg).hex(), expected, msg[:24])
            self.assertEqual(sha256_hex(msg), expected)

    def test_matches_hashlib(self):
        for size in range(0, 300):
            data = os.urandom(size)
            self.assertEqual(sha256(data), hashlib.sha256(data).digest(), size)

    def test_multi_block_boundaries(self):
        for extra in (0, 1, 55, 56, 63, 64, 65, 127, 128):
            data = b"a" * extra
            self.assertEqual(sha256(data), hashlib.sha256(data).digest(), extra)


class TestHashDispatch(unittest.TestCase):
    def test_dispatch(self):
        self.assertEqual(hash_algorithm(b"abc", "sha1"), hashlib.sha1(b"abc").digest())
        self.assertEqual(hash_algorithm(b"abc", "sha256"), hashlib.sha256(b"abc").digest())
        self.assertEqual(hash_algorithm(b"abc", "sha512"), hashlib.sha512(b"abc").digest())
        self.assertEqual(hash_algorithm(b"abc", "md5"), hashlib.md5(b"abc").digest())
        self.assertEqual(hash_algorithm(b"abc", "hex_md5"), hashlib.md5(b"abc").hexdigest())
        with self.assertRaises(ValueError):
            hash_algorithm(b"abc", "sha384")


class TestHmac(unittest.TestCase):
    def test_rfc2202_md5(self):
        for key, msg, expected in HMAC_MD5_RFC2202:
            self.assertEqual(
                hmac_md5(key, msg).hex(), expected, "key=%d msg=%d" % (len(key), len(msg))
            )

    def test_rfc4231_sha256(self):
        for key, msg, expected in HMAC_SHA256_RFC4231:
            self.assertEqual(
                hmac_sha256(key, msg).hex(), expected, "key=%d msg=%d" % (len(key), len(msg))
            )

    def test_truncation(self):
        # RFC 4231 test case 5 truncates the output to 128 bits.
        self.assertEqual(
            hmac_sha256(b"\x0c" * 20, b"Test With Truncation")[:16].hex(),
            "a3b6167473100ee06e0c796c2955552b",
        )
        # RFC 2202 test case 5 truncates to 96 bits.
        self.assertEqual(
            hmac_md5(b"\x0c" * 16, b"Test With Truncation")[:12].hex(),
            "56461ef2342edc00f9bab995",
        )

    def test_matches_stdlib(self):
        for size in (0, 1, 5, 63, 64, 65, 100, 200):
            for keylen in (0, 1, 15, 16, 63, 64, 200):
                key = os.urandom(keylen)
                msg = os.urandom(size)
                self.assertEqual(
                    hmac(key, msg, sha256, 64),
                    _hmac_stdlib.new(key, msg, hashlib.sha256).digest(),
                    (size, keylen),
                )
                self.assertEqual(
                    hmac_md5(key, msg),
                    _hmac_stdlib.new(key, msg, hashlib.md5).digest(),
                    (size, keylen),
                )

    def test_key_longer_than_block_is_hashed(self):
        for keylen in (65, 70, 100, 131, 300, 1024):
            key = os.urandom(keylen)
            msg = os.urandom(37)
            self.assertEqual(
                hmac(key, msg, sha256, 64),
                _hmac_stdlib.new(key, msg, hashlib.sha256).digest(),
                keylen,
            )


class TestLengthExtension(unittest.TestCase):
    def test_padded_length(self):
        self.assertEqual(padded_length(0), 64)
        self.assertEqual(padded_length(55), 64)
        self.assertEqual(padded_length(56), 128)
        self.assertEqual(padded_length(64), 128)

    def test_md5_forge(self):
        for secret_len in (1, 10, 32, 60, 64, 100, 255):
            for msg_len in (0, 1, 20, 55, 63, 100):
                secret = os.urandom(secret_len)
                msg = os.urandom(msg_len)
                suffix = os.urandom(7)
                prefix = secret + msg
                mac = hashlib.md5(prefix).digest()
                forged = length_extend_md5(len(prefix), mac, suffix)
                expected = hashlib.md5(prefix + _pad_bytes(len(prefix)) + suffix).digest()
                self.assertEqual(forged, expected, (secret_len, msg_len))

    def test_sha256_forge(self):
        for secret_len in (1, 32, 64, 200):
            for msg_len in (0, 20, 63, 100):
                secret = os.urandom(secret_len)
                msg = os.urandom(msg_len)
                suffix = os.urandom(9)
                prefix = secret + msg
                mac = hashlib.sha256(prefix).digest()
                forged = length_extend_sha256(len(prefix), mac, suffix)
                expected = hashlib.sha256(prefix + _pad_bytes(len(prefix), "big") + suffix).digest()
                self.assertEqual(forged, expected, (secret_len, msg_len))

    def test_dispatch(self):
        with self.assertRaises(ValueError):
            length_extend("sha1", 10, b"x" * 16, b"y")


def _pad_bytes(msg_len: int, endian: str = "little") -> bytes:
    """Merkle-Damgard padding bytes for a message of *msg_len* bytes."""
    bit_len = msg_len * 8
    header = b"\x80" + b"\x00" * ((64 - ((msg_len + 9) % 64)) % 64)
    return header + bit_len.to_bytes(8, endian)


if __name__ == "__main__":
    unittest.main()
