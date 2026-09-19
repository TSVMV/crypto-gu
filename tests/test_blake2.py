import hashlib
import unittest

from crypto_gu.hashes.blake2b import Blake2b, blake2b
from crypto_gu.hashes.blake2s import Blake2s, blake2s


def _selftest_seq(length, seed):
    """Deterministic Fibonacci-generator byte sequence from RFC 7693 Appendix E."""
    out = bytearray()
    a = (0xDEAD4BAD * seed) & 0xFFFFFFFF
    b = 1
    for _ in range(length):
        t = (a + b) & 0xFFFFFFFF
        a, b = b, t
        out.append((t >> 24) & 0xFF)
    return bytes(out)


class TestBlake2bRFC7693(unittest.TestCase):
    def test_appendix_a_abc(self):
        self.assertEqual(
            blake2b(b"abc"),
            bytes.fromhex(
                "ba80a53f981c4d0d6a2797b69f12f6e9"
                "4c212f14685ac4b74b12bb6fdbffa2d1"
                "7d87c5392aab792dc252d5de4533cc95"
                "18d38aa8dbf1925ab92386edd4009923"
            ),
        )

    def test_selftest_grand_hash(self):
        grand = Blake2b(digest_size=32)
        for outlen in (20, 32, 48, 64):
            for inlen in (0, 3, 128, 129, 255, 1024):
                data = _selftest_seq(inlen, inlen)
                grand.update(blake2b(data, digest_size=outlen))
                key = _selftest_seq(outlen, outlen)
                grand.update(blake2b(data, key=key, digest_size=outlen))
        self.assertEqual(
            grand.digest(),
            bytes.fromhex("c23a7800d98123bd10f506c61e29da5603d763b8bbad2e737f5e765a7bccd475"),
        )

    def test_boundaries_vs_hashlib(self):
        for size in (0, 1, 63, 64, 127, 128, 129, 255, 256, 257, 1024):
            with self.subTest(size=size):
                data = (b"blake2b boundary payload material " * 32)[:size]
                self.assertEqual(blake2b(data), hashlib.blake2b(data).digest())

    def test_digest_sizes_vs_hashlib(self):
        for ds in range(1, 65):
            with self.subTest(digest_size=ds):
                self.assertEqual(
                    blake2b(b"payload", digest_size=ds),
                    hashlib.blake2b(b"payload", digest_size=ds).digest(),
                )

    def test_keyed_salt_personal_vs_hashlib(self):
        for key in (b"", b"k", b"K" * 64):
            for salt in (b"", b"salt1234", b"S" * 16):
                for personal in (b"", b"personal", b"P" * 16):
                    with self.subTest(key=len(key), salt=len(salt), personal=len(personal)):
                        self.assertEqual(
                            blake2b(b"message", key=key, salt=salt, personal=personal),
                            hashlib.blake2b(b"message", key=key, salt=salt, person=personal).digest(),
                        )

    def test_incremental_matches_one_shot(self):
        data = bytes(range(256)) * 3
        for split in (1, 127, 128, 200):
            with self.subTest(split=split):
                ctx = Blake2b()
                ctx.update(data[:split])
                ctx.update(data[split:])
                self.assertEqual(ctx.digest(), blake2b(data))


class TestBlake2sRFC7693(unittest.TestCase):
    def test_appendix_b_abc(self):
        self.assertEqual(
            blake2s(b"abc"),
            bytes.fromhex("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"),
        )

    def test_selftest_grand_hash(self):
        grand = Blake2s(digest_size=32)
        for outlen in (16, 20, 28, 32):
            for inlen in (0, 3, 64, 65, 255, 1024):
                data = _selftest_seq(inlen, inlen)
                grand.update(blake2s(data, digest_size=outlen))
                key = _selftest_seq(outlen, outlen)
                grand.update(blake2s(data, key=key, digest_size=outlen))
        self.assertEqual(
            grand.digest(),
            bytes.fromhex("6a411f08ce25adcdfb02aba641451cec53c598b24f4fc787fbdc88797f4c1dfe"),
        )

    def test_boundaries_vs_hashlib(self):
        for size in (0, 1, 31, 32, 63, 64, 65, 255, 256, 257, 1024):
            with self.subTest(size=size):
                data = (b"blake2s boundary payload material " * 32)[:size]
                self.assertEqual(blake2s(data), hashlib.blake2s(data).digest())

    def test_digest_sizes_vs_hashlib(self):
        for ds in range(1, 33):
            with self.subTest(digest_size=ds):
                self.assertEqual(
                    blake2s(b"payload", digest_size=ds),
                    hashlib.blake2s(b"payload", digest_size=ds).digest(),
                )

    def test_keyed_salt_personal_vs_hashlib(self):
        for key in (b"", b"k", b"K" * 32):
            for salt in (b"", b"salt", b"S" * 8):
                for personal in (b"", b"pers", b"P" * 8):
                    with self.subTest(key=len(key), salt=len(salt), personal=len(personal)):
                        self.assertEqual(
                            blake2s(b"message", key=key, salt=salt, personal=personal),
                            hashlib.blake2s(b"message", key=key, salt=salt, person=personal).digest(),
                        )

    def test_incremental_matches_one_shot(self):
        data = bytes(range(256)) * 3
        for split in (1, 63, 64, 100):
            with self.subTest(split=split):
                ctx = Blake2s()
                ctx.update(data[:split])
                ctx.update(data[split:])
                self.assertEqual(ctx.digest(), blake2s(data))


if __name__ == "__main__":
    unittest.main()
