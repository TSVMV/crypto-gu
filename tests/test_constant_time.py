import unittest

from crypto_gu import constant_time


class TestEqual(unittest.TestCase):
    def test_equal_buffers(self):
        self.assertTrue(constant_time.equal(b"abcdef", b"abcdef"))
        self.assertTrue(constant_time.equal(b"", b""))

    def test_single_byte_difference(self):
        self.assertFalse(constant_time.equal(b"abcdef", b"abcdeg"))

    def test_length_mismatch(self):
        self.assertFalse(constant_time.equal(b"abc", b"abcd"))


class TestIsZero(unittest.TestCase):
    def test_zero(self):
        self.assertTrue(constant_time.is_zero(0))

    def test_non_zero(self):
        for value in (1, 2, 255, 256, 2 ** 64):
            self.assertFalse(constant_time.is_zero(value))

    def test_negative_rejected(self):
        with self.assertRaises(ValueError):
            constant_time.is_zero(-1)


class TestSelect(unittest.TestCase):
    def test_selects_true(self):
        self.assertEqual(constant_time.select(1, 0xAA, 0x55), 0xAA)

    def test_selects_false(self):
        self.assertEqual(constant_time.select(0, 0xAA, 0x55), 0x55)

    def test_bad_mask(self):
        with self.assertRaises(ValueError):
            constant_time.select(2, 1, 0)

    def test_select_bytes(self):
        self.assertEqual(constant_time.select_bytes(1, b"\xaa", b"\x55"), b"\xaa")
        self.assertEqual(constant_time.select_bytes(0, b"\xaa", b"\x55"), b"\x55")

    def test_select_bytes_length_mismatch(self):
        with self.assertRaises(ValueError):
            constant_time.select_bytes(1, b"\xaa", b"\x55\x55")


if __name__ == "__main__":
    unittest.main()
