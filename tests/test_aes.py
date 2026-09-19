import unittest

from crypto_gu.symmetric import aes

PT = [
    bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),
    bytes.fromhex("ae2d8a571e03ac9c9eb76fac45af8e51"),
    bytes.fromhex("30c81c46a35ce411e5fbc1191a0a52ef"),
    bytes.fromhex("f69f2445df4f9b17ad2b417be66c3710"),
]
DATA = b"".join(PT)

KEYS = {
    128: bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
    192: bytes.fromhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
    256: bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
}
IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
ICB = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

# SP 800-38A F.1-F.5 vectors, generated with a canonical openssl oracle
# and cross-checked against NIST FIPS-197 App C.
V = {
    "ECB128": "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4",
    "CBC128": "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
    "CFB128": "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6",
    "OFB128": "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e",
    "CTR128": "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee",
    "ECB192": "bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eefef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e",
    "CBC192": "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd",
    "CFB192": "cdc80d6fddf18cab34c25909c99a417467ce7f7f81173621961a2b70171d3d7a2e1e8a1dd59b88b1c8e60fed1efac4c9c05f9f9ca9834fa042ae8fba584b09ff",
    "OFB192": "cdc80d6fddf18cab34c25909c99a4174fcc28b8d4c63837c09e81700c11004018d9a9aeac0f6596f559c6d4daf59a5f26d9f200857ca6c3e9cac524bd9acc92a",
    "CTR192": "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050",
    "ECB256": "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7",
    "CBC256": "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b",
    "CFB256": "dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407bdf10132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d55b1e471",
    "OFB256": "dc7e84bfda79164b7ecd8486985d38604febdc6740d20b3ac88f6ad82a4fb08d71ab47a086e86eedf39d1c5bba97c4080126141d67f37be8538f5a8be740e484",
    "CTR256": "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6",
}


class TestBlockCipher(unittest.TestCase):
    def test_fips197_appendix_c(self):
        vectors = [
            (128, "000102030405060708090a0b0c0d0e0f",
             "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"),
            (192, "000102030405060708090a0b0c0d0e0f1011121314151617",
             "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191"),
            (256, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
             "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"),
        ]
        for bits, key_hex, pt_hex, ct_hex in vectors:
            key = bytes.fromhex(key_hex)
            pt = bytes.fromhex(pt_hex)
            ct = bytes.fromhex(ct_hex)
            with self.subTest(bits=bits):
                self.assertEqual(aes.block_encrypt(key, pt), ct)
                self.assertEqual(aes.block_decrypt(key, ct), pt)


class TestModesVector(unittest.TestCase):
    def _mode_params(self, mode):
        if mode == "ECB":
            return aes.ecb_encrypt, aes.ecb_decrypt
        if mode == "CBC":
            return aes.cbc_encrypt, aes.cbc_decrypt
        if mode == "CFB":
            return aes.cfb_encrypt, aes.cfb_decrypt
        if mode == "OFB":
            return aes.ofb_encrypt, aes.ofb_decrypt
        return aes.ctr_encrypt, aes.ctr_decrypt

    def test_encrypt_vectors(self):
        for label, expect in V.items():
            mode, bits = label[:3], int(label[3:])
            enc, dec = self._mode_params(mode)
            if mode == "ECB":
                ct = enc(KEYS[bits], DATA)
            elif mode == "CTR":
                ct = enc(KEYS[bits], DATA, ICB)
            else:
                ct = enc(KEYS[bits], DATA, IV)
            with self.subTest(mode=label):
                self.assertEqual(ct.hex(), expect)

    def test_roundtrip(self):
        modes = ["ECB", "CBC", "CFB", "OFB", "CTR"]
        for mode in modes:
            for bits in (128, 192, 256):
                enc, dec = self._mode_params(mode)
                if mode == "ECB":
                    ct = enc(KEYS[bits], DATA)
                    back = dec(KEYS[bits], ct)
                elif mode == "CTR":
                    ct = enc(KEYS[bits], DATA, ICB)
                    back = dec(KEYS[bits], ct, ICB)
                else:
                    ct = enc(KEYS[bits], DATA, IV)
                    back = dec(KEYS[bits], ct, IV)
                with self.subTest(mode=mode, bits=bits):
                    self.assertEqual(back, DATA)


class TestAvalanche(unittest.TestCase):
    def test_key_bit_flip_changes_output(self):
        key = bytearray(KEYS[128])
        key[0] ^= 0x01
        a = aes.ecb_encrypt(KEYS[128], DATA)
        b = aes.ecb_encrypt(bytes(key), DATA)
        changed = sum(x != y for x, y in zip(a, b))
        self.assertGreaterEqual(changed, 40)

    def test_plaintext_bit_flip_changes_block(self):
        p = bytearray(DATA[:16])
        p[0] ^= 0x01
        a = aes.ecb_encrypt(KEYS[128], DATA[:16])
        b = aes.ecb_encrypt(KEYS[128], bytes(p))
        changed = sum(x != y for x, y in zip(a, b))
        self.assertGreaterEqual(changed, 8)


class TestApi(unittest.TestCase):
    def test_cipher_dispatcher(self):
        ct, _ = aes.cipher(KEYS[128], DATA, mode="ecb", operation="encrypt")
        self.assertEqual(ct.hex(), V["ECB128"])
        back, _ = aes.cipher(KEYS[128], ct, mode="ecb", operation="decrypt")
        self.assertEqual(back, DATA)
        for mode in ("cbc", "cfb", "ofb"):
            ct, _ = aes.cipher(KEYS[128], DATA, mode=mode, iv=IV)
            back, _ = aes.cipher(KEYS[128], ct, mode=mode, iv=IV, operation="decrypt")
            self.assertEqual(back, DATA)

    def test_invalid_key_size(self):
        with self.assertRaises(aes.InvalidKeyError):
            aes.block_encrypt(b"tooshort", DATA[:16])

    def test_invalid_iv_cbc(self):
        with self.assertRaises(aes.InvalidIVError):
            aes.cbc_encrypt(KEYS[128], DATA, IV[:5])


if __name__ == "__main__":
    unittest.main()
