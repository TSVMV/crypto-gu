import hashlib
import unittest

from crypto_gu.asymmetric import pkcs1
from crypto_gu.asymmetric.rsa import RSAKey
from crypto_gu.errors import DecryptionError, InvalidSignatureError

N = 122587499352606110172799112970429370251480103862760083268012422783620683209490073999330853618344465282626195440352844680500515782015130138319828173697867181130240546659129157298919724164253977061816363737636199968412386824682448629354735477920287405854685394547986242568106431682540973450862393420423232527567
E = 65537
D = 86303380268091205231590983312367681066161717993254001280235976239581834728514618066971729787704583421198560071752443668669809385025193241252095031909393058096491045491602707252507591418778134393193912845070697276376390935883414367235146872999526399103643838374142558177521985740394405805718396607308819828425
P = 11100689203308886970063595350193467872000099179550708301686955056562269155385124553807559149963118580379476272767213441550557845364297853651299934660060379
Q = 11043233181960026390941352029125590877732846825788882897579190711290069043750624125608986379393839173867116053820067808677490715068324439276842671581958173

OAEP_CT = bytes.fromhex(
    "42ae95d210849eb061712ae21dc35b4fb3e7c15042b3107a38732c6e5c08adfc"
    "8ff8f9f07a23307bd5c95f51248dcd4585e837b30499187d6de16d65068b3957"
    "f09c456250e1d153e11a05182d6d62820c700ef1bcc0413dbf863a6e91fd20831f"
    "edd3a3036df7aa33f235ae0b0bcf3d5d1362aa9d4b338b18f31a37f1b593e4"
)
OAEP_MSG = b"crypto-gu OAEP vector"

PSS_SIG = bytes.fromhex(
    "9dd1c09f7288539bb2b6ae5be7bad0618c05dc23469655c4f4d38b16226a80fa"
    "ba8b868e70f867b1f88961caed3d86366b5b325561c3c33dc09d27d17714eaad"
    "e926db8941a5f620213a04dcae55fb1d73c3af44d150bd60a7e49526658afcc2"
    "0e2894157b0639bd589d5f6906dcd36a50d230ebd8b7ea458ef7058d1d4256c6"
)
PSS_MSG = b"crypto-gu PSS vector"


def _reference_mgf1(seed: bytes, length: int, hash_name: str) -> bytes:
    output = b""
    counter = 0
    while len(output) < length:
        digest = hashlib.new(hash_name)
        digest.update(seed)
        digest.update(counter.to_bytes(4, "big"))
        output += digest.digest()
        counter += 1
    return output[:length]


class TestMGF1(unittest.TestCase):
    def test_matches_hashlib_reference(self):
        for hash_name in ("sha1", "sha256", "sha512"):
            for length in (0, 1, 20, 32, 64, 100, 257):
                with self.subTest(hash_name=hash_name, length=length):
                    seed = bytes(range(len(hash_name))) * 7
                    self.assertEqual(
                        pkcs1.mgf1(seed, length, hash_name),
                        _reference_mgf1(seed, length, hash_name),
                    )


class TestOAEP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = RSAKey(n=N, e=E, d=D, p=P, q=Q)

    def test_decrypts_external_ciphertext(self):
        self.assertEqual(pkcs1.oaep_decrypt(self.key, OAEP_CT, "sha256"), OAEP_MSG)

    def test_roundtrip(self):
        for size in (0, 1, 16, 32, 62):
            with self.subTest(size=size):
                message = bytes(range(size))
                ciphertext = pkcs1.oaep_encrypt(self.key, message, "sha256")
                self.assertEqual(pkcs1.oaep_decrypt(self.key, ciphertext, "sha256"), message)

    def test_label_binding(self):
        ciphertext = pkcs1.oaep_encrypt(self.key, b"payload", "sha256", label=b"ctx")
        self.assertEqual(pkcs1.oaep_decrypt(self.key, ciphertext, "sha256", b"ctx"), b"payload")
        with self.assertRaises(DecryptionError):
            pkcs1.oaep_decrypt(self.key, ciphertext, "sha256", b"other")

    def test_rejects_tampered_ciphertext(self):
        ciphertext = pkcs1.oaep_encrypt(self.key, b"payload", "sha256")
        tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
        with self.assertRaises(DecryptionError):
            pkcs1.oaep_decrypt(self.key, tampered, "sha256")

    def test_rejects_oversized_message(self):
        with self.assertRaises(ValueError):
            pkcs1.oaep_encrypt(self.key, b"x" * 200, "sha256")


class TestPSS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = RSAKey(n=N, e=E, d=D, p=P, q=Q)

    def test_verifies_external_signature(self):
        self.assertTrue(pkcs1.pss_verify_signature(self.key, PSS_MSG, PSS_SIG, "sha256", 32))

    def test_roundtrip_salt_lengths(self):
        for salt_length in (0, 8, 20, 32):
            with self.subTest(salt_length=salt_length):
                signature = pkcs1.pss_sign(self.key, b"message", "sha256", salt_length)
                self.assertTrue(pkcs1.pss_verify_signature(self.key, b"message", signature, "sha256", salt_length))

    def test_rejects_wrong_message(self):
        signature = pkcs1.pss_sign(self.key, b"message", "sha256", 32)
        self.assertFalse(pkcs1.pss_verify_signature(self.key, b"messagf", signature, "sha256", 32))

    def test_rejects_tampered_signature(self):
        signature = pkcs1.pss_sign(self.key, b"message", "sha256", 32)
        tampered = signature[:-1] + bytes([signature[-1] ^ 1])
        self.assertFalse(pkcs1.pss_verify_signature(self.key, b"message", tampered, "sha256", 32))

    def test_rejects_wrong_salt_length(self):
        signature = pkcs1.pss_sign(self.key, b"message", "sha256", 32)
        self.assertFalse(pkcs1.pss_verify_signature(self.key, b"message", signature, "sha256", 20))

    def test_public_only_key_cannot_sign(self):
        with self.assertRaises(InvalidSignatureError):
            pkcs1.pss_sign(self.key.public(), b"message", "sha256", 32)


if __name__ == "__main__":
    unittest.main()
