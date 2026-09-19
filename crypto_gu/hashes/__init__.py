"""Hash functions: pure-Python SHA-1, SHA-256, SHA-512, MD5, BLAKE2b/s, HMAC and length extension."""

from crypto_gu.hashes.blake2b import blake2b
from crypto_gu.hashes.blake2s import blake2s
from crypto_gu.hashes.md5 import md5, md5_hex, md5_state
from crypto_gu.hashes.sha1 import sha1, sha1_hex
from crypto_gu.hashes.sha256 import sha256, sha256_hex
from crypto_gu.hashes.sha512 import sha512, sha512_hex

HASH_TABLE = {
    "sha1": sha1,
    "sha256": sha256,
    "sha512": sha512,
    "md5": md5,
    "blake2b": blake2b,
    "blake2s": blake2s,
    "hex_sha1": sha1_hex,
    "hex_sha256": sha256_hex,
    "hex_sha512": sha512_hex,
    "hex_md5": md5_hex,
}


def hash_algorithm(data, algorithm: str = "sha256"):
    key = algorithm.lower()
    if key not in HASH_TABLE:
        raise ValueError("unknown hash algorithm: %r (known: %s)" % (algorithm, sorted(HASH_TABLE)))
    return HASH_TABLE[key](data)


__all__ = [
    "sha1",
    "sha1_hex",
    "sha256",
    "sha256_hex",
    "sha512",
    "sha512_hex",
    "md5",
    "md5_hex",
    "md5_state",
    "blake2b",
    "blake2s",
    "HASH_TABLE",
    "hash_algorithm",
]
