"""Encoding primitives.

Every function takes and returns ``bytes`` (or ``str`` where explicitly noted)
so that the library has one uniform data representation. ``to_bytes`` and
``from_bytes`` are the entry points used by the rest of the codebase.
"""

from __future__ import annotations

import base64
import binascii
from typing import Iterable, Optional

BINARY_DIGITS = frozenset(b"\x00\x01")

# --------------------------------------------------------------------------- #
# Integer <-> bytes
# --------------------------------------------------------------------------- #


def to_bytes(data: bytes | bytearray | int | str) -> bytes:
    """Coerce a common input type to ``bytes``.

    Accepts ``bytes``, ``bytearray``, ``int`` (big-endian) and ``str``
    (UTF-8). Anything else raises :class:`TypeError`.
    """
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    if isinstance(data, int):
        if data < 0:
            raise ValueError("cannot convert a negative int to bytes")
        if data == 0:
            return b"\x00"
        return data.to_bytes((data.bit_length() + 7) // 8, "big")
    if isinstance(data, str):
        return data.encode("utf-8")
    raise TypeError("unsupported type for to_bytes: %s" % type(data).__name__)


def from_bytes(data: bytes) -> int:
    """Interpret *data* as a big-endian unsigned integer."""
    return int.from_bytes(to_bytes(data), "big")


def from_bytes_le(data: bytes) -> int:
    """Interpret *data* as a little-endian unsigned integer."""
    return int.from_bytes(to_bytes(data), "little")


# --------------------------------------------------------------------------- #
# Hex / base encoding
# --------------------------------------------------------------------------- #


def hex_encode(data: bytes) -> str:
    return binascii.hexlify(to_bytes(data)).decode("ascii")


def hex_decode(data: bytes | str) -> bytes:
    text = to_bytes(data).decode("ascii")
    text = "".join(text.split())
    if len(text) % 2:
        text = "0" + text
    return binascii.unhexlify(text)


_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}


def b58_encode(data: bytes) -> str:
    """Bitcoin alphabet base58."""
    num = from_bytes(data)
    out = []
    while num:
        num, rem = divmod(num, 58)
        out.append(_B58_ALPHABET[rem])
    for byte in data:
        if byte == 0:
            out.append("1")
        else:
            break
    return "".join(reversed(out))


def b58_decode(data: str) -> bytes:
    num = 0
    for c in data:
        if c not in _B58_INDEX:
            raise ValueError("invalid base58 character: %r" % c)
        num = num * 58 + _B58_INDEX[c]
    raw = b"" if num == 0 else num.to_bytes((num.bit_length() + 7) // 8, "big")
    pad = 0
    for c in data:
        if c != "1":
            break
        pad += 1
    return b"\x00" * pad + raw


_B85_ALPHABET = (
    "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_"
    "abcdefghijklmnopqrstuvwxyz`{|}~"
)


def b85_encode(data: bytes) -> str:
    """Zero-pad to a multiple of 4, then RFC-style base85."""
    raw = to_bytes(data)
    padded = raw + b"\x00" * ((4 - len(raw) % 4) % 4)
    return base64.b85encode(padded).decode("ascii")


def b85_decode(data: bytes | str) -> bytes:
    """Inverse of :func:`b85_encode`; trailing padding zeros are stripped."""
    raw = base64.b85decode(to_bytes(data))
    return raw.rstrip(b"\x00")


def b64_encode(data: bytes) -> str:
    return base64.b64encode(to_bytes(data)).decode("ascii")


def b64_decode(data: bytes | str) -> bytes:
    return base64.b64decode(to_bytes(data), validate=False)


def b32_encode(data: bytes) -> str:
    return base64.b32encode(to_bytes(data)).decode("ascii")


def b32_decode(data: bytes | str) -> bytes:
    return base64.b32decode(to_bytes(data))


def a2b_base64(data: bytes | str) -> bytes:
    return b64_decode(data)


def b2a_base64(data: bytes) -> str:
    return b64_encode(data)


def a2b_base32(data: bytes | str) -> bytes:
    return b32_decode(data)


def b2a_base32(data: bytes) -> str:
    return b32_encode(data)


def a2b_hex(data: bytes | str) -> bytes:
    return hex_decode(data)


def b2a_hex(data: bytes) -> str:
    return hex_encode(data)


# --------------------------------------------------------------------------- #
# XOR
# --------------------------------------------------------------------------- #


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two buffers; the longer one wins, no key cycling."""
    a, b = to_bytes(a), to_bytes(b)
    if len(a) != len(b):
        raise ValueError("xor_bytes: buffers must be equal length")
    return bytes(x ^ y for x, y in zip(a, b))


def xor_crypt(data: bytes, key: bytes) -> bytes:
    """XOR *data* against *key*, cycling the key."""
    data, key = to_bytes(data), to_bytes(key)
    if not key:
        raise ValueError("xor_crypt: key must be non-empty")
    return bytes(x ^ key[i % len(key)] for i, x in enumerate(data))


def xor_key_stream(data: bytes, other: bytes) -> bytes:
    """Recover a keystream by XORing ciphertext with known plaintext."""
    return xor_bytes(data, other)


# --------------------------------------------------------------------------- #
# Misc textual encodings
# --------------------------------------------------------------------------- #


_MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
    "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
    ".": ".-.-.-", ",": "--..--", "?": "..--..", "'": ".----.", "!": "-.-.--",
    "/": "-..-.", "(": "-.--.", ")": "-.--.-", "&": ".-...", ":": "---...",
    ";": "-.-.-.", "=": "-...-", "+": ".-.-.", "-": "-....-", "_": "..--..",
    '"': ".-.--.", "@": ".--.-.", " ": "/",
}
_MORSE_REV = {v: k for k, v in _MORSE.items()}


def morse_encode(text: str) -> str:
    if isinstance(text, bytes):
        text = text.decode("utf-8")
    return " ".join(_MORSE[c.upper()] for c in text)


def morse_decode(text: str) -> str:
    if isinstance(text, bytes):
        text = text.decode("utf-8")
    out = []
    for tok in text.strip().split():
        tok = tok.strip()
        if tok not in _MORSE_REV:
            raise ValueError("invalid morse token: %r" % tok)
        out.append(_MORSE_REV[tok])
    return "".join(out)


def int_to_hex(n: int) -> str:
    return hex_encode(to_bytes(n))


def hex_to_int(data: bytes | str) -> int:
    return from_bytes(hex_decode(data))


def int_to_bytes(n: int, length: Optional[int] = None) -> bytes:
    raw = to_bytes(n)
    if length is not None:
        if len(raw) > length:
            raise ValueError("int does not fit in %d bytes" % length)
        raw = raw.rjust(length, b"\x00")
    return raw


def bcd_encode(data: bytes) -> bytes:
    """BCD-encode decimal digit characters as packed 4-bit nibbles.

    Each input byte must be the ASCII code of '0'..'9'. Two digits are packed
    into one output byte, high nibble first; a trailing odd digit occupies the
    high nibble of the final byte.
    """
    raw = to_bytes(data)
    out = bytearray()
    for i, byte in enumerate(raw):
        if not 0x30 <= byte <= 0x39:
            raise ValueError("bcd_encode: byte %d is not an ASCII digit" % byte)
        digit = byte - 0x30
        if i % 2 == 0:
            out.append(digit << 4)
        else:
            out[-1] |= digit
    return bytes(out)


def unpack_bits(data: bytes) -> list:
    """Unpack bytes into a list of ints in {0, 1}."""
    out = []
    for byte in to_bytes(data):
        for shift in range(7, -1, -1):
            out.append((byte >> shift) & 1)
    return out


def unpack_bytes(bits: Iterable[int]) -> bytes:
    """Inverse of :func:`unpack_bits`."""
    bits = list(bits)
    if len(bits) % 8:
        raise ValueError("bit count is not a multiple of 8")
    out = bytearray()
    for i in range(0, len(bits), 8):
        val = 0
        for bit in bits[i : i + 8]:
            val = (val << 1) | (int(bit) & 1)
        out.append(val)
    return bytes(out)


def to_str(data: bytes, encoding: str = "utf-8") -> str:
    return to_bytes(data).decode(encoding)


def printable(data: bytes) -> bytes:
    """Keep only 7-bit printable ASCII plus space/newline/tab."""
    out = bytearray()
    for b in to_bytes(data):
        if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D):
            out.append(b)
    return bytes(out)


__all__ = [
    "to_bytes",
    "from_bytes",
    "from_bytes_le",
    "hex_encode",
    "hex_decode",
    "b58_encode",
    "b58_decode",
    "b85_encode",
    "b85_decode",
    "b64_encode",
    "b64_decode",
    "b32_encode",
    "b32_decode",
    "a2b_base64",
    "b2a_base64",
    "a2b_base32",
    "b2a_base32",
    "a2b_hex",
    "b2a_hex",
    "xor_bytes",
    "xor_crypt",
    "xor_key_stream",
    "morse_encode",
    "morse_decode",
    "int_to_hex",
    "hex_to_int",
    "int_to_bytes",
    "bcd_encode",
    "unpack_bits",
    "unpack_bytes",
    "to_str",
    "printable",
    "BINARY_DIGITS",
]
