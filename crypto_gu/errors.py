"""Exception types shared by every crypto_gu module."""


class CryptoGuError(Exception):
    """Base class for all crypto_gu errors."""


class InvalidPaddingError(CryptoGuError):
    """Padding does not decode to a consistent block structure."""


class InvalidKeyError(CryptoGuError):
    """Key length, parity, or size is not acceptable for the operation."""


class InvalidIVError(CryptoGuError):
    """IV length does not match the block or stream cipher requirement."""


class InvalidInputError(CryptoGuError):
    """Input is outside the domain of the requested operation."""


class NotPrimitiveError(CryptoGuError):
    """A value that had to be prime, squarefree, or a generator is not."""


class InvalidNonceError(CryptoGuError):
    """Nonce length is wrong for the stream cipher."""


class AttackFailedError(CryptoGuError):
    """A solver tried a technique and it did not apply."""


class OracleError(CryptoGuError):
    """An attacker-supplied oracle raised or returned malformed output."""


class InvalidTagError(CryptoGuError):
    """An AEAD authentication tag did not verify."""


class DecryptionError(CryptoGuError):
    """An encrypted message failed padding or integrity checks."""


class InvalidSignatureError(CryptoGuError):
    """A signature could not be produced or did not verify."""


__all__ = [
    "AttackFailedError",
    "CryptoGuError",
    "DecryptionError",
    "InvalidIVError",
    "InvalidInputError",
    "InvalidKeyError",
    "InvalidNonceError",
    "InvalidPaddingError",
    "InvalidSignatureError",
    "InvalidTagError",
    "NotPrimitiveError",
    "OracleError",
]
