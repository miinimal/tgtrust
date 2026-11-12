"""RSA blind signatures, RFC 9474 variant RSABSSA-SHA384-PSSZERO-Deterministic.

The signer signs a blinded message without seeing it; the holder unblinds the
result into an ordinary RSASSA-PSS signature (SHA-384, MGF1-SHA-384, zero-length
salt). Signer cannot link the final (message, signature) pair to the blinded
request it served. Final signatures verify with any standard PSS verifier.

Reference: https://www.rfc-editor.org/rfc/rfc9474
"""

from __future__ import annotations

import hashlib
import math
import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_HASH = hashlib.sha384
_HASH_LEN = 48
_SALT_LEN = 0


class BlindSignatureError(Exception):
    """Raised on any blind-signature protocol failure."""


def _i2osp(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


def _os2ip(data: bytes) -> int:
    return int.from_bytes(data, "big")


def _mgf1(seed: bytes, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += _HASH(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def emsa_pss_encode(message: bytes, em_bits: int) -> bytes:
    """EMSA-PSS-ENCODE from RFC 8017 section 9.1.1 with an empty salt."""
    em_len = math.ceil(em_bits / 8)
    m_hash = _HASH(message).digest()
    if em_len < _HASH_LEN + _SALT_LEN + 2:
        raise BlindSignatureError("modulus too small for the encoding")
    h = _HASH(b"\x00" * 8 + m_hash).digest()
    ps = b"\x00" * (em_len - _SALT_LEN - _HASH_LEN - 2)
    db = ps + b"\x01"
    masked_db = bytearray(a ^ b for a, b in zip(db, _mgf1(h, em_len - _HASH_LEN - 1)))
    masked_db[0] &= 0xFF >> (8 * em_len - em_bits)
    return bytes(masked_db) + h + b"\xbc"


def _modulus_len(public_key: rsa.RSAPublicKey) -> int:
    return math.ceil(public_key.key_size / 8)


@dataclass(frozen=True)
class BlindingState:
    """Secret the holder keeps between ``blind`` and ``finalize``."""

    inverse: int


def blind(public_key: rsa.RSAPublicKey, message: bytes) -> tuple[bytes, BlindingState]:
    """Blind ``message`` for signing. Returns (blinded_message, state)."""
    numbers = public_key.public_numbers()
    n, e = numbers.n, numbers.e
    encoded = emsa_pss_encode(message, public_key.key_size - 1)
    m = _os2ip(encoded)
    if math.gcd(m, n) != 1:
        raise BlindSignatureError("invalid input")
    while True:
        r = secrets.randbelow(n - 2) + 2
        if math.gcd(r, n) == 1:
            break
    blinded = (m * pow(r, e, n)) % n
    return _i2osp(blinded, _modulus_len(public_key)), BlindingState(inverse=pow(r, -1, n))


def blind_sign(private_key: rsa.RSAPrivateKey, blinded_message: bytes) -> bytes:
    """Signer side: sign a blinded message it cannot read."""
    numbers = private_key.private_numbers()
    pub = numbers.public_numbers
    k = _modulus_len(private_key.public_key())
    if len(blinded_message) != k:
        raise BlindSignatureError("blinded message has wrong length")
    m = _os2ip(blinded_message)
    if not 0 < m < pub.n:
        raise BlindSignatureError("blinded message out of range")
    s = pow(m, numbers.d, pub.n)
    # Fault check from RFC 9474: re-verify before releasing the signature.
    if pow(s, pub.e, pub.n) != m:
        raise BlindSignatureError("signing failed")
    return _i2osp(s, k)


def finalize(
    public_key: rsa.RSAPublicKey,
    message: bytes,
    blind_signature: bytes,
    state: BlindingState,
) -> bytes:
    """Holder side: unblind and verify, producing a standard PSS signature."""
    n = public_key.public_numbers().n
    k = _modulus_len(public_key)
    if len(blind_signature) != k:
        raise BlindSignatureError("blind signature has wrong length")
    z = _os2ip(blind_signature)
    signature = _i2osp((z * state.inverse) % n, k)
    if not verify(public_key, message, signature):
        raise BlindSignatureError("unblinded signature does not verify")
    return signature


def verify(public_key: rsa.RSAPublicKey, message: bytes, signature: bytes) -> bool:
    """Standard RSASSA-PSS verification (SHA-384, MGF1-SHA-384, salt length 0)."""
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=_SALT_LEN),
            hashes.SHA384(),
        )
    except InvalidSignature:
        return False
    return True


def generate_key(bits: int = 3072) -> rsa.RSAPrivateKey:
    """Generate an issuer key. 3072 bits is the production default."""
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)
