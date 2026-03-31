"""Core cryptographic operations: ECDH (secp256k1), HKDF-SHA256, AES-256-GCM.

Uses the `cryptography` library for all operations. Wire-format compatible
with the TypeScript implementation using @noble/secp256k1 + Web Crypto.
"""

import os
import re

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_HKDF_INFO = b"ecdsa_encryption"
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def to_hex(data: bytes) -> str:
    """Encode bytes as lowercase hex string."""
    return data.hex()


def from_hex(hex_str: str) -> bytes:
    """Decode hex string to bytes. Accepts optional 0x prefix."""
    if hex_str.startswith(("0x", "0X")):
        hex_str = hex_str[2:]
    return bytes.fromhex(hex_str)


def generate_keypair() -> tuple[bytes, bytes, str]:
    """Generate an ephemeral secp256k1 keypair.

    Returns:
        (private_key, public_key, pub_key_hex)
        - private_key: 32 bytes
        - public_key: 65 bytes uncompressed (0x04 || x || y)
        - pub_key_hex: hex-encoded public_key
    """
    priv = ec.generate_private_key(ec.SECP256K1())

    priv_bytes = priv.private_numbers().private_value.to_bytes(32, "big")
    pub_bytes = priv.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )

    return priv_bytes, pub_bytes, to_hex(pub_bytes)


def _load_private_key(raw: bytes) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(raw, "big"), ec.SECP256K1())


def _load_public_key(raw: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), raw)


def derive_aes_key(my_private_key: bytes, their_public_key_hex: str) -> bytes:
    """ECDH shared secret -> HKDF-SHA256 -> 32-byte AES-256 key.

    Matches the TypeScript implementation:
      getSharedSecret(priv, pub).slice(1,33)  // x-coordinate
      -> HKDF(SHA-256, salt=empty, info="ecdsa_encryption") -> AES-256 key

    Args:
        my_private_key: 32-byte private key
        their_public_key_hex: hex-encoded uncompressed public key

    Returns:
        32-byte AES-256 key
    """
    priv = _load_private_key(my_private_key)
    pub = _load_public_key(from_hex(their_public_key_hex))

    # ECDH: returns raw x-coordinate of shared point (32 bytes)
    shared_x = priv.exchange(ec.ECDH(), pub)

    # HKDF-SHA256 with empty salt (defaults to HashLen zeros per RFC 5869)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_HKDF_INFO,
    )
    return hkdf.derive(shared_x)


def encrypt_message(aes_key: bytes, client_pub_key: bytes, plaintext: str) -> str:
    """Encrypt a message for Venice TEE.

    Output format: hex(clientPubKey[65] || nonce[12] || ciphertext)
    AES-256-GCM with random 12-byte IV, no additional authenticated data.
    """
    iv = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ct = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)

    return to_hex(client_pub_key + iv + ct)


def decrypt_chunk(client_private_key: bytes, hex_string: str) -> str:
    """Decrypt a streaming response chunk with per-chunk ephemeral keys.

    Input format: hex(serverEphemeralPub[65] || nonce[12] || ciphertext)
    Non-encrypted content (whitespace tokens, short strings) passes through.
    """
    # Passthrough: empty, too short, or non-hex
    if not hex_string or len(hex_string) < 154 or not _HEX_RE.match(hex_string):
        return hex_string

    raw = from_hex(hex_string)

    # Must start with 0x04 (uncompressed EC point)
    if raw[0] != 0x04:
        return hex_string

    server_pub = raw[:65]
    iv = raw[65:77]
    ciphertext = raw[77:]

    aes_key = derive_aes_key(client_private_key, to_hex(server_pub))
    aesgcm = AESGCM(aes_key)
    pt = aesgcm.decrypt(iv, ciphertext, None)

    return pt.decode("utf-8")
