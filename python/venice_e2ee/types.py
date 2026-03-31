"""Type definitions for venice-e2ee."""

from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable, Optional


@dataclass
class VeniceE2EEOptions:
    api_key: str
    base_url: str = "https://api.venice.ai"
    session_ttl: float = 1800.0  # 30 minutes in seconds
    verify_attestation: bool = True
    dcap_verifier: Optional[Callable[[bytes], Awaitable[dict[str, Any]]]] = None


@dataclass
class E2EESession:
    private_key: bytes  # 32-byte secp256k1 scalar
    public_key: bytes  # 65-byte uncompressed point (0x04 || x || y)
    pub_key_hex: str
    model_pub_key_hex: str
    aes_key: bytes  # 32-byte AES-256 key
    model_id: str
    created: float  # time.time() timestamp
    attestation: Optional["AttestationResult"] = None


@dataclass
class EncryptedPayload:
    encrypted_messages: list[dict[str, str]]
    headers: dict[str, str]
    venice_parameters: dict[str, bool]


@dataclass
class AttestationResult:
    nonce_verified: bool
    signing_key_bound: bool
    debug_mode: bool
    server_tdx_valid: Optional[bool]
    dcap: Optional[dict[str, Any]] = None
    errors: list[str] = field(default_factory=list)
