"""Venice AI End-to-End Encryption Library (Python port).

ECDH (secp256k1) key exchange, HKDF-SHA256 derivation, AES-256-GCM encryption
for Venice AI's TEE-backed LLM inference. Wire-format compatible with the
TypeScript implementation.

Usage::

    from venice_e2ee import create_venice_e2ee

    e2ee = create_venice_e2ee(api_key="...")
    session = await e2ee.create_session("e2ee-deepseek-r1-671b")
    payload = await e2ee.encrypt(messages, session)
    # Send payload to Venice API, then decrypt the streaming response:
    async for text in e2ee.decrypt_stream(response, session):
        print(text, end="")
"""

import os
import time
from typing import Any, AsyncIterator, Awaitable, Callable, Optional

import httpx

from .crypto import (
    decrypt_chunk,
    derive_aes_key,
    encrypt_message,
    from_hex,
    generate_keypair,
    to_hex,
)
from .attestation import derive_eth_address, verify_attestation
from .stream import decrypt_sse_stream
from .types import (
    AttestationResult,
    E2EESession,
    EncryptedPayload,
    VeniceE2EEOptions,
)


class VeniceE2EE:
    """Venice AI E2EE client with session caching."""

    def __init__(self, options: VeniceE2EEOptions) -> None:
        self._api_key = options.api_key
        self._base_url = options.base_url
        self._session_ttl = options.session_ttl
        self._verify_attestation = options.verify_attestation
        self._dcap_verifier = options.dcap_verifier
        self._session: Optional[E2EESession] = None

    async def create_session(self, model_id: str) -> E2EESession:
        """Create or reuse an E2EE session for a model.

        Fetches TEE attestation, verifies the quote (if enabled),
        and derives an AES-256-GCM key via ECDH + HKDF.
        """
        if (
            self._session
            and self._session.model_id == model_id
            and time.time() - self._session.created < self._session_ttl
        ):
            return self._session

        private_key, public_key, pub_key_hex = generate_keypair()
        nonce = os.urandom(32)

        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self._base_url}/api/v1/tee/attestation",
                params={"model": model_id, "nonce": nonce.hex()},
                headers={"Authorization": f"Bearer {self._api_key}"},
                timeout=30.0,
            )
            resp.raise_for_status()
            attestation_resp = resp.json()

        model_pub_key_hex = (
            attestation_resp.get("signing_key")
            or attestation_resp.get("signing_public_key")
        )
        if not model_pub_key_hex:
            raise ValueError("No signing key in attestation response")

        attestation_result = None
        if self._verify_attestation:
            attestation_result = await verify_attestation(
                attestation_resp, nonce, self._dcap_verifier
            )
            if attestation_result.errors:
                raise ValueError(
                    "TEE attestation verification failed:\n  - "
                    + "\n  - ".join(attestation_result.errors)
                )

        aes_key = derive_aes_key(private_key, model_pub_key_hex)

        session = E2EESession(
            private_key=private_key,
            public_key=public_key,
            pub_key_hex=pub_key_hex,
            model_pub_key_hex=model_pub_key_hex,
            aes_key=aes_key,
            model_id=model_id,
            created=time.time(),
            attestation=attestation_result,
        )
        self._session = session
        return session

    async def encrypt(
        self,
        messages: list[dict[str, str]],
        session: E2EESession,
    ) -> EncryptedPayload:
        """Encrypt messages for Venice API."""
        encrypted = [
            {
                "role": msg["role"],
                "content": encrypt_message(
                    session.aes_key, session.public_key, msg["content"]
                ),
            }
            for msg in messages
        ]

        return EncryptedPayload(
            encrypted_messages=encrypted,
            headers={
                "X-Venice-TEE-Client-Pub-Key": session.pub_key_hex,
                "X-Venice-TEE-Model-Pub-Key": session.model_pub_key_hex,
                "X-Venice-TEE-Signing-Algo": "ecdsa",
            },
            venice_parameters={"enable_e2ee": True},
        )

    def decrypt_chunk(self, hex_chunk: str, session: E2EESession) -> str:
        """Decrypt a single response chunk."""
        return decrypt_chunk(session.private_key, hex_chunk)

    async def decrypt_stream(
        self,
        response: httpx.Response,
        session: E2EESession,
    ) -> AsyncIterator[str]:
        """Decrypt SSE streaming response."""
        async for text in decrypt_sse_stream(response, session.private_key):
            yield text

    def clear_session(self) -> None:
        """Clear cached session."""
        self._session = None


def create_venice_e2ee(
    api_key: str,
    base_url: str = "https://api.venice.ai",
    session_ttl: float = 1800.0,
    verify_attestation: bool = True,
    dcap_verifier: Optional[Callable[[bytes], Awaitable[dict[str, Any]]]] = None,
) -> VeniceE2EE:
    """Create a Venice E2EE client instance.

    Args:
        api_key: Venice API key
        base_url: Venice API base URL
        session_ttl: Session TTL in seconds (default 30 minutes)
        verify_attestation: Whether to verify TEE attestation (default True)
        dcap_verifier: Optional async function for full TDX DCAP quote verification
    """
    return VeniceE2EE(
        VeniceE2EEOptions(
            api_key=api_key,
            base_url=base_url,
            session_ttl=session_ttl,
            verify_attestation=verify_attestation,
            dcap_verifier=dcap_verifier,
        )
    )


def is_e2ee_model(model_id: str) -> bool:
    """Check if a model ID is an E2EE model (prefixed with 'e2ee-')."""
    return model_id.startswith("e2ee-")


__all__ = [
    # High-level API
    "VeniceE2EE",
    "create_venice_e2ee",
    "is_e2ee_model",
    # Low-level crypto
    "generate_keypair",
    "derive_aes_key",
    "encrypt_message",
    "decrypt_chunk",
    "to_hex",
    "from_hex",
    # Streaming
    "decrypt_sse_stream",
    # Attestation
    "verify_attestation",
    "derive_eth_address",
    # Types
    "VeniceE2EEOptions",
    "E2EESession",
    "EncryptedPayload",
    "AttestationResult",
]
