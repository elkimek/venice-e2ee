"""Live integration test against Venice API.

Requires VENICE_API_KEY environment variable.
Run with: pytest tests/test_live.py -v -s
"""

import os

import httpx
import pytest

from venice_e2ee import create_venice_e2ee, is_e2ee_model

API_KEY = os.environ.get("VENICE_API_KEY", "")
MODEL = os.environ.get("VENICE_E2EE_MODEL", "e2ee-qwen3-5-122b-a10b")

pytestmark = pytest.mark.skipif(not API_KEY, reason="VENICE_API_KEY not set")


@pytest.mark.asyncio
async def test_session_creation():
    """Fetch attestation and verify TDX quote against live API."""
    e2ee = create_venice_e2ee(api_key=API_KEY)
    session = await e2ee.create_session(MODEL)

    assert session.model_id == MODEL
    assert len(session.private_key) == 32
    assert len(session.public_key) == 65
    assert len(session.aes_key) == 32
    assert session.attestation is not None
    assert session.attestation.nonce_verified is True
    assert session.attestation.signing_key_bound is True
    assert session.attestation.debug_mode is False
    assert session.attestation.errors == []

    print(f"\nAttestation verified: nonce={session.attestation.nonce_verified}, "
          f"bound={session.attestation.signing_key_bound}, "
          f"server_tdx={session.attestation.server_tdx_valid}")

    e2ee.clear_session()


@pytest.mark.asyncio
async def test_e2ee_chat_roundtrip():
    """Full E2EE roundtrip: session -> encrypt -> send -> decrypt stream."""
    e2ee = create_venice_e2ee(api_key=API_KEY)
    session = await e2ee.create_session(MODEL)

    messages = [{"role": "user", "content": "Say exactly: Hello E2EE"}]
    payload = await e2ee.encrypt(messages, session)

    assert "X-Venice-TEE-Client-Pub-Key" in payload.headers
    assert payload.venice_parameters["enable_e2ee"] is True

    collected = []
    async with httpx.AsyncClient() as client:
        async with client.stream(
            "POST",
            f"https://api.venice.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Content-Type": "application/json",
                **payload.headers,
            },
            json={
                "model": MODEL,
                "messages": payload.encrypted_messages,
                "venice_parameters": payload.venice_parameters,
                "stream": True,
                "max_tokens": 50,
            },
            timeout=60.0,
        ) as response:
            response.raise_for_status()
            async for text in e2ee.decrypt_stream(response, session):
                collected.append(text)
                print(text, end="", flush=True)

    full_response = "".join(collected)
    print(f"\n\nFull response ({len(collected)} chunks): {full_response[:200]}")
    assert len(full_response) > 0, "Got empty response"

    e2ee.clear_session()
