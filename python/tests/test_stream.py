"""Tests for SSE stream parsing and decryption — mirrors the TypeScript vitest suite."""

import json

import pytest

from venice_e2ee.crypto import derive_aes_key, encrypt_message, generate_keypair
from venice_e2ee.stream import decrypt_sse_stream


class FakeResponse:
    """Mock httpx.Response with aiter_text() from pre-built SSE text."""

    def __init__(self, chunks: list[str]) -> None:
        self._chunks = chunks

    async def aiter_text(self):
        for chunk in self._chunks:
            yield chunk


def _sse_events(events: list[str]) -> str:
    """Format events as SSE text (each line prefixed with 'data: ', double newline)."""
    return "".join(f"data: {e}\n\n" for e in events)


def _encrypt_for_stream(plaintext: str, client_pub_hex: str) -> str:
    """Encrypt plaintext using a fresh server ephemeral key."""
    eph_priv, eph_pub, _ = generate_keypair()
    aes_key = derive_aes_key(eph_priv, client_pub_hex)
    return encrypt_message(aes_key, eph_pub, plaintext)


def _event(content: str) -> str:
    return json.dumps({"choices": [{"delta": {"content": content}}]})


@pytest.mark.asyncio
class TestDecryptSSEStream:
    async def test_single_chunk(self):
        client_priv, _, client_hex = generate_keypair()
        cipher = _encrypt_for_stream("Hello!", client_hex)

        response = FakeResponse([_sse_events([_event(cipher), "[DONE]"])])
        chunks = [t async for t in decrypt_sse_stream(response, client_priv)]
        assert chunks == ["Hello!"]

    async def test_multiple_chunks_ephemeral_keys(self):
        client_priv, _, client_hex = generate_keypair()
        plaintexts = ["The ", "answer ", "is ", "42."]

        events = [_event(_encrypt_for_stream(pt, client_hex)) for pt in plaintexts]
        events.append("[DONE]")

        response = FakeResponse([_sse_events(events)])
        chunks = [t async for t in decrypt_sse_stream(response, client_priv)]
        assert chunks == plaintexts

    async def test_chunked_delivery(self):
        """SSE text split across multiple aiter_text() yields."""
        client_priv, _, client_hex = generate_keypair()
        cipher = _encrypt_for_stream("streamed", client_hex)

        full_text = _sse_events([_event(cipher), "[DONE]"])
        # Split into 20-byte chunks to simulate real streaming
        small_chunks = [full_text[i : i + 20] for i in range(0, len(full_text), 20)]

        response = FakeResponse(small_chunks)
        chunks = [t async for t in decrypt_sse_stream(response, client_priv)]
        assert chunks == ["streamed"]

    async def test_plaintext_passthrough(self):
        """Whitespace tokens pass through without decryption."""
        client_priv, _, _ = generate_keypair()

        events = [_event(" "), _event("\n"), "[DONE]"]
        response = FakeResponse([_sse_events(events)])
        chunks = [t async for t in decrypt_sse_stream(response, client_priv)]
        assert chunks == [" ", "\n"]

    async def test_skips_events_without_content(self):
        client_priv, _, client_hex = generate_keypair()
        cipher = _encrypt_for_stream("data", client_hex)

        events = [
            json.dumps({"choices": [{"delta": {}}]}),
            _event(cipher),
            json.dumps({"choices": []}),
            "[DONE]",
        ]
        response = FakeResponse([_sse_events(events)])
        chunks = [t async for t in decrypt_sse_stream(response, client_priv)]
        assert chunks == ["data"]

    async def test_empty_stream(self):
        client_priv, _, _ = generate_keypair()
        response = FakeResponse([_sse_events(["[DONE]"])])
        chunks = [t async for t in decrypt_sse_stream(response, client_priv)]
        assert chunks == []

    async def test_stale_session_raises(self):
        """AES-GCM auth failure (wrong key) raises RuntimeError about stale session."""
        client_priv, _, client_hex = generate_keypair()
        wrong_priv, _, _ = generate_keypair()

        cipher = _encrypt_for_stream("secret", client_hex)
        response = FakeResponse([_sse_events([_event(cipher), "[DONE]"])])

        with pytest.raises(RuntimeError, match="stale"):
            _ = [t async for t in decrypt_sse_stream(response, wrong_priv)]
