"""SSE stream parsing and per-chunk decryption.

Parses Server-Sent Events from Venice's chat completions endpoint,
extracting and decrypting `choices[0].delta.content` from each event.
"""

import json
from typing import AsyncIterator

import httpx
from cryptography.exceptions import InvalidTag

from .crypto import decrypt_chunk


async def decrypt_sse_stream(
    response: httpx.Response,
    private_key: bytes,
) -> AsyncIterator[str]:
    """Parse an SSE stream and yield decrypted text chunks.

    Usage::

        async with httpx.AsyncClient() as client:
            resp = await client.post(url, ..., headers={"Accept": "text/event-stream"})
            async for text in decrypt_sse_stream(resp, session.private_key):
                print(text, end="", flush=True)

    Args:
        response: httpx streaming response (must be opened with stream=True)
        private_key: 32-byte client private key for per-chunk ECDH
    """
    buffer = ""

    async for raw_chunk in response.aiter_text():
        buffer += raw_chunk
        lines = buffer.split("\n")
        buffer = lines.pop()  # keep incomplete trailing line

        for line in lines:
            text = _process_sse_line(line, private_key)
            if text is _DONE:
                return
            if text is not None:
                yield text

    # Process remaining buffer
    if buffer.strip():
        text = _process_sse_line(buffer, private_key)
        if text is not None and text is not _DONE:
            yield text


_DONE = object()  # sentinel


def _process_sse_line(line: str, private_key: bytes) -> str | object | None:
    """Process a single SSE line. Returns decrypted text, _DONE, or None."""
    line = line.strip()
    if not line or not line.startswith("data: "):
        return None

    data = line[6:].strip()
    if data == "[DONE]":
        return _DONE

    try:
        event = json.loads(data)
    except json.JSONDecodeError:
        return None

    choices = event.get("choices")
    if not choices:
        return None

    content = choices[0].get("delta", {}).get("content")
    if content is None:
        return None

    try:
        return decrypt_chunk(private_key, content)
    except InvalidTag:
        raise RuntimeError(
            "E2EE decryption failed — session may be stale. Clear the session and retry."
        ) from None
