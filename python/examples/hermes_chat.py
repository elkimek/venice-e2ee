"""Example: Venice E2EE chat with streaming — Hermes Agent integration pattern.

This demonstrates the E2EE flow that would be used inside Hermes Agent's
provider system (agent/auxiliary_client.py) as a Venice adapter.

Usage:
    VENICE_API_KEY=... python examples/hermes_chat.py
"""

import asyncio
import os

import httpx

from venice_e2ee import create_venice_e2ee


async def chat_e2ee(api_key: str, model: str, prompt: str) -> None:
    """Full E2EE chat: session -> encrypt -> send -> decrypt stream."""
    e2ee = create_venice_e2ee(api_key=api_key)

    # 1. Create encrypted session (fetches attestation, verifies TEE, derives keys)
    session = await e2ee.create_session(model)
    print(f"Session created (attestation: {'verified' if session.attestation else 'skipped'})")

    # 2. Encrypt messages
    messages = [{"role": "user", "content": prompt}]
    payload = await e2ee.encrypt(messages, session)

    # 3. Send to Venice (standard OpenAI-compatible endpoint + E2EE headers)
    async with httpx.AsyncClient() as client:
        async with client.stream(
            "POST",
            f"{e2ee._base_url}/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                **payload.headers,
            },
            json={
                "model": model,
                "messages": payload.encrypted_messages,
                "venice_parameters": payload.venice_parameters,
                "stream": True,
            },
            timeout=None,
        ) as response:
            response.raise_for_status()

            # 4. Decrypt streaming response
            async for text in e2ee.decrypt_stream(response, session):
                print(text, end="", flush=True)

    print()  # final newline
    e2ee.clear_session()


# ── Hermes Agent Integration Notes ──────────────────────────────────────
#
# To add Venice E2EE as a provider in Hermes Agent:
#
# 1. In agent/auxiliary_client.py, register "venice" as a provider alias
#    that creates a VeniceE2EE client instead of an OpenAI client.
#
# 2. The E2EE layer wraps around the standard OpenAI-compatible API:
#    - encrypt() produces messages + headers for the regular /chat/completions
#    - decrypt_stream() unwraps the SSE response per-chunk
#
# 3. In run_agent.py, for chat_completions mode with Venice:
#    - Before sending: call e2ee.encrypt(messages, session)
#    - Add payload.headers to the request
#    - Use httpx streaming instead of openai SDK (SDK can't handle E2EE)
#    - Decrypt each SSE chunk via e2ee.decrypt_stream()
#
# 4. Credential pool: add VENICE_API_KEY to credential_pool.py scanning


if __name__ == "__main__":
    api_key = os.environ.get("VENICE_API_KEY", "")
    if not api_key:
        print("Set VENICE_API_KEY environment variable")
        raise SystemExit(1)

    asyncio.run(chat_e2ee(
        api_key=api_key,
        model="e2ee-qwen3-5-122b-a10b",
        prompt="What is the meaning of life?",
    ))
