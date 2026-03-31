# venice-e2ee (Python)

Python port of [venice-e2ee](../) — end-to-end encryption for [Venice AI](https://venice.ai)'s TEE-backed inference. Wire-format compatible with the TypeScript implementation.

**Protocol:** ECDH (secp256k1) key exchange → HKDF-SHA256 key derivation → AES-256-GCM encryption

## Install

```bash
pip install venice-e2ee
```

For attestation verification (Ethereum address derivation via keccak-256):

```bash
pip install "venice-e2ee[attestation]"
```

## Usage

```python
import asyncio
import httpx
from venice_e2ee import create_venice_e2ee

async def main():
    e2ee = create_venice_e2ee(api_key="your-venice-api-key")

    # Create session (fetches TEE attestation, verifies quote, ECDH key exchange)
    session = await e2ee.create_session("e2ee-qwen3-5-122b-a10b")

    # Encrypt messages
    messages = [{"role": "user", "content": "Hello from the encrypted side"}]
    payload = await e2ee.encrypt(messages, session)

    # Send to Venice API
    async with httpx.AsyncClient() as client:
        async with client.stream(
            "POST",
            "https://api.venice.ai/api/v1/chat/completions",
            headers={
                "Authorization": "Bearer your-venice-api-key",
                "Content-Type": "application/json",
                **payload.headers,
            },
            json={
                "model": "e2ee-qwen3-5-122b-a10b",
                "messages": payload.encrypted_messages,
                "venice_parameters": payload.venice_parameters,
                "stream": True,
            },
            timeout=None,
        ) as response:
            async for text in e2ee.decrypt_stream(response, session):
                print(text, end="", flush=True)

asyncio.run(main())
```

## API

### `create_venice_e2ee(api_key, **kwargs)`

Creates an E2EE client with session caching and attestation verification.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `api_key` | `str` | required | Venice API key |
| `base_url` | `str` | `https://api.venice.ai` | API base URL |
| `session_ttl` | `float` | `1800.0` (30 min) | Session cache TTL in seconds |
| `verify_attestation` | `bool` | `True` | Verify TEE attestation on session creation |
| `dcap_verifier` | `Callable` | `None` | Optional full DCAP verifier function |

Returns a `VeniceE2EE` instance with:

- **`await create_session(model_id)`** — Generates ephemeral keypair, fetches TEE attestation, verifies the TDX quote, derives AES key. Returns an `E2EESession`. Throws if verification fails.
- **`await encrypt(messages, session)`** — Encrypts a list of `{"role": ..., "content": ...}` dicts. Returns `EncryptedPayload` with `.encrypted_messages`, `.headers`, `.venice_parameters`.
- **`decrypt_chunk(hex_chunk, session)`** — Decrypts a single response chunk (synchronous).
- **`async for text in decrypt_stream(response, session)`** — Async generator that parses an SSE stream and yields decrypted text chunks.
- **`clear_session()`** — Clears the cached session.

### `is_e2ee_model(model_id)`

Returns `True` if the model ID starts with `e2ee-`.

### Low-level exports

```python
from venice_e2ee import (
    generate_keypair,      # secp256k1 ephemeral keypair
    derive_aes_key,        # ECDH shared secret -> HKDF -> AES-256 key
    encrypt_message,       # AES-GCM encrypt -> hex(pubkey + nonce + ciphertext)
    decrypt_chunk,         # per-chunk ECDH + AES-GCM decrypt
    decrypt_sse_stream,    # SSE parser + decryption async generator
    verify_attestation,    # run attestation checks on a raw response
    derive_eth_address,    # secp256k1 pubkey -> Ethereum address
    to_hex, from_hex,
)
```

## Hermes Agent Integration

See [`examples/hermes_chat.py`](examples/hermes_chat.py) for a complete example showing how to integrate with [Hermes Agent](https://github.com/NousResearch/hermes-agent)'s OpenAI-compatible provider system.

The E2EE layer wraps around Venice's standard `/chat/completions` endpoint:
1. `encrypt()` produces encrypted messages + `X-Venice-TEE-*` headers
2. Send via httpx (the openai SDK can't handle encrypted content)
3. `decrypt_stream()` unwraps the SSE response per-chunk

## Dependencies

- **`cryptography`** — secp256k1 ECDH, HKDF-SHA256, AES-256-GCM
- **`httpx`** — async HTTP with SSE streaming
- **`pycryptodome`** (optional) — keccak-256 for attestation Ethereum address verification

## Development

```bash
cd python
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -v
```

## License

GPL-3.0 — see [LICENSE](../LICENSE)
