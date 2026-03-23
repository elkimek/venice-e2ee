# venice-e2ee

End-to-end encryption for [Venice AI](https://venice.ai)'s TEE-backed inference. Prompts are encrypted in the client and only decrypted inside AMD SEV-SNP Trusted Execution Environments — Venice never sees plaintext.

**Protocol:** ECDH (secp256k1) key exchange → HKDF-SHA256 key derivation → AES-256-GCM encryption

## Install

```bash
npm install venice-e2ee
```

Or use the browser bundle directly:

```html
<script type="module">
  import { createVeniceE2EE } from './venice-e2ee.browser.js';
</script>
```

## Usage

```js
import { createVeniceE2EE } from 'venice-e2ee';

const e2ee = createVeniceE2EE({ apiKey: 'your-venice-api-key' });

// Create session (fetches TEE attestation, ECDH key exchange)
const session = await e2ee.createSession('e2ee-qwen3-5-122b-a10b');

// Encrypt messages
const { encryptedMessages, headers, veniceParameters } = await e2ee.encrypt(
  [{ role: 'user', content: 'Hello from the encrypted side' }],
  session
);

// Send to Venice API
const response = await fetch('https://api.venice.ai/api/v1/chat/completions', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}`, ...headers },
  body: JSON.stringify({
    model: 'e2ee-qwen3-5-122b-a10b',
    messages: encryptedMessages,
    stream: true,
    venice_parameters: veniceParameters,
  }),
});

// Decrypt streaming response
for await (const chunk of e2ee.decryptStream(response.body, session)) {
  process.stdout.write(chunk);
}
```

## API

### `createVeniceE2EE(options)`

Creates an E2EE instance with session caching.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `apiKey` | `string` | required | Venice API key |
| `baseUrl` | `string` | `https://api.venice.ai` | API base URL |
| `sessionTTL` | `number` | `1800000` (30 min) | Session cache TTL in ms |

Returns an object with:

- **`createSession(modelId)`** — Generates ephemeral keypair, fetches TEE attestation, derives AES key. Returns an `E2EESession`. Sessions are cached per model with a 30-minute TTL.
- **`encrypt(messages, session)`** — Encrypts an array of `{role, content}` messages. Returns `{ encryptedMessages, headers, veniceParameters }`.
- **`decryptChunk(hexChunk, session)`** — Decrypts a single response chunk (hex-encoded ciphertext with embedded server ephemeral key).
- **`decryptStream(body, session)`** — Async generator that parses an SSE stream and yields decrypted text chunks. Handles per-chunk ephemeral keys, plaintext passthrough, and `[DONE]` sentinel.
- **`clearSession()`** — Clears the cached session.

### `isE2EEModel(modelId)`

Returns `true` if the model ID starts with `e2ee-`.

### Low-level exports

For custom integrations, the individual crypto primitives are also exported:

```js
import {
  generateKeypair,    // secp256k1 ephemeral keypair
  deriveAESKey,       // ECDH shared secret → HKDF → AES-256-GCM key
  encryptMessage,     // AES-GCM encrypt → hex(pubkey + nonce + ciphertext)
  decryptChunk,       // per-chunk ECDH + AES-GCM decrypt
  decryptSSEStream,   // SSE parser + decryption async generator
  toHex,
  fromHex,
} from 'venice-e2ee';
```

## How it works

```
Client                              Venice TEE (AMD SEV-SNP)
  |                                        |
  |── GET /tee/attestation?model=...  ────>|
  |<── { signing_public_key: "04..." } ────|
  |                                        |
  |  generateKeypair()                     |
  |  deriveAESKey(clientPriv, teePub)       |
  |  encryptMessage(aesKey, msg)           |
  |                                        |
  |── POST /chat/completions  ────────────>|
  |   X-Venice-TEE-Client-Pub-Key: ...     |
  |   X-Venice-TEE-Model-Pub-Key: ...      |
  |   { messages: [encrypted] }            |
  |                                        |
  |<── SSE stream (per-chunk encryption) ──|
  |    each chunk: hex(ephemeralPub +       |
  |                     nonce + ciphertext) |
  |                                        |
  |  decryptChunk(clientPriv, chunk)        |
  |  → ECDH(clientPriv, chunkEphPub)       |
  |  → HKDF → AES-GCM decrypt             |
```

Each response chunk uses a fresh server ephemeral key, so every chunk requires its own ECDH key derivation.

## Development

```bash
npm install
npm test              # unit + integration tests
npm run build         # TypeScript → dist/
npm run build:browser # single-file ESM bundle
```

Set `VENICE_API_KEY` in `.env` to run integration tests against the live API.

## License

GPL-3.0 — see [LICENSE](LICENSE)
