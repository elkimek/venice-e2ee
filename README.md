# venice-e2ee

End-to-end encryption for [Venice AI](https://venice.ai)'s TEE-backed inference. Prompts are encrypted client-side and only decrypted inside Intel TDX Trusted Execution Environments — Venice never sees plaintext.

> **Note:** This library uses standard cryptographic primitives (ECDH, HKDF, AES-256-GCM) via audited implementations (`@noble/secp256k1`, Web Crypto API). No custom cryptography — just Venice's E2EE protocol extracted into a reusable package. Vibecoded.

**Protocol:** ECDH (secp256k1) key exchange → HKDF-SHA256 key derivation → AES-256-GCM encryption

## Install

```bash
npm install venice-e2ee
```

> **Python:** See [venice-e2ee-python](https://github.com/elkimek/venice-e2ee-python) for the Python port.

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

// Create session (fetches TEE attestation, verifies quote, ECDH key exchange)
const session = await e2ee.createSession('e2ee-qwen3-5-122b-a10b');

// Inspect attestation result
console.log(session.attestation);
// { nonceVerified: true, signingKeyBound: true, debugMode: false, serverTdxValid: true, errors: [] }

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

Creates an E2EE instance with session caching and attestation verification.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `apiKey` | `string` | required | Venice API key |
| `baseUrl` | `string` | `https://api.venice.ai` | API base URL |
| `sessionTTL` | `number` | `1800000` (30 min) | Session cache TTL in ms |
| `verifyAttestation` | `boolean` | `true` | Verify TEE attestation on session creation |
| `dcapVerifier` | `DcapVerifier` | — | Optional full DCAP verifier (see below) |

Returns an object with:

- **`createSession(modelId)`** — Generates ephemeral keypair, fetches TEE attestation, verifies the TDX quote, derives AES key. Returns an `E2EESession` with attestation results. Throws if verification fails. Sessions are cached per model with a 30-minute TTL.
- **`encrypt(messages, session)`** — Encrypts an array of `{role, content}` messages. Returns `{ encryptedMessages, headers, veniceParameters }`.
- **`decryptChunk(hexChunk, session)`** — Decrypts a single response chunk (hex-encoded ciphertext with embedded server ephemeral key).
- **`decryptStream(body, session)`** — Async generator that parses an SSE stream and yields decrypted text chunks. Handles per-chunk ephemeral keys, plaintext passthrough, and `[DONE]` sentinel.
- **`clearSession()`** — Zeroizes the private key and clears the cached session.

## Attestation verification

Every `createSession` call fetches a TDX attestation quote from Venice and verifies it client-side:

1. **Nonce binding** — confirms the client nonce appears in REPORTDATA (raw or SHA-256)
2. **Signing key binding** — confirms the signing key's Ethereum address matches REPORTDATA
3. **Debug mode rejection** — rejects TEEs running in debug mode
4. **Server cross-check** — flags inconsistencies with Venice's own verification results

If any check fails, `createSession` throws with a descriptive error. The attestation result is available on `session.attestation`.

To disable verification (not recommended):

```js
const e2ee = createVeniceE2EE({ apiKey, verifyAttestation: false });
```

### Full DCAP verification (optional)

For full TDX DCAP verification (PCK cert chain, quote signatures, TCB evaluation), install the optional peer dependency and inject the verifier:

```bash
npm install @phala/dcap-qvl
```

```js
import { createVeniceE2EE } from 'venice-e2ee';
import { createDcapVerifier } from 'venice-e2ee/dcap';

const e2ee = createVeniceE2EE({
  apiKey: 'your-venice-api-key',
  dcapVerifier: createDcapVerifier(), // uses Phala PCCS by default
});
```

This adds ~500KB to browser bundles. For most use cases, the default binding checks + server cross-check are sufficient.

### `isE2EEModel(modelId)`

Returns `true` if the model ID starts with `e2ee-`.

### Low-level exports

For custom integrations, the individual crypto and attestation primitives are also exported:

```js
import {
  generateKeypair,      // secp256k1 ephemeral keypair
  deriveAESKey,         // ECDH shared secret → HKDF → AES-256-GCM key
  encryptMessage,       // AES-GCM encrypt → hex(pubkey + nonce + ciphertext)
  decryptChunk,         // per-chunk ECDH + AES-GCM decrypt
  decryptSSEStream,     // SSE parser + decryption async generator
  verifyAttestation,    // run attestation checks on a raw response
  deriveEthAddress,     // secp256k1 pubkey → Ethereum address
  toHex,
  fromHex,
} from 'venice-e2ee';
```

## How it works

```
Client                              Venice TEE (Intel TDX)
  |                                        |
  |── GET /tee/attestation?model=&nonce= ─>|
  |<── { signing_key, intel_quote, ... } ──|
  |                                        |
  |  Parse TDX quote                       |
  |  Verify nonce in REPORTDATA            |
  |  Verify signing key address binding    |
  |  Reject debug mode                     |
  |                                        |
  |  generateKeypair()                     |
  |  deriveAESKey(clientPriv, teePub)      |
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

## Security

**What's verified:**
- Signing key is cryptographically bound to the TEE via TDX REPORTDATA
- Client nonce prevents replay attacks
- Debug-mode TEEs are rejected
- ECDH intermediates are zeroized after key derivation
- Private keys are zeroized on session clear/replacement

**What's not verified client-side (by default):**
- TDX quote signature chain (available via optional DCAP verifier)
- NVIDIA GPU attestation
- TEE code measurements (Venice doesn't publish expected values yet)

## Development

```bash
npm install
npm test              # unit + integration tests
npm run build         # TypeScript → dist/
npm run build:browser # single-file ESM bundle
```

Set `VENICE_API_KEY` in `.env` to run integration tests against the live API.

## Acknowledgments

- [Phala Network](https://phala.network/) — TDX DCAP quote verification is powered by [`@phala/dcap-qvl`](https://github.com/Phala-Network/dcap-qvl) (Apache-2.0), a pure JavaScript implementation of the Intel DCAP Quote Verification Library.
- [Paul Miller](https://paulmillr.com/) — ECDH key exchange uses [`@noble/secp256k1`](https://github.com/paulmillr/noble-secp256k1) and key derivation uses [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) (MIT), audited noble cryptography libraries.

## License

GPL-3.0 — see [LICENSE](LICENSE)
