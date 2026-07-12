# venice-e2ee

Browser-side message encryption for [Venice AI](https://venice.ai)'s E2EE inference protocol.

The library encrypts message `content` before transmission and decrypts model-output chunks in the client. The default attestation policy verifies freshness, signing-key binding, and debug mode directly from the TDX quote. It does **not** perform full DCAP validation, validate NVIDIA evidence, enforce a code-measurement allowlist, or authenticate each response to the attested signing key unless the caller adds the relevant policy and protocol checks.

Do not treat the default `binding` result as proof of a fully verified production enclave. Venice still receives request metadata including the API credential, selected model, roles, request shape, token settings, timing, sizes, and network metadata.

See the [changelog](CHANGELOG.md) for a user-readable summary of each release and its security boundaries.

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

// Create session (fetches the quote and runs the configured verification policy)
const session = await e2ee.createSession('e2ee-qwen3-5-122b-a10b');

// Inspect attestation result
console.log(session.attestation);
// { verificationLevel: 'binding', nonceVerified: true,
//   signingKeyBound: true, dcapVerified: false,
//   measurementsVerified: null, errors: [] }

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
| `dcapVerifier` | `DcapVerifier` | — | Optional quote/certificate/TCB verifier (see below) |
| `requireDcap` | `boolean` | `false` | Fail unless the injected DCAP verifier succeeds |
| `expectedMeasurements` | `ExpectedTdxMeasurements` | — | Allowlist selected TDX measurements; requires successful DCAP verification |
| `allowPlaintextResponses` | `boolean` | `false` | Compatibility escape hatch for legacy plaintext response content |

Returns an object with:

- **`createSession(modelId)`** — Generates an ephemeral keypair, fetches TEE evidence, runs the configured checks, and derives the message-encryption key. Returns an `E2EESession` with structured verification evidence. Sessions are cached per model with a 30-minute TTL.
- **`encrypt(messages, session)`** — Encrypts an array of `{role, content}` messages. Returns `{ encryptedMessages, headers, veniceParameters }`.
- **`decryptChunk(hexChunk, session)`** — Decrypts one response chunk. Non-whitespace plaintext fails closed by default.
- **`decryptStream(body, session)`** — Parses an SSE stream and yields decrypted text chunks. A successful response containing plaintext model output fails closed by default.
- **`clearSession()`** — Zeroizes the private key and clears the cached session.

## Attestation verification

Every `createSession` call fetches a TDX quote from Venice. The default `binding` policy checks:

1. **Nonce binding** — confirms the client nonce appears in REPORTDATA (raw or SHA-256)
2. **Signing key binding** — confirms the signing key's Ethereum address matches REPORTDATA
3. **Debug mode rejection** — rejects TEEs running in debug mode
4. **Server cross-check** — flags negative or inconsistent Venice-reported results
5. **Model binding** — confirms the evidence names the requested model

These checks show that a fresh quote contains the supplied key and is not marked for debug. They do not validate the quote signature or certificate chain. If any configured check fails, `createSession` throws. The evidence and `verificationLevel` are available on `session.attestation`.

To disable verification (not recommended):

```js
const e2ee = createVeniceE2EE({ apiKey, verifyAttestation: false });
```

### Full DCAP verification

For full TDX DCAP verification (PCK cert chain, quote signatures, TCB evaluation), install the optional peer dependency and inject the verifier:

```bash
npm install @phala/dcap-qvl
```

> **Upstream dependency note:** Current `@phala/dcap-qvl` releases depend on `elliptic`, which has an open advisory affecting ECDSA signing. This adapter uses Phala only for signature verification and never gives it a signing private key, so that key-exposure mechanism is not exercised here. If your policy rejects every dependency with an open advisory regardless of reachability, leave the optional DCAP adapter disabled until Phala changes its dependency tree.

```js
import { createVeniceE2EE } from 'venice-e2ee';
import { createDcapVerifier } from 'venice-e2ee/dcap';

const e2ee = createVeniceE2EE({
  apiKey: 'your-venice-api-key',
  dcapVerifier: createDcapVerifier(),
  requireDcap: true,
});
```

The provided adapter uses Phala PCCS by default. It validates Intel DCAP quote signatures, certificate/TCB collateral, and revocation information. This is stronger than the default binding checks, but it still does not validate NVIDIA GPU evidence or establish that the measured software is approved.

### Measurement policy

Measurements are always reported in `session.attestation.measurements`. Reporting a measurement is not validating it. Callers with trusted expected values can enforce an allowlist:

```js
const e2ee = createVeniceE2EE({
  apiKey,
  dcapVerifier: createDcapVerifier(),
  requireDcap: true,
  expectedMeasurements: {
    mrTd: ['trusted-mrtd-hex'],
    rtMr0: ['trusted-rtmr0-hex'],
  },
});
```

Venice does not currently publish a stable measurement allowlist in its public E2EE guide, so consumers cannot safely invent these values.

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
  |  Parse TDX quote and measurements      |
  |  Check nonce and key binding           |
  |  Reject debug mode                     |
  |  Apply optional DCAP/measurement policy|
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

**Default client-side checks:**
- Signing-key address is present in TDX REPORTDATA
- Client nonce prevents replay attacks
- Debug-mode TEEs are rejected
- ECDH intermediates are zeroized after key derivation
- Private keys are zeroized on session clear/replacement

**Not verified client-side by default:**
- TDX quote signature chain (available via optional DCAP verifier)
- NVIDIA GPU attestation
- TEE code measurements
- Response signatures or a cryptographic binding between each response chunk's ephemeral key and the attested signing key

**Visible metadata:** The library encrypts message `content`, not the surrounding HTTP request. Venice can observe authentication, model selection, roles, token and streaming settings, request structure, timing, sizes, billing information, and network metadata.

**Response origin:** AES-GCM authenticates each chunk under a key derived from the client key and the chunk's server-supplied ephemeral key. The current streaming format does not itself prove that this ephemeral key belongs to the attested enclave. Venice documents a separate response-signature endpoint, but its signed payload format is not yet implemented here.

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
