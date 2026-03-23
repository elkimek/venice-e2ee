# CLAUDE.md

## Project Goal

Extract Venice AI's end-to-end encryption into a standalone, reusable library. Currently implemented inside getbased (`/home/elkim/Documents/Claude Code/Lab Charts/js/venice-e2ee.js`) — needs to be extracted, improved, and packaged as an npm library.

## What Venice E2EE Does

Venice AI runs LLM inference inside AMD SEV-SNP TEEs (Trusted Execution Environments). The E2EE protocol ensures prompts are encrypted client-side and only decrypted inside the TEE — Venice never sees plaintext.

Protocol: ECDH (secp256k1) key exchange → HKDF-SHA256 key derivation → AES-256-GCM encryption. Streaming responses use per-chunk ephemeral keys (each chunk has its own server ephemeral pubkey + nonce + ciphertext).

## Current Implementation (in getbased)

Reference: `/home/elkim/Documents/Claude Code/Lab Charts/js/venice-e2ee.js` (93 lines)

What it does:
- `generateE2EESession()` — ephemeral secp256k1 keypair via `@noble/secp256k1`
- `fetchModelPublicKey(modelId, apiKey)` — fetches TEE attestation, extracts signing public key
- `deriveAESKey(privateKey, pubKeyHex)` — ECDH shared secret → HKDF-SHA256 → AES-256-GCM CryptoKey
- `encryptMessage(aesKey, pubKeyBytes, plaintext)` — encrypt to hex(pubKey65 + nonce12 + ciphertext)
- `decryptChunk(privateKey, hexString)` — per-chunk ECDH derivation + AES-GCM decrypt
- `getOrCreateE2EESession(modelId, apiKey)` — session cache with 30-min TTL

What it does NOT do (v2 scope):
- **Attestation verification** — currently trusts the public key Venice returns without verifying the AMD SEV-SNP attestation report
- **Measurement validation** — doesn't check that the TEE code measurement matches Venice's published values
- **Nonce verification** — sends a nonce but doesn't verify it appears in the attestation response

## Library Design

### API Surface

```js
import { createVeniceE2EE } from 'venice-e2ee';

const e2ee = createVeniceE2EE({ apiKey: '...' });

// Create session (fetches attestation, verifies TEE, derives keys)
const session = await e2ee.createSession(modelId);

// Encrypt messages for Venice API
const { encryptedMessages, headers } = await e2ee.encrypt(messages, session);

// Decrypt streaming response chunks
const plaintext = await e2ee.decryptChunk(hexChunk, session);

// Session management
e2ee.clearSession();
```

### Dependencies

- `@noble/secp256k1` (or `@noble/curves`) — ECDH key exchange
- Web Crypto API — HKDF, AES-256-GCM (browser-native, zero deps)
- No Node.js-specific APIs — must work in browsers

### Attestation Verification (v2)

The attestation endpoint returns an AMD SEV-SNP report. Full verification means:
1. Validate the attestation report signature against AMD's root of trust
2. Check the TEE measurement (code hash) against Venice's published values
3. Verify the nonce matches what the client sent
4. Confirm the signing public key is bound to the attestation

Venice docs: https://docs.venice.ai/api-reference/e2ee (check for attestation format details)

## Build

TypeScript, ESM output, no bundler. Should work as:
- npm package (`import { createVeniceE2EE } from 'venice-e2ee'`)
- Browser ESM (`<script type="module">`)

## Testing

- Unit tests for crypto operations (encrypt/decrypt roundtrip)
- Integration test against Venice's attestation endpoint (needs API key)
- Test vectors if Venice publishes any

## After the Library

Once published, update getbased to use it:
1. `npm install venice-e2ee` or vendor the built file
2. Replace `js/venice-e2ee.js` with imports from the library
3. Remove vendored `noble-secp256k1.js` (library handles its own deps)
