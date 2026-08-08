# CLAUDE.md

Guidance for coding agents working in this repository.

## Project Status

`venice-e2ee` is a published TypeScript ESM package for Venice AI's E2EE inference protocol. It encrypts message content in the client, decrypts streaming model output, and exposes opt-in verification for Intel TDX/DCAP evidence, NVIDIA NRAS evidence, ACI trust anchors, attested sessions, and response receipts.

The surrounding HTTP request is not end-to-end encrypted. API credentials, model selection, roles, request shape, token settings, timing, sizes, billing information, and network metadata remain visible to Venice.

## Repository Layout

- `src/` — TypeScript source and Vitest tests
- `dist/` — committed ESM, declarations, source maps, and the browser bundle
- `README.md` — public API, usage, and security boundaries
- `CHANGELOG.md` — user-visible release history
- `SECURITY.md` — private vulnerability reporting policy
- `RELEASING.md` — release and npm publication checklist

The package is ESM-only, targets ES2022, and is tested on Node.js 24 in GitHub Actions. Browser code relies on Web Crypto, `fetch`, streams, and text encoders. The single-file browser bundle is built with esbuild.

## Public API Map

- `createVeniceE2EE()` — session creation, message encryption, stream decryption, raw attestation, and receipt fetching
- package root — low-level crypto, binding checks, receipts, ACI reports, attested sessions, and encrypted tool-calling helpers
- `venice-e2ee/dcap` — optional `@phala/dcap-qvl` adapter
- `venice-e2ee/nvidia` — NVIDIA NRAS evidence and token-signature verification

Read the implementation and exported types before changing the API. Keep `README.md` examples and the package exports synchronized with source changes.

## Security Invariants

- The default `binding` level parses and cross-checks fields in a supplied TDX quote; it does not authenticate the quote signature or certificate chain.
- Full Intel quote authentication is opt-in through a `DcapVerifier`; `requireDcap` makes it mandatory.
- Measurement reporting is not measurement approval. An allowlist is meaningful only after DCAP verification succeeds.
- NVIDIA verification is optional and does not prove GPU/TDX co-location. Token signature verification is a separate opt-in policy.
- Receipt verification fails closed without an independently established trust anchor and exact request/response bytes.
- A relayed upstream ACI report currently cannot bind its keyset to REPORTDATA because the gateway nonce is not published; no anchor may be returned.
- Unexpected plaintext model output fails closed unless `allowPlaintextResponses` is explicitly enabled.
- Do not weaken these boundaries or describe a structural binding check as proof of enclave authenticity.

## Development Workflow

```bash
npm ci
npm audit
npm test
npm run build
npm run build:browser
git diff --exit-code -- dist
```

Set `VENICE_API_KEY` in `.env` to enable the live integration tests. They are skipped when the key is absent.

Source changes that affect generated output must commit the corresponding `dist/` changes. Keep `@phala/dcap-qvl` optional and outside the default lockfile; CI installs version 0.6.1 separately for compatibility testing.

Follow `RELEASING.md` for versioning, changelog, tags, GitHub releases, npm publishing, and post-publish verification.
