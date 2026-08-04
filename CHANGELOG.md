# Changelog

This changelog summarizes user-visible changes to `venice-e2ee`. It also calls out the privacy and verification limits that matter when deciding whether to use a release.

## Unreleased

### GPU attestation policy

- Added `createNvidiaVerifier()` (exported from `venice-e2ee/nvidia`) and the `gpuVerifier` / `requireGpu` options. When the attestation response carries an `nvidia_payload`, the evidence is submitted verbatim to NVIDIA's Remote Attestation Service and checked against NVIDIA's root of trust instead of the provider's own claim about it.
- The policy requires NVIDIA's `eat_nonce` to equal the nonce the session sent, so a passing verdict describes this request rather than a replayed report. It also requires `secboot`, `dbgstat: "disabled"` and `measres: "success"` on every GPU named, and `requireGpu` fails closed when no evidence is served at all.
- Results are reported in `session.attestation.gpu` / `.gpuVerified`, with the signed tokens carried through as `gpu.rawTokens`.
- Limits, stated in the README rather than implied: the verdict is NVIDIA's, and nothing binds the GPU evidence to the TDX quote beyond the shared nonce — for Venice's E2EE models the attested CVM reports `num_gpus: 0`, so the two are not the same machine.

### NVIDIA token signature verification

- Added `createNrasTokenVerifier()` (exported from `venice-e2ee/nvidia`) and the `tokenVerifier` option on `createNvidiaVerifier()`. Tokens are checked with ES384 against NVIDIA's published key set instead of resting on TLS to NRAS, so a token stays checkable when relayed, cached, or logged.
- The algorithm is pinned to ES384 rather than read from the token, closing the algorithm-confusion family including `alg: none`. `iss`, `exp` and `nbf` are checked, and every token is verified — overall and per-GPU — with any failure rejecting the whole result.
- The signing certificate's validity window is enforced per token. This is what bounds a withdrawn key — NVIDIA issues these leaves for about 48 hours — so the key set is cached for 12 hours rather than polled, and refetched on an unknown `kid`, rate-limited so malformed tokens or a failing NVIDIA cannot become a request flood.
- `pinnedCertSha256` requires named certificates to appear in the token's `x5c` chain for operators who obtained NVIDIA's intermediate or root out of band; `chainSha256` reports the digests. This is not RFC 5280 path validation, and the README says so — the leaf is required to carry the JWK's public key rather than a hand-rolled X.509 validator being introduced.
- `GpuVerifyResult.tokensVerified` reports whether signatures were checked.

## 0.3.0 — 2026-08-03

### Function calling over E2EE

- Added helpers that carry tool schemas, tool calls, and tool results inside encrypted message content instead of leaking OpenAI `tools` metadata outside the encrypted channel.
- Added incremental and one-shot tool-call parsers with support for tagged JSON, OpenAI-shaped calls, schema-guided bare arguments, parallel calls, and the lossy native formats emitted by GLM models.
- Expanded message encryption to flatten multipart text content, encrypt assistant and tool messages, and preserve the `tool_call_id` correlation value required for tool results.

### Response receipt verification

- Added `attest()` and `fetchResponseSignature()` client methods plus `verifyReceipt()` and the ACI digest, body-hash, and receipt-signing helpers needed by custom integrations.
- Receipt verification now fails closed unless the caller supplies an independently established workload ID and workload-keyset digest, the expected completion ID, and the exact request and response bytes. Callers must explicitly select whether the response bytes represent `wire_hash` or `cleartext_hash`.
- Added adversarial coverage for attacker-selected keysets, receipt substitution, changed request or response bodies, malformed keysets and signatures, duplicate or missing events, and unsupported protocol versions.

### Receipt trust boundary

Venice's legacy compatibility attestation quote binds the E2EE key and nonce, not the ACI workload-keyset digest. Values copied from that response therefore do not establish a receipt trust anchor. Applications must use a separately verified canonical ACI attestation or an independently pinned workload identity and keyset digest; when neither is available, receipt verification intentionally remains unavailable.

## 0.2.1 — 2026-07-12

### Security maintenance

- Upgraded Vitest, Vite, esbuild, and PostCSS to patched versions, clearing the repository's development-tool vulnerability alerts.
- Removed the optional Phala DCAP verifier and its transitive dependencies from the default development lockfile. `@phala/dcap-qvl` remains an opt-in peer dependency and is not installed or shipped by default.
- Added pull-request CI that runs the test suite, both builds, a clean-build diff check, and `npm audit`.
- Enabled GitHub's automated Dependabot security-update pull requests for future patched advisories.

### Optional DCAP dependency note

The current `@phala/dcap-qvl` releases depend on `elliptic`, which has an open advisory affecting ECDSA signing. The Venice adapter uses Phala only to verify Intel DCAP signatures and does not provide signing private keys to that dependency, so the advisory's key-exposure mechanism is not exercised by this integration. Consumers whose policy forbids any dependency with an open advisory should not enable the optional Phala verifier until its upstream dependency tree changes.

## 0.2.0 — 2026-07-12

### Overview

Version 0.2.0 makes the library's security result explicit instead of presenting every encrypted session as equally verified. It also rejects unexpected plaintext model output by default, so a server cannot silently downgrade an encrypted response.

### What changed

- **Encrypted responses fail closed.** Non-empty plaintext model output is rejected unless the caller deliberately enables the legacy `allowPlaintext` compatibility option.
- **Attestation results describe what was actually checked.** Sessions report `binding`, `dcap`, or `measured` verification levels alongside structured evidence and errors.
- **Stronger verification is available as an option.** Callers can add Intel TDX DCAP certificate, signature, revocation, and TCB checks through the optional `@phala/dcap-qvl` adapter.
- **Known measurements can be enforced.** Applications with a trusted allowlist can require expected MRTD and RTMR values rather than merely displaying measurements reported by the quote.
- **Browser use is supported directly.** The release includes an ES-module browser bundle as well as the typed package exports.
- **Quote parsing and policy checks are tested more thoroughly.** Coverage now includes malformed evidence, debug-mode rejection, nonce and signing-key binding, plaintext downgrade attempts, and optional verification policies.

### Privacy and verification boundaries

- Message content is encrypted in the client and model-output chunks are decrypted in the client. Venice still sees connection and request metadata such as the API credential, model, roles, request shape, token settings, timing, sizes, and network information.
- The default `binding` policy checks freshness, signing-key binding, model binding, and debug mode. It does **not** validate the Intel quote signature or certificate chain.
- Optional DCAP verification strengthens the Intel TDX evidence, but it does not by itself verify NVIDIA GPU evidence or prove that the measured application code is approved.
- A measurement is only trusted when the caller supplies and enforces a known-good allowlist.
- The current response protocol does not cryptographically bind each response chunk's ephemeral key to the signing key found in the attestation evidence.

Do not describe the default result as proof of a fully verified production enclave. Applications should show the returned verification level and explain which checks they require.

### Upgrading from 0.1.0

- Applications that intentionally accept plaintext responses must now set `allowPlaintext: true`. This is a compatibility escape hatch, not the recommended configuration.
- Applications that require full Intel quote validation should configure a DCAP verifier and set `requireDcap: true`.
- Applications that require approved code measurements should additionally provide `expectedMeasurements`.

## 0.1.0 — 2026-03-23

Initial package development release with browser-side message encryption, encrypted stream decryption, session handling, and basic Venice TEE evidence checks.
