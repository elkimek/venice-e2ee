# Changelog

This changelog summarizes user-visible changes to `venice-e2ee`. It also calls out the privacy and verification limits that matter when deciding whether to use a release.

## 0.5.3 — 2026-08-08

### Documentation and distribution

- Fixed the primary usage example and browser-bundle path now that the package is available from npm.
- Aligned the API reference with the GPU verification options and the single-session cache actually implemented by the library.
- Clarified that the default `binding` policy checks fields inside the supplied quote but does not authenticate the quote without DCAP verification.
- Replaced the obsolete development notes, documented the tested runtime and ESM packaging, and added the GitHub/npm release procedure.

## 0.5.2 — 2026-08-08

### ACI URL handling hardening

- Replaced the end-anchored trailing-slash regular expressions in ACI attestation and attested-session URL construction with linear-time trimming. This removes the regex-backtracking denial-of-service risk for unusually long caller-supplied base URLs without changing the accepted URL shapes.
- Added regression coverage for repeated trailing slashes and long slash runs followed by a non-slash character.

### Toolchain and CI maintenance

- Upgraded TypeScript from 5.9.3 to 7.0.2 and regenerated the committed Node and browser build output.
- Upgraded `actions/setup-node` from 6 to 7 and `actions/dependency-review-action` from 4 to 5.

## 0.5.1 — 2026-08-07

### DCAP QVL 0.6 compatibility

- Added explicit support for `@phala/dcap-qvl` 0.6.x while retaining compatibility with the established 0.3.x integration.
- Added CI coverage for both the optional-peer error path and a real 0.6.1 module load and verifier invocation.
- Kept Phala DCAP optional and outside the default lockfile. Its current `elliptic` dependency still carries the signing-related advisory described below, while Venice E2EE uses the package only for verification.

## 0.5.0 — 2026-08-07

### A receipt trust anchor that is proven rather than pinned

- Added `verifyAciAttestation()`, `establishAciTrustAnchor()`, and `fetchAciAttestation()` for the gateway's native ACI attestation report. Its TDX quote covers `sha256(JCS({purpose: "aci.report_data.v1", workload_id, workload_keyset_digest, nonce}))`, so a verified quote commits to the workload keyset digest. Callers who previously had to pin an anchor on first use can now derive one from Intel's root of trust.
- This closes the gap the 0.3.0 notes described as unavoidable. Venice's `/api/v1/tee/attestation` serves the legacy report shape, whose `report_data` is `[address(20) | zeros(12) | nonce(32)]` and binds only the E2EE key and the nonce. The same enclave also answers `GET /v1/aci/attestation` on its own hostnames, unauthenticated, and that report carries the binding. Which host served it does not matter: the quote authenticates itself, and the digest it commits to is compared against the one Venice reports.
- `anchor` is returned only when every check passes, and DCAP verification is required by default. An anchor taken from an unverified quote is no better than a pinned one, so the function refuses to hand one back.
- Checks cover keyset-digest and workload-id recomputation, the `report_data` statement binding, an unused REPORTDATA tail, debug mode, the report's freshness window, an optional measurement allowlist, and the `keyset_endorsement` signature. Added `aciReportData()`, `aciReportDataStatement()`, and `aciKeysetEndorsementPayload()` for callers who want the canonical bytes directly.
- The `keyset_endorsement` encoding is ECDSA-secp256k1 over `sha256(JCS({purpose: "aci.keyset.endorsement.v1", workload_keyset_digest}))` under the workload identity key. Previously undocumented here and left unverified; it now corroborates the anchor, though the `report_data` binding is what proves it.

### Inspecting the gateway's evidence for the machine it forwarded to

- Added `verifyAttestedSession()`, `fetchAttestedSession()`, `computeAttestedSessionId()`, and `decodeSessionEvidence()`. A receipt's `upstream.verified` event names a `session_id` that is content-addressed over the verified material — `"as_" + hex(sha256(JCS({upstream_name, endpoint, verifier_id, identity, channel_binding, claims, evidence_digest})))` — so the id inside a signed receipt commits to the whole record, including a digest of the upstream's own attestation report.
- The session store is public and unsigned, and does not need to be signed: recomputing the id is what makes a record tamper-evident, and the receipt is what makes the id trustworthy. Verified against the live store, where all 346 records recomputed correctly.
- Fetched by id, a session carries the evidence inline as a `data:` URI: the upstream's complete ACI report, quote included. `verifyAttestedSession()` checks the digest, DCAP-validates the quote, inspects its measurements and debug bit, and folds the results in under an `upstream.` prefix. Malformed base64 or JSON is reported as a failed `evidence_decodes` check rather than escaping the check-based API as an exception.
- Added `verifyRelayedAciAttestation()` and `AciAttestationResult.nonceBound` for reports obtained second-hand. The nonce the gateway used is not published, so the REPORTDATA statement cannot be recomputed. Comparing the served `report_data` with the quote only compares opaque bytes; it does not bind the reported workload id or keyset digest to that quote. The relayed result therefore fails closed, returns no anchor, and does not describe a matching TLS key as attested.
- Publishing the original gateway nonce in the content-addressed evidence would allow the quote-to-keyset statement to be checked. It still would not make the nonce caller-chosen or independently prove freshness, so those properties must remain distinct.

### The receipt signature that reaches the quote

- `verifyReceipt()` now verifies the top-level `signature` when the gateway serves one, adding the `signed_text_matches_receipt_hashes` and `signature_recovers_to_attested_key` checks. It is EIP-191 `personal_sign` over `"<request_body_hash>:<response_body_hash>"`, made by the secp256k1 key whose Ethereum address the TDX quote carries in REPORTDATA.
- This is the only binding in a receipt that reaches the quote without passing through the workload keyset, and it was previously only string-compared. The signed text is recomputed from the receipt's own hash events, so a valid signature over some other pair of hashes fails. Exported as `recoverReceiptSigner()`.
- Both checks are skipped on gateways that serve neither field, so pre-ACI responses are unaffected. If either field is present, both strings and the attested signing address are required; partial responses fail rather than silently downgrading verification.

## 0.4.1 — 2026-08-05

### Receipt body-binding diagnostics

- Added `BODY_BINDING_CHECKS`, naming the request and response body-hash checks so callers can distinguish an unreachable public-gateway binding from any other receipt-verification failure without duplicating string literals.
- Documented that `api.venice.ai` currently re-serializes request and response bodies before the enclave sees them, making those two checks unreproducible from the public client vantage point.
- Receipt verification remains fail closed: `verified` is still false when either body binding is missing, and the caller remains responsible for deciding how to report that known gateway limitation.

## 0.4.0 — 2026-08-05

### GPU attestation policy

- Added `createNvidiaVerifier()` (exported from `venice-e2ee/nvidia`) and the `gpuVerifier` / `requireGpu` options. When the attestation response carries an `nvidia_payload`, the evidence is submitted verbatim to NVIDIA's Remote Attestation Service and checked against NVIDIA's root of trust instead of the provider's own claim about it.
- The policy requires `eat_nonce` in the overall and every per-GPU token to equal the nonce the session sent, so a passing verdict describes this request rather than a replayed report. It also requires positive `secboot`, `dbgstat: "disabled"`, `measres: "success"`, and report-nonce-match claims on every GPU named. Missing or mistyped claims fail closed, and `requireGpu` also fails when no evidence is served at all.
- Results are reported in `session.attestation.gpu` / `.gpuVerified`, with the signed tokens carried through as `gpu.rawTokens`.
- Limits, stated in the README rather than implied: the verdict is NVIDIA's, and nothing binds the GPU evidence to the TDX quote beyond the shared nonce — for Venice's E2EE models the attested CVM reports `num_gpus: 0`, so the two are not the same machine.

### NVIDIA token signature verification

- Added `createNrasTokenVerifier()` (exported from `venice-e2ee/nvidia`) and the `tokenVerifier` option on `createNvidiaVerifier()`. Tokens are checked with ES384 against NVIDIA's published key set instead of resting on TLS to NRAS, so a token stays checkable when relayed, cached, or logged.
- The algorithm is pinned to ES384 rather than read from the token, closing the algorithm-confusion family including `alg: none`. `iss` and a finite `exp` are required, optional `nbf` is checked when present, and every token is verified — overall and per-GPU — with any failure rejecting the whole result.
- The key set is cached for 12 hours and refetched on an unknown `kid`, rate-limited so malformed tokens or a failing NVIDIA cannot become a request flood. TTL refresh notices withdrawn keys; NVIDIA's roughly 48-hour signing-leaf validity window is enforced as an additional bound whenever the key carries an `x5c` chain.
- `pinnedLeafCertSha256` accepts only exact leaf-certificate fingerprints obtained out of band. It cannot be satisfied by appending an unrelated pinned root or intermediate to an unvalidated `x5c` array. `chainSha256` reports the observed chain digests.
- `GpuVerifyResult.tokensVerified` reports whether signatures were checked.

### Tool-call parser resilience

- Repaired malformed JSON, parenthesized calls, and stray argument tags observed in GLM tool-call output, while preserving escapes and multi-line string content.
- Fixed separator ordering in the tagged argument parser so spaces inside values cannot be mistaken for key boundaries.
- Kept ambiguous repairs fail closed rather than silently producing corrupted tool arguments, with captured-output and streaming regression coverage.

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

- **Encrypted responses fail closed.** Non-empty plaintext model output is rejected unless the caller deliberately enables the `allowPlaintextResponses` compatibility option.
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

- Applications that intentionally accept plaintext responses must now set `allowPlaintextResponses: true`. This is a compatibility escape hatch, not the recommended configuration.
- Applications that require full Intel quote validation should configure a DCAP verifier and set `requireDcap: true`.
- Applications that require approved code measurements should additionally provide `expectedMeasurements`.

## 0.1.0 — 2026-03-23

Initial package development release with browser-side message encryption, encrypted stream decryption, session handling, and basic Venice TEE evidence checks.
