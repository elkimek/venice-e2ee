# Changelog

This changelog summarizes user-visible changes to `venice-e2ee`. It also calls out the privacy and verification limits that matter when deciding whether to use a release.

## 0.2.1 — 2026-07-12

### Security maintenance

- Upgraded Vitest, Vite, esbuild, and PostCSS to patched versions, clearing the repository's development-tool vulnerability alerts.
- Removed the optional Phala DCAP verifier and its transitive dependencies from the default development lockfile. `@phala/dcap-qvl` remains an opt-in peer dependency and is not installed or shipped by default.
- Added pull-request CI that runs the test suite, both builds, a clean-build diff check, and `npm audit`.
- Added weekly grouped Dependabot updates for npm development tooling.

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
