# Security Policy

## Supported Versions

Security fixes are made for the latest release. If a report affects an older
release, please test the latest release when practical and include both version
numbers in the report.

## Reporting a Vulnerability

If you discover a security vulnerability, please report it privately via [GitHub Security Advisories](https://github.com/elkimek/venice-e2ee/security/advisories/new).

Do **not** open a public issue for security vulnerabilities.

Please include the affected version, expected and observed behavior, reproduction
steps or evidence, and the likely impact. Never include live credentials or
personal data in a report.

I'll acknowledge receipt within 48 hours and aim to release a fix within 7 days
for confirmed critical issues. Disclosure will be coordinated with the reporter
after a fix is available.

## Scope

- ECDH key exchange (secp256k1)
- AES-256-GCM encryption/decryption
- HKDF key derivation
- Encrypted request, response, stream, and tool-call handling
- Session management and fail-closed downgrade behavior
- Intel TDX/DCAP, NVIDIA NRAS, and ACI attestation verification
- Attested-session evidence and response-receipt verification
- Workload identity, keyset, nonce, measurement, and signature binding
- Per-chunk streaming decryption
