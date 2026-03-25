# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please report it privately via [GitHub Security Advisories](https://github.com/elkimek/venice-e2ee/security/advisories/new).

Do **not** open a public issue for security vulnerabilities.

I'll acknowledge receipt within 48 hours and aim to release a fix within 7 days for critical issues.

## Scope

- ECDH key exchange (secp256k1)
- AES-256-GCM encryption/decryption
- HKDF key derivation
- Session management and TEE attestation
- Per-chunk streaming decryption
