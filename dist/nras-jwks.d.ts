/**
 * Signature verification for NVIDIA attestation tokens (NRAS EATs).
 *
 * NRAS answers with ES384-signed JWTs. `createNvidiaVerifier()` on its own
 * authenticates them by TLS to nras.attestation.nvidia.com — sound for a call
 * you make yourself, and worth nothing for a token that reached you any other
 * way. This module checks the signature instead, against keys fetched from
 * NVIDIA's JWKS, which makes a token stand on its own: it can be relayed,
 * cached, logged, or handed on, and still be checkable.
 *
 * Usage:
 *   import { createNvidiaVerifier } from 'venice-e2ee/nvidia';
 *   import { createNrasTokenVerifier } from 'venice-e2ee/nvidia';
 *
 *   const gpuVerifier = createNvidiaVerifier({
 *     tokenVerifier: createNrasTokenVerifier(),
 *   });
 *
 * What this does and does not do:
 *
 *  - It verifies ES384 over the JWS signing input using the key whose `kid`
 *    the token names, refusing any other algorithm so a token cannot talk the
 *    verifier into a weaker one. `exp`, `nbf` and `iss` are checked too.
 *  - It authenticates the *key set* by TLS to NVIDIA, the same anchor the
 *    direct call uses. It does not perform RFC 5280 path validation over the
 *    `x5c` chain — that is a hand-rolled X.509 validator's worth of
 *    security-critical code, and getting it subtly wrong is the normal outcome.
 *    Instead the leaf certificate is required to carry the same public key as
 *    the JWK, and `pinnedCertSha256` lets an operator who obtained NVIDIA's
 *    intermediate or root out of band require it to appear in the chain.
 */
/** NVIDIA's published key set for attestation tokens. */
export declare const NRAS_JWKS_URL = "https://nras.attestation.nvidia.com/.well-known/jwks.json";
/** The only issuer these tokens may claim. */
export declare const NRAS_ISSUER = "https://nras.attestation.nvidia.com";
export interface NrasTokenVerifierOptions {
    /** Override the JWKS location (a mirror, or a test double). */
    jwksUrl?: string;
    /** How long a fetched key set may be reused. Default 15 minutes. */
    cacheTtlMs?: number;
    /** Tolerance for exp/nbf against local clock drift. Default 60s. */
    clockSkewSec?: number;
    /**
     * SHA-256 hex digests of DER certificates that must appear in the token's
     * `x5c` chain. Supply NVIDIA's intermediate or root, obtained out of band, to
     * stop trusting the TLS fetch alone. Empty means no pinning.
     */
    pinnedCertSha256?: string[];
    /** Override the fetch implementation. Defaults to global fetch. */
    fetchImpl?: typeof fetch;
    /** Override the clock, in ms since epoch. For tests. */
    now?: () => number;
}
/** Claims carried by a verified NRAS token. */
export interface VerifiedNrasToken {
    claims: Record<string, unknown>;
    kid: string;
    /** SHA-256 hex of each DER certificate in the token's x5c chain, leaf first. */
    chainSha256: string[];
}
export type NrasTokenVerifier = (token: string) => Promise<VerifiedNrasToken>;
/** Decode base64url to bytes. Browser-safe: no Buffer. */
export declare function base64UrlToBytes(input: string): Uint8Array;
/**
 * Read notBefore/notAfter from a DER certificate, in ms since epoch.
 *
 * Walks Certificate -> TBSCertificate -> {version?, serialNumber, signature,
 * issuer, validity}, which is fixed ordering in RFC 5280.
 */
export declare function certificateValidity(der: Uint8Array): {
    notBefore: number;
    notAfter: number;
};
/** Split a JWT into its three parts, rejecting anything that is not one. */
export declare function splitJwt(token: string): {
    header: string;
    payload: string;
    signature: string;
};
/** Parse a base64url JSON segment into an object. */
export declare function decodeJsonSegment(segment: string, what: string): Record<string, unknown>;
/**
 * Create a verifier for NRAS attestation tokens.
 *
 * The returned function throws on any failure and resolves with the verified
 * claims otherwise — there is no "verified: false" return, so a caller cannot
 * accidentally treat a failure as a pass.
 */
export declare function createNrasTokenVerifier(options?: NrasTokenVerifierOptions): NrasTokenVerifier;
//# sourceMappingURL=nras-jwks.d.ts.map