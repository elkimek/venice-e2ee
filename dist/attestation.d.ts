import type { DcapVerifier, DcapVerifyResult } from './types.js';
export interface AttestationResponse {
    verified?: boolean;
    nonce: string;
    model: string;
    intel_quote?: string;
    signing_address?: string;
    signing_key?: string;
    signing_public_key?: string;
    nvidia_payload?: string;
    server_verification?: ServerVerification;
    tee_provider?: string;
}
export interface ServerVerification {
    tdx?: {
        valid: boolean;
        error?: string;
        signatureValid?: boolean;
        certificateChainValid?: boolean;
        attestationKeyMatch?: boolean;
    };
    nvidia?: {
        valid: boolean;
        error?: string;
    };
    signingAddressBinding?: {
        bound: boolean;
        reportDataAddress?: string;
        error?: string;
    };
    nonceBinding?: {
        bound: boolean;
        method?: 'sha256' | 'raw';
        error?: string;
    };
    verifiedAt: string;
    verificationDurationMs: number;
}
export interface AttestationResult {
    /** Client nonce was found in REPORTDATA bytes 32-63 */
    nonceVerified: boolean;
    /** Signing key Ethereum address matches REPORTDATA bytes 0-19 */
    signingKeyBound: boolean;
    /** TEE is running in debug mode (untrusted) */
    debugMode: boolean;
    /** Server-side TDX DCAP verification result (null if not present) */
    serverTdxValid: boolean | null;
    /** Full DCAP verification result (present when dcapVerifier was provided) */
    dcap?: DcapVerifyResult;
    /** List of verification failures */
    errors: string[];
}
/**
 * Derive an Ethereum address from an uncompressed secp256k1 public key.
 * address = keccak256(pubkey_64_bytes).slice(12)
 */
export declare function deriveEthAddress(pubKeyHex: string): Uint8Array;
/**
 * Verify a Venice TEE attestation response.
 *
 * Always runs v1 binding checks:
 * 1. Parse TDX quote, reject debug mode
 * 2. Verify client nonce in REPORTDATA bytes 32-63 (raw or SHA-256)
 * 3. Verify signing key's Ethereum address in REPORTDATA bytes 0-19
 * 4. Cross-check server's own verification results
 *
 * When `dcapVerifier` is provided, also runs full DCAP verification
 * (cert chain, quote signature, TCB level evaluation).
 *
 * @param response - Full attestation endpoint response
 * @param clientNonce - The 32 raw nonce bytes sent to the endpoint
 * @param dcapVerifier - Optional DCAP verifier function
 * @returns AttestationResult with per-check pass/fail and error list
 */
export declare function verifyAttestation(response: AttestationResponse, clientNonce: Uint8Array, dcapVerifier?: DcapVerifier): Promise<AttestationResult>;
//# sourceMappingURL=attestation.d.ts.map