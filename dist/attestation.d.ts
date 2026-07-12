import type { DcapVerifier, DcapVerifyResult, ExpectedTdxMeasurements, TdxMeasurements } from './types.js';
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
    /** Top-level Venice server verification result (null if not present) */
    serverVerified: boolean | null;
    /** Full DCAP verification result (present when dcapVerifier was provided) */
    dcap?: DcapVerifyResult;
    /** Whether an injected DCAP verifier completed without a rejected TCB status. */
    dcapVerified: boolean;
    /** Measurements parsed from the TDX quote. Reporting them is not validation. */
    measurements?: TdxMeasurements;
    /** Result of the caller-supplied measurement allowlist, or null if none was supplied. */
    measurementsVerified: boolean | null;
    /** Honest summary of the strongest client-side verification completed. */
    verificationLevel: 'none' | 'binding' | 'dcap' | 'measured';
    /** List of verification failures */
    errors: string[];
}
export interface AttestationVerificationOptions {
    dcapVerifier?: DcapVerifier;
    requireDcap?: boolean;
    expectedMeasurements?: ExpectedTdxMeasurements;
    expectedModelId?: string;
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
 * @param verifierOrOptions - Optional DCAP verifier or verification policy
 * @returns AttestationResult with per-check pass/fail and error list
 */
export declare function verifyAttestation(response: AttestationResponse, clientNonce: Uint8Array, verifierOrOptions?: DcapVerifier | AttestationVerificationOptions): Promise<AttestationResult>;
//# sourceMappingURL=attestation.d.ts.map