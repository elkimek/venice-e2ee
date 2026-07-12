/** Result of full DCAP quote signature and certificate chain verification. */
export interface DcapVerifyResult {
    /** TCB status: 'UpToDate', 'SWHardeningNeeded', 'OutOfDate', etc. */
    status: string;
    /** Intel security advisory IDs (e.g. 'INTEL-SA-00334') */
    advisoryIds: string[];
}
/**
 * Function that performs full TDX DCAP quote verification.
 * Accepts raw quote bytes and returns verification result.
 * Use `createDcapVerifier()` from `venice-e2ee/dcap` for the default implementation.
 */
export type DcapVerifier = (quoteBytes: Uint8Array) => Promise<DcapVerifyResult>;
/** TDX measurements extracted from the quote body. */
export interface TdxMeasurements {
    mrSeam: string;
    mrSignerSeam: string;
    mrTd: string;
    mrConfigId: string;
    mrOwner: string;
    mrOwnerConfig: string;
    rtMr0: string;
    rtMr1: string;
    rtMr2: string;
    rtMr3: string;
}
/**
 * Allowlisted TDX measurements. Each configured field accepts one value or a
 * list of values. Unconfigured fields are reported but are not policy checks.
 */
export type ExpectedTdxMeasurements = Partial<{
    [K in keyof TdxMeasurements]: string | string[];
}>;
export interface VeniceE2EEOptions {
    apiKey: string;
    baseUrl?: string;
    sessionTTL?: number;
    /** Set to false to skip TEE attestation verification. Default: true */
    verifyAttestation?: boolean;
    /**
     * Optional DCAP verifier for full TDX quote signature and cert chain verification.
     * When provided, validates the quote and TCB alongside the binding checks.
     * GPU evidence and code measurements remain separate policy decisions.
     *
     * ```ts
     * import { createDcapVerifier } from 'venice-e2ee/dcap';
     * const e2ee = createVeniceE2EE({ apiKey, dcapVerifier: createDcapVerifier() });
     * ```
     */
    dcapVerifier?: DcapVerifier;
    /** Fail session creation unless full DCAP verification ran. Default: false. */
    requireDcap?: boolean;
    /** Optional measurement allowlist. Requires successful DCAP verification. */
    expectedMeasurements?: ExpectedTdxMeasurements;
    /**
     * Permit non-encrypted response content to pass through. Default: false.
     * Whitespace-only chunks remain allowed because they reveal no model output.
     */
    allowPlaintextResponses?: boolean;
}
export interface E2EESession {
    privateKey: Uint8Array;
    publicKey: Uint8Array;
    pubKeyHex: string;
    modelPubKeyHex: string;
    aesKey: CryptoKey;
    modelId: string;
    created: number;
    /** Attestation verification result (present when verifyAttestation is true) */
    attestation?: import('./attestation.js').AttestationResult;
}
export interface EncryptedPayload {
    encryptedMessages: Array<{
        role: string;
        content: string;
    }>;
    headers: Record<string, string>;
    veniceParameters: {
        enable_e2ee: true;
    };
}
//# sourceMappingURL=types.d.ts.map