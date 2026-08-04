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

/** Claims NVIDIA asserts about one GPU in an attested node. */
export interface NvidiaGpuClaims {
  /** Hardware model, e.g. "GH100 A01 GSP BROM". */
  hwModel: string | null;
  /** Secure boot enabled on the GPU. */
  secureBoot: boolean | null;
  /** "disabled" when the GPU is not in debug mode. */
  debugStatus: string | null;
  /** "success" when measurements matched NVIDIA's reference values. */
  measurementResult: string | null;
  /** NVIDIA's own check that the report echoes the submitted nonce. */
  reportNonceMatch: boolean | null;
  eatNonce: string | null;
}

/** What NVIDIA's Remote Attestation Service asserts about the GPU evidence. */
export interface GpuVerifyResult {
  /** NVIDIA's overall verdict (`x-nvidia-overall-att-result`). */
  overallResult: boolean;
  /** Nonce echoed in the signed token. Must be compared against the one sent. */
  eatNonce: string | null;
  /** GPU architecture named in the evidence, e.g. "HOPPER". Reporting only. */
  arch: string | null;
  /** Per-GPU claims, keyed as NVIDIA labels them ("GPU-0", ...). */
  gpus: Record<string, NvidiaGpuClaims>;
  /**
   * Whether every token's ES384 signature was checked against NVIDIA's
   * published keys. False means the claims rest on TLS to NRAS alone, which
   * says nothing about a token that arrived by any other route.
   */
  tokensVerified: boolean;
  /** Signed tokens as received, for callers who verify them against NVIDIA's JWKS. */
  rawTokens: { overall: string; perGpu: Record<string, string> };
}

/**
 * Function that verifies NVIDIA GPU evidence, given the raw `nvidia_payload`
 * string from the attestation response.
 * Use `createNvidiaVerifier()` from `venice-e2ee/nvidia` for the default
 * implementation, which submits it to NVIDIA's Remote Attestation Service.
 */
export type GpuVerifier = (nvidiaPayload: string) => Promise<GpuVerifyResult>;

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
  /**
   * Optional GPU verifier for the `nvidia_payload` carried alongside the TDX
   * quote. When provided, the evidence is checked against NVIDIA's root of
   * trust and its `eat_nonce` is required to match the nonce this session sent
   * — so the result describes this request rather than a replayed one.
   *
   * This says nothing about co-location: the GPU evidence and the TDX quote
   * share only a nonce, not a proof that they came from the same machine.
   *
   * ```ts
   * import { createNvidiaVerifier } from 'venice-e2ee/nvidia';
   * const e2ee = createVeniceE2EE({ apiKey, gpuVerifier: createNvidiaVerifier() });
   * ```
   */
  gpuVerifier?: GpuVerifier;
  /**
   * Fail session creation unless GPU attestation verified. Default: false.
   * Also fails when the response carries no GPU evidence at all, which is the
   * point — otherwise a provider can silently drop the payload to skip the check.
   */
  requireGpu?: boolean;
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
  encryptedMessages: Array<{ role: string; content: string; tool_call_id?: string }>;
  headers: Record<string, string>;
  veniceParameters: { enable_e2ee: true };
}
