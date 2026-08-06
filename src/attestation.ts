import { keccak_256 } from '@noble/hashes/sha3.js';
import { fromHex, toHex } from './crypto.js';
import type {
  DcapVerifier,
  DcapVerifyResult,
  ExpectedTdxMeasurements,
  GpuVerifier,
  GpuVerifyResult,
  TdxMeasurements,
} from './types.js';
import type { WorkloadKeyset } from './receipt.js';

// ── Types ──────────────────────────────────────────────────────────────

export interface AttestationResponse {
  api_version?: string;
  verified?: boolean;
  nonce: string;
  model: string;
  workload_id?: string;
  workload_keyset_digest?: string;
  attestation?: {
    workload_keyset?: WorkloadKeyset;
    report_data?: string;
    [key: string]: unknown;
  };
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
  nvidia?: { valid: boolean; error?: string };
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
  /** GPU attestation result (present when gpuVerifier ran against GPU evidence) */
  gpu?: GpuVerifyResult;
  /**
   * Whether NVIDIA vouched for the GPU evidence *and* its `eat_nonce` matched
   * the nonce sent. False when no verifier ran, or no evidence was served.
   */
  gpuVerified: boolean;
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
  gpuVerifier?: GpuVerifier;
  requireGpu?: boolean;
  expectedMeasurements?: ExpectedTdxMeasurements;
  expectedModelId?: string;
}

// ── TDX quote layout ──────────────────────────────────────────────────
// Header: 48 bytes (version, attestationKeyType, teeType, ...)
// TDX Body starts at offset 48:
//   tdAttributes   @ body+120  (8 bytes)
//   reportData     @ body+520  (64 bytes)

const TDX_BODY_OFFSET = 48;
const TD_ATTRIBUTES_OFFSET = TDX_BODY_OFFSET + 120;
const TD_ATTRIBUTES_LEN = 8;
const REPORT_DATA_OFFSET = TDX_BODY_OFFSET + 520;
const REPORT_DATA_LEN = 64;
const MIN_QUOTE_LEN = REPORT_DATA_OFFSET + REPORT_DATA_LEN; // 632 bytes

const MEASUREMENT_LAYOUT: Array<[keyof TdxMeasurements, number]> = [
  ['mrSeam', 16],
  ['mrSignerSeam', 64],
  ['mrTd', 136],
  ['mrConfigId', 184],
  ['mrOwner', 232],
  ['mrOwnerConfig', 280],
  ['rtMr0', 328],
  ['rtMr1', 376],
  ['rtMr2', 424],
  ['rtMr3', 472],
];

const TDX_TEE_TYPE = 0x00000081;

// ── Helpers ───────────────────────────────────────────────────────────

/**
 * Derive an Ethereum address from an uncompressed secp256k1 public key.
 * address = keccak256(pubkey_64_bytes).slice(12)
 */
export function deriveEthAddress(pubKeyHex: string): Uint8Array {
  let hex = pubKeyHex.startsWith('0x') ? pubKeyHex.slice(2) : pubKeyHex;
  if (hex.length === 128) hex = '04' + hex;
  if (hex.length !== 130 || !hex.startsWith('04')) {
    throw new Error(
      `Invalid uncompressed secp256k1 public key (got ${hex.length} hex chars)`
    );
  }
  const keyBytes = fromHex(hex.slice(2)); // 64 bytes without 04 prefix
  const hash = keccak_256(keyBytes);
  return hash.slice(12); // last 20 bytes
}

/** Constant-time comparison of two byte arrays. */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/** Decode the endpoint's quote representation. Venice has documented both hex and base64. */
function decodeQuote(quote: string): Uint8Array {
  const value = quote.startsWith('0x') ? quote.slice(2) : quote;
  if (value.length % 2 === 0 && /^[0-9a-f]+$/i.test(value)) return fromHex(value);
  try {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
    const binary = atob(padded);
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  } catch {
    throw new Error('TDX quote is neither valid hex nor base64');
  }
}

/**
 * Parse a TDX quote and extract fields needed for verification.
 *
 * Exported for the ACI report profile in `./aci.js`, which reads the same
 * REPORTDATA and measurements out of the same quote layout but checks a
 * different statement against them.
 */
export function parseTdxQuote(quote: string) {
  const bytes = decodeQuote(quote);

  if (bytes.length < MIN_QUOTE_LEN) {
    throw new Error(
      `TDX quote too short: ${bytes.length} bytes (need >= ${MIN_QUOTE_LEN})`
    );
  }

  // teeType is a uint32LE at offset 4
  const teeType =
    bytes[4] | (bytes[5] << 8) | (bytes[6] << 16) | (bytes[7] << 24);
  if (teeType !== TDX_TEE_TYPE) {
    throw new Error(
      `Not a TDX quote: teeType=0x${teeType.toString(16)} (expected 0x81)`
    );
  }

  return {
    bytes,
    tdAttributes: bytes.slice(TD_ATTRIBUTES_OFFSET, TD_ATTRIBUTES_OFFSET + TD_ATTRIBUTES_LEN),
    reportData: bytes.slice(REPORT_DATA_OFFSET, REPORT_DATA_OFFSET + REPORT_DATA_LEN),
    measurements: Object.fromEntries(
      MEASUREMENT_LAYOUT.map(([name, offset]) => [
        name,
        toHex(bytes.slice(TDX_BODY_OFFSET + offset, TDX_BODY_OFFSET + offset + 48)),
      ])
    ) as unknown as TdxMeasurements,
  };
}

function normalizeMeasurement(value: string): string {
  return value.toLowerCase().replace(/^0x/, '');
}

function verifyMeasurements(
  actual: TdxMeasurements,
  expected: ExpectedTdxMeasurements,
  errors: string[]
): boolean {
  let checked = 0;
  let matched = true;
  for (const [name, allowedValue] of Object.entries(expected) as Array<[
    keyof TdxMeasurements,
    string | string[]
  ]>) {
    const allowed = (Array.isArray(allowedValue) ? allowedValue : [allowedValue])
      .map(normalizeMeasurement);
    checked += 1;
    if (!actual[name] || !allowed.includes(normalizeMeasurement(actual[name]))) {
      matched = false;
      errors.push(`TDX measurement mismatch: ${name}`);
    }
  }
  if (checked === 0) {
    errors.push('Expected measurement policy is empty');
    return false;
  }
  return matched;
}

// ── Main verification ─────────────────────────────────────────────────

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
export async function verifyAttestation(
  response: AttestationResponse,
  clientNonce: Uint8Array,
  verifierOrOptions?: DcapVerifier | AttestationVerificationOptions
): Promise<AttestationResult> {
  const options: AttestationVerificationOptions = typeof verifierOrOptions === 'function'
    ? { dcapVerifier: verifierOrOptions }
    : verifierOrOptions ?? {};
  const {
    dcapVerifier,
    requireDcap = false,
    gpuVerifier,
    requireGpu = false,
    expectedMeasurements,
    expectedModelId,
  } = options;
  const errors: string[] = [];
  let nonceVerified = false;
  let signingKeyBound = false;
  let debugMode = false;
  let serverTdxValid: boolean | null = null;
  let serverVerified: boolean | null = response.verified ?? null;
  let dcap: DcapVerifyResult | undefined;
  let dcapVerified = false;
  let measurements: TdxMeasurements | undefined;
  let measurementsVerified: boolean | null = null;
  let gpu: GpuVerifyResult | undefined;
  let gpuVerified = false;

  const result = (): AttestationResult => ({
    nonceVerified,
    signingKeyBound,
    debugMode,
    serverTdxValid,
    serverVerified,
    dcap,
    dcapVerified,
    gpu,
    gpuVerified,
    measurements,
    measurementsVerified,
    verificationLevel: dcapVerified
      ? (measurementsVerified === true ? 'measured' : 'dcap')
      : (nonceVerified && signingKeyBound && !debugMode ? 'binding' : 'none'),
    errors,
  });

  if (clientNonce.length !== 32) {
    errors.push(`Invalid client nonce length: ${clientNonce.length} (expected 32)`);
    return result();
  }

  const clientNonceHex = toHex(clientNonce);
  if (response.nonce && normalizeMeasurement(response.nonce) !== clientNonceHex) {
    errors.push('Attestation response nonce does not match the requested nonce');
  }
  if (expectedModelId && response.model !== expectedModelId) {
    errors.push(`Attestation model mismatch: expected ${expectedModelId}, received ${response.model || 'missing'}`);
  }
  if (response.verified === false) {
    errors.push('Venice reported that server-side attestation verification failed');
  }

  const signingKey = response.signing_key || response.signing_public_key;
  if (!signingKey) {
    errors.push('No signing key in attestation response');
    return result();
  }

  // ── Server-side cross-check ────────────────────────────────────────
  if (response.server_verification) {
    const sv = response.server_verification;
    serverTdxValid = sv.tdx?.valid ?? null;
    if (sv.tdx && !sv.tdx.valid) {
      errors.push(
        `Server TDX verification failed: ${sv.tdx.error || 'unknown reason'}`
      );
    }
    if (sv.tdx?.signatureValid === false) {
      errors.push('Venice reported an invalid TDX quote signature');
    }
    if (sv.tdx?.certificateChainValid === false) {
      errors.push('Venice reported an invalid TDX certificate chain');
    }
    if (sv.tdx?.attestationKeyMatch === false) {
      errors.push('Venice reported a TDX attestation-key mismatch');
    }
    if (sv.nvidia && !sv.nvidia.valid) {
      errors.push(`Venice reported failed NVIDIA attestation: ${sv.nvidia.error || 'unknown reason'}`);
    }
  }

  // ── Client-side quote checks ───────────────────────────────────────
  if (!response.intel_quote) {
    errors.push('No intel_quote in attestation response — cannot verify client-side');
    return result();
  }

  let reportData: Uint8Array;
  let tdAttributes: Uint8Array;
  let quoteBytes: Uint8Array;
  try {
    ({ bytes: quoteBytes, reportData, tdAttributes, measurements } = parseTdxQuote(response.intel_quote));
  } catch (e) {
    errors.push(`Failed to parse TDX quote: ${(e as Error).message}`);
    return result();
  }

  // Check 1: Debug mode
  debugMode = (tdAttributes[0] & 0x01) !== 0;
  if (debugMode) {
    errors.push('TEE is running in DEBUG mode — attestation cannot be trusted');
  }

  // Check 2: Nonce binding (try raw first, then SHA-256)
  const nonceInReport = reportData.slice(32, 64);
  if (constantTimeEqual(nonceInReport, clientNonce)) {
    nonceVerified = true;
  } else {
    const hashInput = new ArrayBuffer(clientNonce.byteLength);
    new Uint8Array(hashInput).set(clientNonce);
    const hashedNonce = new Uint8Array(
      await crypto.subtle.digest('SHA-256', hashInput)
    );
    if (constantTimeEqual(nonceInReport, hashedNonce)) {
      nonceVerified = true;
    } else {
      errors.push(
        'Nonce verification failed: client nonce not found in REPORTDATA'
      );
    }
  }

  // Check 3: Signing key → Ethereum address binding
  try {
    const expectedAddress = deriveEthAddress(signingKey);
    const addressInReport = reportData.slice(0, 20);
    signingKeyBound = constantTimeEqual(addressInReport, expectedAddress);
    if (!signingKeyBound) {
      errors.push(
        'Signing key not bound to TEE: Ethereum address mismatch in REPORTDATA'
      );
    }
  } catch (e) {
    errors.push(
      `Failed to verify signing key binding: ${(e as Error).message}`
    );
  }

  // Check 4: Cross-check server binding results against our own
  if (response.server_verification?.signingAddressBinding) {
    const sab = response.server_verification.signingAddressBinding;
    if (signingKeyBound !== sab.bound) {
      errors.push(
        `Signing key binding inconsistency: client=${signingKeyBound}, server=${sab.bound}`
      );
    }
  }
  if (response.server_verification?.nonceBinding) {
    const nb = response.server_verification.nonceBinding;
    if (nonceVerified !== nb.bound) {
      errors.push(
        `Nonce binding inconsistency: client=${nonceVerified}, server=${nb.bound}`
      );
    }
  }

  if (expectedMeasurements) {
    measurementsVerified = verifyMeasurements(measurements, expectedMeasurements, errors);
  }

  // Check 5: Full DCAP verification (if verifier provided)
  if (dcapVerifier) {
    try {
      dcap = await dcapVerifier(quoteBytes);
      const status = dcap.status;
      const acceptedStatuses = new Set([
        'UpToDate',
        'SWHardeningNeeded',
        'ConfigurationNeeded',
        'ConfigurationAndSWHardeningNeeded',
      ]);
      if (acceptedStatuses.has(status)) {
        dcapVerified = true;
      } else {
        errors.push(`DCAP verification: unacceptable TCB status ${status || 'Unknown'}`);
      }
    } catch (e) {
      errors.push(`DCAP verification failed: ${(e as Error).message}`);
    }
  }

  // Check 6: GPU attestation against NVIDIA's root of trust (if verifier provided).
  //
  // The nonce comparison is the load-bearing part. NVIDIA will happily vouch for
  // any well-formed evidence; only `eat_nonce` ties its verdict to the challenge
  // this session issued, rather than to a report captured earlier.
  if (gpuVerifier && response.nvidia_payload) {
    const errorsBeforeGpu = errors.length;
    try {
      gpu = await gpuVerifier(response.nvidia_payload);

      if (!gpu.overallResult) {
        errors.push('NVIDIA did not vouch for the GPU evidence (overall attestation result false)');
      }
      if (gpu.eatNonce === null) {
        errors.push('NVIDIA attestation token carries no eat_nonce to bind it to this request');
      } else if (normalizeMeasurement(gpu.eatNonce) !== clientNonceHex) {
        errors.push(
          'NVIDIA attestation token eat_nonce does not match the nonce sent — the GPU evidence ' +
          'describes some other request'
        );
      }

      for (const [name, claims] of Object.entries(gpu.gpus)) {
        if (claims.debugStatus !== 'disabled') {
          errors.push(
            `GPU ${name} did not assert debug mode disabled ` +
            `(dbgstat=${claims.debugStatus ?? 'missing'})`
          );
        }
        if (claims.secureBoot !== true) {
          errors.push(
            `GPU ${name} did not assert secure boot enabled ` +
            `(secboot=${claims.secureBoot ?? 'missing'})`
          );
        }
        if (claims.measurementResult !== 'success') {
          errors.push(
            `GPU ${name} did not assert measurements matched NVIDIA's reference values ` +
            `(measres=${claims.measurementResult ?? 'missing'})`
          );
        }
        if (claims.reportNonceMatch !== true) {
          errors.push(
            `GPU ${name} did not assert that its attestation report echoed the submitted nonce ` +
            `(nonce-match=${claims.reportNonceMatch ?? 'missing'})`
          );
        }
        if (claims.eatNonce === null) {
          errors.push(`GPU ${name} token carries no eat_nonce to bind it to this request`);
        } else if (normalizeMeasurement(claims.eatNonce) !== clientNonceHex) {
          errors.push(`GPU ${name} token eat_nonce does not match the nonce sent`);
        }
      }

      if (Object.keys(gpu.gpus).length === 0) {
        errors.push('NVIDIA returned no per-GPU claims to check');
      }

      gpuVerified = errors.length === errorsBeforeGpu;
    } catch (e) {
      errors.push(`GPU attestation failed: ${(e as Error).message}`);
    }
  }

  if (requireGpu && !gpuVerified) {
    if (!gpuVerifier) {
      errors.push('GPU attestation is required but no gpuVerifier was provided');
    } else if (!response.nvidia_payload) {
      errors.push('GPU attestation is required but the response carried no GPU evidence');
    } else {
      errors.push('GPU attestation did not complete successfully');
    }
  }

  if (requireDcap && !dcapVerified) {
    errors.push(dcapVerifier
      ? 'Full DCAP verification did not complete successfully'
      : 'Full DCAP verification is required but no dcapVerifier was provided');
  }
  if (measurementsVerified === true && !dcapVerified) {
    errors.push('Measurement allowlist requires successful DCAP verification of the quote');
  }

  return result();
}
