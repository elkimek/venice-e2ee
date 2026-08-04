import { describe, it, expect } from 'vitest';
import { getPublicKey, utils } from '@noble/secp256k1';
import {
  deriveEthAddress,
  verifyAttestation,
  type AttestationResponse,
} from './attestation.js';
import { toHex, fromHex } from './crypto.js';

// ── Helpers to build mock TDX quotes ──────────────────────────────────

/**
 * Build a minimal TDX quote hex string with the given REPORTDATA
 * and tdAttributes embedded at the correct offsets.
 */
function buildMockQuote(opts: {
  reportData: Uint8Array; // 64 bytes
  debugMode?: boolean;
}): string {
  // Total min size: 48 (header) + 584 (body through reportData) = 632 bytes
  const quote = new Uint8Array(632);

  // Header: version=4 at offset 0 (uint16LE)
  quote[0] = 4;
  // teeType = 0x81 at offset 4 (uint32LE)
  quote[4] = 0x81;

  // tdAttributes at offset 48+120 = 168 (8 bytes)
  if (opts.debugMode) {
    quote[168] = 0x01; // DEBUG bit = LSB of first byte
  }

  // reportData at offset 48+520 = 568 (64 bytes)
  quote.set(opts.reportData, 568);

  return toHex(quote);
}

/** Build REPORTDATA: ethAddress (20) + zeroPad (12) + nonce (32) = 64 bytes */
function buildReportData(
  ethAddress: Uint8Array,
  nonce: Uint8Array
): Uint8Array {
  const rd = new Uint8Array(64);
  rd.set(ethAddress, 0);
  // bytes 20-31 are zero padding
  rd.set(nonce, 32);
  return rd;
}

// ── Tests ─────────────────────────────────────────────────────────────

describe('deriveEthAddress', () => {
  it('derives correct Ethereum address from known key', () => {
    // Well-known test vector: private key = 1
    // Public key (uncompressed, 65 bytes starting with 04)
    const privKey = new Uint8Array(32);
    privKey[31] = 1;
    const pubKey = getPublicKey(privKey, false);
    const pubHex = toHex(pubKey);

    const addr = deriveEthAddress(pubHex);
    expect(addr).toBeInstanceOf(Uint8Array);
    expect(addr.length).toBe(20);

    // Known Ethereum address for private key = 1:
    // 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
    const expected = '7e5f4552091a69125d5dfcb7b8c2659029395bdf';
    expect(toHex(addr)).toBe(expected);
  });

  it('handles 128-char hex (no 04 prefix)', () => {
    const privKey = new Uint8Array(32);
    privKey[31] = 1;
    const pubKey = getPublicKey(privKey, false);
    const pubHexNo04 = toHex(pubKey).slice(2); // remove '04'
    expect(pubHexNo04.length).toBe(128);

    const addr = deriveEthAddress(pubHexNo04);
    expect(toHex(addr)).toBe('7e5f4552091a69125d5dfcb7b8c2659029395bdf');
  });

  it('handles 0x prefix', () => {
    const privKey = new Uint8Array(32);
    privKey[31] = 1;
    const pubKey = getPublicKey(privKey, false);

    const addr = deriveEthAddress('0x' + toHex(pubKey));
    expect(toHex(addr)).toBe('7e5f4552091a69125d5dfcb7b8c2659029395bdf');
  });

  it('rejects compressed keys', () => {
    const privKey = new Uint8Array(32);
    privKey[31] = 1;
    const compressed = getPublicKey(privKey, true);
    expect(() => deriveEthAddress(toHex(compressed))).toThrow(
      'Invalid uncompressed secp256k1 public key'
    );
  });
});

describe('verifyAttestation', () => {
  // Generate a test keypair and derive its Ethereum address
  const privKey = utils.randomPrivateKey();
  const pubKey = getPublicKey(privKey, false);
  const pubKeyHex = toHex(pubKey);
  const ethAddr = deriveEthAddress(pubKeyHex);

  // Client nonce (32 bytes)
  const clientNonce = crypto.getRandomValues(new Uint8Array(32));

  function makeResponse(
    overrides: Partial<AttestationResponse> & { quoteOverrides?: { debugMode?: boolean; reportData?: Uint8Array } } = {}
  ): AttestationResponse {
    const { quoteOverrides, ...rest } = overrides;
    const reportData = quoteOverrides?.reportData ?? buildReportData(ethAddr, clientNonce);
    return {
      nonce: toHex(clientNonce),
      model: 'e2ee-test-model',
      signing_key: pubKeyHex,
      intel_quote: buildMockQuote({
        reportData,
        debugMode: quoteOverrides?.debugMode ?? false,
      }),
      server_verification: {
        tdx: { valid: true },
        signingAddressBinding: { bound: true },
        nonceBinding: { bound: true, method: 'raw' },
        verifiedAt: new Date().toISOString(),
        verificationDurationMs: 42,
      },
      ...rest,
    };
  }

  it('passes when all checks succeed', async () => {
    const result = await verifyAttestation(makeResponse(), clientNonce);
    expect(result.errors).toEqual([]);
    expect(result.nonceVerified).toBe(true);
    expect(result.signingKeyBound).toBe(true);
    expect(result.debugMode).toBe(false);
    expect(result.serverTdxValid).toBe(true);
    expect(result.verificationLevel).toBe('binding');
    expect(result.dcapVerified).toBe(false);
    expect(result.measurements?.mrTd).toBe('0'.repeat(96));
  });

  it('accepts the documented base64 quote representation', async () => {
    const response = makeResponse();
    const quoteBytes = fromHex(response.intel_quote!);
    response.intel_quote = btoa(String.fromCharCode(...quoteBytes));
    const result = await verifyAttestation(response, clientNonce);
    expect(result.errors).toEqual([]);
    expect(result.verificationLevel).toBe('binding');
  });

  it('rejects a mismatched attested model', async () => {
    const result = await verifyAttestation(makeResponse(), clientNonce, {
      expectedModelId: 'e2ee-other-model',
    });
    expect(result.errors).toContainEqual(expect.stringContaining('model mismatch'));
  });

  it('rejects a negative top-level server verification result', async () => {
    const result = await verifyAttestation(makeResponse({ verified: false }), clientNonce);
    expect(result.errors).toContainEqual(expect.stringContaining('server-side'));
  });

  it('fails on nonce mismatch', async () => {
    const wrongNonce = crypto.getRandomValues(new Uint8Array(32));
    const reportData = buildReportData(ethAddr, wrongNonce);
    const result = await verifyAttestation(
      makeResponse({ quoteOverrides: { reportData } }),
      clientNonce
    );
    expect(result.nonceVerified).toBe(false);
    expect(result.errors).toContainEqual(
      expect.stringContaining('Nonce verification failed')
    );
  });

  it('accepts SHA-256 hashed nonce', async () => {
    const hashInput = new ArrayBuffer(clientNonce.byteLength);
    new Uint8Array(hashInput).set(clientNonce);
    const hashedNonce = new Uint8Array(
      await crypto.subtle.digest('SHA-256', hashInput)
    );
    const reportData = buildReportData(ethAddr, hashedNonce);
    const result = await verifyAttestation(
      makeResponse({ quoteOverrides: { reportData } }),
      clientNonce
    );
    expect(result.nonceVerified).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it('fails on signing key address mismatch', async () => {
    const wrongAddr = crypto.getRandomValues(new Uint8Array(20));
    const reportData = buildReportData(wrongAddr, clientNonce);
    const result = await verifyAttestation(
      makeResponse({ quoteOverrides: { reportData } }),
      clientNonce
    );
    expect(result.signingKeyBound).toBe(false);
    expect(result.errors).toContainEqual(
      expect.stringContaining('Signing key not bound to TEE')
    );
  });

  it('rejects debug-mode TEEs', async () => {
    const result = await verifyAttestation(
      makeResponse({ quoteOverrides: { debugMode: true } }),
      clientNonce
    );
    expect(result.debugMode).toBe(true);
    expect(result.errors).toContainEqual(
      expect.stringContaining('DEBUG mode')
    );
  });

  it('reports server TDX failure', async () => {
    const result = await verifyAttestation(
      makeResponse({
        server_verification: {
          tdx: { valid: false, error: 'signature invalid' },
          signingAddressBinding: { bound: true },
          nonceBinding: { bound: true, method: 'raw' },
          verifiedAt: new Date().toISOString(),
          verificationDurationMs: 42,
        },
      }),
      clientNonce
    );
    expect(result.serverTdxValid).toBe(false);
    expect(result.errors).toContainEqual(
      expect.stringContaining('Server TDX verification failed')
    );
  });

  it('rejects negative server-reported GPU evidence', async () => {
    const response = makeResponse();
    response.server_verification!.nvidia = { valid: false, error: 'GPU evidence invalid' };
    const result = await verifyAttestation(response, clientNonce);
    expect(result.errors).toContainEqual(expect.stringContaining('NVIDIA attestation'));
  });

  // ── GPU attestation policy ──────────────────────────────────────────
  //
  // The verifier is stubbed here on purpose: these tests are about what the
  // policy does with NVIDIA's answer, not about reaching NVIDIA.

  const GPU_PAYLOAD = JSON.stringify({ arch: 'HOPPER', evidence_list: [] });

  function gpuResult(overrides: Record<string, unknown> = {}) {
    return {
      overallResult: true,
      eatNonce: toHex(clientNonce),
      arch: 'HOPPER',
      gpus: {
        'GPU-0': {
          hwModel: 'GH100',
          secureBoot: true,
          debugStatus: 'disabled',
          measurementResult: 'success',
          reportNonceMatch: true,
          eatNonce: toHex(clientNonce),
        },
      },
      rawTokens: { overall: 'a.b.c', perGpu: { 'GPU-0': 'a.b.c' } },
      ...overrides,
    };
  }

  const gpuVerifier = (result = gpuResult()) => async () => result as never;

  it('accepts GPU evidence NVIDIA vouches for with a matching nonce', async () => {
    const result = await verifyAttestation(
      makeResponse({ nvidia_payload: GPU_PAYLOAD }),
      clientNonce,
      { gpuVerifier: gpuVerifier() }
    );
    expect(result.errors).toEqual([]);
    expect(result.gpuVerified).toBe(true);
    expect(result.gpu?.arch).toBe('HOPPER');
  });

  it('rejects GPU evidence whose eat_nonce belongs to another request', async () => {
    const result = await verifyAttestation(
      makeResponse({ nvidia_payload: GPU_PAYLOAD }),
      clientNonce,
      { gpuVerifier: gpuVerifier(gpuResult({ eatNonce: 'b'.repeat(64) })) }
    );
    expect(result.errors).toContainEqual(expect.stringContaining('eat_nonce does not match'));
    expect(result.gpuVerified).toBe(false);
  });

  it('rejects GPU evidence with no eat_nonce at all', async () => {
    const result = await verifyAttestation(
      makeResponse({ nvidia_payload: GPU_PAYLOAD }),
      clientNonce,
      { gpuVerifier: gpuVerifier(gpuResult({ eatNonce: null })) }
    );
    expect(result.errors).toContainEqual(expect.stringContaining('no eat_nonce'));
  });

  it('rejects a negative overall verdict from NVIDIA', async () => {
    const result = await verifyAttestation(
      makeResponse({ nvidia_payload: GPU_PAYLOAD }),
      clientNonce,
      { gpuVerifier: gpuVerifier(gpuResult({ overallResult: false })) }
    );
    expect(result.errors).toContainEqual(expect.stringContaining('did not vouch'));
  });

  it('rejects a GPU in debug mode', async () => {
    const bad = gpuResult();
    bad.gpus['GPU-0'].debugStatus = 'enabled';
    const result = await verifyAttestation(
      makeResponse({ nvidia_payload: GPU_PAYLOAD }),
      clientNonce,
      { gpuVerifier: gpuVerifier(bad) }
    );
    expect(result.errors).toContainEqual(expect.stringContaining('debug mode'));
  });

  it('rejects a GPU with secure boot off or failed measurements', async () => {
    const bad = gpuResult();
    bad.gpus['GPU-0'].secureBoot = false;
    bad.gpus['GPU-0'].measurementResult = 'failure';
    const result = await verifyAttestation(
      makeResponse({ nvidia_payload: GPU_PAYLOAD }),
      clientNonce,
      { gpuVerifier: gpuVerifier(bad) }
    );
    expect(result.errors).toContainEqual(expect.stringContaining('secure boot disabled'));
    expect(result.errors).toContainEqual(expect.stringContaining('reference values'));
  });

  it('rejects a verdict that names no GPUs', async () => {
    const result = await verifyAttestation(
      makeResponse({ nvidia_payload: GPU_PAYLOAD }),
      clientNonce,
      { gpuVerifier: gpuVerifier(gpuResult({ gpus: {} })) }
    );
    expect(result.errors).toContainEqual(expect.stringContaining('no per-GPU claims'));
  });

  it('surfaces a verifier that throws instead of swallowing it', async () => {
    const result = await verifyAttestation(
      makeResponse({ nvidia_payload: GPU_PAYLOAD }),
      clientNonce,
      { gpuVerifier: async () => { throw new Error('NRAS unreachable'); } }
    );
    expect(result.errors).toContainEqual(expect.stringContaining('NRAS unreachable'));
    expect(result.gpuVerified).toBe(false);
  });

  it('ignores GPU policy when no evidence is served and requireGpu is off', async () => {
    const result = await verifyAttestation(makeResponse(), clientNonce, {
      gpuVerifier: gpuVerifier(),
    });
    expect(result.errors).toEqual([]);
    expect(result.gpuVerified).toBe(false);
  });

  it('requireGpu fails closed when the response carries no GPU evidence', async () => {
    const result = await verifyAttestation(makeResponse(), clientNonce, {
      gpuVerifier: gpuVerifier(),
      requireGpu: true,
    });
    expect(result.errors).toContainEqual(expect.stringContaining('carried no GPU evidence'));
  });

  it('requireGpu fails closed when no verifier was supplied', async () => {
    const result = await verifyAttestation(
      makeResponse({ nvidia_payload: GPU_PAYLOAD }),
      clientNonce,
      { requireGpu: true }
    );
    expect(result.errors).toContainEqual(expect.stringContaining('no gpuVerifier was provided'));
  });

  it('detects client/server binding inconsistency', async () => {
    const wrongAddr = crypto.getRandomValues(new Uint8Array(20));
    const reportData = buildReportData(wrongAddr, clientNonce);
    // Client will see binding fail, but server says bound
    const result = await verifyAttestation(
      makeResponse({
        quoteOverrides: { reportData },
        server_verification: {
          tdx: { valid: true },
          signingAddressBinding: { bound: true },
          nonceBinding: { bound: true, method: 'raw' },
          verifiedAt: new Date().toISOString(),
          verificationDurationMs: 42,
        },
      }),
      clientNonce
    );
    expect(result.errors).toContainEqual(
      expect.stringContaining('Signing key binding inconsistency')
    );
  });

  it('handles missing intel_quote', async () => {
    const result = await verifyAttestation(
      makeResponse({ intel_quote: undefined }),
      clientNonce
    );
    expect(result.errors).toContainEqual(
      expect.stringContaining('No intel_quote')
    );
  });

  it('handles missing signing key', async () => {
    const result = await verifyAttestation(
      { nonce: '', model: '', intel_quote: '' },
      clientNonce
    );
    expect(result.errors).toContainEqual(
      expect.stringContaining('No signing key')
    );
  });

  it('handles non-TDX quote', async () => {
    // Build a quote with SGX teeType (0x00) instead of TDX (0x81)
    const quote = new Uint8Array(632);
    quote[0] = 4; // version
    // teeType stays 0x00 (SGX)
    const result = await verifyAttestation(
      makeResponse({ intel_quote: toHex(quote) }),
      clientNonce
    );
    expect(result.errors).toContainEqual(
      expect.stringContaining('Not a TDX quote')
    );
  });

  it('includes dcap result when verifier succeeds', async () => {
    const mockVerifier = async () => ({
      status: 'UpToDate',
      advisoryIds: ['INTEL-SA-00334'],
    });
    const result = await verifyAttestation(
      makeResponse(),
      clientNonce,
      mockVerifier
    );
    expect(result.errors).toEqual([]);
    expect(result.dcap).toEqual({
      status: 'UpToDate',
      advisoryIds: ['INTEL-SA-00334'],
    });
    expect(result.dcapVerified).toBe(true);
    expect(result.verificationLevel).toBe('dcap');
  });

  it('enforces an explicit DCAP requirement', async () => {
    const result = await verifyAttestation(makeResponse(), clientNonce, {
      requireDcap: true,
    });
    expect(result.errors).toContainEqual(expect.stringContaining('no dcapVerifier'));
    expect(result.verificationLevel).toBe('binding');
  });

  it('reports and validates caller-supplied measurements', async () => {
    const result = await verifyAttestation(makeResponse(), clientNonce, {
      dcapVerifier: async () => ({ status: 'UpToDate', advisoryIds: [] }),
      expectedMeasurements: { mrTd: '0'.repeat(96) },
    });
    expect(result.errors).toEqual([]);
    expect(result.measurementsVerified).toBe(true);
    expect(result.verificationLevel).toBe('measured');
  });

  it('does not accept a measurement allowlist on an unverified quote', async () => {
    const result = await verifyAttestation(makeResponse(), clientNonce, {
      expectedMeasurements: { mrTd: '0'.repeat(96) },
    });
    expect(result.measurementsVerified).toBe(true);
    expect(result.verificationLevel).toBe('binding');
    expect(result.errors).toContainEqual(expect.stringContaining('requires successful DCAP'));
  });

  it('rejects a measurement mismatch', async () => {
    const result = await verifyAttestation(makeResponse(), clientNonce, {
      expectedMeasurements: { mrTd: 'f'.repeat(96) },
    });
    expect(result.measurementsVerified).toBe(false);
    expect(result.errors).toContainEqual(expect.stringContaining('mrTd'));
  });

  it('reports dcap verifier failure', async () => {
    const failingVerifier = async () => {
      throw new Error('PCK cert chain invalid');
    };
    const result = await verifyAttestation(
      makeResponse(),
      clientNonce,
      failingVerifier
    );
    expect(result.errors).toContainEqual(
      expect.stringContaining('DCAP verification failed: PCK cert chain invalid')
    );
    expect(result.dcap).toBeUndefined();
  });

  it('rejects an unknown DCAP TCB status', async () => {
    const result = await verifyAttestation(
      makeResponse(),
      clientNonce,
      async () => ({ status: 'Unknown', advisoryIds: [] })
    );
    expect(result.dcapVerified).toBe(false);
    expect(result.errors).toContainEqual(expect.stringContaining('unacceptable TCB status'));
  });

  it('skips dcap when no verifier provided', async () => {
    const result = await verifyAttestation(makeResponse(), clientNonce);
    expect(result.dcap).toBeUndefined();
  });
});
