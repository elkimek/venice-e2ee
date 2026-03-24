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

  it('skips dcap when no verifier provided', async () => {
    const result = await verifyAttestation(makeResponse(), clientNonce);
    expect(result.dcap).toBeUndefined();
  });
});
