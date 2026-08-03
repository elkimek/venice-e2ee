/**
 * Full TDX DCAP quote verification using @phala/dcap-qvl.
 *
 * This module wraps @phala/dcap-qvl to provide a DcapVerifier function
 * that can be passed to createVeniceE2EE({ dcapVerifier }).
 *
 * @phala/dcap-qvl is an optional peer dependency — install it separately:
 *   npm install @phala/dcap-qvl
 *
 * Usage:
 *   import { createDcapVerifier } from 'venice-e2ee/dcap';
 *   const e2ee = createVeniceE2EE({ apiKey, dcapVerifier: createDcapVerifier() });
 */
import type { DcapVerifier, DcapVerifyResult } from './types.js';

interface PhalaDcapModule {
  PHALA_PCCS_URL: string;
  getCollateralAndVerify(
    quoteBytes: Uint8Array,
    pccsUrl: string
  ): Promise<{ status: unknown; advisory_ids?: unknown[] }>;
}

// Keep the package name indirect so TypeScript and browser bundlers do not
// require an optional peer dependency unless the verifier is actually used.
async function loadPhala(): Promise<PhalaDcapModule> {
  const packageName = '@phala/dcap-qvl';
  try {
    return await import(packageName) as PhalaDcapModule;
  } catch {
    throw new Error(
      '@phala/dcap-qvl is required for DCAP verification. Install it: npm install @phala/dcap-qvl'
    );
  }
}

/**
 * Create a DCAP verifier backed by @phala/dcap-qvl.
 *
 * Performs full Intel TDX DCAP verification:
 * - PCK certificate chain validation up to Intel SGX Root CA
 * - Quote signature verification (ECDSA P-256)
 * - QE identity validation
 * - TCB level evaluation
 * - CRL checking
 *
 * @param pccsUrl - PCCS server URL for collateral fetching. Default: Phala PCCS (https://pccs.phala.network)
 */
export function createDcapVerifier(pccsUrl?: string): DcapVerifier {
  return async (quoteBytes: Uint8Array): Promise<DcapVerifyResult> => {
    const phala = await loadPhala();
    const url = pccsUrl ?? phala.PHALA_PCCS_URL;
    const result = await phala.getCollateralAndVerify(quoteBytes, url);

    return {
      status: String(result.status),
      advisoryIds: Array.isArray(result.advisory_ids)
        ? result.advisory_ids.map(String)
        : [],
    };
  };
}

export type { DcapVerifier, DcapVerifyResult } from './types.js';
