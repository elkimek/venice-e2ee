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
import type { DcapVerifier } from './types.js';
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
export declare function createDcapVerifier(pccsUrl?: string): DcapVerifier;
export type { DcapVerifier, DcapVerifyResult } from './types.js';
//# sourceMappingURL=dcap.d.ts.map