/**
 * NVIDIA GPU attestation via NVIDIA's Remote Attestation Service (NRAS).
 *
 * This module provides a GpuVerifier function that can be passed to
 * createVeniceE2EE({ gpuVerifier }). It submits the `nvidia_payload` from the
 * attestation response to NRAS and returns the claims NVIDIA asserts about the
 * GPUs that produced it. Policy — whether those claims are acceptable, and
 * whether `eat_nonce` matches the nonce actually sent — is applied by
 * `verifyAttestation`, which is the only place that holds the client nonce.
 *
 * Usage:
 *   import { createNvidiaVerifier } from 'venice-e2ee/nvidia';
 *   const e2ee = createVeniceE2EE({ apiKey, gpuVerifier: createNvidiaVerifier() });
 *
 * What this establishes, and what it does not:
 *
 *  - NRAS validates the GPU's attestation report against the endorsement
 *    certificate chain rooted in a key NVIDIA burns into the die, and against
 *    NVIDIA's reference measurements (RIM) for the running VBIOS and driver.
 *    That is a real root of trust, and a stronger statement than a provider's
 *    own claim about its hardware.
 *  - The verdict is still NRAS's rather than yours. The returned tokens are
 *    signed (ES384), but this module authenticates them by TLS to
 *    nras.attestation.nvidia.com rather than by checking that signature, so a
 *    relayed or cached token proves nothing here. `rawTokens` is exposed for
 *    callers who want to verify the signature against NVIDIA's JWKS themselves.
 *  - Nothing in the GPU evidence binds it to the TDX quote in the same
 *    attestation response. A shared nonce shows both were produced for the same
 *    request; it does not show they came from the same machine.
 */
import type { GpuVerifier } from './types.js';
/** NVIDIA's public Remote Attestation Service endpoint for GPU evidence. */
export declare const NRAS_GPU_URL = "https://nras.attestation.nvidia.com/v3/attest/gpu";
export interface NvidiaVerifierOptions {
    /** Override the NRAS endpoint (self-hosted verifier, or a test double). */
    nrasUrl?: string;
    /** Override the fetch implementation. Defaults to global fetch. */
    fetchImpl?: typeof fetch;
}
/**
 * Create a GPU verifier backed by NVIDIA's Remote Attestation Service.
 *
 * The returned function takes the raw `nvidia_payload` string exactly as Venice
 * served it — it is already the JSON body NRAS expects, and is forwarded
 * verbatim so no re-serialization can alter what NVIDIA signs over.
 */
export declare function createNvidiaVerifier(options?: NvidiaVerifierOptions): GpuVerifier;
export type { GpuVerifier, GpuVerifyResult, NvidiaGpuClaims } from './types.js';
//# sourceMappingURL=nvidia.d.ts.map