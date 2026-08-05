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
 *  - The verdict is still NRAS's rather than yours. By default the returned
 *    tokens are authenticated by TLS to nras.attestation.nvidia.com. Pass a
 *    `tokenVerifier` from `createNrasTokenVerifier()` to check every ES384
 *    signature against NVIDIA's JWKS as well.
 *  - Nothing in the GPU evidence binds it to the TDX quote in the same
 *    attestation response. A shared nonce shows both were produced for the same
 *    request; it does not show they came from the same machine.
 */
import type { GpuVerifier } from './types.js';
import { type NrasTokenVerifier } from './nras-jwks.js';
/** NVIDIA's public Remote Attestation Service endpoint for GPU evidence. */
export declare const NRAS_GPU_URL = "https://nras.attestation.nvidia.com/v3/attest/gpu";
export interface NvidiaVerifierOptions {
    /** Override the NRAS endpoint (self-hosted verifier, or a test double). */
    nrasUrl?: string;
    /** Override the fetch implementation. Defaults to global fetch. */
    fetchImpl?: typeof fetch;
    /**
     * Verify each returned token's signature against NVIDIA's published keys,
     * instead of relying on TLS to NRAS alone. Any token that fails rejects the
     * whole result, so there is no path where an unverified token is used.
     *
     * ```ts
     * import { createNvidiaVerifier, createNrasTokenVerifier } from 'venice-e2ee/nvidia';
     * const gpuVerifier = createNvidiaVerifier({ tokenVerifier: createNrasTokenVerifier() });
     * ```
     */
    tokenVerifier?: NrasTokenVerifier;
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
export { createNrasTokenVerifier, NRAS_JWKS_URL, NRAS_ISSUER, type NrasTokenVerifier, type NrasTokenVerifierOptions, type VerifiedNrasToken, } from './nras-jwks.js';
//# sourceMappingURL=nvidia.d.ts.map