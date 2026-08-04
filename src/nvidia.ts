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
import type { GpuVerifier, GpuVerifyResult, NvidiaGpuClaims } from './types.js';

/** NVIDIA's public Remote Attestation Service endpoint for GPU evidence. */
export const NRAS_GPU_URL = 'https://nras.attestation.nvidia.com/v3/attest/gpu';

export interface NvidiaVerifierOptions {
  /** Override the NRAS endpoint (self-hosted verifier, or a test double). */
  nrasUrl?: string;
  /** Override the fetch implementation. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

/**
 * Decode a JWT payload WITHOUT verifying its signature.
 *
 * Authentication here comes from TLS to NRAS, not from this decode. Callers who
 * need a self-standing proof should verify `rawTokens` against NVIDIA's JWKS.
 */
function decodeJwtClaims(token: string): Record<string, unknown> {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('NRAS returned a token that is not a JWT');
  }
  const padded = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    .padEnd(parts[1].length + ((4 - (parts[1].length % 4)) % 4), '=');
  let json: string;
  try {
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    json = new TextDecoder().decode(bytes);
  } catch {
    throw new Error('NRAS token payload is not valid base64url');
  }
  const claims = JSON.parse(json) as unknown;
  if (typeof claims !== 'object' || claims === null) {
    throw new Error('NRAS token payload is not a JSON object');
  }
  return claims as Record<string, unknown>;
}

function readString(claims: Record<string, unknown>, key: string): string | null {
  const v = claims[key];
  return typeof v === 'string' ? v : null;
}

function readBoolean(claims: Record<string, unknown>, key: string): boolean | null {
  const v = claims[key];
  return typeof v === 'boolean' ? v : null;
}

function toGpuClaims(claims: Record<string, unknown>): NvidiaGpuClaims {
  return {
    hwModel: readString(claims, 'hwmodel'),
    secureBoot: readBoolean(claims, 'secboot'),
    debugStatus: readString(claims, 'dbgstat'),
    measurementResult: readString(claims, 'measres'),
    reportNonceMatch: readBoolean(claims, 'x-nvidia-gpu-attestation-report-nonce-match'),
    eatNonce: readString(claims, 'eat_nonce'),
  };
}

/**
 * NRAS answers with a detached EAT bundle:
 *   [["JWT", "<overall token>"], { "GPU-0": "<token>", ... }]
 */
function parseNrasResponse(body: unknown): { overall: string; perGpu: Record<string, string> } {
  if (!Array.isArray(body) || body.length < 2) {
    throw new Error('NRAS response is not a detached EAT bundle');
  }
  const head = body[0];
  if (!Array.isArray(head) || typeof head[1] !== 'string') {
    throw new Error('NRAS response carries no overall attestation token');
  }
  const tail = body[1];
  if (typeof tail !== 'object' || tail === null) {
    throw new Error('NRAS response carries no per-GPU tokens');
  }
  const perGpu: Record<string, string> = {};
  for (const [name, token] of Object.entries(tail as Record<string, unknown>)) {
    if (typeof token === 'string') perGpu[name] = token;
  }
  return { overall: head[1], perGpu };
}

/**
 * Create a GPU verifier backed by NVIDIA's Remote Attestation Service.
 *
 * The returned function takes the raw `nvidia_payload` string exactly as Venice
 * served it — it is already the JSON body NRAS expects, and is forwarded
 * verbatim so no re-serialization can alter what NVIDIA signs over.
 */
export function createNvidiaVerifier(options: NvidiaVerifierOptions = {}): GpuVerifier {
  const { nrasUrl = NRAS_GPU_URL, fetchImpl } = options;

  return async (nvidiaPayload: string): Promise<GpuVerifyResult> => {
    const doFetch = fetchImpl ?? globalThis.fetch;
    if (!doFetch) {
      throw new Error('No fetch implementation available for NRAS verification');
    }

    // `arch` is read for reporting only. The payload itself is forwarded
    // untouched; parsing it here must never change what gets submitted.
    let arch: string | null = null;
    try {
      const parsed = JSON.parse(nvidiaPayload) as Record<string, unknown>;
      arch = typeof parsed.arch === 'string' ? parsed.arch : null;
    } catch {
      throw new Error('nvidia_payload is not valid JSON');
    }

    const response = await doFetch(nrasUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: nvidiaPayload,
    });

    if (!response.ok) {
      const detail = await response.text().catch(() => '');
      throw new Error(`NRAS rejected the GPU evidence (${response.status}): ${detail.slice(0, 200)}`);
    }

    const { overall, perGpu } = parseNrasResponse(await response.json());
    const overallClaims = decodeJwtClaims(overall);

    const gpus: Record<string, NvidiaGpuClaims> = {};
    for (const [name, token] of Object.entries(perGpu)) {
      gpus[name] = toGpuClaims(decodeJwtClaims(token));
    }

    return {
      overallResult: readBoolean(overallClaims, 'x-nvidia-overall-att-result') === true,
      eatNonce: readString(overallClaims, 'eat_nonce'),
      arch,
      gpus,
      rawTokens: { overall, perGpu },
    };
  };
}

export type { GpuVerifier, GpuVerifyResult, NvidiaGpuClaims } from './types.js';
