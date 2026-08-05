import { decodeJsonSegment, splitJwt } from './nras-jwks.js';
/** NVIDIA's public Remote Attestation Service endpoint for GPU evidence. */
export const NRAS_GPU_URL = 'https://nras.attestation.nvidia.com/v3/attest/gpu';
/**
 * Decode a JWT payload WITHOUT verifying its signature.
 *
 * Used only when no `tokenVerifier` is configured, where authentication comes
 * from TLS to NRAS rather than from this decode.
 */
function decodeJwtClaims(token) {
    const { payload } = splitJwt(token);
    return decodeJsonSegment(payload, 'payload');
}
function readString(claims, key) {
    const v = claims[key];
    return typeof v === 'string' ? v : null;
}
function readBoolean(claims, key) {
    const v = claims[key];
    return typeof v === 'boolean' ? v : null;
}
function toGpuClaims(claims) {
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
function parseNrasResponse(body) {
    if (!Array.isArray(body) || body.length < 2) {
        throw new Error('NRAS response is not a detached EAT bundle');
    }
    const head = body[0];
    if (!Array.isArray(head) || head[0] !== 'JWT' || typeof head[1] !== 'string') {
        throw new Error('NRAS response carries no overall attestation token');
    }
    const tail = body[1];
    if (typeof tail !== 'object' || tail === null || Array.isArray(tail)) {
        throw new Error('NRAS response carries no per-GPU tokens');
    }
    const perGpu = {};
    for (const [name, token] of Object.entries(tail)) {
        if (typeof token !== 'string') {
            throw new Error(`NRAS response carries an invalid token for GPU ${name}`);
        }
        perGpu[name] = token;
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
export function createNvidiaVerifier(options = {}) {
    const { nrasUrl = NRAS_GPU_URL, fetchImpl, tokenVerifier } = options;
    return async (nvidiaPayload) => {
        const doFetch = fetchImpl ?? globalThis.fetch;
        if (!doFetch) {
            throw new Error('No fetch implementation available for NRAS verification');
        }
        // `arch` is read for reporting only. The payload itself is forwarded
        // untouched; parsing it here must never change what gets submitted.
        let arch = null;
        try {
            const parsed = JSON.parse(nvidiaPayload);
            arch = typeof parsed.arch === 'string' ? parsed.arch : null;
        }
        catch {
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
        // Every token is verified, not just the overall one: the per-GPU tokens
        // carry the secboot/dbgstat/measres claims the policy acts on.
        const readClaims = tokenVerifier
            ? async (token) => (await tokenVerifier(token)).claims
            : async (token) => decodeJwtClaims(token);
        const overallClaims = await readClaims(overall);
        const gpus = {};
        for (const [name, token] of Object.entries(perGpu)) {
            gpus[name] = toGpuClaims(await readClaims(token));
        }
        return {
            overallResult: readBoolean(overallClaims, 'x-nvidia-overall-att-result') === true,
            eatNonce: readString(overallClaims, 'eat_nonce'),
            arch,
            gpus,
            tokensVerified: tokenVerifier !== undefined,
            rawTokens: { overall, perGpu },
        };
    };
}
export { createNrasTokenVerifier, NRAS_JWKS_URL, NRAS_ISSUER, } from './nras-jwks.js';
//# sourceMappingURL=nvidia.js.map