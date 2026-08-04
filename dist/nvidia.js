/** NVIDIA's public Remote Attestation Service endpoint for GPU evidence. */
export const NRAS_GPU_URL = 'https://nras.attestation.nvidia.com/v3/attest/gpu';
/**
 * Decode a JWT payload WITHOUT verifying its signature.
 *
 * Authentication here comes from TLS to NRAS, not from this decode. Callers who
 * need a self-standing proof should verify `rawTokens` against NVIDIA's JWKS.
 */
function decodeJwtClaims(token) {
    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new Error('NRAS returned a token that is not a JWT');
    }
    const padded = parts[1].replace(/-/g, '+').replace(/_/g, '/')
        .padEnd(parts[1].length + ((4 - (parts[1].length % 4)) % 4), '=');
    let json;
    try {
        const binary = atob(padded);
        const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
        json = new TextDecoder().decode(bytes);
    }
    catch {
        throw new Error('NRAS token payload is not valid base64url');
    }
    const claims = JSON.parse(json);
    if (typeof claims !== 'object' || claims === null) {
        throw new Error('NRAS token payload is not a JSON object');
    }
    return claims;
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
    if (!Array.isArray(head) || typeof head[1] !== 'string') {
        throw new Error('NRAS response carries no overall attestation token');
    }
    const tail = body[1];
    if (typeof tail !== 'object' || tail === null) {
        throw new Error('NRAS response carries no per-GPU tokens');
    }
    const perGpu = {};
    for (const [name, token] of Object.entries(tail)) {
        if (typeof token === 'string')
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
    const { nrasUrl = NRAS_GPU_URL, fetchImpl } = options;
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
        const overallClaims = decodeJwtClaims(overall);
        const gpus = {};
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
//# sourceMappingURL=nvidia.js.map