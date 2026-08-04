import { describe, it, expect } from 'vitest';
import { createNvidiaVerifier, NRAS_GPU_URL } from './nvidia.js';

// ── Helpers to build mock NRAS responses ──────────────────────────────

/** Encode claims as a JWT payload. The signature is never checked, so it is filler. */
function makeToken(claims: Record<string, unknown>): string {
  const b64url = (s: string) =>
    btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const header = b64url(JSON.stringify({ kid: 'test', alg: 'ES384' }));
  const payload = b64url(JSON.stringify(claims));
  return `${header}.${payload}.c2lnbmF0dXJl`;
}

const NONCE = 'a'.repeat(64);

function makeBundle(opts: {
  overall?: Record<string, unknown>;
  gpus?: Record<string, Record<string, unknown>>;
} = {}) {
  const overall = makeToken({
    sub: 'NVIDIA-PLATFORM-ATTESTATION',
    iss: 'https://nras.attestation.nvidia.com',
    'x-nvidia-overall-att-result': true,
    eat_nonce: NONCE,
    ...opts.overall,
  });
  const gpus = opts.gpus ?? {
    'GPU-0': {
      hwmodel: 'GH100 A01 GSP BROM',
      secboot: true,
      dbgstat: 'disabled',
      measres: 'success',
      'x-nvidia-gpu-attestation-report-nonce-match': true,
      eat_nonce: NONCE,
    },
  };
  return [
    ['JWT', overall],
    Object.fromEntries(Object.entries(gpus).map(([k, v]) => [k, makeToken(v)])),
  ];
}

/** A fetch double that records what it was called with. */
function stubFetch(body: unknown, init: { ok?: boolean; status?: number; text?: string } = {}) {
  const calls: Array<{ url: string; options: RequestInit }> = [];
  const impl = (async (url: string, options: RequestInit) => {
    calls.push({ url, options });
    return {
      ok: init.ok ?? true,
      status: init.status ?? 200,
      json: async () => body,
      text: async () => init.text ?? '',
    };
  }) as unknown as typeof fetch;
  return { impl, calls };
}

const PAYLOAD = JSON.stringify({ nonce: NONCE, arch: 'HOPPER', evidence_list: [{ evidence: 'x' }] });

describe('createNvidiaVerifier', () => {
  it('submits the payload verbatim to NRAS', async () => {
    const { impl, calls } = stubFetch(makeBundle());
    await createNvidiaVerifier({ fetchImpl: impl })(PAYLOAD);

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe(NRAS_GPU_URL);
    expect(calls[0].options.method).toBe('POST');
    // Byte-identical: re-serializing could change what NVIDIA signs over.
    expect(calls[0].options.body).toBe(PAYLOAD);
  });

  it('reports NVIDIA\'s verdict, nonce and per-GPU claims', async () => {
    const { impl } = stubFetch(makeBundle());
    const result = await createNvidiaVerifier({ fetchImpl: impl })(PAYLOAD);

    expect(result.overallResult).toBe(true);
    expect(result.eatNonce).toBe(NONCE);
    expect(result.arch).toBe('HOPPER');
    expect(result.gpus['GPU-0']).toEqual({
      hwModel: 'GH100 A01 GSP BROM',
      secureBoot: true,
      debugStatus: 'disabled',
      measurementResult: 'success',
      reportNonceMatch: true,
      eatNonce: NONCE,
    });
  });

  it('carries the raw tokens through for callers who verify signatures', async () => {
    const { impl } = stubFetch(makeBundle());
    const result = await createNvidiaVerifier({ fetchImpl: impl })(PAYLOAD);

    expect(result.rawTokens.overall.split('.')).toHaveLength(3);
    expect(result.rawTokens.perGpu['GPU-0'].split('.')).toHaveLength(3);
  });

  it('reports a negative overall verdict rather than throwing', async () => {
    const { impl } = stubFetch(makeBundle({ overall: { 'x-nvidia-overall-att-result': false } }));
    const result = await createNvidiaVerifier({ fetchImpl: impl })(PAYLOAD);
    expect(result.overallResult).toBe(false);
  });

  it('treats a missing overall verdict as not vouched for', async () => {
    const { impl } = stubFetch(makeBundle({ overall: { 'x-nvidia-overall-att-result': undefined } }));
    const result = await createNvidiaVerifier({ fetchImpl: impl })(PAYLOAD);
    expect(result.overallResult).toBe(false);
  });

  it('honours a custom NRAS endpoint', async () => {
    const { impl, calls } = stubFetch(makeBundle());
    await createNvidiaVerifier({ fetchImpl: impl, nrasUrl: 'https://verifier.internal/gpu' })(PAYLOAD);
    expect(calls[0].url).toBe('https://verifier.internal/gpu');
  });

  it('rejects a non-JSON payload before contacting NRAS', async () => {
    const { impl, calls } = stubFetch(makeBundle());
    await expect(createNvidiaVerifier({ fetchImpl: impl })('not json')).rejects.toThrow(
      /not valid JSON/
    );
    expect(calls).toHaveLength(0);
  });

  it('surfaces an NRAS error status', async () => {
    const { impl } = stubFetch(null, { ok: false, status: 422, text: 'bad evidence' });
    await expect(createNvidiaVerifier({ fetchImpl: impl })(PAYLOAD)).rejects.toThrow(
      /NRAS rejected the GPU evidence \(422\)/
    );
  });

  it('rejects a response that is not a detached EAT bundle', async () => {
    const { impl } = stubFetch({ unexpected: true });
    await expect(createNvidiaVerifier({ fetchImpl: impl })(PAYLOAD)).rejects.toThrow(
      /not a detached EAT bundle/
    );
  });

  it('rejects a bundle whose overall token is not a JWT', async () => {
    const { impl } = stubFetch([['JWT', 'nonsense'], {}]);
    await expect(createNvidiaVerifier({ fetchImpl: impl })(PAYLOAD)).rejects.toThrow(
      /well-formed JWT/
    );
  });

  it('reports that signatures went unchecked when no token verifier is set', async () => {
    const { impl } = stubFetch(makeBundle());
    const result = await createNvidiaVerifier({ fetchImpl: impl })(PAYLOAD);
    expect(result.tokensVerified).toBe(false);
  });

  it('runs the token verifier over the overall and every per-GPU token', async () => {
    const seen: string[] = [];
    const { impl } = stubFetch(
      makeBundle({
        gpus: {
          'GPU-0': { secboot: true, dbgstat: 'disabled', measres: 'success' },
          'GPU-1': { secboot: true, dbgstat: 'disabled', measres: 'success' },
        },
      })
    );
    const result = await createNvidiaVerifier({
      fetchImpl: impl,
      tokenVerifier: async (token) => {
        seen.push(token);
        const payload = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
        return {
          claims: JSON.parse(atob(payload.padEnd(payload.length + ((4 - (payload.length % 4)) % 4), '='))),
          kid: 'test',
          chainSha256: [],
        };
      },
    })(PAYLOAD);

    expect(seen).toHaveLength(3); // overall + 2 GPUs
    expect(result.tokensVerified).toBe(true);
    expect(result.overallResult).toBe(true);
  });

  it('fails the whole result when any token fails verification', async () => {
    const { impl } = stubFetch(makeBundle());
    await expect(
      createNvidiaVerifier({
        fetchImpl: impl,
        tokenVerifier: async () => {
          throw new Error('signature does not verify under key nv-eat-kid-prod');
        },
      })(PAYLOAD)
    ).rejects.toThrow(/signature does not verify/);
  });

  it('reads every GPU in a multi-GPU node', async () => {
    const gpus = Object.fromEntries(
      Array.from({ length: 8 }, (_, i) => [
        `GPU-${i}`,
        { hwmodel: 'GH100', secboot: true, dbgstat: 'disabled', measres: 'success', eat_nonce: NONCE },
      ])
    );
    const { impl } = stubFetch(makeBundle({ gpus }));
    const result = await createNvidiaVerifier({ fetchImpl: impl })(PAYLOAD);
    expect(Object.keys(result.gpus)).toHaveLength(8);
  });
});
