import { describe, it, expect } from 'vitest';
import {
  base64UrlToBytes,
  certificateValidity,
  createNrasTokenVerifier,
  NRAS_ISSUER,
} from './nras-jwks.js';

/**
 * A real NRAS signing certificate, fetched from NVIDIA's key set.
 * kid nv-eat-kid-prod-20260804094140946-9e0f8319-7775-4eb3-87fd-425b4206d7e7
 *
 * openssl reads its window as:
 *   notBefore=Aug  4 09:41:05 2026 GMT
 *   notAfter =Aug  6 09:41:35 2026 GMT
 */
const REAL_NVIDIA_CERT_B64 =
  'MIIDDjCCAfagAwIBAgIUdZ/LCJzG7ej2EjSiVTutJUwx/eowDQYJKoZIhvcNAQELBQAwZDE4MDYGA1UEAwwvTlZJRElBIEF0dGVz' +
  'dGF0aW9uIFNlcnZpY2UgR1BVIEludGVybWVkaWF0ZSAwMDQxGzAZBgNVBAoMEk5WSURJQSBDb3Jwb3JhdGlvbjELMAkGA1UEBhMC' +
  'VVMwHhcNMjYwODA0MDk0MTA1WhcNMjYwODA2MDk0MTM1WjBZMQswCQYDVQQGEwJVUzEbMBkGA1UEChMSTlZJRElBIENvcnBvcmF0' +
  'aW9uMS0wKwYDVQQDEyROVklESUEgQXR0ZXN0YXRpb24gU2VydmljZSBHUFUgR0gxMDAwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATc' +
  'QXVxRD5tAitMkzp3rRaJpbI1AZjFCkSUiux5RuVNw4l65drL8ndB7LgRmSGJwz/jWnANm/n8mmEJfbHK93p3Fio7Ns2/QzJg8Wi4' +
  'jCH6p/CcK0tPRZLZR5Cf39+YuSijcTBvMA4GA1UdDwEB/wQEAwIDqDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHQYD' +
  'VR0OBBYEFOOXAk4BYAAzw90OziYVC4Esr+hRMB8GA1UdIwQYMBaAFPqoANOPTac6XGds31E7pGryjK7dMA0GCSqGSIb3DQEBCwUA' +
  'A4IBAQCqUVrOTzu0Ddd8wcT3gyS29QXU2KwYzX9DnipIc1oi9JmPz4TKDE8bs9lNcEwmcnKmdVqnnDQotBjyr6EhDuPAxcL3MutI' +
  'vYjg5A8HUOrUc3ivn44zP1/gIX6glvM+19Crou3Pl0gcrwbv7KGHQjRDaAonEjR/jWH0NzjLJMhoSlH9AhUQ6iTWCQqr7IXSvenf' +
  'Q1JlEXfI019GDXghOH7KI/pvTCLCIYFt6XhadOphiiLNMlGBPpUeN45XPMMIaKS07x4JJZF6AWLpq/8tgm4uXehrH3eoV5zumx3M' +
  'G2GLw/UWHLEUlmI1k1cdAzARv0WCw8A1ejFyEbdUxyPpCKBM';

describe('certificateValidity', () => {
  it('agrees with openssl on a real NVIDIA signing certificate', () => {
    const der = Uint8Array.from(atob(REAL_NVIDIA_CERT_B64), (c) => c.charCodeAt(0));
    const { notBefore, notAfter } = certificateValidity(der);
    expect(new Date(notBefore).toISOString()).toBe('2026-08-04T09:41:05.000Z');
    expect(new Date(notAfter).toISOString()).toBe('2026-08-06T09:41:35.000Z');
  });

  it('confirms NVIDIA issues these for about 48 hours', () => {
    const der = Uint8Array.from(atob(REAL_NVIDIA_CERT_B64), (c) => c.charCodeAt(0));
    const { notBefore, notAfter } = certificateValidity(der);
    expect((notAfter - notBefore) / 3_600_000).toBeCloseTo(48, 1);
  });

  it('refuses a truncated certificate rather than guessing', () => {
    const der = Uint8Array.from(atob(REAL_NVIDIA_CERT_B64), (c) => c.charCodeAt(0));
    expect(() => certificateValidity(der.subarray(0, 40))).toThrow(/truncated/);
  });

  it('refuses something that is not a certificate', () => {
    expect(() => certificateValidity(new TextEncoder().encode('nope nope nope'))).toThrow();
  });
});

// These tests sign with a real P-384 key and verify through Web Crypto, so the
// signature path is exercised rather than stubbed. A test that mocks the
// signature check would pass just as happily with the check removed.

const KEY_PAIR = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-384' },
  true,
  ['sign', 'verify']
);
const OTHER_PAIR = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-384' },
  true,
  ['sign', 'verify']
);

const KID = 'nv-eat-kid-test-0001';
const NOW_MS = 1_760_000_000_000;
/** Mirrors MIN_REFETCH_INTERVAL_MS in the module under test. */
const MIN_REFETCH_MS = 30 * 1000;
const nowSec = Math.floor(NOW_MS / 1000);

function b64url(bytes: Uint8Array | string): string {
  const binary = typeof bytes === 'string'
    ? bytes
    : Array.from(bytes, (b) => String.fromCharCode(b)).join('');
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function jwkFor(pair: CryptoKeyPair) {
  return (await crypto.subtle.exportKey('jwk', pair.publicKey)) as { x: string; y: string };
}

/** Sign a real ES384 JWT. `signWith` may differ from the advertised kid. */
async function makeToken(
  claims: Record<string, unknown> = {},
  opts: { alg?: string; kid?: string; signWith?: CryptoKeyPair; tamper?: boolean } = {}
): Promise<string> {
  const header = b64url(JSON.stringify({ alg: opts.alg ?? 'ES384', kid: opts.kid ?? KID }));
  const payload = b64url(
    JSON.stringify({
      iss: NRAS_ISSUER,
      iat: nowSec - 10,
      nbf: nowSec - 10,
      exp: nowSec + 3600,
      'x-nvidia-overall-att-result': true,
      ...claims,
    })
  );
  const signingInput = new TextEncoder().encode(`${header}.${payload}`);
  const sig = new Uint8Array(
    await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-384' },
      (opts.signWith ?? KEY_PAIR).privateKey,
      signingInput
    )
  );
  if (opts.tamper) sig[0] ^= 0xff;
  return `${header}.${payload}.${b64url(sig)}`;
}

async function jwksBody(extra: Record<string, unknown> = {}) {
  const jwk = await jwkFor(KEY_PAIR);
  return { keys: [{ kty: 'EC', crv: 'P-384', kid: KID, x: jwk.x, y: jwk.y, ...extra }] };
}

function stubFetch(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  const calls: string[] = [];
  const impl = (async (url: string) => {
    calls.push(url);
    return {
      ok: init.ok ?? true,
      status: init.status ?? 200,
      json: async () => body,
      text: async () => '',
    };
  }) as unknown as typeof fetch;
  return { impl, calls };
}

async function verifierWith(body: unknown, opts: Record<string, unknown> = {}) {
  const { impl, calls } = stubFetch(body);
  const verify = createNrasTokenVerifier({ fetchImpl: impl, now: () => NOW_MS, ...opts });
  return { verify, calls };
}

describe('createNrasTokenVerifier', () => {
  it('verifies a correctly signed token', async () => {
    const { verify } = await verifierWith(await jwksBody());
    const result = await verify(await makeToken());
    expect(result.kid).toBe(KID);
    expect(result.claims['x-nvidia-overall-att-result']).toBe(true);
  });

  it('rejects a tampered signature', async () => {
    const { verify } = await verifierWith(await jwksBody());
    await expect(verify(await makeToken({}, { tamper: true }))).rejects.toThrow(
      /signature does not verify/
    );
  });

  it('rejects a token signed by a different key', async () => {
    const { verify } = await verifierWith(await jwksBody());
    await expect(verify(await makeToken({}, { signWith: OTHER_PAIR }))).rejects.toThrow(
      /signature does not verify/
    );
  });

  it('rejects a payload edited after signing', async () => {
    const { verify } = await verifierWith(await jwksBody());
    const token = await makeToken({ 'x-nvidia-overall-att-result': false });
    const [h, , s] = token.split('.');
    const forged = b64url(
      JSON.stringify({ iss: NRAS_ISSUER, exp: nowSec + 3600, 'x-nvidia-overall-att-result': true })
    );
    await expect(verify(`${h}.${forged}.${s}`)).rejects.toThrow(/signature does not verify/);
  });

  it('refuses alg=none rather than accepting an unsigned token', async () => {
    const { verify } = await verifierWith(await jwksBody());
    const header = b64url(JSON.stringify({ alg: 'none', kid: KID }));
    const payload = b64url(JSON.stringify({ iss: NRAS_ISSUER }));
    await expect(verify(`${header}.${payload}.x`)).rejects.toThrow(/unexpected algorithm none/);
  });

  it('refuses an algorithm downgrade', async () => {
    const { verify } = await verifierWith(await jwksBody());
    await expect(verify(await makeToken({}, { alg: 'HS256' }))).rejects.toThrow(
      /unexpected algorithm HS256/
    );
  });

  it('rejects a token whose kid is not in the key set', async () => {
    const { verify } = await verifierWith(await jwksBody());
    await expect(verify(await makeToken({}, { kid: 'unknown-kid' }))).rejects.toThrow(
      /no key for kid unknown-kid/
    );
  });

  it('rejects an unexpected issuer', async () => {
    const { verify } = await verifierWith(await jwksBody());
    await expect(verify(await makeToken({ iss: 'https://evil.example' }))).rejects.toThrow(
      /issuer is https:\/\/evil.example/
    );
  });

  it('rejects an expired token', async () => {
    const { verify } = await verifierWith(await jwksBody());
    await expect(verify(await makeToken({ exp: nowSec - 3600 }))).rejects.toThrow(/has expired/);
  });

  it('rejects a token that is not valid yet', async () => {
    const { verify } = await verifierWith(await jwksBody());
    await expect(verify(await makeToken({ nbf: nowSec + 3600 }))).rejects.toThrow(/not valid yet/);
  });

  it('tolerates small clock skew around exp', async () => {
    const { verify } = await verifierWith(await jwksBody());
    await expect(verify(await makeToken({ exp: nowSec - 30 }))).resolves.toBeDefined();
  });

  it('rejects anything that is not a JWT', async () => {
    const { verify } = await verifierWith(await jwksBody());
    await expect(verify('not.a')).rejects.toThrow(/well-formed JWT/);
    await expect(verify('')).rejects.toThrow(/well-formed JWT/);
  });

  it('caches the key set across tokens', async () => {
    const { verify, calls } = await verifierWith(await jwksBody());
    await verify(await makeToken());
    await verify(await makeToken());
    expect(calls).toHaveLength(1);
  });

  // ── Cache refresh: two mechanisms, two jobs ─────────────────────────
  //
  // Unknown kid catches keys being added. Only TTL expiry catches keys being
  // removed, which is why both exist.

  /** A fetch double whose body and clock can move between calls. */
  function movingFetch(bodies: unknown[]) {
    const calls: string[] = [];
    const impl = (async (url: string) => {
      calls.push(url);
      const body = bodies[Math.min(calls.length - 1, bodies.length - 1)];
      return { ok: true, status: 200, json: async () => body, text: async () => '' };
    }) as unknown as typeof fetch;
    return { impl, calls };
  }

  it('refetches when a token names a kid it does not hold', async () => {
    const rotated = await jwkFor(OTHER_PAIR);
    const { impl, calls } = movingFetch([
      await jwksBody(),
      { keys: [{ kty: 'EC', crv: 'P-384', kid: 'rotated-kid', x: rotated.x, y: rotated.y }] },
    ]);
    let clock = NOW_MS;
    const verify = createNrasTokenVerifier({ fetchImpl: impl, now: () => clock });

    await verify(await makeToken());
    expect(calls).toHaveLength(1);

    clock += MIN_REFETCH_MS + 1000; // past the anti-flood gap, still inside the TTL
    const rotatedToken = await makeToken({}, { kid: 'rotated-kid', signWith: OTHER_PAIR });
    await expect(verify(rotatedToken)).resolves.toBeDefined();
    expect(calls).toHaveLength(2);
  });

  it('does not refetch on a burst of unknown kids', async () => {
    const { impl, calls } = movingFetch([await jwksBody()]);
    const verify = createNrasTokenVerifier({ fetchImpl: impl, now: () => NOW_MS });

    await verify(await makeToken());
    for (let i = 0; i < 5; i++) {
      await expect(verify(await makeToken({}, { kid: `junk-${i}` }))).rejects.toThrow(/no key/);
    }
    expect(calls).toHaveLength(1);
  });

  it('drops a key withdrawn from the key set once the TTL expires', async () => {
    // The case an unknown-kid-only cache can never see: the kid stays known, so
    // nothing prompts a refetch, and a revoked key keeps verifying forever.
    const { impl, calls } = movingFetch([await jwksBody(), { keys: [{ kty: 'EC', crv: 'P-384', kid: 'other', x: 'a', y: 'b' }] }]);
    let clock = NOW_MS;
    const verify = createNrasTokenVerifier({
      fetchImpl: impl,
      cacheTtlMs: 15 * 60 * 1000,
      now: () => clock,
    });

    await expect(verify(await makeToken())).resolves.toBeDefined();
    expect(calls).toHaveLength(1);

    clock += 15 * 60 * 1000 + 1;
    await expect(verify(await makeToken())).rejects.toThrow(new RegExp(`no key for kid ${KID}`));
    expect(calls).toHaveLength(2);
  });

  it('keeps honouring a still-published key across TTL expiry', async () => {
    const { impl, calls } = movingFetch([await jwksBody()]);
    let clock = NOW_MS;
    const verify = createNrasTokenVerifier({
      fetchImpl: impl,
      cacheTtlMs: 15 * 60 * 1000,
      now: () => clock,
    });

    await verify(await makeToken());
    clock += 15 * 60 * 1000 + 1;
    await expect(verify(await makeToken())).resolves.toBeDefined();
    expect(calls).toHaveLength(2);
  });

  it('rate-limits retries while the key set is failing', async () => {
    const calls: string[] = [];
    const impl = (async (url: string) => {
      calls.push(url);
      return { ok: false, status: 503, json: async () => null, text: async () => '' };
    }) as unknown as typeof fetch;
    let clock = NOW_MS;
    const verify = createNrasTokenVerifier({ fetchImpl: impl, now: () => clock });

    // A failing NVIDIA must not have every waiting session retry at once.
    await expect(verify(await makeToken())).rejects.toThrow(/503/);
    await expect(verify(await makeToken())).rejects.toThrow();
    await expect(verify(await makeToken())).rejects.toThrow();
    expect(calls.length).toBeLessThan(3);
  });

  it('surfaces a JWKS fetch failure instead of skipping verification', async () => {
    const { impl } = stubFetch(null, { ok: false, status: 503 });
    const verify = createNrasTokenVerifier({ fetchImpl: impl, now: () => NOW_MS });
    await expect(verify(await makeToken())).rejects.toThrow(/Could not fetch NVIDIA JWKS \(503\)/);
  });

  it('rejects a key set with no keys', async () => {
    const { verify } = await verifierWith({ keys: [] });
    await expect(verify(await makeToken())).rejects.toThrow(/no usable keys/);
  });

  describe('certificate handling', () => {
    // Builds a structurally real DER certificate. A stub blob would sail past a
    // parser that never descends, so the fixture has to have the shape.
    function tlv(tag: number, content: Uint8Array): Uint8Array {
      const len = content.length;
      const header =
        len < 0x80
          ? [tag, len]
          : len < 0x100
            ? [tag, 0x81, len]
            : [tag, 0x82, (len >> 8) & 0xff, len & 0xff];
      return new Uint8Array([...header, ...content]);
    }

    const cat = (...parts: Uint8Array[]) => {
      const total = parts.reduce((n, p) => n + p.length, 0);
      const out = new Uint8Array(total);
      let at = 0;
      for (const p of parts) {
        out.set(p, at);
        at += p.length;
      }
      return out;
    };

    /** UTCTime, as RFC 5280 requires for dates before 2050. */
    function utcTime(ms: number): Uint8Array {
      const d = new Date(ms);
      const p = (n: number) => String(n).padStart(2, '0');
      const text =
        `${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}` +
        `${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
      return tlv(0x17, new TextEncoder().encode(text));
    }

    async function buildCert(opts: { notBefore: number; notAfter: number }): Promise<Uint8Array> {
      const jwk = await jwkFor(KEY_PAIR);
      const point = cat(
        new Uint8Array([0x04]),
        base64UrlToBytes(jwk.x),
        base64UrlToBytes(jwk.y)
      );
      const tbs = tlv(
        0x30,
        cat(
          tlv(0xa0, tlv(0x02, new Uint8Array([2]))), // version
          tlv(0x02, new Uint8Array([1])), // serialNumber
          tlv(0x30, new Uint8Array()), // signature algorithm
          tlv(0x30, new Uint8Array()), // issuer
          tlv(0x30, cat(utcTime(opts.notBefore), utcTime(opts.notAfter))),
          tlv(0x30, new Uint8Array()), // subject
          tlv(0x03, cat(new Uint8Array([0x00]), point)) // SPKI bit string
        )
      );
      return tlv(0x30, tbs);
    }

    /** A certificate valid around the frozen test clock, as NVIDIA issues them. */
    async function chainBody(window?: { notBefore: number; notAfter: number }) {
      const der = await buildCert(
        window ?? { notBefore: NOW_MS - 3600_000, notAfter: NOW_MS + 44 * 3600_000 }
      );
      const b64 = btoa(Array.from(der, (b) => String.fromCharCode(b)).join(''));
      const digest = Array.from(
        new Uint8Array(await crypto.subtle.digest('SHA-256', der.buffer as ArrayBuffer)),
        (b) => b.toString(16).padStart(2, '0')
      ).join('');
      return { body: await jwksBody({ x5c: [b64] }), digest };
    }

    it('accepts a certificate inside its validity window', async () => {
      const { body } = await chainBody();
      const { verify } = await verifierWith(body);
      await expect(verify(await makeToken())).resolves.toBeDefined();
    });

    it('rejects a token signed by an expired certificate', async () => {
      // The bound that lets the key set be cached for hours rather than minutes:
      // a withdrawn key stops working on NVIDIA's ~48h schedule regardless.
      const { body } = await chainBody({
        notBefore: NOW_MS - 72 * 3600_000,
        notAfter: NOW_MS - 24 * 3600_000,
      });
      const { verify } = await verifierWith(body);
      await expect(verify(await makeToken())).rejects.toThrow(/certificate for kid .* expired at/);
    });

    it('rejects a certificate that is not valid yet', async () => {
      const { body } = await chainBody({
        notBefore: NOW_MS + 24 * 3600_000,
        notAfter: NOW_MS + 72 * 3600_000,
      });
      const { verify } = await verifierWith(body);
      await expect(verify(await makeToken())).rejects.toThrow(/is not valid until/);
    });

    it('tolerates clock skew at the expiry boundary', async () => {
      const { body } = await chainBody({
        notBefore: NOW_MS - 48 * 3600_000,
        notAfter: NOW_MS - 30_000,
      });
      const { verify } = await verifierWith(body);
      await expect(verify(await makeToken())).resolves.toBeDefined();
    });

    it('accepts a chain containing the pinned certificate', async () => {
      const { body, digest } = await chainBody();
      const { verify } = await verifierWith(body, { pinnedCertSha256: [digest] });
      await expect(verify(await makeToken())).resolves.toBeDefined();
    });

    it('rejects a chain that lacks every pinned certificate', async () => {
      const { body } = await chainBody();
      const { verify } = await verifierWith(body, { pinnedCertSha256: ['00'.repeat(32)] });
      await expect(verify(await makeToken())).rejects.toThrow(/none of the pinned certificates/);
    });

    it('reports the chain digests for an operator to pin', async () => {
      const { body, digest } = await chainBody();
      const { verify } = await verifierWith(body);
      const result = await verify(await makeToken());
      expect(result.chainSha256).toEqual([digest]);
    });

    it('rejects a chain whose leaf does not carry the JWK key', async () => {
      const junk = btoa('not a certificate carrying that point');
      const { verify } = await verifierWith(await jwksBody({ x5c: [junk] }));
      await expect(verify(await makeToken())).rejects.toThrow(/does not carry the JWK public key/);
    });
  });
});
