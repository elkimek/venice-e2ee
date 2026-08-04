import { describe, it, expect } from 'vitest';
import { base64UrlToBytes, createNrasTokenVerifier, NRAS_ISSUER } from './nras-jwks.js';

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

  it('surfaces a JWKS fetch failure instead of skipping verification', async () => {
    const { impl } = stubFetch(null, { ok: false, status: 503 });
    const verify = createNrasTokenVerifier({ fetchImpl: impl, now: () => NOW_MS });
    await expect(verify(await makeToken())).rejects.toThrow(/Could not fetch NVIDIA JWKS \(503\)/);
  });

  it('rejects a key set with no keys', async () => {
    const { verify } = await verifierWith({ keys: [] });
    await expect(verify(await makeToken())).rejects.toThrow(/no usable keys/);
  });

  describe('certificate pinning', () => {
    // A DER blob that embeds the uncompressed EC point, standing in for the
    // leaf certificate. sha256 of it is what an operator would pin.
    async function chainBody() {
      const jwk = await jwkFor(KEY_PAIR);
      const x = base64UrlToBytes(jwk.x);
      const y = base64UrlToBytes(jwk.y);
      const der = new Uint8Array(8 + 1 + x.length + y.length);
      der.set([0x30, 0x82, 0x01, 0x00, 0xa0, 0x03, 0x02, 0x01], 0);
      der[8] = 0x04;
      der.set(x, 9);
      der.set(y, 9 + x.length);
      const b64 = btoa(Array.from(der, (b) => String.fromCharCode(b)).join(''));
      const digest = Array.from(
        new Uint8Array(await crypto.subtle.digest('SHA-256', der.buffer as ArrayBuffer)),
        (b) => b.toString(16).padStart(2, '0')
      ).join('');
      return { body: await jwksBody({ x5c: [b64] }), digest };
    }

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
