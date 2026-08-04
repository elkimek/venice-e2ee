/**
 * Signature verification for NVIDIA attestation tokens (NRAS EATs).
 *
 * NRAS answers with ES384-signed JWTs. `createNvidiaVerifier()` on its own
 * authenticates them by TLS to nras.attestation.nvidia.com — sound for a call
 * you make yourself, and worth nothing for a token that reached you any other
 * way. This module checks the signature instead, against keys fetched from
 * NVIDIA's JWKS, which makes a token stand on its own: it can be relayed,
 * cached, logged, or handed on, and still be checkable.
 *
 * Usage:
 *   import { createNvidiaVerifier } from 'venice-e2ee/nvidia';
 *   import { createNrasTokenVerifier } from 'venice-e2ee/nvidia';
 *
 *   const gpuVerifier = createNvidiaVerifier({
 *     tokenVerifier: createNrasTokenVerifier(),
 *   });
 *
 * What this does and does not do:
 *
 *  - It verifies ES384 over the JWS signing input using the key whose `kid`
 *    the token names, refusing any other algorithm so a token cannot talk the
 *    verifier into a weaker one. `exp`, `nbf` and `iss` are checked too.
 *  - It authenticates the *key set* by TLS to NVIDIA, the same anchor the
 *    direct call uses. It does not perform RFC 5280 path validation over the
 *    `x5c` chain — that is a hand-rolled X.509 validator's worth of
 *    security-critical code, and getting it subtly wrong is the normal outcome.
 *    Instead the leaf certificate is required to carry the same public key as
 *    the JWK, and `pinnedCertSha256` lets an operator who obtained NVIDIA's
 *    intermediate or root out of band require it to appear in the chain.
 */

/** NVIDIA's published key set for attestation tokens. */
export const NRAS_JWKS_URL = 'https://nras.attestation.nvidia.com/.well-known/jwks.json';

/** The only issuer these tokens may claim. */
export const NRAS_ISSUER = 'https://nras.attestation.nvidia.com';

/**
 * NVIDIA rotates NRAS signing certificates roughly every 48 hours, so a long
 * cache guarantees misses. Refetching is also triggered by an unknown `kid`.
 */
const DEFAULT_CACHE_TTL_MS = 15 * 60 * 1000;

/** Smallest gap between refetches provoked by an unknown kid, so a bad token cannot spam NVIDIA. */
const MIN_REFETCH_INTERVAL_MS = 30 * 1000;

const DEFAULT_CLOCK_SKEW_SEC = 60;

export interface NrasTokenVerifierOptions {
  /** Override the JWKS location (a mirror, or a test double). */
  jwksUrl?: string;
  /** How long a fetched key set may be reused. Default 15 minutes. */
  cacheTtlMs?: number;
  /** Tolerance for exp/nbf against local clock drift. Default 60s. */
  clockSkewSec?: number;
  /**
   * SHA-256 hex digests of DER certificates that must appear in the token's
   * `x5c` chain. Supply NVIDIA's intermediate or root, obtained out of band, to
   * stop trusting the TLS fetch alone. Empty means no pinning.
   */
  pinnedCertSha256?: string[];
  /** Override the fetch implementation. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
  /** Override the clock, in ms since epoch. For tests. */
  now?: () => number;
}

/** Claims carried by a verified NRAS token. */
export interface VerifiedNrasToken {
  claims: Record<string, unknown>;
  kid: string;
  /** SHA-256 hex of each DER certificate in the token's x5c chain, leaf first. */
  chainSha256: string[];
}

export type NrasTokenVerifier = (token: string) => Promise<VerifiedNrasToken>;

interface JwksKey {
  kty?: string;
  crv?: string;
  kid?: string;
  x?: string;
  y?: string;
  x5c?: string[];
}

// ── Encoding helpers ──────────────────────────────────────────────────

/** Decode base64url to bytes. Browser-safe: no Buffer. */
export function base64UrlToBytes(input: string): Uint8Array {
  const padded = input
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(input.length + ((4 - (input.length % 4)) % 4), '=');
  const binary = atob(padded);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** Copy into a plain ArrayBuffer — Web Crypto will not take a SharedArrayBuffer view. */
function toBuffer(bytes: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buf).set(bytes);
  return buf;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', toBuffer(bytes))));
}

/** Split a JWT into its three parts, rejecting anything that is not one. */
export function splitJwt(token: string): { header: string; payload: string; signature: string } {
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((p) => p.length === 0)) {
    throw new Error('Not a well-formed JWT');
  }
  return { header: parts[0], payload: parts[1], signature: parts[2] };
}

/** Parse a base64url JSON segment into an object. */
export function decodeJsonSegment(segment: string, what: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(base64UrlToBytes(segment)));
  } catch {
    throw new Error(`NRAS token ${what} is not valid base64url JSON`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(`NRAS token ${what} is not a JSON object`);
  }
  return parsed as Record<string, unknown>;
}

// ── Verifier ──────────────────────────────────────────────────────────

/**
 * Create a verifier for NRAS attestation tokens.
 *
 * The returned function throws on any failure and resolves with the verified
 * claims otherwise — there is no "verified: false" return, so a caller cannot
 * accidentally treat a failure as a pass.
 */
export function createNrasTokenVerifier(options: NrasTokenVerifierOptions = {}): NrasTokenVerifier {
  const {
    jwksUrl = NRAS_JWKS_URL,
    cacheTtlMs = DEFAULT_CACHE_TTL_MS,
    clockSkewSec = DEFAULT_CLOCK_SKEW_SEC,
    pinnedCertSha256 = [],
    fetchImpl,
    now = () => Date.now(),
  } = options;

  const pinned = new Set(pinnedCertSha256.map((d) => d.toLowerCase()));

  let cache: Map<string, JwksKey> | null = null;
  let cachedAt = 0;
  let lastFetchAt = 0;
  let inFlight: Promise<Map<string, JwksKey>> | null = null;

  async function fetchJwks(): Promise<Map<string, JwksKey>> {
    const doFetch = fetchImpl ?? globalThis.fetch;
    if (!doFetch) throw new Error('No fetch implementation available for JWKS retrieval');

    const response = await doFetch(jwksUrl, { headers: { Accept: 'application/json' } });
    if (!response.ok) {
      throw new Error(`Could not fetch NVIDIA JWKS (${response.status})`);
    }
    const body = (await response.json()) as { keys?: unknown };
    if (!body || !Array.isArray(body.keys)) {
      throw new Error('NVIDIA JWKS has no keys array');
    }

    const keys = new Map<string, JwksKey>();
    for (const entry of body.keys as JwksKey[]) {
      if (entry && typeof entry.kid === 'string') keys.set(entry.kid, entry);
    }
    if (keys.size === 0) throw new Error('NVIDIA JWKS contains no usable keys');

    cache = keys;
    cachedAt = now();
    lastFetchAt = cachedAt;
    return keys;
  }

  /** Fetch at most once concurrently; parallel sessions share one round trip. */
  function loadJwks(): Promise<Map<string, JwksKey>> {
    if (!inFlight) {
      inFlight = fetchJwks().finally(() => {
        inFlight = null;
      });
    }
    return inFlight;
  }

  async function keyFor(kid: string): Promise<JwksKey> {
    const fresh = cache && now() - cachedAt < cacheTtlMs;
    if (fresh && cache!.has(kid)) return cache!.get(kid)!;

    // An unknown kid usually means rotation, so refetch — but not on every
    // unknown token, or a malformed one turns into a request flood at NVIDIA.
    if (!fresh || now() - lastFetchAt > MIN_REFETCH_INTERVAL_MS) {
      const keys = await loadJwks();
      const key = keys.get(kid);
      if (key) return key;
    } else if (cache?.has(kid)) {
      return cache.get(kid)!;
    }
    throw new Error(`NVIDIA JWKS has no key for kid ${kid}`);
  }

  async function importVerifyKey(key: JwksKey): Promise<CryptoKey> {
    if (key.kty !== 'EC' || key.crv !== 'P-384') {
      throw new Error(`Unsupported NRAS signing key type (${key.kty}/${key.crv})`);
    }
    if (!key.x || !key.y) {
      throw new Error('NRAS signing key is missing its EC coordinates');
    }
    return crypto.subtle.importKey(
      'jwk',
      { kty: 'EC', crv: 'P-384', x: key.x, y: key.y, ext: true },
      { name: 'ECDSA', namedCurve: 'P-384' },
      false,
      ['verify']
    );
  }

  /**
   * Require the leaf certificate to carry the same public key as the JWK.
   *
   * This is a containment check on the uncompressed EC point rather than an
   * ASN.1 parse: the point is 97 bytes and appears verbatim in the DER SPKI, so
   * finding it is sufficient to show the two agree, without a certificate
   * parser to get wrong.
   */
  function leafCarriesKey(leafDer: Uint8Array, key: JwksKey): boolean {
    const x = base64UrlToBytes(key.x!);
    const y = base64UrlToBytes(key.y!);
    const point = new Uint8Array(1 + x.length + y.length);
    point[0] = 0x04;
    point.set(x, 1);
    point.set(y, 1 + x.length);

    outer: for (let i = 0; i + point.length <= leafDer.length; i++) {
      for (let j = 0; j < point.length; j++) {
        if (leafDer[i + j] !== point[j]) continue outer;
      }
      return true;
    }
    return false;
  }

  return async function verifyNrasToken(token: string): Promise<VerifiedNrasToken> {
    const { header, payload, signature } = splitJwt(token);
    const headerClaims = decodeJsonSegment(header, 'header');

    // Pin the algorithm rather than following the token's lead — the whole
    // family of JWT algorithm-confusion attacks starts with trusting this field.
    if (headerClaims.alg !== 'ES384') {
      throw new Error(`NRAS token uses unexpected algorithm ${String(headerClaims.alg)}, expected ES384`);
    }
    const kid = headerClaims.kid;
    if (typeof kid !== 'string' || kid.length === 0) {
      throw new Error('NRAS token names no signing key (kid)');
    }

    const key = await keyFor(kid);
    const cryptoKey = await importVerifyKey(key);

    // JWS ECDSA signatures are raw r||s, which is what Web Crypto expects.
    const signatureBytes = base64UrlToBytes(signature);
    const signingInput = new TextEncoder().encode(`${header}.${payload}`);
    const valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-384' },
      cryptoKey,
      toBuffer(signatureBytes),
      toBuffer(signingInput)
    );
    if (!valid) {
      throw new Error(`NRAS token signature does not verify under key ${kid}`);
    }

    const chainDer = (key.x5c ?? []).map((c) => base64UrlToBytes(c.replace(/\s+/g, '')));
    if (chainDer.length > 0 && !leafCarriesKey(chainDer[0], key)) {
      throw new Error('NRAS certificate chain does not carry the JWK public key');
    }
    const chainSha256 = await Promise.all(chainDer.map(sha256Hex));

    if (pinned.size > 0 && !chainSha256.some((d) => pinned.has(d))) {
      throw new Error('NRAS certificate chain contains none of the pinned certificates');
    }

    const claims = decodeJsonSegment(payload, 'payload');

    if (claims.iss !== NRAS_ISSUER) {
      throw new Error(`NRAS token issuer is ${String(claims.iss)}, expected ${NRAS_ISSUER}`);
    }

    const nowSec = Math.floor(now() / 1000);
    if (typeof claims.exp === 'number' && nowSec > claims.exp + clockSkewSec) {
      throw new Error('NRAS token has expired');
    }
    if (typeof claims.nbf === 'number' && nowSec + clockSkewSec < claims.nbf) {
      throw new Error('NRAS token is not valid yet');
    }

    return { claims, kid, chainSha256 };
  };
}
