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
 * How long a fetched key set may be reused.
 *
 * Deliberately long, because neither job this could do needs it short:
 *
 *  - Rotation is handled by refetching when a token names an unknown `kid`,
 *    which needs no TTL at all.
 *  - A key being *withdrawn* is invisible to that check, but the signing
 *    certificates carry their own ~48-hour expiry, and that is enforced per
 *    token. So a withdrawn key stops working on NVIDIA's schedule rather than
 *    on the cache's, and polling faster buys almost nothing.
 *
 * NVIDIA publishes no Cache-Control, ETag or Expires on the key set, so there
 * is nothing to honour and the value is ours to choose. Twelve hours keeps the
 * set from going indefinitely stale without turning verification into a poll.
 */
const DEFAULT_CACHE_TTL_MS = 12 * 60 * 60 * 1000;

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

// ── Minimal DER reader, for certificate validity only ─────────────────
//
// Deliberately not a certificate parser. It walks to the Validity field and
// stops, because that one field is what bounds how long a withdrawn signing key
// stays usable. Everything else about the chain is left to NVIDIA.

interface Tlv {
  tag: number;
  valueStart: number;
  valueEnd: number;
  next: number;
}

function readTlv(der: Uint8Array, offset: number): Tlv {
  if (offset + 2 > der.length) throw new Error('Certificate is truncated');
  const tag = der[offset];
  let p = offset + 1;
  let len = der[p++];
  if (len & 0x80) {
    const count = len & 0x7f;
    if (count === 0 || count > 4) throw new Error('Unsupported certificate length encoding');
    len = 0;
    for (let i = 0; i < count; i++) {
      if (p >= der.length) throw new Error('Certificate is truncated');
      len = len * 256 + der[p++];
    }
  }
  const valueEnd = p + len;
  if (valueEnd > der.length) throw new Error('Certificate is truncated');
  return { tag, valueStart: p, valueEnd, next: valueEnd };
}

const TAG_INTEGER = 0x02;
const TAG_SEQUENCE = 0x30;
const TAG_UTC_TIME = 0x17;
const TAG_GENERALIZED_TIME = 0x18;
const TAG_CONTEXT_0 = 0xa0;

function parseAsn1Time(der: Uint8Array, tlv: Tlv): number {
  const text = new TextDecoder().decode(der.subarray(tlv.valueStart, tlv.valueEnd));
  let year: number;
  let rest: string;
  if (tlv.tag === TAG_UTC_TIME) {
    // YYMMDDHHMMSSZ, with the RFC 5280 pivot at 50.
    const yy = Number(text.slice(0, 2));
    year = yy >= 50 ? 1900 + yy : 2000 + yy;
    rest = text.slice(2);
  } else if (tlv.tag === TAG_GENERALIZED_TIME) {
    year = Number(text.slice(0, 4));
    rest = text.slice(4);
  } else {
    throw new Error('Certificate validity is not an ASN.1 time');
  }
  const value = Date.UTC(
    year,
    Number(rest.slice(0, 2)) - 1,
    Number(rest.slice(2, 4)),
    Number(rest.slice(4, 6)),
    Number(rest.slice(6, 8)),
    Number(rest.slice(8, 10)) || 0
  );
  if (Number.isNaN(value)) throw new Error('Certificate validity is not a parsable time');
  return value;
}

/**
 * Read notBefore/notAfter from a DER certificate, in ms since epoch.
 *
 * Walks Certificate -> TBSCertificate -> {version?, serialNumber, signature,
 * issuer, validity}, which is fixed ordering in RFC 5280.
 */
export function certificateValidity(der: Uint8Array): { notBefore: number; notAfter: number } {
  const cert = readTlv(der, 0);
  if (cert.tag !== TAG_SEQUENCE) throw new Error('Certificate is not a DER SEQUENCE');

  const tbs = readTlv(der, cert.valueStart);
  if (tbs.tag !== TAG_SEQUENCE) throw new Error('Certificate has no TBSCertificate');

  let field = readTlv(der, tbs.valueStart);
  if (field.tag === TAG_CONTEXT_0) field = readTlv(der, field.next); // optional version
  if (field.tag !== TAG_INTEGER) throw new Error('Certificate has no serial number');
  field = readTlv(der, field.next);
  if (field.tag !== TAG_SEQUENCE) throw new Error('Certificate has no signature algorithm');
  field = readTlv(der, field.next);
  if (field.tag !== TAG_SEQUENCE) throw new Error('Certificate has no issuer');

  const validity = readTlv(der, field.next);
  if (validity.tag !== TAG_SEQUENCE) throw new Error('Certificate has no validity period');

  const notBefore = readTlv(der, validity.valueStart);
  const notAfter = readTlv(der, notBefore.next);
  return {
    notBefore: parseAsn1Time(der, notBefore),
    notAfter: parseAsn1Time(der, notAfter),
  };
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

    // Stamped before the request, not after a success: a failing NVIDIA would
    // otherwise leave every session free to retry immediately, turning an
    // outage into a stampede against the thing that is already struggling.
    lastFetchAt = now();

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

  /**
   * Resolve a kid to its key, refetching when needed.
   *
   * Two mechanisms, doing two different jobs — neither replaces the other:
   *
   *  - An **unknown kid** refetches, which is how rotation is picked up. This
   *    handles keys being *added*, and only that.
   *  - The **TTL** expires a cache that still answers every kid asked of it,
   *    which is the only way a key being *removed* is ever noticed. NVIDIA
   *    withdrawing a compromised key is invisible to the kid check, and token
   *    `exp` does not help: whoever holds the leaked private key mints tokens
   *    with whatever expiry they like. So the TTL is the revocation window.
   *
   * NVIDIA serves this key set with no Cache-Control, ETag, or Expires header,
   * so there is nothing to honour and the interval is ours to choose. At ~100 KB
   * per fetch the bandwidth is irrelevant; the TTL is set for how long a
   * withdrawn key stays trusted, not to save a request.
   */
  async function keyFor(kid: string): Promise<JwksKey> {
    const fresh = cache !== null && now() - cachedAt < cacheTtlMs;
    if (fresh && cache!.has(kid)) return cache!.get(kid)!;

    // A fetch already running is not a recent failure — join it. Without this,
    // requests arriving during the very first fetch get turned away by a
    // backoff meant for failures, while the fetch that would answer them is
    // still in flight. `lastFetchAt` is stamped before the request precisely so
    // failures back off, which makes an in-flight fetch look identical to one.
    //
    // Otherwise the backoff covers every refetch, warm cache or not: on a cold
    // start against a failing NVIDIA, each session would retry and aim a
    // stampede at a service already in trouble.
    if (inFlight !== null || now() - lastFetchAt > MIN_REFETCH_INTERVAL_MS) {
      const keys = await loadJwks();
      const key = keys.get(kid);
      if (key) return key;
      throw new Error(`NVIDIA JWKS has no key for kid ${kid}`);
    }

    if (cache === null) {
      throw new Error(
        'NVIDIA JWKS could not be fetched, and no key set is cached from an earlier attempt. ' +
        `Waiting ${Math.ceil(MIN_REFETCH_INTERVAL_MS / 1000)}s before asking NVIDIA again.`
      );
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
    if (chainDer.length > 0) {
      if (!leafCarriesKey(chainDer[0], key)) {
        throw new Error('NRAS certificate chain does not carry the JWK public key');
      }

      // This is what bounds a withdrawn key. NVIDIA issues these leaves for
      // about 48 hours, so a key that leaves the published set stops being
      // usable on its own schedule rather than only when the cache expires.
      const { notBefore, notAfter } = certificateValidity(chainDer[0]);
      const skewMs = clockSkewSec * 1000;
      if (now() > notAfter + skewMs) {
        throw new Error(
          `NRAS signing certificate for kid ${kid} expired at ${new Date(notAfter).toISOString()}`
        );
      }
      if (now() + skewMs < notBefore) {
        throw new Error(
          `NRAS signing certificate for kid ${kid} is not valid until ${new Date(notBefore).toISOString()}`
        );
      }
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
