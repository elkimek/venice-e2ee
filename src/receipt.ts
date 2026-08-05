/**
 * Verification of Venice's `/api/v1/tee/signature` response receipts.
 *
 * A receipt is useful only when three independent bindings hold:
 *
 * 1. its signing key belongs to a workload keyset the caller already trusts;
 * 2. it names the completion the caller made; and
 * 3. its request/response hashes match the bytes the caller intended to send
 *    and accept.
 *
 * Venice's legacy `/api/v1/tee/attestation` quote binds an E2EE key and nonce,
 * not the ACI workload-keyset digest. Consequently this module never promotes
 * self-described values from that response into a trust root. The caller must
 * supply a trust anchor established from canonical ACI attestation verification
 * or an independently pinned workload identity and keyset digest.
 *
 * Binding (3) is currently unreachable for a client of `api.venice.ai`. Measured on the
 * E2EE and TEE-only paths, streaming and not, with the exact bytes sent and
 * received: both body hashes fail in all four combinations, which places a
 * re-serializing hop between the caller and the enclave that issues the receipt.
 * The requirement stays — `verified` is false without it, and this module does
 * not get to decide the binding is optional — but callers behind such a gateway
 * should distinguish that from a receipt that failed for any other reason. See
 * {@link BODY_BINDING_CHECKS}.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { toHex } from './crypto.js';
import type { AttestationResponse } from './attestation.js';

export interface WorkloadPublicKey {
  algo: string;
  public_key: string;
  [key: string]: unknown;
}

export interface WorkloadIdentity {
  public_key: WorkloadPublicKey;
  subject?: string | null;
  [key: string]: unknown;
}

/** A key entry inside a workload keyset. */
export interface KeysetKey {
  key_id: string;
  algo: string;
  public_key: string;
  [key: string]: unknown;
}

export interface WorkloadKeyset {
  workload_identity: WorkloadIdentity;
  receipt_signing_keys: KeysetKey[];
  [key: string]: unknown;
}

export interface ReceiptSignature {
  algo: string;
  key_id: string;
  value: string;
}

export interface ReceiptEvent {
  seq: number;
  type: string;
  body_hash?: string;
  wire_hash?: string;
  cleartext_hash?: string;
  [key: string]: unknown;
}

export interface Receipt {
  api_version: string;
  receipt_id: string;
  chat_id: string;
  workload_id: string;
  workload_keyset_digest: string;
  event_log: ReceiptEvent[];
  signature: ReceiptSignature;
  [key: string]: unknown;
}

/** The body of `GET /api/v1/tee/signature`. */
export interface SignatureResponse {
  api_version?: string;
  text?: string;
  signature?: string;
  signing_address?: string;
  receipt: Receipt;
  [key: string]: unknown;
}

export interface ReceiptCheck {
  name: string;
  ok: boolean;
  detail?: string;
}

export interface ReceiptVerification {
  /** True only when every required trust, signature, identity, and body check passed. */
  verified: boolean;
  checks: ReceiptCheck[];
}

/** Values established by canonical quote verification or pinned independently. */
export interface ReceiptTrustAnchor {
  workloadId: string;
  workloadKeysetDigest: string;
}

/**
 * The check names that bind a receipt to specific request and response bytes.
 *
 * Exported so a caller can tell "this binding is not reachable from here" apart
 * from "this receipt is wrong" without matching on string literals. A caller
 * behind a re-serializing gateway will see exactly these two fail on every
 * completion; anything else failing alongside them is a real problem.
 */
export const BODY_BINDING_CHECKS: readonly string[] = [
  'request_body_hash_matches',
  'response_body_hash_matches',
];

export type ReceiptBody = string | Uint8Array;
export type ReceiptResponseHashField = 'wire_hash' | 'cleartext_hash';

export interface VerifyReceiptOptions {
  /** Independently established identity and keyset digest. Never copy unverified report fields. */
  trustAnchor: ReceiptTrustAnchor;
  /** Venice completion id the receipt must name. */
  requestId: string;
  /** Exact request bytes whose hash must match `request.received.body_hash`. */
  requestBody: ReceiptBody;
  /** Exact response bytes whose hash must match the explicitly selected receipt field. */
  responseBody: ReceiptBody;
  /** Select the response representation the caller supplies. Required to avoid ambiguity. */
  responseHashField: ReceiptResponseHashField;
}

type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue | undefined };

/** RFC 8785 JSON Canonicalization Scheme for the JSON subset ACI uses. */
export function jcsStringify(value: JsonValue): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) {
      throw new TypeError(`JCS: ACI restricts numbers to integers, got ${value}`);
    }
    return Object.is(value, -0) ? '0' : String(value);
  }
  if (typeof value !== 'object') {
    throw new TypeError(`JCS: unsupported type ${typeof value}`);
  }
  if (Array.isArray(value)) return `[${value.map((item) => jcsStringify(item)).join(',')}]`;

  const entries = Object.keys(value)
    .filter((key) => value[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${jcsStringify(value[key] as JsonValue)}`);
  return `{${entries.join(',')}}`;
}

/** `sha256:<hex>` over the UTF-8 bytes of `text`. */
export function sha256Prefixed(text: string): string {
  return hashReceiptBody(text);
}

/** `sha256:<hex>` over exact body bytes. Strings are encoded as UTF-8. */
export function hashReceiptBody(body: ReceiptBody): string {
  if (typeof body !== 'string' && !(body instanceof Uint8Array)) {
    throw new TypeError('Receipt body must be a string or Uint8Array');
  }
  const bytes = typeof body === 'string' ? new TextEncoder().encode(body) : body;
  return `sha256:${toHex(sha256(bytes))}`;
}

/** ACI workload id: SHA-256 of the JCS identity public-key object. */
export function computeWorkloadId(publicKey: WorkloadPublicKey): string {
  return sha256Prefixed(
    jcsStringify({ algo: publicKey.algo, public_key: publicKey.public_key })
  );
}

/** ACI workload-keyset digest: SHA-256 of the whole JCS keyset. */
export function computeWorkloadKeysetDigest(keyset: WorkloadKeyset): string {
  return sha256Prefixed(jcsStringify(keyset as unknown as JsonValue));
}

/** The exact bytes the receipt signature covers: JCS minus `signature.value`. */
export function receiptSigningBytes(receipt: Receipt): Uint8Array {
  const { value: _omitted, ...signatureWithoutValue } = receipt.signature;
  const forSigning = {
    ...(receipt as unknown as Record<string, JsonValue>),
    signature: signatureWithoutValue as unknown as JsonValue,
  };
  return new TextEncoder().encode(jcsStringify(forSigning));
}

function fromHexBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length === 0 || clean.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(clean)) {
    throw new TypeError('Expected non-empty, even-length hexadecimal bytes');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function verifyEd25519(
  publicKey: Uint8Array,
  signature: Uint8Array,
  message: Uint8Array
): Promise<boolean> {
  const key = await crypto.subtle.importKey('raw', publicKey as BufferSource, 'Ed25519', false, [
    'verify',
  ]);
  return crypto.subtle.verify(
    'Ed25519',
    key,
    signature as BufferSource,
    message as BufferSource
  );
}

function exactlyOneEvent(receipt: Receipt, type: string): ReceiptEvent | undefined {
  const matches = receipt.event_log.filter(
    (event) => event && typeof event === 'object' && event.type === type
  );
  return matches.length === 1 ? matches[0] : undefined;
}

function isReceiptBody(value: unknown): value is ReceiptBody {
  return typeof value === 'string' || value instanceof Uint8Array;
}

/**
 * Verify a receipt against an independently established workload trust anchor.
 *
 * Every required check is reported rather than thrown. Missing options, trust
 * material, events, or hashes fail closed at runtime even for untyped callers.
 */
export async function verifyReceipt(
  signatureResponse: SignatureResponse,
  attestation: AttestationResponse,
  options: VerifyReceiptOptions
): Promise<ReceiptVerification> {
  const checks: ReceiptCheck[] = [];
  const add = (name: string, ok: boolean, detail?: string): void => {
    checks.push(detail === undefined ? { name, ok } : { name, ok, detail });
  };

  const receipt = signatureResponse?.receipt;
  if (!receipt || !receipt.signature || !Array.isArray(receipt.event_log)) {
    add('receipt_present', false, 'signature response carried no complete receipt');
    return { verified: false, checks };
  }

  if (!options || typeof options !== 'object') {
    add('verification_context_present', false, 'trust anchor and request/response context required');
    return { verified: false, checks };
  }

  const { trustAnchor, requestId, requestBody, responseBody, responseHashField } = options;
  const contextComplete = Boolean(
    trustAnchor?.workloadId &&
      trustAnchor?.workloadKeysetDigest &&
      requestId &&
      isReceiptBody(requestBody) &&
      isReceiptBody(responseBody) &&
      (responseHashField === 'wire_hash' || responseHashField === 'cleartext_hash')
  );
  add(
    'verification_context_present',
    contextComplete,
    contextComplete
      ? undefined
      : 'trustAnchor, requestId, requestBody, responseBody, and responseHashField are required'
  );
  if (!contextComplete) return { verified: false, checks };

  const unsupportedVersions = [
    receipt.api_version === 'aci/1' ? undefined : `receipt "${receipt.api_version}"`,
    signatureResponse.api_version === undefined || signatureResponse.api_version === 'aci/1'
      ? undefined
      : `signature response "${signatureResponse.api_version}"`,
    attestation?.api_version === undefined || attestation.api_version === 'aci/1'
      ? undefined
      : `attestation "${attestation.api_version}"`,
  ].filter((value): value is string => value !== undefined);
  add(
    'api_version_supported',
    unsupportedVersions.length === 0,
    unsupportedVersions.length === 0
      ? undefined
      : `unsupported api_version: ${unsupportedVersions.join(', ')}`
  );

  const keyset = attestation?.attestation?.workload_keyset;
  if (!keyset) {
    add('keyset_present', false, 'attestation carried no workload_keyset');
    return { verified: false, checks };
  }

  const identityKey = keyset.workload_identity?.public_key;
  const signingKeys = keyset.receipt_signing_keys;
  const keysetShapeValid = Boolean(
    identityKey &&
      typeof identityKey.algo === 'string' &&
      typeof identityKey.public_key === 'string' &&
      Array.isArray(signingKeys) &&
      signingKeys.every(
        (key) =>
          key &&
          typeof key === 'object' &&
          typeof key.key_id === 'string' &&
          typeof key.algo === 'string' &&
          typeof key.public_key === 'string'
      )
  );
  if (!keysetShapeValid) {
    add('keyset_well_formed', false, 'workload identity or receipt signing keys are malformed');
    return { verified: false, checks };
  }

  let keysetDigest: string;
  let workloadId: string;
  try {
    keysetDigest = computeWorkloadKeysetDigest(keyset);
    workloadId = computeWorkloadId(identityKey);
  } catch (error: unknown) {
    add(
      'keyset_well_formed',
      false,
      `invalid workload keyset: ${error instanceof Error ? error.message : String(error)}`
    );
    return { verified: false, checks };
  }

  add('keyset_well_formed', true);
  add(
    'keyset_digest_matches_trust_anchor',
    keysetDigest === trustAnchor.workloadKeysetDigest,
    keysetDigest === trustAnchor.workloadKeysetDigest
      ? undefined
      : `computed ${keysetDigest}, trusted ${trustAnchor.workloadKeysetDigest}`
  );
  add(
    'attestation_keyset_digest_matches_trust_anchor',
    attestation.workload_keyset_digest === trustAnchor.workloadKeysetDigest,
    attestation.workload_keyset_digest === trustAnchor.workloadKeysetDigest
      ? undefined
      : `attestation says ${attestation.workload_keyset_digest ?? 'missing'}`
  );
  add(
    'receipt_keyset_digest_matches_trust_anchor',
    receipt.workload_keyset_digest === trustAnchor.workloadKeysetDigest,
    receipt.workload_keyset_digest === trustAnchor.workloadKeysetDigest
      ? undefined
      : `receipt says ${receipt.workload_keyset_digest}`
  );
  add(
    'workload_id_matches_trust_anchor',
    workloadId === trustAnchor.workloadId &&
      attestation.workload_id === trustAnchor.workloadId &&
      receipt.workload_id === trustAnchor.workloadId,
    workloadId === trustAnchor.workloadId &&
      attestation.workload_id === trustAnchor.workloadId &&
      receipt.workload_id === trustAnchor.workloadId
      ? undefined
      : `computed ${workloadId}, attestation ${attestation.workload_id ?? 'missing'}, receipt ${receipt.workload_id ?? 'missing'}, trusted ${trustAnchor.workloadId}`
  );

  const entry = signingKeys.find(
    (key) => key.key_id === receipt.signature.key_id
  );
  add(
    'key_in_trusted_keyset',
    Boolean(entry),
    entry ? undefined : `key_id "${receipt.signature.key_id}" is not in receipt_signing_keys`
  );

  if (entry) {
    const algoMatches = entry.algo === receipt.signature.algo;
    add(
      'key_algo_matches',
      algoMatches,
      algoMatches ? undefined : `receipt says ${receipt.signature.algo}, keyset says ${entry.algo}`
    );

    if (algoMatches && entry.algo === 'ed25519') {
      try {
        const ok = await verifyEd25519(
          fromHexBytes(entry.public_key),
          fromHexBytes(receipt.signature.value),
          receiptSigningBytes(receipt)
        );
        add('receipt_signature', ok, ok ? undefined : 'Ed25519 verification failed');
      } catch (error: unknown) {
        add(
          'receipt_signature',
          false,
          `Ed25519 unavailable or input rejected: ${error instanceof Error ? error.message : String(error)}`
        );
      }
    } else if (algoMatches) {
      add('receipt_signature', false, `unsupported receipt signing algorithm "${entry.algo}"`);
    }
  }

  add(
    'chat_id_matches_request',
    receipt.chat_id === requestId,
    receipt.chat_id === requestId
      ? undefined
      : `receipt is for ${receipt.chat_id}, expected ${requestId}`
  );

  const requestEvent = exactlyOneEvent(receipt, 'request.received');
  const requestHash = hashReceiptBody(requestBody);
  add(
    'request_body_hash_matches',
    requestEvent?.body_hash === requestHash,
    requestEvent?.body_hash === requestHash
      ? undefined
      : `computed ${requestHash}, receipt says ${requestEvent?.body_hash ?? 'missing or ambiguous event'}`
  );

  const responseEvent = exactlyOneEvent(receipt, 'response.returned');
  const responseHash = hashReceiptBody(responseBody);
  const receiptResponseHash = responseEvent?.[responseHashField];
  add(
    'response_body_hash_matches',
    receiptResponseHash === responseHash,
    receiptResponseHash === responseHash
      ? undefined
      : `computed ${responseHash}, receipt ${responseHashField} says ${typeof receiptResponseHash === 'string' ? receiptResponseHash : 'missing or ambiguous event'}`
  );

  const rawAttestationAddress = attestation.signing_address;
  const rawSignatureAddress = signatureResponse.signing_address;
  const attestationAddress =
    typeof rawAttestationAddress === 'string' ? rawAttestationAddress.toLowerCase() : undefined;
  const signatureAddress =
    typeof rawSignatureAddress === 'string' ? rawSignatureAddress.toLowerCase() : undefined;
  if (rawAttestationAddress !== undefined || rawSignatureAddress !== undefined) {
    add(
      'signing_address_cross_check',
      Boolean(attestationAddress && signatureAddress && attestationAddress === signatureAddress),
      attestationAddress && signatureAddress && attestationAddress === signatureAddress
        ? undefined
        : `${signatureAddress ?? 'missing'} vs attestation ${attestationAddress ?? 'missing'}`
    );
  }

  return { verified: checks.length > 0 && checks.every((check) => check.ok), checks };
}
