import { beforeAll, describe, expect, it } from 'vitest';
import {
  computeWorkloadId,
  computeWorkloadKeysetDigest,
  hashReceiptBody,
  jcsStringify,
  receiptSigningBytes,
  sha256Prefixed,
  verifyReceipt,
} from './receipt.js';
import type {
  Receipt,
  ReceiptTrustAnchor,
  SignatureResponse,
  VerifyReceiptOptions,
  WorkloadKeyset,
} from './receipt.js';
import type { AttestationResponse } from './attestation.js';
import { toHex } from './crypto.js';

const enc = new TextEncoder();
const REQUEST_BODY = '{"model":"e2ee-test","messages":[{"role":"user","content":"hi"}]}';
const RESPONSE_BODY = '{"id":"chat-123","choices":[{"message":{"content":"hello"}}]}';
const CLEARTEXT_RESPONSE_BODY = '{"choices":[{"delta":{"content":"hello"}}]}';

function rawHex(bytes: ArrayBuffer): string {
  return toHex(new Uint8Array(bytes));
}

describe('jcsStringify', () => {
  it('sorts object keys recursively and emits no whitespace', () => {
    expect(jcsStringify({ z: { y: 1, x: 2 }, a: [1, 2] })).toBe(
      '{"a":[1,2],"z":{"x":2,"y":1}}'
    );
  });

  it('keeps null and drops undefined object properties', () => {
    expect(jcsStringify({ a: null, b: undefined, c: 1 })).toBe('{"a":null,"c":1}');
  });

  it('rejects numbers outside the integer-only ACI subset', () => {
    expect(() => jcsStringify({ value: Number.NaN })).toThrow('integers');
    expect(() => jcsStringify({ value: 1.5 })).toThrow('integers');
    expect(jcsStringify({ value: -0 })).toBe('{"value":0}');
  });
});

describe('receipt digest helpers', () => {
  it('produces the ACI sha256:<hex> form', () => {
    expect(sha256Prefixed('abc')).toBe(
      'sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    );
  });

  it('hashes raw bytes without a text conversion', () => {
    expect(hashReceiptBody(new Uint8Array([0xff]))).not.toBe(hashReceiptBody('ÿ'));
  });

  it('removes signature.value but keeps signature metadata', () => {
    const receipt = {
      signature: { algo: 'ed25519', key_id: 'k1', value: 'deadbeef' },
    } as unknown as Receipt;
    const text = new TextDecoder().decode(receiptSigningBytes(receipt));
    expect(text).toContain('"algo":"ed25519"');
    expect(text).toContain('"key_id":"k1"');
    expect(text).not.toContain('deadbeef');
  });
});

describe('verifyReceipt', () => {
  let trustedKeyPair: CryptoKeyPair;

  interface Fixture {
    attestation: AttestationResponse;
    signatureResponse: SignatureResponse;
    trustAnchor: ReceiptTrustAnchor;
  }

  async function build(overrides: {
    signingKeyPair?: CryptoKeyPair;
    receipt?: Partial<Receipt>;
    keyset?: Partial<WorkloadKeyset>;
    attestation?: Partial<AttestationResponse>;
    signatureResponse?: Partial<SignatureResponse>;
    corruptSignature?: boolean;
  } = {}): Promise<Fixture> {
    const signingKeyPair = overrides.signingKeyPair ?? trustedKeyPair;
    const publicKeyHex = rawHex(await crypto.subtle.exportKey('raw', signingKeyPair.publicKey));
    const keyset = {
      workload_identity: {
        public_key: { algo: 'ed25519', public_key: publicKeyHex },
      },
      keyset_epoch: { version: 1, not_after: 4_000_000_000 },
      receipt_signing_keys: [
        { key_id: 'test-key', algo: 'ed25519', public_key: publicKeyHex },
      ],
      ...overrides.keyset,
    } as WorkloadKeyset;
    const trustAnchor = {
      workloadId: computeWorkloadId(keyset.workload_identity.public_key),
      workloadKeysetDigest: computeWorkloadKeysetDigest(keyset),
    };
    const receipt = {
      api_version: 'aci/1',
      receipt_id: 'rcpt-test',
      chat_id: 'chat-123',
      workload_id: trustAnchor.workloadId,
      workload_keyset_digest: trustAnchor.workloadKeysetDigest,
      event_log: [
        {
          seq: 0,
          type: 'request.received',
          body_hash: hashReceiptBody(REQUEST_BODY),
        },
        {
          seq: 1,
          type: 'response.returned',
          wire_hash: hashReceiptBody(RESPONSE_BODY),
          cleartext_hash: hashReceiptBody(CLEARTEXT_RESPONSE_BODY),
        },
      ],
      signature: { algo: 'ed25519', key_id: 'test-key', value: '' },
      ...overrides.receipt,
    } as Receipt;

    const signed = await crypto.subtle.sign(
      'Ed25519',
      signingKeyPair.privateKey,
      receiptSigningBytes(receipt) as BufferSource
    );
    receipt.signature.value = overrides.corruptSignature
      ? rawHex(signed).replace(/^../, '00')
      : rawHex(signed);

    const attestation = {
      api_version: 'aci/1',
      nonce: '00'.repeat(32),
      model: 'e2ee-test',
      signing_address: '0xabc',
      workload_id: trustAnchor.workloadId,
      workload_keyset_digest: trustAnchor.workloadKeysetDigest,
      attestation: { workload_keyset: keyset },
      ...overrides.attestation,
    } as AttestationResponse;
    const signatureResponse = {
      api_version: 'aci/1',
      signing_address: '0xabc',
      receipt,
      ...overrides.signatureResponse,
    } as SignatureResponse;
    return { attestation, signatureResponse, trustAnchor };
  }

  function options(
    fixture: Fixture,
    overrides: Partial<VerifyReceiptOptions> = {}
  ): VerifyReceiptOptions {
    return {
      trustAnchor: fixture.trustAnchor,
      requestId: 'chat-123',
      requestBody: REQUEST_BODY,
      responseBody: RESPONSE_BODY,
      responseHashField: 'wire_hash',
      ...overrides,
    };
  }

  beforeAll(async () => {
    trustedKeyPair = (await crypto.subtle.generateKey('Ed25519', true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;
  });

  it('verifies a receipt only with a complete trust and body context', async () => {
    const fixture = await build();
    const result = await verifyReceipt(
      fixture.signatureResponse,
      fixture.attestation,
      options(fixture)
    );
    expect(result.verified).toBe(true);
    expect(result.checks.every((check) => check.ok)).toBe(true);
  });

  it('fails closed when an untyped caller omits verification context', async () => {
    const fixture = await build();
    const result = await verifyReceipt(
      fixture.signatureResponse,
      fixture.attestation,
      undefined as never
    );
    expect(result.verified).toBe(false);
    expect(result.checks).toContainEqual(
      expect.objectContaining({ name: 'verification_context_present', ok: false })
    );
  });

  it('fails closed when an untyped caller supplies non-byte bodies', async () => {
    const fixture = await build();
    const result = await verifyReceipt(
      fixture.signatureResponse,
      fixture.attestation,
      options(fixture, { requestBody: {} as never })
    );
    expect(result.verified).toBe(false);
    expect(result.checks).toContainEqual(
      expect.objectContaining({ name: 'verification_context_present', ok: false })
    );
  });

  it('rejects an attacker-selected keyset and matching forged receipt', async () => {
    const trusted = await build();
    const attackerKeyPair = (await crypto.subtle.generateKey('Ed25519', true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;
    const forged = await build({ signingKeyPair: attackerKeyPair });
    const result = await verifyReceipt(
      forged.signatureResponse,
      forged.attestation,
      options(forged, { trustAnchor: trusted.trustAnchor })
    );
    expect(result.verified).toBe(false);
    expect(result.checks).toContainEqual(
      expect.objectContaining({ name: 'keyset_digest_matches_trust_anchor', ok: false })
    );
  });

  it('rejects a receipt or attestation that names another workload', async () => {
    const fixture = await build({
      receipt: { workload_id: `sha256:${'1'.repeat(64)}` },
      attestation: { workload_id: `sha256:${'1'.repeat(64)}` },
    });
    const result = await verifyReceipt(
      fixture.signatureResponse,
      fixture.attestation,
      options(fixture)
    );
    expect(result.verified).toBe(false);
    expect(result.checks).toContainEqual(
      expect.objectContaining({ name: 'workload_id_matches_trust_anchor', ok: false })
    );
  });

  it('rejects a keyset changed after the trust anchor was established', async () => {
    const fixture = await build();
    fixture.attestation.attestation!.workload_keyset!.injected = true;
    const result = await verifyReceipt(
      fixture.signatureResponse,
      fixture.attestation,
      options(fixture)
    );
    expect(result.verified).toBe(false);
    expect(result.checks).toContainEqual(
      expect.objectContaining({ name: 'keyset_digest_matches_trust_anchor', ok: false })
    );
  });

  it('rejects a receipt for a different completion', async () => {
    const fixture = await build();
    const result = await verifyReceipt(
      fixture.signatureResponse,
      fixture.attestation,
      options(fixture, { requestId: 'chat-999' })
    );
    expect(result.verified).toBe(false);
    expect(result.checks).toContainEqual(
      expect.objectContaining({ name: 'chat_id_matches_request', ok: false })
    );
  });

  it('rejects a receipt for different request bytes', async () => {
    const fixture = await build();
    const result = await verifyReceipt(
      fixture.signatureResponse,
      fixture.attestation,
      options(fixture, { requestBody: '{"different":true}' })
    );
    expect(result.verified).toBe(false);
    expect(result.checks).toContainEqual(
      expect.objectContaining({ name: 'request_body_hash_matches', ok: false })
    );
  });

  it('rejects a receipt for different response bytes', async () => {
    const fixture = await build();
    const result = await verifyReceipt(
      fixture.signatureResponse,
      fixture.attestation,
      options(fixture, { responseBody: '{"different":true}' })
    );
    expect(result.verified).toBe(false);
    expect(result.checks).toContainEqual(
      expect.objectContaining({ name: 'response_body_hash_matches', ok: false })
    );
  });

  it('requires callers to select and match the cleartext representation explicitly', async () => {
    const fixture = await build();
    const result = await verifyReceipt(
      fixture.signatureResponse,
      fixture.attestation,
      options(fixture, {
        responseBody: CLEARTEXT_RESPONSE_BODY,
        responseHashField: 'cleartext_hash',
      })
    );
    expect(result.verified).toBe(true);
  });

  it('rejects missing or ambiguous required events', async () => {
    const fixture = await build({
      receipt: {
        event_log: [
          { seq: 0, type: 'request.received', body_hash: hashReceiptBody(REQUEST_BODY) },
          { seq: 1, type: 'request.received', body_hash: hashReceiptBody(REQUEST_BODY) },
        ],
      },
    });
    const result = await verifyReceipt(
      fixture.signatureResponse,
      fixture.attestation,
      options(fixture)
    );
    expect(result.verified).toBe(false);
    expect(result.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: 'request_body_hash_matches', ok: false }),
        expect.objectContaining({ name: 'response_body_hash_matches', ok: false }),
      ])
    );
  });

  it('rejects a tampered event log through the receipt signature', async () => {
    const fixture = await build();
    fixture.signatureResponse.receipt.event_log[0].body_hash = hashReceiptBody('tampered');
    const result = await verifyReceipt(
      fixture.signatureResponse,
      fixture.attestation,
      options(fixture, { requestBody: 'tampered' })
    );
    expect(result.verified).toBe(false);
    expect(result.checks).toContainEqual(
      expect.objectContaining({ name: 'receipt_signature', ok: false })
    );
  });

  it('rejects malformed or corrupted signatures without throwing', async () => {
    const malformed = await build();
    malformed.signatureResponse.receipt.signature.value = 'not-hex';
    const malformedResult = await verifyReceipt(
      malformed.signatureResponse,
      malformed.attestation,
      options(malformed)
    );
    expect(malformedResult.verified).toBe(false);

    const corrupted = await build({ corruptSignature: true });
    const corruptedResult = await verifyReceipt(
      corrupted.signatureResponse,
      corrupted.attestation,
      options(corrupted)
    );
    expect(corruptedResult.verified).toBe(false);
  });

  it('rejects unsupported receipt protocol versions', async () => {
    const fixture = await build({ receipt: { api_version: 'aci/2' } });
    const result = await verifyReceipt(
      fixture.signatureResponse,
      fixture.attestation,
      options(fixture)
    );
    expect(result.verified).toBe(false);
    expect(result.checks).toContainEqual(
      expect.objectContaining({ name: 'api_version_supported', ok: false })
    );
  });

  it('rejects unsupported wrapper protocol versions', async () => {
    const fixture = await build({ signatureResponse: { api_version: 'aci/2' } });
    const result = await verifyReceipt(
      fixture.signatureResponse,
      fixture.attestation,
      options(fixture)
    );
    expect(result.verified).toBe(false);
    expect(result.checks).toContainEqual(
      expect.objectContaining({ name: 'api_version_supported', ok: false })
    );
  });

  it('reports missing receipt or keyset instead of throwing', async () => {
    const fixture = await build();
    const noReceipt = await verifyReceipt(
      { receipt: undefined } as unknown as SignatureResponse,
      fixture.attestation,
      options(fixture)
    );
    expect(noReceipt.verified).toBe(false);
    expect(noReceipt.checks[0].name).toBe('receipt_present');

    const noKeyset = await verifyReceipt(
      fixture.signatureResponse,
      { nonce: '', model: '' },
      options(fixture)
    );
    expect(noKeyset.verified).toBe(false);
    expect(noKeyset.checks).toContainEqual(
      expect.objectContaining({ name: 'keyset_present', ok: false })
    );
  });
});

describe('encoding sanity', () => {
  it('canonicalizes the same object identically regardless of key order', () => {
    const a = jcsStringify({ x: 1, y: { b: 2, a: 3 } });
    const b = jcsStringify({ y: { a: 3, b: 2 }, x: 1 });
    expect(a).toBe(b);
    expect(sha256Prefixed(a)).toBe(sha256Prefixed(b));
  });

  it('hashes UTF-8 bytes, not code units', () => {
    expect(sha256Prefixed('é')).toBe(sha256Prefixed(new TextDecoder().decode(enc.encode('é'))));
  });
});
