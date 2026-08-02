import { describe, it, expect, beforeAll } from 'vitest';
import { verifyReceipt, jcsStringify, sha256Prefixed, receiptSigningBytes } from './receipt.js';
import type { Receipt, SignatureResponse, WorkloadKeyset } from './receipt.js';
import type { AttestationResponse } from './attestation.js';
import { toHex } from './crypto.js';

const enc = new TextEncoder();

function rawHex(bytes: ArrayBuffer): string {
  return toHex(new Uint8Array(bytes));
}

describe('jcsStringify', () => {
  it('sorts object keys', () => {
    expect(jcsStringify({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });

  it('emits no insignificant whitespace', () => {
    expect(jcsStringify({ a: [1, 2, { c: 3 }] })).toBe('{"a":[1,2,{"c":3}]}');
  });

  it('sorts nested keys too', () => {
    expect(jcsStringify({ z: { y: 1, x: 2 } })).toBe('{"z":{"x":2,"y":1}}');
  });

  it('keeps null and drops undefined, as JSON does', () => {
    expect(jcsStringify({ a: null, b: undefined as never, c: 1 })).toBe('{"a":null,"c":1}');
  });

  it('sorts by UTF-16 code unit, so uppercase sorts before lowercase', () => {
    expect(jcsStringify({ a: 1, B: 2 })).toBe('{"B":2,"a":1}');
  });
});

describe('sha256Prefixed', () => {
  it('produces the sha256:<hex> form ACI digests use', () => {
    // Well-known vector: sha256("abc")
    expect(sha256Prefixed('abc')).toBe(
      'sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    );
  });
});

describe('receiptSigningBytes', () => {
  it('removes signature.value but keeps the other signature fields', () => {
    const receipt = {
      chat_id: 'c1',
      signature: { algo: 'ed25519', key_id: 'k1', value: 'deadbeef' },
    } as unknown as Receipt;
    const text = new TextDecoder().decode(receiptSigningBytes(receipt));
    expect(text).toContain('"algo":"ed25519"');
    expect(text).toContain('"key_id":"k1"');
    expect(text).not.toContain('deadbeef');
  });
});

describe('verifyReceipt', () => {
  let keyPair: CryptoKeyPair;
  let publicKeyHex: string;

  // Build a receipt, sign it the way the gateway does, and wrap it in the
  // attestation + signature-response shapes the endpoints return.
  async function build(overrides: {
    receipt?: Partial<Receipt>;
    keyset?: Partial<WorkloadKeyset>;
    signatureResponse?: Partial<SignatureResponse>;
    corruptSignature?: boolean;
  } = {}) {
    const receipt = {
      api_version: 'aci/1',
      receipt_id: 'rcpt-test',
      chat_id: 'chat-123',
      model: 'z-ai/glm-5.2',
      workload_keyset_digest: 'placeholder',
      event_log: [{ seq: 0, type: 'request.received', body_hash: 'sha256:aa' }],
      signature: { algo: 'ed25519', key_id: 'test-key', value: '' },
      ...overrides.receipt,
    } as unknown as Receipt;

    const keyset = {
      receipt_signing_keys: [{ key_id: 'test-key', algo: 'ed25519', public_key: publicKeyHex }],
      ...overrides.keyset,
    } as WorkloadKeyset;

    if (receipt.workload_keyset_digest === 'placeholder') {
      receipt.workload_keyset_digest = sha256Prefixed(jcsStringify(keyset as never));
    }

    const signed = await crypto.subtle.sign('Ed25519', keyPair.privateKey, receiptSigningBytes(receipt) as BufferSource);
    receipt.signature.value = overrides.corruptSignature
      ? rawHex(signed).replace(/^../, '00')
      : rawHex(signed);

    const attestation = {
      signing_address: '0xabc',
      attestation: { workload_keyset: keyset },
    } as unknown as AttestationResponse;

    const signatureResponse = {
      signing_address: '0xabc',
      receipt,
      ...overrides.signatureResponse,
    } as SignatureResponse;

    return { attestation, signatureResponse };
  }

  beforeAll(async () => {
    keyPair = (await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])) as CryptoKeyPair;
    publicKeyHex = rawHex(await crypto.subtle.exportKey('raw', keyPair.publicKey));
  });

  it('verifies a well-formed receipt', async () => {
    const { attestation, signatureResponse } = await build();
    const result = await verifyReceipt(signatureResponse, attestation, { requestId: 'chat-123' });
    expect(result.verified).toBe(true);
    expect(result.checks.every((c) => c.ok)).toBe(true);
  });

  it('rejects a tampered event log', async () => {
    const { attestation, signatureResponse } = await build();
    // Rewrite a hash after signing: the signature covers the whole receipt.
    signatureResponse.receipt.event_log[0].body_hash = 'sha256:bb';
    const result = await verifyReceipt(signatureResponse, attestation);
    expect(result.verified).toBe(false);
    expect(result.checks.find((c) => c.name === 'receipt_signature')?.ok).toBe(false);
  });

  it('rejects a corrupted signature', async () => {
    const { attestation, signatureResponse } = await build({ corruptSignature: true });
    const result = await verifyReceipt(signatureResponse, attestation);
    expect(result.verified).toBe(false);
    expect(result.checks.find((c) => c.name === 'receipt_signature')?.ok).toBe(false);
  });

  it('rejects a key that is not in the attested keyset', async () => {
    const { attestation, signatureResponse } = await build();
    signatureResponse.receipt.signature.key_id = 'some-other-key';
    const result = await verifyReceipt(signatureResponse, attestation);
    expect(result.verified).toBe(false);
    expect(result.checks.find((c) => c.name === 'key_in_attested_keyset')?.ok).toBe(false);
  });

  it('rejects a keyset swapped after the digest was computed', async () => {
    const { attestation, signatureResponse } = await build();
    const keyset = (attestation as unknown as { attestation: { workload_keyset: WorkloadKeyset } })
      .attestation.workload_keyset;
    (keyset as { extra?: string }).extra = 'injected';
    const result = await verifyReceipt(signatureResponse, attestation);
    expect(result.verified).toBe(false);
    expect(result.checks.find((c) => c.name === 'keyset_digest_matches')?.ok).toBe(false);
  });

  it('rejects a receipt for a different completion', async () => {
    const { attestation, signatureResponse } = await build();
    const result = await verifyReceipt(signatureResponse, attestation, { requestId: 'chat-999' });
    expect(result.verified).toBe(false);
    expect(result.checks.find((c) => c.name === 'chat_id_matches_request')?.ok).toBe(false);
  });

  it('does not check the request id when none is supplied', async () => {
    const { attestation, signatureResponse } = await build();
    const result = await verifyReceipt(signatureResponse, attestation);
    expect(result.verified).toBe(true);
    expect(result.checks.find((c) => c.name === 'chat_id_matches_request')).toBeUndefined();
  });

  it('flags a signing address that disagrees with the attestation', async () => {
    const { attestation, signatureResponse } = await build({
      signatureResponse: { signing_address: '0xdifferent' },
    });
    const result = await verifyReceipt(signatureResponse, attestation);
    expect(result.verified).toBe(false);
    expect(
      result.checks.find((c) => c.name === 'signing_address_matches_attestation')?.ok
    ).toBe(false);
  });

  it('reports rather than throws when there is no receipt', async () => {
    const result = await verifyReceipt(
      { receipt: undefined } as unknown as SignatureResponse,
      {} as AttestationResponse
    );
    expect(result.verified).toBe(false);
    expect(result.checks[0].name).toBe('receipt_present');
  });

  it('reports rather than throws when the attestation has no keyset', async () => {
    const { signatureResponse } = await build();
    const result = await verifyReceipt(signatureResponse, {} as AttestationResponse);
    expect(result.verified).toBe(false);
    expect(result.checks.find((c) => c.name === 'keyset_present')?.ok).toBe(false);
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
