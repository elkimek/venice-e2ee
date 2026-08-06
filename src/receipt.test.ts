import { beforeAll, describe, expect, it } from 'vitest';
import { getPublicKey, signAsync, utils } from '@noble/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3.js';
import {
  BODY_BINDING_CHECKS,
  computeWorkloadId,
  computeWorkloadKeysetDigest,
  hashReceiptBody,
  jcsStringify,
  receiptSigningBytes,
  recoverReceiptSigner,
  sha256Prefixed,
  verifyReceipt,
} from './receipt.js';
import { deriveEthAddress } from './attestation.js';
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

  it('names exactly the checks a caller behind a re-serializing gateway will see fail', async () => {
    // Callers of api.venice.ai cannot reproduce either body hash — the bytes are
    // re-serialized before the enclave sees them. BODY_BINDING_CHECKS lets them
    // tell that apart from a receipt that is actually wrong, so it has to stay
    // in step with the names the verifier emits.
    const fixture = await build();
    const result = await verifyReceipt(
      fixture.signatureResponse,
      fixture.attestation,
      options(fixture, { requestBody: 'other bytes', responseBody: 'other bytes' })
    );

    expect(result.verified).toBe(false);
    const failed = result.checks.filter((check) => !check.ok).map((check) => check.name);
    expect(failed.sort()).toEqual([...BODY_BINDING_CHECKS].sort());
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

  // ── The one binding that reaches the quote without the keyset ──────
  //
  // The receipt body is signed by an Ed25519 key out of the workload keyset,
  // which is only as good as the anchor that keyset came under. The top-level
  // signature is made by the secp256k1 key whose address the TDX quote carries
  // in REPORTDATA, so it is checkable against the quote directly.
  describe('top-level signature', () => {
    const privateKey = utils.randomPrivateKey();
    const address = `0x${toHex(deriveEthAddress(toHex(getPublicKey(privateKey, false))))}`;
    const strip = (hash: string): string => hash.replace(/^sha256:/, '');
    const signedText = `${strip(hashReceiptBody(REQUEST_BODY))}:${strip(hashReceiptBody(RESPONSE_BODY))}`;

    async function personalSign(text: string, key: Uint8Array): Promise<string> {
      const message = enc.encode(text);
      const prefix = enc.encode(`\x19Ethereum Signed Message:\n${message.length}`);
      const signature = await signAsync(keccak_256(new Uint8Array([...prefix, ...message])), key);
      return `0x${signature.toCompactHex()}${signature.recovery.toString(16).padStart(2, '0')}`;
    }

    async function signedFixture(overrides: { text?: string; key?: Uint8Array } = {}) {
      const text = overrides.text ?? signedText;
      return build({
        attestation: { signing_address: address },
        signatureResponse: {
          signing_address: address,
          text,
          signature: await personalSign(text, overrides.key ?? privateKey),
        },
      });
    }

    it('recovers the signer of a known EIP-191 signature', async () => {
      const signature = await personalSign('hello', privateKey);
      expect(recoverReceiptSigner('hello', signature).toLowerCase()).toBe(address.toLowerCase());
    });

    it('rejects a signature that is not 65 recoverable bytes', () => {
      expect(() => recoverReceiptSigner('hello', '0xdeadbeef')).toThrow('65 recoverable bytes');
    });

    it('accepts a receipt whose hashes the attested key signed', async () => {
      const fixture = await signedFixture();
      const result = await verifyReceipt(
        fixture.signatureResponse,
        fixture.attestation,
        options(fixture)
      );
      expect(result.checks).toContainEqual(
        expect.objectContaining({ name: 'signature_recovers_to_attested_key', ok: true })
      );
      expect(result.checks).toContainEqual(
        expect.objectContaining({ name: 'signed_text_matches_receipt_hashes', ok: true })
      );
      expect(result.verified).toBe(true);
    });

    it('refuses a signature made by a key the quote does not bind', async () => {
      const fixture = await signedFixture({ key: utils.randomPrivateKey() });
      const result = await verifyReceipt(
        fixture.signatureResponse,
        fixture.attestation,
        options(fixture)
      );
      expect(result.verified).toBe(false);
      expect(result.checks).toContainEqual(
        expect.objectContaining({ name: 'signature_recovers_to_attested_key', ok: false })
      );
    });

    it('refuses a validly signed statement about some other pair of hashes', async () => {
      // The signature verifies; it just does not describe this receipt.
      const fixture = await signedFixture({ text: `${'11'.repeat(32)}:${'22'.repeat(32)}` });
      const result = await verifyReceipt(
        fixture.signatureResponse,
        fixture.attestation,
        options(fixture)
      );
      expect(result.verified).toBe(false);
      expect(result.checks).toContainEqual(
        expect.objectContaining({ name: 'signed_text_matches_receipt_hashes', ok: false })
      );
    });

    it('refuses a partial top-level signature instead of silently skipping it', async () => {
      const textOnly = await build({ signatureResponse: { text: signedText } });
      const textOnlyResult = await verifyReceipt(
        textOnly.signatureResponse,
        textOnly.attestation,
        options(textOnly)
      );
      expect(textOnlyResult.verified).toBe(false);
      expect(textOnlyResult.checks).toContainEqual(
        expect.objectContaining({ name: 'top_level_signature_complete', ok: false })
      );

      const signatureOnly = await build({
        signatureResponse: { signature: await personalSign(signedText, privateKey) },
      });
      const signatureOnlyResult = await verifyReceipt(
        signatureOnly.signatureResponse,
        signatureOnly.attestation,
        options(signatureOnly)
      );
      expect(signatureOnlyResult.verified).toBe(false);
      expect(signatureOnlyResult.checks).toContainEqual(
        expect.objectContaining({ name: 'top_level_signature_complete', ok: false })
      );
    });

    it('refuses a top-level signature when no attested signing address is available', async () => {
      const fixture = await signedFixture();
      delete fixture.attestation.signing_address;
      delete fixture.signatureResponse.signing_address;

      const result = await verifyReceipt(
        fixture.signatureResponse,
        fixture.attestation,
        options(fixture)
      );

      expect(result.verified).toBe(false);
      expect(result.checks).toContainEqual(
        expect.objectContaining({ name: 'signature_recovers_to_attested_key', ok: false })
      );
    });

    it('stays silent on gateways that serve neither field', async () => {
      const fixture = await build();
      const result = await verifyReceipt(
        fixture.signatureResponse,
        fixture.attestation,
        options(fixture)
      );
      const names = result.checks.map((check) => check.name);
      expect(names).not.toContain('signature_recovers_to_attested_key');
      expect(names).not.toContain('signed_text_matches_receipt_hashes');
    });
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
