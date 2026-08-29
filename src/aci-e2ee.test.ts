import { describe, expect, it } from 'vitest';
import {
  ACI_E2EE_ALGORITHM,
  aciE2eeAad,
  createAciE2eeClientKeyPair,
  decryptAciE2eeField,
  encryptAciE2eeField,
  generateAciE2eeNonce,
} from './aci-e2ee.js';
import { toHex } from './crypto.js';

const NONCE = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';

describe('provider-neutral ACI E2EE v2', () => {
  it('generates a 32-byte hexadecimal request nonce', () => {
    expect(generateAciE2eeNonce()).toMatch(/^[0-9a-f]{64}$/);
  });

  it('matches the ACI request and response canonical AAD vectors', () => {
    expect(new TextDecoder().decode(aciE2eeAad({
      purpose: 'aci.e2ee.request.v2',
      model: 'demo/model',
      field: 'messages.0.content',
      nonce: NONCE,
      timestamp: 1750000000,
    }))).toBe(
      `{"algo":"${ACI_E2EE_ALGORITHM}","field":"messages.0.content","model":"demo/model","nonce":"${NONCE}","purpose":"aci.e2ee.request.v2","ts":1750000000}`
    );

    expect(new TextDecoder().decode(aciE2eeAad({
      purpose: 'aci.e2ee.response.v2',
      model: 'demo/model',
      responseId: 'chatcmpl-123',
      field: 'choices.0.message.content',
      nonce: NONCE,
      timestamp: 1750000000,
    }))).toBe(
      `{"algo":"${ACI_E2EE_ALGORITHM}","field":"choices.0.message.content","id":"chatcmpl-123","model":"demo/model","nonce":"${NONCE}","purpose":"aci.e2ee.response.v2","ts":1750000000}`
    );
  });

  it('round-trips deterministic field encryption and binds all AAD fields', async () => {
    const recipient = createAciE2eeClientKeyPair({
      secretKey: Uint8Array.from({ length: 32 }, (_, index) => index + 1),
    });
    const context = {
      purpose: 'aci.e2ee.request.v2' as const,
      model: 'demo/model',
      field: 'messages.0.content',
      nonce: NONCE,
      timestamp: 1750000000,
    };
    const ciphertext = await encryptAciE2eeField(
      'synthetic interoperability prompt',
      recipient.publicKeyHex,
      context,
      {
        ephemeralSecretKey: Uint8Array.from({ length: 32 }, (_, index) => index + 33),
        aesNonce: Uint8Array.from({ length: 12 }, (_, index) => index + 65),
      }
    );

    expect(ciphertext).not.toContain(
      toHex(new TextEncoder().encode('synthetic interoperability prompt'))
    );
    await expect(
      decryptAciE2eeField(ciphertext, recipient.secretKey, context)
    ).resolves.toBe('synthetic interoperability prompt');
    await expect(
      decryptAciE2eeField(ciphertext, recipient.secretKey, {
        ...context,
        field: 'messages.1.content',
      })
    ).rejects.toThrow(/authentication failed/i);
  });

  it('rejects malformed key and ciphertext lengths', async () => {
    expect(() => createAciE2eeClientKeyPair({ secretKey: new Uint8Array(31) }))
      .toThrow(/exactly 32 bytes/i);
    await expect(encryptAciE2eeField(
      'synthetic',
      '00'.repeat(31),
      {
        purpose: 'aci.e2ee.request.v2',
        model: 'demo/model',
        field: 'messages.0.content',
        nonce: NONCE,
        timestamp: 1750000000,
      }
    )).rejects.toThrow(/recipient key/i);
    await expect(decryptAciE2eeField(
      '00'.repeat(60),
      new Uint8Array(32),
      {
        purpose: 'aci.e2ee.response.v2',
        model: 'demo/model',
        responseId: 'chatcmpl-malformed',
        field: 'choices.0.message.content',
        nonce: NONCE,
        timestamp: 1750000000,
      }
    )).rejects.toThrow(/malformed/i);
  });

  it('rejects malformed hexadecimal input and ambiguous AAD contexts', async () => {
    const context = {
      purpose: 'aci.e2ee.request.v2' as const,
      model: 'demo/model',
      field: 'messages.0.content',
      nonce: NONCE,
      timestamp: 1750000000,
    };
    await expect(encryptAciE2eeField('synthetic', '0g'.repeat(32), context))
      .rejects.toThrow(/hexadecimal/i);
    expect(() => aciE2eeAad({ ...context, nonce: '00' }))
      .toThrow(/exactly 32 hexadecimal bytes/i);
    expect(() => aciE2eeAad({ ...context, responseId: 'request-must-not-have-this' }))
      .toThrow(/must not contain a response id/i);
    expect(() => aciE2eeAad({
      ...context,
      purpose: 'aci.e2ee.response.v2',
    })).toThrow(/needs a bounded response id/i);
  });
});
