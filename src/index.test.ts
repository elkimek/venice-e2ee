import { describe, expect, it } from 'vitest';
import { generateKeypair, deriveAESKey } from './crypto.js';
import { createVeniceE2EE } from './index.js';
import type { E2EESession } from './types.js';

describe('createVeniceE2EE.encrypt', () => {
  it('does not copy plaintext tool metadata into encrypted messages', async () => {
    const client = generateKeypair();
    const model = generateKeypair();
    const session: E2EESession = {
      ...client,
      aesKey: await deriveAESKey(client.privateKey, model.pubKeyHex),
      modelPubKeyHex: model.pubKeyHex,
      modelId: 'e2ee-test',
      created: Date.now(),
    };
    const e2ee = createVeniceE2EE({
      apiKey: 'unused',
      verifyAttestation: false,
    });

    const payload = await e2ee.encrypt(
      [
        {
          role: 'assistant',
          content: null,
          tool_call_id: 'call_secret_opaque_id',
          tool_calls: [
            {
              id: 'call_1',
              type: 'function',
              function: { name: 'secret_function', arguments: '{"secret":"value"}' },
            },
          ],
          name: 'secret_function',
          custom_metadata: 'secret value',
        },
      ],
      session
    );

    expect(payload.encryptedMessages[0]).toEqual({
      role: 'assistant',
      content: expect.any(String),
    });
    expect(payload.encryptedMessages[0].content).not.toContain('secret');

    const toolPayload = await e2ee.encrypt(
      [
        {
          role: 'tool',
          content: 'tool result',
          tool_call_id: 'call_required_by_venice',
          name: 'secret_function',
        },
      ],
      session
    );
    expect(toolPayload.encryptedMessages[0]).toEqual({
      role: 'tool',
      content: expect.any(String),
      tool_call_id: 'call_required_by_venice',
    });
    expect(toolPayload.encryptedMessages[0].content).not.toContain(
      'secret_function'
    );
  });
});

describe('createVeniceE2EE policy configuration', () => {
  it('rejects a required DCAP policy when verification is disabled', () => {
    expect(() =>
      createVeniceE2EE({
        apiKey: 'test-key',
        verifyAttestation: false,
        requireDcap: true,
      })
    ).toThrow('Attestation policy cannot be required');
  });

  it('rejects a measurement policy when verification is disabled', () => {
    expect(() =>
      createVeniceE2EE({
        apiKey: 'test-key',
        verifyAttestation: false,
        expectedMeasurements: { mrTd: '0'.repeat(96) },
      })
    ).toThrow('Attestation policy cannot be required');
  });
});
