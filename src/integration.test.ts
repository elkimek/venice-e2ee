import { describe, it, expect } from 'vitest';
import { createVeniceE2EE, isE2EEModel } from './index.js';

const API_KEY = process.env.VENICE_API_KEY;
const MODEL = process.env.VENICE_E2EE_MODEL || 'e2ee-qwen3-5-122b-a10b';

describe.skipIf(!API_KEY)('Venice E2EE integration', () => {
  it('fetches attestation and creates session', { timeout: 30000 }, async () => {
    const e2ee = createVeniceE2EE({ apiKey: API_KEY! });
    const session = await e2ee.createSession(MODEL);

    expect(session.privateKey).toBeInstanceOf(Uint8Array);
    expect(session.publicKey.length).toBe(65);
    expect(session.modelPubKeyHex).toMatch(/^[0-9a-f]+$/i);
    expect(session.modelId).toBe(MODEL);
  });

  it('encrypts and sends a chat completion with streaming decryption', async () => {
    const e2ee = createVeniceE2EE({ apiKey: API_KEY! });
    const session = await e2ee.createSession(MODEL);

    const messages = [
      { role: 'user', content: 'Reply with exactly: "E2EE works"' },
    ];

    const { encryptedMessages, headers, veniceParameters } =
      await e2ee.encrypt(messages, session);

    // Verify encryption happened
    expect(encryptedMessages[0].content).not.toBe(messages[0].content);
    expect(encryptedMessages[0].content).toMatch(/^[0-9a-f]+$/i);

    // Send to Venice
    const res = await fetch(
      'https://api.venice.ai/api/v1/chat/completions',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${API_KEY}`,
          ...headers,
        },
        body: JSON.stringify({
          model: MODEL,
          messages: encryptedMessages,
          stream: true,
          max_tokens: 50,
          venice_parameters: veniceParameters,
        }),
      }
    );

    expect(res.ok).toBe(true);

    // Decrypt streaming response
    let fullText = '';
    for await (const chunk of e2ee.decryptStream(res.body!, session)) {
      fullText += chunk;
    }

    console.log('Decrypted response:', fullText);
    expect(fullText.length).toBeGreaterThan(0);
  }, 30000);

  it('model detection works', () => {
    expect(isE2EEModel('e2ee-qwen3-5-122b-a10b')).toBe(true);
    expect(isE2EEModel('llama-3.3-70b')).toBe(false);
  });
});
