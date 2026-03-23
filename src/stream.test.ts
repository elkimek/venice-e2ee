import { describe, it, expect } from 'vitest';
import {
  generateKeypair,
  deriveAESKey,
  encryptMessage,
} from './crypto.js';
import { decryptSSEStream } from './stream.js';

function createSSEStream(events: string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  const sseText = events.map((e) => `data: ${e}\n\n`).join('');
  return new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode(sseText));
      controller.close();
    },
  });
}

function createChunkedSSEStream(events: string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  const sseText = events.map((e) => `data: ${e}\n\n`).join('');
  // Split into small chunks to simulate real streaming
  const bytes = encoder.encode(sseText);
  const chunkSize = 20;
  return new ReadableStream({
    start(controller) {
      for (let i = 0; i < bytes.length; i += chunkSize) {
        controller.enqueue(bytes.slice(i, i + chunkSize));
      }
      controller.close();
    },
  });
}

async function encryptForStream(
  plaintext: string,
  serverPrivateKey: Uint8Array,
  clientPubKeyHex: string
): Promise<string> {
  const serverEphemeral = generateKeypair();
  const aesKey = await deriveAESKey(serverEphemeral.privateKey, clientPubKeyHex);
  return encryptMessage(aesKey, serverEphemeral.publicKey, plaintext);
}

describe('decryptSSEStream', () => {
  it('decrypts a single-chunk stream', async () => {
    const client = generateKeypair();
    const cipherHex = await encryptForStream('Hello!', client.privateKey, client.pubKeyHex);

    // Wait — encryptForStream uses a server ephemeral key and client pub key.
    // decryptSSEStream uses client private key to decrypt.
    // The cipher was created with ECDH(server_eph_priv, client_pub), embedded server_eph_pub.
    // decryptChunk does ECDH(client_priv, server_eph_pub) — same shared secret. ✓

    const sseEvent = JSON.stringify({
      choices: [{ delta: { content: cipherHex } }],
    });

    const stream = createSSEStream([sseEvent, '[DONE]']);
    const chunks: string[] = [];
    for await (const chunk of decryptSSEStream(stream, client.privateKey)) {
      chunks.push(chunk);
    }

    expect(chunks).toEqual(['Hello!']);
  });

  it('decrypts multiple chunks with per-chunk ephemeral keys', async () => {
    const client = generateKeypair();
    const plaintexts = ['The ', 'answer ', 'is ', '42.'];

    const events: string[] = [];
    for (const pt of plaintexts) {
      const cipherHex = await encryptForStream(pt, client.privateKey, client.pubKeyHex);
      events.push(
        JSON.stringify({ choices: [{ delta: { content: cipherHex } }] })
      );
    }
    events.push('[DONE]');

    const stream = createSSEStream(events);
    const chunks: string[] = [];
    for await (const chunk of decryptSSEStream(stream, client.privateKey)) {
      chunks.push(chunk);
    }

    expect(chunks).toEqual(plaintexts);
  });

  it('handles chunked delivery (split across reads)', async () => {
    const client = generateKeypair();
    const cipherHex = await encryptForStream('streamed', client.privateKey, client.pubKeyHex);

    const events = [
      JSON.stringify({ choices: [{ delta: { content: cipherHex } }] }),
      '[DONE]',
    ];

    const stream = createChunkedSSEStream(events);
    const chunks: string[] = [];
    for await (const chunk of decryptSSEStream(stream, client.privateKey)) {
      chunks.push(chunk);
    }

    expect(chunks).toEqual(['streamed']);
  });

  it('passes through plaintext content (whitespace tokens)', async () => {
    const client = generateKeypair();

    const events = [
      JSON.stringify({ choices: [{ delta: { content: ' ' } }] }),
      JSON.stringify({ choices: [{ delta: { content: '\n' } }] }),
      '[DONE]',
    ];

    const stream = createSSEStream(events);
    const chunks: string[] = [];
    for await (const chunk of decryptSSEStream(stream, client.privateKey)) {
      chunks.push(chunk);
    }

    expect(chunks).toEqual([' ', '\n']);
  });

  it('skips events without content', async () => {
    const client = generateKeypair();
    const cipherHex = await encryptForStream('data', client.privateKey, client.pubKeyHex);

    const events = [
      JSON.stringify({ choices: [{ delta: {} }] }),
      JSON.stringify({ choices: [{ delta: { content: cipherHex } }] }),
      JSON.stringify({ choices: [] }),
      '[DONE]',
    ];

    const stream = createSSEStream(events);
    const chunks: string[] = [];
    for await (const chunk of decryptSSEStream(stream, client.privateKey)) {
      chunks.push(chunk);
    }

    expect(chunks).toEqual(['data']);
  });

  it('handles empty stream', async () => {
    const client = generateKeypair();
    const stream = createSSEStream(['[DONE]']);
    const chunks: string[] = [];
    for await (const chunk of decryptSSEStream(stream, client.privateKey)) {
      chunks.push(chunk);
    }
    expect(chunks).toEqual([]);
  });
});
