import { describe, it, expect } from 'vitest';
import {
  generateKeypair,
  deriveAESKey,
  encryptMessage,
} from './crypto.js';
import { decryptSSEStream, VeniceStreamError } from './stream.js';

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

function createRawStream(text: string): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  return new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode(text));
      controller.close();
    },
  });
}

async function collect(
  stream: ReadableStream<Uint8Array>,
  privateKey: Uint8Array
): Promise<string[]> {
  const chunks: string[] = [];
  for await (const chunk of decryptSSEStream(stream, privateKey)) {
    chunks.push(chunk);
  }
  return chunks;
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

  it('fails closed on plaintext model output', async () => {
    const client = generateKeypair();
    const event = JSON.stringify({ choices: [{ delta: { content: 'not encrypted' } }] });
    const stream = createSSEStream([event, '[DONE]']);

    const read = async () => {
      for await (const _chunk of decryptSSEStream(stream, client.privateKey)) {
        // consume
      }
    };
    await expect(read()).rejects.toThrow('unencrypted content');
  });

  it('allows explicit legacy plaintext passthrough', async () => {
    const client = generateKeypair();
    const event = JSON.stringify({ choices: [{ delta: { content: 'legacy' } }] });
    const stream = createSSEStream([event, '[DONE]']);
    const chunks: string[] = [];
    for await (const chunk of decryptSSEStream(stream, client.privateKey, true)) {
      chunks.push(chunk);
    }
    expect(chunks).toEqual(['legacy']);
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

  it('completes on [DONE] without a trailing newline', async () => {
    const client = generateKeypair();
    const cipherHex = await encryptForStream('done', client.privateKey, client.pubKeyHex);
    const event = JSON.stringify({ choices: [{ delta: { content: cipherHex } }] });
    const stream = createRawStream(`data: ${event}\n\ndata: [DONE]`);

    expect(await collect(stream, client.privateKey)).toEqual(['done']);
  });

  it('throws on a malformed JSON event', async () => {
    const client = generateKeypair();
    const first = await encryptForStream('kept', client.privateKey, client.pubKeyHex);
    const lost = await encryptForStream('lost', client.privateKey, client.pubKeyHex);
    const last = await encryptForStream('after', client.privateKey, client.pubKeyHex);
    const events = [
      JSON.stringify({ choices: [{ delta: { content: first } }] }),
      `{"choices":[{"delta":{"content":"${lost}"}}`,
      JSON.stringify({ choices: [{ delta: { content: last } }] }),
      '[DONE]',
    ];

    await expect(collect(createSSEStream(events), client.privateKey)).rejects.toThrow(
      'malformed event'
    );
  });

  it('throws when the stream ends without [DONE]', async () => {
    const client = generateKeypair();
    const cipherHex = await encryptForStream('cut', client.privateKey, client.pubKeyHex);
    const event = JSON.stringify({ choices: [{ delta: { content: cipherHex } }] });

    await expect(collect(createSSEStream([event]), client.privateKey)).rejects.toThrow(
      'ended without [DONE]'
    );
  });

  it('throws when the stream ends after a complete event without a newline', async () => {
    const client = generateKeypair();
    const cipherHex = await encryptForStream('cut', client.privateKey, client.pubKeyHex);
    const event = JSON.stringify({ choices: [{ delta: { content: cipherHex } }] });

    await expect(collect(createRawStream(`data: ${event}`), client.privateKey)).rejects.toThrow(
      'ended without [DONE]'
    );
  });

  it('throws when the stream ends inside a partial event', async () => {
    const client = generateKeypair();
    const first = await encryptForStream('kept', client.privateKey, client.pubKeyHex);
    const partial = await encryptForStream('partial', client.privateKey, client.pubKeyHex);
    const event = JSON.stringify({ choices: [{ delta: { content: first } }] });
    const text = `data: ${event}\n\ndata: {"choices":[{"delta":{"content":"${partial.slice(0, 40)}`;

    await expect(collect(createRawStream(text), client.privateKey)).rejects.toThrow(
      'malformed event'
    );
  });

  it('throws on tampered ciphertext', async () => {
    const client = generateKeypair();
    const cipherHex = await encryptForStream('tampered', client.privateKey, client.pubKeyHex);
    // The last hex digit lies in the AES-GCM authentication tag.
    const lastDigit = cipherHex.slice(-1);
    const tampered = cipherHex.slice(0, -1) + (lastDigit === '0' ? '1' : '0');
    const event = JSON.stringify({ choices: [{ delta: { content: tampered } }] });

    await expect(
      collect(createSSEStream([event, '[DONE]']), client.privateKey)
    ).rejects.toThrow('E2EE decryption failed');
  });
  it('throws VeniceStreamError on an in-band error event after partial output', async () => {
    const client = generateKeypair();
    const cipherHex = await encryptForStream('partial', client.privateKey, client.pubKeyHex);
    // Shape observed live from Venice on an E2EE model after 120s without tokens.
    const error = {
      message: 'Streaming request timed out after 120 seconds of inactivity.',
      type: 'api_error',
      code: 'stream_inactivity_timeout',
      param: null,
    };
    const events = [
      JSON.stringify({ choices: [{ delta: { content: cipherHex } }] }),
      JSON.stringify({ error }),
      '[DONE]',
    ];

    const chunks: string[] = [];
    let thrown: unknown;
    try {
      for await (const chunk of decryptSSEStream(createSSEStream(events), client.privateKey)) {
        chunks.push(chunk);
      }
    } catch (e) {
      thrown = e;
    }

    expect(chunks).toEqual(['partial']);
    expect(thrown).toBeInstanceOf(VeniceStreamError);
    const err = thrown as VeniceStreamError;
    expect(err.message).toBe(
      'Venice stream reported an error: Streaming request timed out after 120 seconds of inactivity.'
    );
    expect(err.code).toBe('stream_inactivity_timeout');
    expect(err.type).toBe('api_error');
    expect(err.error).toEqual(error);
  });

  it('throws on an error event even when [DONE] follows immediately', async () => {
    const client = generateKeypair();
    const events = [JSON.stringify({ error: { message: 'upstream failed' } }), '[DONE]'];

    await expect(collect(createSSEStream(events), client.privateKey)).rejects.toThrow(
      'Venice stream reported an error: upstream failed'
    );
  });

  it('throws on an error event split across reads', async () => {
    const client = generateKeypair();
    const events = [JSON.stringify({ error: { message: 'split', code: 503 } }), '[DONE]'];

    await expect(collect(createChunkedSSEStream(events), client.privateKey)).rejects.toMatchObject({
      name: 'VeniceStreamError',
      code: 503,
      type: null,
    });
  });

  it('reports a string or shapeless error value', async () => {
    const client = generateKeypair();

    await expect(
      collect(createSSEStream([JSON.stringify({ error: 'rate limited' }), '[DONE]']), client.privateKey)
    ).rejects.toThrow('Venice stream reported an error: rate limited');
    await expect(
      collect(createSSEStream([JSON.stringify({ error: {} }), '[DONE]']), client.privateKey)
    ).rejects.toThrow('Venice stream reported an error: unknown error');
  });

  it('ignores a null error field', async () => {
    const client = generateKeypair();
    const cipherHex = await encryptForStream('ok', client.privateKey, client.pubKeyHex);
    const events = [
      JSON.stringify({ error: null, choices: [{ delta: { content: cipherHex } }] }),
      '[DONE]',
    ];

    expect(await collect(createSSEStream(events), client.privateKey)).toEqual(['ok']);
  });
});
