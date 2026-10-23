import { decryptChunk } from './crypto.js';

/**
 * Parse an SSE stream from Venice's chat completions endpoint and yield
 * decrypted text chunks. Each SSE event contains a JSON object with
 * `choices[0].delta.content` holding an encrypted hex string (or plaintext
 * for whitespace tokens).
 *
 * A malformed event or a stream that ends without `data: [DONE]` throws, so a
 * visibly truncated response is not mistaken for a complete one. An in-band
 * `data: {"error": ...}` event throws a {@link VeniceStreamError} carrying the
 * error Venice reported. This does not detect whole events dropped, reordered
 * or replayed by a relay.
 *
 * Usage:
 *   const response = await fetch(url, { ... });
 *   for await (const text of decryptSSEStream(response.body, session.privateKey)) {
 *     process.stdout.write(text);
 *   }
 */
/**
 * An error Venice reported inside a stream that had already started, as a
 * `data: {"error": {...}}` event — for example `stream_inactivity_timeout` once
 * the upstream model stops producing tokens. The HTTP status is 200 by then, so
 * this event is the only signal that the response did not complete.
 *
 * The fields are Venice's own plaintext error metadata, not model output.
 */
export class VeniceStreamError extends Error {
  /** Venice's error code, e.g. `stream_inactivity_timeout`, when provided. */
  readonly code: string | number | null;
  /** Venice's error type, e.g. `api_error`, when provided. */
  readonly type: string | null;
  /** The `error` value exactly as received. */
  readonly error: unknown;

  constructor(error: unknown) {
    const obj = error && typeof error === 'object' ? (error as Record<string, unknown>) : {};
    const message =
      typeof obj.message === 'string' && obj.message
        ? obj.message
        : typeof error === 'string' && error
          ? error
          : 'unknown error';
    super(`Venice stream reported an error: ${message}`);
    this.name = 'VeniceStreamError';
    this.code =
      typeof obj.code === 'string' || typeof obj.code === 'number' ? obj.code : null;
    this.type = typeof obj.type === 'string' ? obj.type : null;
    this.error = error;
  }
}

export async function* decryptSSEStream(
  body: ReadableStream<Uint8Array>,
  privateKey: Uint8Array,
  allowPlaintextResponses = false
): AsyncGenerator<string> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  try {
    while (true) {
      const { done, value } = await reader.read();
      buffer += done ? decoder.decode() : decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      // At EOF the remainder is the final line, not the start of a later one.
      buffer = done ? '' : lines.pop()!;

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const data = line.slice(6).trim();
        if (data === '[DONE]') return;

        let event: { choices?: Array<{ delta?: { content?: string } }>; error?: unknown };
        try {
          event = JSON.parse(data);
        } catch {
          throw new Error('Venice stream contained a malformed event; the response is incomplete');
        }

        // Venice reports failures after the 200 status as an in-band event. Skipping
        // it made a failed response indistinguishable from an empty one until EOF.
        if (event.error !== undefined && event.error !== null) {
          throw new VeniceStreamError(event.error);
        }

        const content = event.choices?.[0]?.delta?.content;
        if (content === undefined || content === null) continue;

        try {
          yield await decryptChunk(privateKey, content, allowPlaintextResponses);
        } catch (e: unknown) {
          if (e instanceof DOMException && e.name === 'OperationError') {
            throw new Error(
              'E2EE decryption failed — session may be stale. Clear the session and retry.'
            );
          }
          throw e;
        }
      }

      if (done) break;
    }

    throw new Error('Venice stream ended without [DONE]; the response is truncated');
  } finally {
    reader.releaseLock();
  }
}
