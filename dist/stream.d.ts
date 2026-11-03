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
export declare class VeniceStreamError extends Error {
    /** Venice's error code, e.g. `stream_inactivity_timeout`, when provided. */
    readonly code: string | number | null;
    /** Venice's error type, e.g. `api_error`, when provided. */
    readonly type: string | null;
    /** The `error` value exactly as received. */
    readonly error: unknown;
    constructor(error: unknown);
}
export declare function decryptSSEStream(body: ReadableStream<Uint8Array>, privateKey: Uint8Array, allowPlaintextResponses?: boolean): AsyncGenerator<string>;
//# sourceMappingURL=stream.d.ts.map