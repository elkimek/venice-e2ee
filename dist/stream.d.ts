/**
 * Parse an SSE stream from Venice's chat completions endpoint and yield
 * decrypted text chunks. Each SSE event contains a JSON object with
 * `choices[0].delta.content` holding an encrypted hex string (or plaintext
 * for whitespace tokens).
 *
 * Usage:
 *   const response = await fetch(url, { ... });
 *   for await (const text of decryptSSEStream(response.body, session.privateKey)) {
 *     process.stdout.write(text);
 *   }
 */
export declare function decryptSSEStream(body: ReadableStream<Uint8Array>, privateKey: Uint8Array): AsyncGenerator<string>;
//# sourceMappingURL=stream.d.ts.map