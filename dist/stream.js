import { decryptChunk } from './crypto.js';
/**
 * Parse an SSE stream from Venice's chat completions endpoint and yield
 * decrypted text chunks. Each SSE event contains a JSON object with
 * `choices[0].delta.content` holding an encrypted hex string (or plaintext
 * for whitespace tokens).
 *
 * A malformed event or a stream that ends without `data: [DONE]` throws, so a
 * visibly truncated response is not mistaken for a complete one. This does not
 * detect whole events dropped, reordered or replayed by a relay.
 *
 * Usage:
 *   const response = await fetch(url, { ... });
 *   for await (const text of decryptSSEStream(response.body, session.privateKey)) {
 *     process.stdout.write(text);
 *   }
 */
export async function* decryptSSEStream(body, privateKey, allowPlaintextResponses = false) {
    const reader = body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    try {
        while (true) {
            const { done, value } = await reader.read();
            buffer += done ? decoder.decode() : decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            // At EOF the remainder is the final line, not the start of a later one.
            buffer = done ? '' : lines.pop();
            for (const line of lines) {
                if (!line.startsWith('data: '))
                    continue;
                const data = line.slice(6).trim();
                if (data === '[DONE]')
                    return;
                let event;
                try {
                    event = JSON.parse(data);
                }
                catch {
                    throw new Error('Venice stream contained a malformed event; the response is incomplete');
                }
                const content = event.choices?.[0]?.delta?.content;
                if (content === undefined || content === null)
                    continue;
                try {
                    yield await decryptChunk(privateKey, content, allowPlaintextResponses);
                }
                catch (e) {
                    if (e instanceof DOMException && e.name === 'OperationError') {
                        throw new Error('E2EE decryption failed — session may be stale. Clear the session and retry.');
                    }
                    throw e;
                }
            }
            if (done)
                break;
        }
        throw new Error('Venice stream ended without [DONE]; the response is truncated');
    }
    finally {
        reader.releaseLock();
    }
}
//# sourceMappingURL=stream.js.map