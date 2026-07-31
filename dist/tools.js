/**
 * Function calling over E2EE.
 *
 * Venice's E2EE gateway drops the OpenAI `tools` parameter: a request carrying
 * encrypted messages never reaches the model with its tool schemas attached
 * (verified against `e2ee-glm-5-2-p` — the same model returns native tool_calls
 * when the E2EE headers are absent). Tool definitions therefore have to travel
 * inside the encrypted channel like any other prompt content.
 *
 * This module renders tool schemas and tool-call history into text that is
 * encrypted with the rest of the conversation, and parses the model's emitted
 * `<tool_call>` blocks back into OpenAI-shaped tool calls. Venice sees only
 * ciphertext — the tool names, descriptions, arguments and results stay private,
 * which the plaintext `tools` parameter would not have achieved anyway.
 */
/**
 * Reduce OpenAI message content to the string that gets encrypted.
 *
 * Content may be a plain string or a multipart array — the Vercel AI SDK,
 * LangChain and other clients always send arrays, e.g.
 * `[{type: 'text', text: 'hello'}]`. Treating those as "not a string" and
 * substituting an empty string silently sends an empty prompt to the model.
 *
 * Throws on parts that cannot be represented as text rather than dropping them,
 * so an unsupported attachment fails loudly instead of producing an answer to a
 * question the model never saw.
 */
export function flattenMessageContent(content) {
    if (typeof content === 'string')
        return content;
    if (content === null || content === undefined)
        return '';
    if (!Array.isArray(content))
        return String(content);
    return content
        .map((part) => {
        if (typeof part === 'string')
            return part;
        // 'input_text'/'output_text' are the newer OpenAI part names.
        if (part?.type === 'text' || part?.type === 'input_text' || part?.type === 'output_text') {
            return part.text ?? '';
        }
        if (part?.type === 'refusal')
            return '';
        throw new Error(`Unsupported message content part "${part?.type}": Venice E2EE models accept text only.`);
    })
        .join('');
}
export const TOOL_CALL_OPEN = '<tool_call>';
export const TOOL_CALL_CLOSE = '</tool_call>';
export const TOOL_RESPONSE_OPEN = '<tool_response>';
export const TOOL_RESPONSE_CLOSE = '</tool_response>';
/**
 * Generate an OpenAI-style tool call id. Random rather than sequential so ids
 * stay unique across the parallel requests that share one session.
 */
export function generateToolCallId() {
    const bytes = crypto.getRandomValues(new Uint8Array(12));
    return `call_${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`;
}
/**
 * Build the system prompt that carries the tool schemas to the model.
 *
 * Returns `null` when the model must not be offered tools (`tool_choice: 'none'`
 * or an empty tool list), in which case no prompt should be injected.
 */
export function buildToolSystemPrompt(tools, toolChoice = 'auto') {
    if (!tools || tools.length === 0)
        return null;
    if (toolChoice === 'none')
        return null;
    const schemas = tools
        .filter((t) => t && t.function)
        .map((t) => JSON.stringify(t.function))
        .join('\n');
    if (!schemas)
        return null;
    let instruction;
    if (typeof toolChoice === 'object' && toolChoice?.function?.name) {
        instruction = `You MUST call the function \`${toolChoice.function.name}\` now. Emit only the tool call block.`;
    }
    else if (toolChoice === 'required') {
        instruction = 'You MUST call at least one of the functions above. Emit only tool call blocks.';
    }
    else {
        instruction =
            'Call a function only when it helps answer the request. Otherwise reply normally without a tool call block.';
    }
    return `# Tools

You have access to the following functions, described as JSON schemas:

<tools>
${schemas}
</tools>

To call a function, emit a block in exactly this format:

${TOOL_CALL_OPEN}
{"name": "<function-name>", "arguments": {<json-arguments>}}
${TOOL_CALL_CLOSE}

Rules:
- \`arguments\` must be a JSON object matching the function's parameter schema.
- Emit the block on its own, with no surrounding prose or markdown fences.
- To call several functions, emit several blocks in a row.
- Function results come back as ${TOOL_RESPONSE_OPEN} blocks; use them to answer.

${instruction}`;
}
function parseArgumentsToJsonString(raw) {
    if (typeof raw === 'string') {
        // Model may already have emitted a JSON string; keep it if it parses.
        try {
            JSON.parse(raw);
            return raw;
        }
        catch {
            return JSON.stringify(raw);
        }
    }
    return JSON.stringify(raw ?? {});
}
/** Render one assistant tool call as a `<tool_call>` block. */
function renderToolCall(tc) {
    let args = {};
    try {
        args = tc.function?.arguments ? JSON.parse(tc.function.arguments) : {};
    }
    catch {
        args = tc.function?.arguments ?? {};
    }
    const payload = JSON.stringify({ name: tc.function?.name, arguments: args });
    return `${TOOL_CALL_OPEN}\n${payload}\n${TOOL_CALL_CLOSE}`;
}
/**
 * Fold OpenAI tool-calling history into plain `{role, content}` messages whose
 * content can be encrypted wholesale.
 *
 * - assistant `tool_calls` become `<tool_call>` blocks in the assistant's content
 *   and the plaintext `tool_calls` field is dropped, so argument values are not
 *   leaked to Venice alongside the ciphertext.
 * - `tool` results become `<tool_response>` blocks, annotated with the function
 *   name resolved from the matching `tool_call_id` so the model can pair them up.
 *
 * The `tool` role is preserved: Venice's TEE accepts and decrypts it.
 */
export function renderToolMessages(messages) {
    // tool_call_id -> function name, collected from earlier assistant turns.
    const callNames = new Map();
    for (const msg of messages) {
        if (Array.isArray(msg.tool_calls)) {
            for (const tc of msg.tool_calls) {
                if (tc?.id && tc.function?.name)
                    callNames.set(tc.id, tc.function.name);
            }
        }
    }
    return messages.map((msg) => {
        const text = flattenMessageContent(msg.content);
        if (msg.role === 'assistant' && Array.isArray(msg.tool_calls) && msg.tool_calls.length > 0) {
            const blocks = msg.tool_calls.map(renderToolCall).join('\n');
            return { role: 'assistant', content: text ? `${text}\n${blocks}` : blocks };
        }
        if (msg.role === 'tool') {
            const name = (msg.tool_call_id && callNames.get(msg.tool_call_id)) || msg.name;
            const payload = name ? JSON.stringify({ name, result: text }) : text;
            return {
                role: 'tool',
                content: `${TOOL_RESPONSE_OPEN}\n${payload}\n${TOOL_RESPONSE_CLOSE}`,
            };
        }
        return { role: msg.role, content: text };
    });
}
/**
 * Length of the longest suffix of `text` that is a proper prefix of `tag`.
 * Used to hold back a partially-received opening tag instead of emitting it as
 * content and then having to retract it.
 */
function partialTagSuffixLength(text, tag) {
    const max = Math.min(text.length, tag.length - 1);
    for (let n = max; n > 0; n--) {
        if (text.endsWith(tag.slice(0, n)))
            return n;
    }
    return 0;
}
/** Strip markdown fences the model may wrap the JSON payload in. */
function stripFences(block) {
    const trimmed = block.trim();
    const fenced = /^```(?:json)?\s*([\s\S]*?)\s*```$/.exec(trimmed);
    return fenced ? fenced[1].trim() : trimmed;
}
/** Find a delimiter without matching delimiter text inside a JSON string. */
function findTagOutsideJsonString(text, tag) {
    let inString = false;
    let escaped = false;
    for (let i = 0; i <= text.length - tag.length; i++) {
        const ch = text[i];
        if (inString) {
            if (escaped)
                escaped = false;
            else if (ch === '\\')
                escaped = true;
            else if (ch === '"')
                inString = false;
            continue;
        }
        if (ch === '"')
            inString = true;
        else if (text.startsWith(tag, i))
            return i;
    }
    return -1;
}
/**
 * Extract the first balanced JSON object from `text`, ignoring braces inside
 * strings. Lets a block parse even when the model appends stray text after the
 * payload or leaves the block unterminated.
 */
function firstJsonObject(text) {
    const start = text.indexOf('{');
    if (start === -1)
        return null;
    let depth = 0;
    let inString = false;
    let escaped = false;
    for (let i = start; i < text.length; i++) {
        const ch = text[i];
        if (inString) {
            if (escaped)
                escaped = false;
            else if (ch === '\\')
                escaped = true;
            else if (ch === '"')
                inString = false;
            continue;
        }
        if (ch === '"')
            inString = true;
        else if (ch === '{')
            depth++;
        else if (ch === '}' && --depth === 0)
            return text.slice(start, i + 1);
    }
    return null;
}
/**
 * Incremental parser that separates assistant prose from `<tool_call>` blocks in
 * a streaming response.
 *
 * Text arrives in arbitrary chunks, so a tag can be split across pushes. Content
 * is emitted eagerly except for a trailing partial tag, which is held until the
 * next push resolves it.
 */
export class ToolCallStreamParser {
    buffer = '';
    inToolCall = false;
    calls = [];
    /** Feed the next decrypted text chunk. */
    push(chunk) {
        this.buffer += chunk;
        let content = '';
        const toolCalls = [];
        // Loop: a single chunk can close one block and open the next.
        for (;;) {
            if (!this.inToolCall) {
                const open = this.buffer.indexOf(TOOL_CALL_OPEN);
                if (open === -1) {
                    // Hold back anything that might be the start of an opening tag.
                    const hold = partialTagSuffixLength(this.buffer, TOOL_CALL_OPEN);
                    content += this.buffer.slice(0, this.buffer.length - hold);
                    this.buffer = hold ? this.buffer.slice(this.buffer.length - hold) : '';
                    break;
                }
                content += this.buffer.slice(0, open);
                this.buffer = this.buffer.slice(open + TOOL_CALL_OPEN.length);
                this.inToolCall = true;
            }
            else {
                // A block ends at `</tool_call>` — or at the next `<tool_call>`, because
                // GLM emits parallel calls as `<tool_call>{..}<tool_call>{..}</tool_call>`,
                // using the opening tag as a separator instead of closing each block.
                const close = findTagOutsideJsonString(this.buffer, TOOL_CALL_CLOSE);
                const nextOpen = findTagOutsideJsonString(this.buffer, TOOL_CALL_OPEN);
                const closesFirst = close !== -1 && (nextOpen === -1 || close <= nextOpen);
                const chained = nextOpen !== -1 && !closesFirst;
                if (!closesFirst && !chained)
                    break; // wait for the rest of the block
                const end = closesFirst ? close : nextOpen;
                const skip = closesFirst ? TOOL_CALL_CLOSE.length : TOOL_CALL_OPEN.length;
                const block = this.buffer.slice(0, end);
                this.buffer = this.buffer.slice(end + skip);
                this.inToolCall = !closesFirst; // a chained tag opens the next block
                const call = this.parseBlock(block);
                if (call) {
                    toolCalls.push(call);
                    this.calls.push(call);
                }
            }
        }
        return { content, toolCalls };
    }
    /**
     * Finish the stream. Returns any trailing content still held back, plus a tool
     * call recovered from an unterminated block if the model omitted the closing
     * tag (some models stop right after the JSON).
     */
    flush() {
        const toolCalls = [];
        let content = '';
        if (this.inToolCall) {
            const call = this.parseBlock(this.buffer);
            if (call) {
                toolCalls.push(call);
                this.calls.push(call);
            }
            else {
                // Not parseable as a tool call — surface it rather than swallowing it.
                content = TOOL_CALL_OPEN + this.buffer;
            }
        }
        else {
            content = this.buffer;
        }
        this.buffer = '';
        this.inToolCall = false;
        return { content, toolCalls };
    }
    /** Every tool call parsed so far. */
    get toolCalls() {
        return this.calls;
    }
    /** True once any tool call has been parsed (drives `finish_reason`). */
    get sawToolCall() {
        return this.calls.length > 0;
    }
    parseBlock(block) {
        const text = stripFences(block);
        if (!text)
            return null;
        let parsed;
        try {
            parsed = JSON.parse(text);
        }
        catch {
            const candidate = firstJsonObject(text);
            if (!candidate)
                return null;
            try {
                parsed = JSON.parse(candidate);
            }
            catch {
                return null;
            }
        }
        if (!parsed || typeof parsed.name !== 'string' || !parsed.name)
            return null;
        // Accept `parameters` as an alias some models emit.
        const rawArgs = parsed.arguments !== undefined ? parsed.arguments : parsed.parameters;
        return {
            id: generateToolCallId(),
            type: 'function',
            function: { name: parsed.name, arguments: parseArgumentsToJsonString(rawArgs) },
        };
    }
}
/**
 * Parse a complete (non-streamed) response body into content plus tool calls.
 */
export function parseToolCalls(text) {
    const parser = new ToolCallStreamParser();
    const a = parser.push(text);
    const b = parser.flush();
    return {
        content: a.content + b.content,
        toolCalls: [...a.toolCalls, ...b.toolCalls],
    };
}
//# sourceMappingURL=tools.js.map