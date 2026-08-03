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
export interface ToolFunctionDefinition {
    name: string;
    description?: string;
    parameters?: Record<string, unknown>;
}
export interface ToolDefinition {
    type: 'function';
    function: ToolFunctionDefinition;
}
export interface ToolCall {
    id: string;
    type: 'function';
    /** OpenAI shape: `arguments` is a JSON *string*, not an object. */
    function: {
        name: string;
        arguments: string;
    };
}
export type ToolChoice = 'none' | 'auto' | 'required' | {
    type: 'function';
    function: {
        name: string;
    };
};
/** One part of a multipart message content array. */
export interface ContentPart {
    type: string;
    text?: string;
    [key: string]: unknown;
}
/** A chat message in OpenAI shape, including the tool-calling fields. */
export interface ToolChatMessage {
    role: string;
    content?: string | ContentPart[] | null;
    tool_calls?: ToolCall[];
    tool_call_id?: string;
    name?: string;
    [key: string]: unknown;
}
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
export declare function flattenMessageContent(content: string | ContentPart[] | null | undefined): string;
export declare const TOOL_CALL_OPEN = "<tool_call>";
export declare const TOOL_CALL_CLOSE = "</tool_call>";
export declare const TOOL_RESPONSE_OPEN = "<tool_response>";
export declare const TOOL_RESPONSE_CLOSE = "</tool_response>";
/**
 * Generate an OpenAI-style tool call id. Random rather than sequential so ids
 * stay unique across the parallel requests that share one session.
 */
export declare function generateToolCallId(): string;
/**
 * Build the system prompt that carries the tool schemas to the model.
 *
 * Returns `null` when the model must not be offered tools (`tool_choice: 'none'`
 * or an empty tool list), in which case no prompt should be injected.
 */
export declare function buildToolSystemPrompt(tools: ToolDefinition[], toolChoice?: ToolChoice): string | null;
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
export declare function renderToolMessages(messages: ToolChatMessage[]): Array<{
    role: string;
    content: string;
    tool_call_id?: string;
}>;
export interface ParseResult {
    /** Text safe to forward to the client as assistant content. */
    content: string;
    /** Tool calls completed by this push. */
    toolCalls: ToolCall[];
}
export interface ToolParserOptions {
    /**
     * The tools offered to the model. Supplying them buys two things: arguments
     * get coerced against the declared schema, and a reply that is a bare JSON
     * call with no tags at all can be recognised — but only when it names a tool
     * that was actually offered, so ordinary JSON answers stay content.
     */
    tools?: ToolDefinition[];
}
/**
 * Incremental parser that separates assistant prose from `<tool_call>` blocks in
 * a streaming response.
 *
 * Text arrives in arbitrary chunks, so a tag can be split across pushes. Content
 * is emitted eagerly except for a trailing partial tag, which is held until the
 * next push resolves it.
 */
export declare class ToolCallStreamParser {
    private buffer;
    /** The tag pair that opened the block being accumulated, if any. */
    private openTag;
    private calls;
    private lookup;
    /** Content withheld while it might still turn out to be an untagged call. */
    private held;
    /** Once open, content streams straight through with no further inspection. */
    private gateOpen;
    constructor(options?: ToolParserOptions);
    /** Feed the next decrypted text chunk. */
    push(chunk: string): ParseResult;
    /**
     * Finish the stream. Returns any trailing content still held back, plus tool
     * calls recovered from an unterminated block if the model omitted the closing
     * tag (some models stop right after the JSON).
     */
    flush(): ParseResult;
    /** Every tool call parsed so far. */
    get toolCalls(): ToolCall[];
    /** True once any tool call has been parsed (drives `finish_reason`). */
    get sawToolCall(): boolean;
    /**
     * Decide how much plain content may be released.
     *
     * A model that ignores the tag format and answers with the raw JSON payload is
     * the most common way prompt-driven tool calling fails, so content that starts
     * like JSON is withheld until it either completes into a call to a declared
     * tool or proves to be something else. Everything else opens the gate on the
     * first chunk and streams normally from then on.
     */
    private gate;
    private parseBlocks;
}
/**
 * Parse a complete (non-streamed) response body into content plus tool calls.
 */
export declare function parseToolCalls(text: string, options?: ToolParserOptions): ParseResult;
//# sourceMappingURL=tools.d.ts.map