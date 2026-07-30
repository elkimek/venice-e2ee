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
/** A chat message in OpenAI shape, including the tool-calling fields. */
export interface ToolChatMessage {
    role: string;
    content?: string | null;
    tool_calls?: ToolCall[];
    tool_call_id?: string;
    name?: string;
    [key: string]: unknown;
}
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
    private inToolCall;
    private calls;
    /** Feed the next decrypted text chunk. */
    push(chunk: string): ParseResult;
    /**
     * Finish the stream. Returns any trailing content still held back, plus a tool
     * call recovered from an unterminated block if the model omitted the closing
     * tag (some models stop right after the JSON).
     */
    flush(): ParseResult;
    /** Every tool call parsed so far. */
    get toolCalls(): ToolCall[];
    /** True once any tool call has been parsed (drives `finish_reason`). */
    get sawToolCall(): boolean;
    private parseBlock;
}
/**
 * Parse a complete (non-streamed) response body into content plus tool calls.
 */
export declare function parseToolCalls(text: string): ParseResult;
//# sourceMappingURL=tools.d.ts.map