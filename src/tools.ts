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
  function: { name: string; arguments: string };
}

export type ToolChoice =
  | 'none'
  | 'auto'
  | 'required'
  | { type: 'function'; function: { name: string } };

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
export function flattenMessageContent(
  content: string | ContentPart[] | null | undefined
): string {
  if (typeof content === 'string') return content;
  if (content === null || content === undefined) return '';
  if (!Array.isArray(content)) return String(content);

  return content
    .map((part) => {
      if (typeof part === 'string') return part;
      // 'input_text'/'output_text' are the newer OpenAI part names.
      if (part?.type === 'text' || part?.type === 'input_text' || part?.type === 'output_text') {
        return part.text ?? '';
      }
      if (part?.type === 'refusal') return '';
      throw new Error(
        `Unsupported message content part "${part?.type}": Venice E2EE models accept text only.`
      );
    })
    .join('');
}

export const TOOL_CALL_OPEN = '<tool_call>';
export const TOOL_CALL_CLOSE = '</tool_call>';
export const TOOL_RESPONSE_OPEN = '<tool_response>';
export const TOOL_RESPONSE_CLOSE = '</tool_response>';

interface TagPair {
  open: string;
  close: string;
}

/**
 * Tag pairs recognised while parsing. The first is canonical: it is what the
 * system prompt asks for and what {@link renderToolMessages} emits. The rest are
 * forms models reach for on their own regardless of what the prompt said —
 * accepting them costs nothing and turns a dropped call into a working one.
 */
const TOOL_CALL_TAGS: readonly TagPair[] = [
  { open: TOOL_CALL_OPEN, close: TOOL_CALL_CLOSE },
  { open: '<function_call>', close: '</function_call>' },
  { open: '<|tool_call|>', close: '<|/tool_call|>' },
];

/** Cap on content held back while deciding whether it is an untagged tool call. */
const UNTAGGED_HOLD_LIMIT = 64 * 1024;

/**
 * Generate an OpenAI-style tool call id. Random rather than sequential so ids
 * stay unique across the parallel requests that share one session.
 */
export function generateToolCallId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  return `call_${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`;
}

/**
 * Build the system prompt that carries the tool schemas to the model.
 *
 * Returns `null` when the model must not be offered tools (`tool_choice: 'none'`
 * or an empty tool list), in which case no prompt should be injected.
 */
export function buildToolSystemPrompt(
  tools: ToolDefinition[],
  toolChoice: ToolChoice = 'auto'
): string | null {
  if (!tools || tools.length === 0) return null;
  if (toolChoice === 'none') return null;

  const schemas = tools
    .filter((t) => t && t.function)
    .map((t) => JSON.stringify(t.function))
    .join('\n');
  if (!schemas) return null;

  let instruction: string;
  if (typeof toolChoice === 'object' && toolChoice?.function?.name) {
    instruction = `You MUST call the function \`${toolChoice.function.name}\` now. Emit only the tool call block.`;
  } else if (toolChoice === 'required') {
    instruction = 'You MUST call at least one of the functions above. Emit only tool call blocks.';
  } else {
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
- \`arguments\` must be a JSON object matching the function's parameter schema,
  even when the function takes a single parameter.
- Emit the block on its own, with no surrounding prose or markdown fences.
- To call several functions, emit several blocks in a row.
- Never emit the JSON payload on its own — without the surrounding tags it is
  read as an ordinary answer and the function is not called.

Results come back as:

${TOOL_RESPONSE_OPEN}
{"id": "<id-of-the-call>", "name": "<function-name>", "result": <result>}
${TOOL_RESPONSE_CLOSE}

Match \`id\` against the call it answers when several calls are outstanding.

${instruction}`;
}

/**
 * Normalise whatever the model put in `arguments` into the JSON *string* OpenAI
 * clients expect.
 *
 * Models routinely emit the sole argument bare — `"arguments": "Bratislava"` or
 * `"arguments": 5` instead of `{"city": "Bratislava"}`. When the schema declares
 * exactly one property there is only one thing that value can mean, so wrap it
 * rather than handing the client a scalar it will fail to destructure.
 */
function parseArgumentsToJsonString(raw: unknown, fn?: ToolFunctionDefinition): string {
  let value: unknown = raw;

  if (typeof raw === 'string') {
    try {
      value = JSON.parse(raw);
    } catch {
      value = raw; // Bare string — may still be wrappable below.
    }
  }

  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    return JSON.stringify(value);
  }
  if (value === undefined || value === null || value === '') return '{}';

  const properties = fn?.parameters?.properties;
  const keys =
    properties && typeof properties === 'object' ? Object.keys(properties) : [];
  if (keys.length === 1) return JSON.stringify({ [keys[0]]: value });

  // Ambiguous: hand it over unchanged rather than guessing a parameter name.
  return JSON.stringify(value);
}

/**
 * Render one assistant tool call as a `<tool_call>` block.
 *
 * The call id rides along so the model can pair a `<tool_response>` with the
 * right call — otherwise two parallel calls to the same function come back as
 * two indistinguishable results.
 */
function renderToolCall(tc: ToolCall): string {
  let args: unknown = {};
  try {
    args = tc.function?.arguments ? JSON.parse(tc.function.arguments) : {};
  } catch {
    args = tc.function?.arguments ?? {};
  }
  const payload = JSON.stringify({
    ...(tc.id ? { id: tc.id } : {}),
    name: tc.function?.name,
    arguments: args,
  });
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
export function renderToolMessages(
  messages: ToolChatMessage[]
): Array<{ role: string; content: string; tool_call_id?: string }> {
  // tool_call_id -> function name, collected from earlier assistant turns.
  const callNames = new Map<string, string>();
  for (const msg of messages) {
    if (Array.isArray(msg.tool_calls)) {
      for (const tc of msg.tool_calls) {
        if (tc?.id && tc.function?.name) callNames.set(tc.id, tc.function.name);
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
      const payload =
        name || msg.tool_call_id
          ? JSON.stringify({
              ...(msg.tool_call_id ? { id: msg.tool_call_id } : {}),
              ...(name ? { name } : {}),
              result: text,
            })
          : text;
      return {
        role: 'tool',
        content: `${TOOL_RESPONSE_OPEN}\n${payload}\n${TOOL_RESPONSE_CLOSE}`,
        ...(msg.tool_call_id ? { tool_call_id: msg.tool_call_id } : {}),
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
function partialTagSuffixLength(text: string, tag: string): number {
  const max = Math.min(text.length, tag.length - 1);
  for (let n = max; n > 0; n--) {
    if (text.endsWith(tag.slice(0, n))) return n;
  }
  return 0;
}

/** Strip markdown fences the model may wrap the JSON payload in. */
function stripFences(block: string): string {
  const trimmed = block.trim();
  const fenced = /^```(?:json)?\s*([\s\S]*?)\s*```$/.exec(trimmed);
  return fenced ? fenced[1].trim() : trimmed;
}

/** Find a delimiter without matching delimiter text inside a JSON string. */
function findTagOutsideJsonString(text: string, tag: string): number {
  let inString = false;
  let escaped = false;

  for (let i = 0; i <= text.length - tag.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (text.startsWith(tag, i)) return i;
  }

  return -1;
}

/**
 * Extract the first balanced JSON object or array from `text`, ignoring
 * brackets inside strings. Lets a block parse even when the model appends stray
 * text after the payload or leaves the block unterminated.
 */
function firstJsonValue(text: string): string | null {
  const objectAt = text.indexOf('{');
  const arrayAt = text.indexOf('[');
  const start =
    objectAt === -1 ? arrayAt : arrayAt === -1 ? objectAt : Math.min(objectAt, arrayAt);
  if (start === -1) return null;

  const openCh = text[start];
  const closeCh = openCh === '{' ? '}' : ']';
  let depth = 0;
  let inString = false;
  let escaped = false;

  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === openCh) depth++;
    else if (ch === closeCh && --depth === 0) return text.slice(start, i + 1);
  }
  return null;
}

/**
 * Escape control characters that appear raw inside JSON string literals.
 *
 * Models routinely put real newlines in a string value instead of `\n` — a file
 * edit passing `oldString`/`newString` is multi-line by nature, so this is the
 * normal case rather than a rare slip. JSON forbids unescaped control characters
 * in strings, so `JSON.parse` rejects the payload and an otherwise perfectly
 * formed tool call is lost with it.
 *
 * Only characters inside strings are touched; the newlines that separate the
 * JSON structure itself are already legal and are left alone.
 */
function escapeJsonControlChars(text: string): string {
  const named: Record<string, string> = {
    '\n': '\\n',
    '\r': '\\r',
    '\t': '\\t',
    '\b': '\\b',
    '\f': '\\f',
  };

  let out = '';
  let inString = false;
  let escaped = false;

  for (const ch of text) {
    if (inString) {
      if (escaped) {
        escaped = false;
        out += ch;
      } else if (ch === '\\') {
        escaped = true;
        out += ch;
      } else if (ch === '"') {
        inString = false;
        out += ch;
      } else if (named[ch]) {
        out += named[ch];
      } else if (ch < ' ') {
        out += `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`;
      } else {
        out += ch;
      }
      continue;
    }
    if (ch === '"') inString = true;
    out += ch;
  }

  return out;
}

/** Parse `text` as JSON, falling back to the first complete value embedded in it. */
function parseJsonLoose(text: string): unknown {
  const variants = [text];
  const repaired = escapeJsonControlChars(text);
  if (repaired !== text) variants.push(repaired);

  for (const variant of variants) {
    try {
      return JSON.parse(variant);
    } catch {
      const candidate = firstJsonValue(variant);
      if (candidate !== null) {
        try {
          return JSON.parse(candidate);
        } catch {
          // Malformed beyond this variant's repair — try the next one.
        }
      }
    }
  }

  return undefined;
}

function firstString(...values: unknown[]): string | undefined {
  for (const value of values) {
    if (typeof value === 'string' && value) return value;
  }
  return undefined;
}

function firstDefined(...values: unknown[]): unknown {
  for (const value of values) {
    if (value !== undefined) return value;
  }
  return undefined;
}

/**
 * Turn one decoded JSON value into zero or more tool calls.
 *
 * Accepts every shape observed from the models this runs against: the canonical
 * `{name, arguments}`, an OpenAI-style `{function: {name, arguments}}`, a bare
 * array of either, and a `{tool_calls: [...]}` wrapper. Naming varies too —
 * `tool_name` for the function, `parameters`/`args`/`input` for its arguments.
 */
function toToolCalls(
  value: unknown,
  lookup?: Map<string, ToolFunctionDefinition>
): ToolCall[] {
  if (Array.isArray(value)) {
    return value.flatMap((entry) => toToolCalls(entry, lookup));
  }
  if (!value || typeof value !== 'object') return [];

  const obj = value as Record<string, unknown>;

  for (const key of ['tool_calls', 'calls', 'invocations'] as const) {
    if (Array.isArray(obj[key])) {
      return (obj[key] as unknown[]).flatMap((entry) => toToolCalls(entry, lookup));
    }
  }

  const fn = obj.function;
  const fnObj = fn && typeof fn === 'object' ? (fn as Record<string, unknown>) : undefined;

  const name = firstString(
    obj.name,
    obj.tool_name,
    obj.tool,
    typeof fn === 'string' ? fn : undefined,
    fnObj?.name
  );
  if (!name) return [];

  const rawArgs = firstDefined(
    obj.arguments,
    obj.parameters,
    obj.args,
    obj.input,
    fnObj?.arguments,
    fnObj?.parameters
  );

  return [
    {
      id: generateToolCallId(),
      type: 'function',
      function: { name, arguments: parseArgumentsToJsonString(rawArgs, lookup?.get(name)) },
    },
  ];
}

/**
 * Parse GLM's native tool-call body: a bare function name followed by
 * `<arg_key>`/`<arg_value>` pairs.
 *
 * ```
 * <tool_call>read
 * <arg_key>filePath</arg_key>
 * <arg_value>"/etc/hosts"</arg_value>
 * </tool_call>
 * ```
 *
 * GLM is trained on this template and reaches for it over the JSON body the
 * system prompt asks for — the more tools and the longer the prompt, the more
 * often. It uses the same `<tool_call>` tag either way, so the block is found
 * and then fails to yield a call unless this form is understood too.
 *
 * Values are JSON when the model is being careful (`"/etc/hosts"`, `3`, `true`)
 * and bare text when it is not, so each is parsed as JSON with a raw-string
 * fallback.
 */
function parseArgValue(raw: string): unknown {
  const trimmed = raw.trim();
  try {
    return JSON.parse(trimmed);
  } catch {
    // An opening quote with no closing one is a truncated JSON string, not a
    // value that happens to start with a quote.
    return trimmed.length > 1 && trimmed.startsWith('"') && !trimmed.endsWith('"')
      ? trimmed.slice(1)
      : trimmed;
  }
}

const ARG_TAG = /<\/?arg_(?:key|value)>/g;
const ARG_VALUE_CLOSE = '</arg_value>';
const ARG_VALUE_OPEN = '<arg_value>';
const ARG_KEY_OPEN = '<arg_key>';
/** Any arg tag appearing as literal text where a value is expected. */
const ANY_ARG_TAG = /<\/?arg_(?:key|value)>/;
const FUNCTION_NAME = /^[A-Za-z_][\w.-]*$/;

/**
 * A key that arrived with its value still attached by a separator, as happens
 * once the model starts emitting the JSON body inside the tags:
 * `description":"Find …` and `description"]="Find …` are both this shape.
 * The quote/bracket noise between the key and the separator is the wreckage of
 * the JSON syntax it was reaching for.
 */
const KEY_ASSIGNMENT = /^["'\s]*([A-Za-z_][\w.-]*)["'\]\s]*[:=]\s*/;

function declaredProperties(fn?: ToolFunctionDefinition): Set<string> | null {
  const properties = fn?.parameters?.properties;
  if (!properties || typeof properties !== 'object') return null;
  return new Set(Object.keys(properties));
}

function parseArgKeyValueBody(
  text: string,
  lookup?: Map<string, ToolFunctionDefinition>
): ToolCall[] {
  ARG_TAG.lastIndex = 0;
  const firstTag = ARG_TAG.exec(text);
  if (!firstTag) return [];

  const name = text.slice(0, firstTag.index).trim();
  if (!FUNCTION_NAME.test(name)) return [];

  const declared = declaredProperties(lookup?.get(name));

  // Walk (tag, text-after-tag) pairs rather than matching key/value as a unit.
  // The observed output does not keep the tags paired: GLM emits
  // `<arg_key>pattern "**/x.json"</arg_value>` with the key and value run
  // together and the intervening tags missing entirely.
  const args: Record<string, unknown> = {};
  let pendingKey: string | null = null;

  const cleanKey = (key: string): string => key.trim().replace(/^"|"$/g, '');

  const takeKey = (segment: string): void => {
    const trimmed = segment.trim();
    if (!trimmed) return;

    // A separator means the model started emitting the JSON body inside the tag
    // — `filePath":"/etc/hosts"`. A real key never contains one, so everything
    // past it is the value that lost its own tag. This is checked before the
    // whitespace split below because the value routinely contains spaces of its
    // own, and splitting on the first of those cuts the key in half.
    const assigned = KEY_ASSIGNMENT.exec(trimmed);
    if (assigned) {
      args[assigned[1]] = parseArgValue(trimmed.slice(assigned[0].length));
      pendingKey = null;
      return;
    }

    // A key cannot contain whitespace, so anything after the first gap is the
    // value that lost its own tag.
    const gap = trimmed.search(/\s/);
    if (gap !== -1) {
      args[cleanKey(trimmed.slice(0, gap))] = parseArgValue(trimmed.slice(gap + 1));
      pendingKey = null;
      return;
    }

    pendingKey = cleanKey(trimmed);
  };

  ARG_TAG.lastIndex = firstTag.index;
  for (let tag = ARG_TAG.exec(text); tag !== null; ) {
    const start = ARG_TAG.lastIndex;
    const next = ARG_TAG.exec(text);
    const segment = text.slice(start, next ? next.index : text.length);

    if (tag[0] === '<arg_value>') {
      if (pendingKey !== null) {
        // This format has no escaping, so tag text appearing inside a value is
        // indistinguishable from a delimiter. No reading wins both cases: the
        // first close truncates a value that contains one, the last close
        // swallows the arguments that follow. Rather than pick a guess, take the
        // well-formed reading and refuse the whole call when the shape says the
        // input cannot be read that way.
        const rest = text.slice(start);
        const nextKeyAt = rest.indexOf(ARG_KEY_OPEN);
        const window = nextKeyAt === -1 ? rest : rest.slice(0, nextKeyAt);
        const closes = window.split(ARG_VALUE_CLOSE).length - 1;
        const reopens = window.split(ARG_VALUE_OPEN).length - 1;

        // Well-formed is exactly one close, and none for a value the stream cut
        // short. Anything else is ambiguous.
        if (reopens > 0 || closes > 1 || (closes === 0 && nextKeyAt !== -1)) return [];

        const close = window.indexOf(ARG_VALUE_CLOSE);
        args[pendingKey] = parseArgValue(close === -1 ? window : window.slice(0, close));
        pendingKey = null;
        ARG_TAG.lastIndex = start + (close === -1 ? window.length : close);
        tag = ARG_TAG.exec(text);
        continue;
      } else {
        // No key is pending, so this value tag has to carry its own key —
        // `<arg_value>prompt":"Search …`. Dropping it loses a whole argument,
        // but guessing wrong invents one, so it only counts when the schema
        // confirms the key is real.
        const assigned = KEY_ASSIGNMENT.exec(segment.trim());
        if (!assigned || !declared?.has(assigned[1])) {
          // Nothing here identifies a real argument; leave it be.
        } else if (ANY_ARG_TAG.test(segment.slice(assigned[0].length))) {
          // Tag text inside the value it carries — same ambiguity, same answer.
          return [];
        } else {
          takeKey(segment);
        }
      }
    } else if (tag[0] === '<arg_key>' || pendingKey === null) {
      // Closing tags should be followed by nothing, but when the opening tag is
      // the one that went missing this is where the key turns up.
      takeKey(segment);
    }

    tag = next;
  }

  if (Object.keys(args).length === 0) return [];

  return [
    {
      id: generateToolCallId(),
      type: 'function',
      function: { name, arguments: parseArgumentsToJsonString(args, lookup?.get(name)) },
    },
  ];
}

/** A line consisting of nothing but arg tags — a separator, never a value. */
const ONLY_ARG_TAGS = /^(?:<\/?arg_(?:key|value)>)+$/;
/** Leading arg tags on a line that still carries content after them. */
const LEADING_ARG_TAGS = /^(?:<\/?arg_(?:key|value)>)+/;

/**
 * Quote bare object keys — `{filePath: "x"}` becomes `{"filePath": "x"}` —
 * without touching text inside string values.
 */
function quoteBareKeys(text: string): string {
  let out = '';
  let inString = false;
  let escaped = false;
  let i = 0;

  while (i < text.length) {
    const ch = text[i];

    if (inString) {
      out += ch;
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === '"') inString = false;
      i++;
      continue;
    }

    if (ch === '"') {
      inString = true;
      out += ch;
      i++;
      continue;
    }

    const key = /^([A-Za-z_][\w.-]*)(\s*:)/.exec(text.slice(i));
    if (key && /[{,[]\s*$/.test(out)) {
      out += `"${key[1]}"${key[2]}`;
      i += key[0].length;
      continue;
    }

    out += ch;
    i++;
  }

  return out;
}

/**
 * The function name outside the payload, with a JSON-ish body after it.
 *
 * ```
 * <tool_call>edit(filePath:"/src/app.css", oldString:"a", newString:"b")
 * <tool_call>read{filePath: "/src/app.css"}
 * ```
 *
 * Only two liberties are taken over strict JSON — parentheses standing in for
 * braces, and unquoted keys — and both are mechanical to undo. The values
 * themselves are left to `JSON.parse`, so escapes and embedded quotes survive
 * exactly as the model wrote them.
 *
 * Anything more mangled than this is not repaired. Guessing where one argument
 * ends and the next begins produced calls that looked plausible and were wrong,
 * which is worse than not calling at all — see the E2EE caveat in the README.
 */
function parseNameThenJsonBody(
  text: string,
  lookup?: Map<string, ToolFunctionDefinition>
): ToolCall[] {
  if (!lookup || lookup.size === 0) return [];

  const body = text.trim();
  // Longest first, so `read` cannot claim a body that belongs to `read_file`.
  const name = [...lookup.keys()]
    .sort((a, b) => b.length - a.length)
    .find((candidate) => body.startsWith(candidate));
  if (!name) return [];

  const rest = body.slice(name.length).trim();
  const inner = rest.startsWith('(')
    ? rest.replace(/^\(/, '').replace(/\)\s*$/, '')
    : rest.startsWith('{')
      ? rest.replace(/^\{/, '').replace(/\}\s*$/, '')
      : null;
  if (inner === null) return [];

  const parsed = parseJsonLoose(quoteBareKeys(`{${inner}}`));
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return [];

  return [
    {
      id: generateToolCallId(),
      type: 'function',
      function: {
        name,
        arguments: parseArgumentsToJsonString(parsed, lookup.get(name)),
      },
    },
  ];
}

/**
 * Last-resort form: the tags are gone entirely and only their contents survive,
 * one per line.
 *
 * ```
 * <tool_call>glob
 * pattern
 * ** /opencode.json
 * path
 * /Users/juraj/.config/opencode
 * </tool_call>
 * ```
 *
 * Nothing here marks it as a call rather than prose, so this only fires when the
 * schemas confirm it: the first line must name a declared tool and every key
 * line must be one of that tool's declared properties. Without `tools` it never
 * fires at all.
 */
function parseLineDelimitedBody(
  text: string,
  lookup?: Map<string, ToolFunctionDefinition>
): ToolCall[] {
  if (!lookup || lookup.size === 0) return [];

  // A half-dropped `</arg_value>` or `<arg_key>` is common in this form. Lines
  // that are nothing but tags are separators the model failed to place, so they
  // are dropped; anything else keeps its text for now. Nothing here edits a line
  // that might be a value — the positions that decides are not known yet.
  const lines: string[] = text
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
  // Only a trailing run of tag-only lines is a separator the model misplaced.
  // Dropping one from the middle would shift the key/value alternation and can
  // pair a key with somebody else's value, so those are left in place — they
  // break the parity check below and the call is refused rather than invented.
  while (lines.length > 0 && ONLY_ARG_TAGS.test(lines[lines.length - 1])) lines.pop();
  if (lines.length < 3) return [];

  const name = lines[0];
  const fn = lookup.get(name);
  if (!fn) return [];

  const rest = lines.slice(1);
  if (rest.length % 2 !== 0) return [];

  const properties = fn.parameters?.properties;
  if (!properties || typeof properties !== 'object') return [];
  const declared = new Set(Object.keys(properties));

  const args: Record<string, unknown> = {};
  for (let i = 0; i < rest.length; i += 2) {
    // Now the alternation is fixed, so `rest[i]` is a key and `rest[i + 1]` is
    // its value. A key may still carry the tag whose partner went missing —
    // `<arg_key>include` — and stripping it there is safe precisely because a
    // value can never reach this branch. Values are passed through untouched:
    // searching for the literal text of a tag is a legitimate thing to do, and
    // a silently edited pattern would run and return the wrong answer.
    const key = rest[i].replace(LEADING_ARG_TAGS, '');
    if (!declared.has(key)) return [];
    args[key] = parseArgValue(rest[i + 1]);
  }

  return [
    {
      id: generateToolCallId(),
      type: 'function',
      function: { name, arguments: parseArgumentsToJsonString(args, fn) },
    },
  ];
}

/** True when `text` could still turn out to be a bare JSON tool call. */
function looksLikeJsonStart(text: string): boolean {
  const trimmed = text.trimStart();
  if (!trimmed) return true; // only whitespace so far — undecided
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) return true;
  // A fence may not have its language tag yet, so match progressively.
  return '```json'.startsWith(trimmed.slice(0, 7)) && trimmed.startsWith('`');
}

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
export class ToolCallStreamParser {
  private buffer = '';
  /** The tag pair that opened the block being accumulated, if any. */
  private openTag: TagPair | null = null;
  private calls: ToolCall[] = [];
  private lookup = new Map<string, ToolFunctionDefinition>();

  /** Content withheld while it might still turn out to be an untagged call. */
  private held = '';
  /** Once open, content streams straight through with no further inspection. */
  private gateOpen: boolean;

  constructor(options: ToolParserOptions = {}) {
    for (const tool of options.tools ?? []) {
      if (tool?.function?.name) this.lookup.set(tool.function.name, tool.function);
    }
    // With no schemas to match against, untagged JSON is just JSON.
    this.gateOpen = this.lookup.size === 0;
  }

  /** Feed the next decrypted text chunk. */
  push(chunk: string): ParseResult {
    this.buffer += chunk;
    let raw = '';
    const toolCalls: ToolCall[] = [];

    // Loop: a single chunk can close one block and open the next.
    for (;;) {
      if (!this.openTag) {
        const opened = findFirst(this.buffer, (tag) => this.buffer.indexOf(tag.open));
        if (!opened) {
          // Hold back anything that might be the start of an opening tag.
          const hold = maxPartialTagSuffix(this.buffer);
          raw += this.buffer.slice(0, this.buffer.length - hold);
          this.buffer = hold ? this.buffer.slice(this.buffer.length - hold) : '';
          break;
        }
        raw += this.buffer.slice(0, opened.index);
        this.buffer = this.buffer.slice(opened.index + opened.tag.open.length);
        this.openTag = opened.tag;
      } else {
        // A block ends at its closing tag — or at the next opening tag, because
        // GLM emits parallel calls as `<tool_call>{..}<tool_call>{..}</tool_call>`,
        // using the opening tag as a separator instead of closing each block.
        const close = findTagOutsideJsonString(this.buffer, this.openTag.close);
        const chainedOpen = findFirst(this.buffer, (tag) =>
          findTagOutsideJsonString(this.buffer, tag.open)
        );
        const nextOpen = chainedOpen ? chainedOpen.index : -1;
        const closesFirst = close !== -1 && (nextOpen === -1 || close <= nextOpen);
        if (!closesFirst && nextOpen === -1) break; // wait for the rest of the block

        const end = closesFirst ? close : nextOpen;
        const skip = closesFirst ? this.openTag.close.length : chainedOpen!.tag.open.length;
        const block = this.buffer.slice(0, end);
        const consumed = this.openTag;
        this.buffer = this.buffer.slice(end + skip);
        this.openTag = closesFirst ? null : chainedOpen!.tag;

        const calls = this.parseBlocks(block);
        if (calls.length > 0) {
          toolCalls.push(...calls);
          this.calls.push(...calls);
        } else {
          // A block that yields nothing must not vanish. Dropping it silently
          // costs the caller the whole turn with no way to tell what happened,
          // so put it back as content and let the failure be visible.
          raw += consumed.open + block + (closesFirst ? consumed.close : '');
        }
      }
    }

    const gated = this.gate(raw, toolCalls.length > 0, false);
    return { content: gated.content, toolCalls: [...toolCalls, ...gated.toolCalls] };
  }

  /**
   * Finish the stream. Returns any trailing content still held back, plus tool
   * calls recovered from an unterminated block if the model omitted the closing
   * tag (some models stop right after the JSON).
   */
  flush(): ParseResult {
    const toolCalls: ToolCall[] = [];
    let raw = '';

    if (this.openTag) {
      // The block never closed as far as the string-aware scan could tell, but
      // that scan is defeated by an unbalanced quote in a non-JSON body — GLM's
      // `<arg_value>"/etc/hosts</arg_value>` for instance. Nothing more is
      // coming, so trust a plain text match for the terminator now.
      let block = this.buffer;
      const plainClose = this.buffer.indexOf(this.openTag.close);
      if (plainClose !== -1) block = this.buffer.slice(0, plainClose);

      const calls = this.parseBlocks(block);
      if (calls.length > 0) {
        toolCalls.push(...calls);
        this.calls.push(...calls);
      } else {
        // Not parseable as a tool call — surface it rather than swallowing it.
        raw = this.openTag.open + this.buffer;
      }
    } else {
      raw = this.buffer;
    }

    this.buffer = '';
    this.openTag = null;

    const gated = this.gate(raw, toolCalls.length > 0, true);
    return { content: gated.content, toolCalls: [...toolCalls, ...gated.toolCalls] };
  }

  /** Every tool call parsed so far. */
  get toolCalls(): ToolCall[] {
    return this.calls;
  }

  /** True once any tool call has been parsed (drives `finish_reason`). */
  get sawToolCall(): boolean {
    return this.calls.length > 0;
  }

  /**
   * Decide how much plain content may be released.
   *
   * A model that ignores the tag format and answers with the raw JSON payload is
   * the most common way prompt-driven tool calling fails, so content that starts
   * like JSON is withheld until it either completes into a call to a declared
   * tool or proves to be something else. Everything else opens the gate on the
   * first chunk and streams normally from then on.
   */
  private gate(text: string, sawTaggedCall: boolean, atEnd: boolean): ParseResult {
    if (this.gateOpen) return { content: text, toolCalls: [] };

    // Tagged calls settle it: the model knows the format, so leading text is prose.
    if (sawTaggedCall) {
      this.gateOpen = true;
      const content = this.held + text;
      this.held = '';
      return { content, toolCalls: [] };
    }

    this.held += text;

    const release = (): ParseResult => {
      this.gateOpen = true;
      const content = this.held;
      this.held = '';
      return { content, toolCalls: [] };
    };

    if (!looksLikeJsonStart(this.held)) return release();
    if (this.held.length > UNTAGGED_HOLD_LIMIT) return release();

    const candidate = firstJsonValue(stripFences(this.held));
    if (candidate === null) return atEnd ? release() : { content: '', toolCalls: [] };

    const calls = this.parseBlocks(this.held).filter((call) =>
      this.lookup.has(call.function.name)
    );
    if (calls.length === 0) return release();

    this.gateOpen = true;
    this.held = '';
    this.calls.push(...calls);
    return { content: '', toolCalls: calls };
  }

  private parseBlocks(block: string): ToolCall[] {
    const text = stripFences(block);
    if (!text) return [];

    // JSON is the canonical body, so try it first.
    const value = parseJsonLoose(text);
    if (value !== undefined) {
      const calls = toToolCalls(value, this.lookup);
      if (calls.length > 0) return calls;
    }

    const tagged = parseArgKeyValueBody(text, this.lookup);
    if (tagged.length > 0) return tagged;

    const jsonBody = parseNameThenJsonBody(text, this.lookup);
    if (jsonBody.length > 0) return jsonBody;

    return parseLineDelimitedBody(text, this.lookup);
  }
}

/** Lowest non-negative index across all known tag pairs, with the tag that matched. */
function findFirst(
  text: string,
  locate: (tag: TagPair) => number
): { index: number; tag: TagPair } | null {
  let best: { index: number; tag: TagPair } | null = null;
  for (const tag of TOOL_CALL_TAGS) {
    const index = locate(tag);
    if (index !== -1 && (best === null || index < best.index)) best = { index, tag };
  }
  return best;
}

/** Longest trailing run of `text` that could be the start of any opening tag. */
function maxPartialTagSuffix(text: string): number {
  let longest = 0;
  for (const tag of TOOL_CALL_TAGS) {
    longest = Math.max(longest, partialTagSuffixLength(text, tag.open));
  }
  return longest;
}

/**
 * Parse a complete (non-streamed) response body into content plus tool calls.
 */
export function parseToolCalls(text: string, options: ToolParserOptions = {}): ParseResult {
  const parser = new ToolCallStreamParser(options);
  const a = parser.push(text);
  const b = parser.flush();
  return {
    content: a.content + b.content,
    toolCalls: [...a.toolCalls, ...b.toolCalls],
  };
}
