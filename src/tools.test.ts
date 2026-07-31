import { describe, it, expect } from 'vitest';
import {
  buildToolSystemPrompt,
  renderToolMessages,
  parseToolCalls,
  ToolCallStreamParser,
  flattenMessageContent,
  TOOL_CALL_OPEN,
  TOOL_CALL_CLOSE,
  type ToolDefinition,
} from './tools.js';

const weatherTool: ToolDefinition = {
  type: 'function',
  function: {
    name: 'get_weather',
    description: 'Get the current weather in a given city',
    parameters: {
      type: 'object',
      properties: { city: { type: 'string' } },
      required: ['city'],
    },
  },
};

const block = (payload: string) => `${TOOL_CALL_OPEN}\n${payload}\n${TOOL_CALL_CLOSE}`;

describe('buildToolSystemPrompt', () => {
  it('embeds the function schema', () => {
    const prompt = buildToolSystemPrompt([weatherTool])!;
    expect(prompt).toContain('get_weather');
    expect(prompt).toContain('Get the current weather in a given city');
    expect(prompt).toContain(TOOL_CALL_OPEN);
  });

  it('returns null when there are no tools', () => {
    expect(buildToolSystemPrompt([])).toBeNull();
  });

  it('returns null for tool_choice none', () => {
    expect(buildToolSystemPrompt([weatherTool], 'none')).toBeNull();
  });

  it('demands a call for tool_choice required', () => {
    expect(buildToolSystemPrompt([weatherTool], 'required')).toContain('MUST call at least one');
  });

  it('names the forced function', () => {
    const prompt = buildToolSystemPrompt([weatherTool], {
      type: 'function',
      function: { name: 'get_weather' },
    })!;
    expect(prompt).toContain('MUST call the function `get_weather`');
  });
});

describe('renderToolMessages', () => {
  it('folds assistant tool_calls into content and drops the plaintext field', () => {
    const [msg] = renderToolMessages([
      {
        role: 'assistant',
        content: null,
        tool_calls: [
          {
            id: 'call_1',
            type: 'function',
            function: { name: 'get_weather', arguments: '{"city":"Bratislava"}' },
          },
        ],
      },
    ]);
    expect(msg.role).toBe('assistant');
    expect(msg.content).toContain('"name":"get_weather"');
    expect(msg.content).toContain('Bratislava');
    expect((msg as Record<string, unknown>).tool_calls).toBeUndefined();
  });

  it('annotates tool results with the function name from the matching call', () => {
    const rendered = renderToolMessages([
      {
        role: 'assistant',
        content: null,
        tool_calls: [
          { id: 'call_1', type: 'function', function: { name: 'get_weather', arguments: '{}' } },
        ],
      },
      { role: 'tool', tool_call_id: 'call_1', content: '{"temp":18}' },
    ]);
    expect(rendered[1].content).toContain('get_weather');
    expect(rendered[1].content).toContain('{\\"temp\\":18}');
    expect(rendered[1].tool_call_id).toBe('call_1');
  });

  it('leaves ordinary messages untouched', () => {
    const rendered = renderToolMessages([{ role: 'user', content: 'hello' }]);
    expect(rendered).toEqual([{ role: 'user', content: 'hello' }]);
  });

  it('turns null content into an empty string', () => {
    expect(renderToolMessages([{ role: 'assistant', content: null }])[0].content).toBe('');
  });
});

describe('flattenMessageContent', () => {
  it('passes strings through', () => {
    expect(flattenMessageContent('hello')).toBe('hello');
  });

  it('flattens the multipart arrays AI SDK clients send', () => {
    expect(flattenMessageContent([{ type: 'text', text: 'hello' }])).toBe('hello');
  });

  it('joins several text parts', () => {
    expect(
      flattenMessageContent([
        { type: 'text', text: 'a' },
        { type: 'text', text: 'b' },
      ])
    ).toBe('ab');
  });

  it('accepts the newer input_text/output_text part names', () => {
    expect(flattenMessageContent([{ type: 'input_text', text: 'in' }])).toBe('in');
    expect(flattenMessageContent([{ type: 'output_text', text: 'out' }])).toBe('out');
  });

  it('maps null and undefined to an empty string', () => {
    expect(flattenMessageContent(null)).toBe('');
    expect(flattenMessageContent(undefined)).toBe('');
  });

  it('throws on parts it cannot represent rather than dropping them', () => {
    expect(() =>
      flattenMessageContent([{ type: 'image_url', image_url: { url: 'http://x/y.png' } }])
    ).toThrow(/text only/);
  });
});

describe('renderToolMessages with multipart content', () => {
  it('does not blank out array content', () => {
    const [msg] = renderToolMessages([
      { role: 'user', content: [{ type: 'text', text: 'Reply with BANANA' }] },
    ]);
    expect(msg.content).toBe('Reply with BANANA');
  });
});

describe('parseToolCalls', () => {
  it('extracts a call and strips the block from content', () => {
    const { content, toolCalls } = parseToolCalls(
      `Let me check.\n${block('{"name": "get_weather", "arguments": {"city": "Bratislava"}}')}`
    );
    expect(content.trim()).toBe('Let me check.');
    expect(toolCalls).toHaveLength(1);
    expect(toolCalls[0].function.name).toBe('get_weather');
    expect(JSON.parse(toolCalls[0].function.arguments)).toEqual({ city: 'Bratislava' });
    expect(toolCalls[0].id).toMatch(/^call_[0-9a-f]{24}$/);
  });

  it('extracts several calls', () => {
    const { toolCalls } = parseToolCalls(
      block('{"name":"a","arguments":{}}') + '\n' + block('{"name":"b","arguments":{"x":1}}')
    );
    expect(toolCalls.map((t) => t.function.name)).toEqual(['a', 'b']);
  });

  it('splits chained calls that use the opening tag as a separator', () => {
    // GLM emits parallel calls as <tool_call>{..}<tool_call>{..}</tool_call>
    const { content, toolCalls } = parseToolCalls(
      `${TOOL_CALL_OPEN}{"name": "get_weather", "arguments": {"city": "Bratislava"}}` +
        `${TOOL_CALL_OPEN}{"name": "get_weather", "arguments": {"city": "Vienna"}}${TOOL_CALL_CLOSE}`
    );
    expect(toolCalls).toHaveLength(2);
    expect(JSON.parse(toolCalls[0].function.arguments)).toEqual({ city: 'Bratislava' });
    expect(JSON.parse(toolCalls[1].function.arguments)).toEqual({ city: 'Vienna' });
    expect(content).toBe('');
  });

  it('splits chained calls with no closing tag at all', () => {
    const { toolCalls } = parseToolCalls(
      `${TOOL_CALL_OPEN}{"name":"a","arguments":{}}${TOOL_CALL_OPEN}{"name":"b","arguments":{}}`
    );
    expect(toolCalls.map((t) => t.function.name)).toEqual(['a', 'b']);
  });

  it('ignores stray text after the JSON payload', () => {
    const { toolCalls } = parseToolCalls(
      block('{"name":"a","arguments":{"note":"has } brace"}} trailing junk')
    );
    expect(toolCalls).toHaveLength(1);
    expect(JSON.parse(toolCalls[0].function.arguments)).toEqual({ note: 'has } brace' });
  });

  it('does not treat a closing tag inside arguments as a block boundary', () => {
    const value = `literal ${TOOL_CALL_CLOSE} text`;
    const { content, toolCalls } = parseToolCalls(
      block(JSON.stringify({ name: 'a', arguments: { value } }))
    );
    expect(content).toBe('');
    expect(toolCalls).toHaveLength(1);
    expect(JSON.parse(toolCalls[0].function.arguments)).toEqual({ value });
  });

  it('does not treat an opening tag inside arguments as a chained call', () => {
    const value = `literal ${TOOL_CALL_OPEN} text`;
    const { content, toolCalls } = parseToolCalls(
      block(JSON.stringify({ name: 'a', arguments: { value } }))
    );
    expect(content).toBe('');
    expect(toolCalls).toHaveLength(1);
    expect(JSON.parse(toolCalls[0].function.arguments)).toEqual({ value });
  });

  it('recovers a call missing its closing tag', () => {
    const { toolCalls } = parseToolCalls(
      `${TOOL_CALL_OPEN}\n{"name":"get_weather","arguments":{"city":"Nitra"}}`
    );
    expect(toolCalls).toHaveLength(1);
    expect(toolCalls[0].function.name).toBe('get_weather');
  });

  it('tolerates markdown fences around the payload', () => {
    const { toolCalls } = parseToolCalls(
      block('```json\n{"name":"get_weather","arguments":{"city":"Kosice"}}\n```')
    );
    expect(toolCalls).toHaveLength(1);
    expect(JSON.parse(toolCalls[0].function.arguments)).toEqual({ city: 'Kosice' });
  });

  it('accepts `parameters` as an alias for `arguments`', () => {
    const { toolCalls } = parseToolCalls(block('{"name":"a","parameters":{"x":2}}'));
    expect(JSON.parse(toolCalls[0].function.arguments)).toEqual({ x: 2 });
  });

  it('keeps unparseable blocks as visible content instead of swallowing them', () => {
    const { content, toolCalls } = parseToolCalls(`${TOOL_CALL_OPEN}\nnot json`);
    expect(toolCalls).toHaveLength(0);
    expect(content).toContain('not json');
  });

  it('passes through plain prose', () => {
    const { content, toolCalls } = parseToolCalls('Just a normal answer.');
    expect(content).toBe('Just a normal answer.');
    expect(toolCalls).toHaveLength(0);
  });
});

describe('ToolCallStreamParser', () => {
  it('never emits a partially-received opening tag as content', () => {
    const parser = new ToolCallStreamParser();
    const first = parser.push('Hi <tool');
    expect(first.content).toBe('Hi ');
    const second = parser.push('_call>\n{"name":"a","arguments":{}}\n</tool_call>');
    expect(second.content).toBe('');
    expect(second.toolCalls).toHaveLength(1);
    expect(parser.flush().content).toBe('');
  });

  it('reassembles a call split across many chunks', () => {
    const parser = new ToolCallStreamParser();
    const chunks = [
      '<tool_',
      'call>\n{"na',
      'me":"get_weather","argu',
      'ments":{"city":"Br',
      'atislava"}}\n</tool',
      '_call>',
    ];
    const calls = chunks.flatMap((c) => parser.push(c).toolCalls);
    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0].function.arguments)).toEqual({ city: 'Bratislava' });
  });

  it('ignores a chunk-split closing tag inside an argument string', () => {
    const parser = new ToolCallStreamParser();
    const first = parser.push(
      `${TOOL_CALL_OPEN}{"name":"a","arguments":{"value":"literal </tool_`
    );
    expect(first).toEqual({ content: '', toolCalls: [] });

    const second = parser.push(`call> text"}}${TOOL_CALL_CLOSE}`);
    expect(second.content).toBe('');
    expect(second.toolCalls).toHaveLength(1);
    expect(JSON.parse(second.toolCalls[0].function.arguments)).toEqual({
      value: `literal ${TOOL_CALL_CLOSE} text`,
    });
  });

  it('streams prose through unchanged', () => {
    const parser = new ToolCallStreamParser();
    expect(parser.push('Hello ').content).toBe('Hello ');
    expect(parser.push('world').content).toBe('world');
    expect(parser.flush().content).toBe('');
    expect(parser.sawToolCall).toBe(false);
  });

  it('holds back a trailing angle bracket until resolved as prose', () => {
    const parser = new ToolCallStreamParser();
    expect(parser.push('5 < 6').content).toBe('5 < 6');
    const parser2 = new ToolCallStreamParser();
    expect(parser2.push('a <').content).toBe('a ');
    expect(parser2.push('b').content).toBe('<b');
  });

  it('handles content following a completed call', () => {
    const parser = new ToolCallStreamParser();
    const r = parser.push(`${block('{"name":"a","arguments":{}}')}done`);
    expect(r.toolCalls).toHaveLength(1);
    expect(r.content + parser.flush().content).toBe('done');
  });

  it('reports sawToolCall for finish_reason selection', () => {
    const parser = new ToolCallStreamParser();
    parser.push(block('{"name":"a","arguments":{}}'));
    expect(parser.sawToolCall).toBe(true);
    expect(parser.toolCalls).toHaveLength(1);
  });
});
