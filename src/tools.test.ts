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

describe('parseToolCalls with alternative shapes', () => {
  it('accepts an OpenAI-shaped payload nested under function', () => {
    const { toolCalls } = parseToolCalls(
      block('{"function": {"name": "get_weather", "arguments": "{\\"city\\":\\"Bratislava\\"}"}}')
    );
    expect(toolCalls).toHaveLength(1);
    expect(toolCalls[0].function.name).toBe('get_weather');
    expect(JSON.parse(toolCalls[0].function.arguments)).toEqual({ city: 'Bratislava' });
  });

  it('accepts tool_name and args aliases', () => {
    const { toolCalls } = parseToolCalls(block('{"tool_name":"a","args":{"x":1}}'));
    expect(toolCalls[0].function.name).toBe('a');
    expect(JSON.parse(toolCalls[0].function.arguments)).toEqual({ x: 1 });
  });

  it('splits an array of calls inside one block', () => {
    const { toolCalls } = parseToolCalls(
      block('[{"name":"a","arguments":{}},{"name":"b","arguments":{"x":1}}]')
    );
    expect(toolCalls.map((t) => t.function.name)).toEqual(['a', 'b']);
  });

  it('unwraps a tool_calls wrapper object', () => {
    const { toolCalls } = parseToolCalls(
      block('{"tool_calls":[{"name":"a","arguments":{}},{"name":"b","arguments":{}}]}')
    );
    expect(toolCalls.map((t) => t.function.name)).toEqual(['a', 'b']);
  });

  it('reads a <function_call> block', () => {
    const { content, toolCalls } = parseToolCalls(
      '<function_call>{"name":"get_weather","arguments":{"city":"Vienna"}}</function_call>'
    );
    expect(toolCalls).toHaveLength(1);
    expect(toolCalls[0].function.name).toBe('get_weather');
    expect(content).toBe('');
  });

  it('wraps a bare argument value using the single declared parameter', () => {
    const { toolCalls } = parseToolCalls(block('{"name":"get_weather","arguments":"Bratislava"}'), {
      tools: [weatherTool],
    });
    expect(JSON.parse(toolCalls[0].function.arguments)).toEqual({ city: 'Bratislava' });
  });

  it('leaves a bare argument alone when the schema is ambiguous', () => {
    const twoParams: ToolDefinition = {
      type: 'function',
      function: {
        name: 'move',
        parameters: { type: 'object', properties: { x: {}, y: {} } },
      },
    };
    const { toolCalls } = parseToolCalls(block('{"name":"move","arguments":"5"}'), {
      tools: [twoParams],
    });
    expect(toolCalls[0].function.arguments).toBe('5');
  });

  it('treats missing arguments as an empty object', () => {
    const { toolCalls } = parseToolCalls(block('{"name":"ping"}'));
    expect(toolCalls[0].function.arguments).toBe('{}');
  });
});

describe("GLM's native arg_key/arg_value body", () => {
  // GLM is trained on this template and falls back to it over the JSON body the
  // system prompt asks for, using the same <tool_call> tag either way.
  const readTool: ToolDefinition = {
    type: 'function',
    function: {
      name: 'read',
      description: 'Read a file',
      parameters: {
        type: 'object',
        properties: { filePath: { type: 'string' }, limit: { type: 'number' } },
        required: ['filePath'],
      },
    },
  };

  const native = (body: string) => `${TOOL_CALL_OPEN}${body}${TOOL_CALL_CLOSE}`;

  it('parses a single argument', () => {
    const { content, toolCalls } = parseToolCalls(
      native('read\n<arg_key>filePath</arg_key>\n<arg_value>"/etc/hosts"</arg_value>\n'),
      { tools: [readTool] }
    );
    expect(toolCalls).toHaveLength(1);
    expect(toolCalls[0].function.name).toBe('read');
    expect(JSON.parse(toolCalls[0].function.arguments)).toEqual({ filePath: '/etc/hosts' });
    expect(content).toBe('');
  });

  it('parses several arguments and keeps their JSON types', () => {
    const { toolCalls } = parseToolCalls(
      native(
        'read\n<arg_key>filePath</arg_key>\n<arg_value>"/etc/hosts"</arg_value>\n' +
          '<arg_key>limit</arg_key>\n<arg_value>10</arg_value>\n'
      ),
      { tools: [readTool] }
    );
    expect(JSON.parse(toolCalls[0].function.arguments)).toEqual({ filePath: '/etc/hosts', limit: 10 });
  });

  it('accepts a value the model left unquoted', () => {
    const { toolCalls } = parseToolCalls(
      native('read\n<arg_key>filePath</arg_key>\n<arg_value>/etc/hosts</arg_value>\n'),
      { tools: [readTool] }
    );
    expect(JSON.parse(toolCalls[0].function.arguments)).toEqual({ filePath: '/etc/hosts' });
  });

  it('recovers a value whose closing quote is missing', () => {
    // An unbalanced quote also defeats the string-aware scan for the closing
    // tag, so this exercises the end-of-stream fallback as well.
    const { toolCalls } = parseToolCalls(
      native('read\n<arg_key>filePath</arg_key>\n<arg_value>"/etc/hosts</arg_value>\n'),
      { tools: [readTool] }
    );
    expect(toolCalls).toHaveLength(1);
    expect(JSON.parse(toolCalls[0].function.arguments)).toEqual({ filePath: '/etc/hosts' });
  });

  it('recovers a block with no closing tag', () => {
    const { toolCalls } = parseToolCalls(
      `${TOOL_CALL_OPEN}read\n<arg_key>filePath</arg_key>\n<arg_value>"/etc/hosts"</arg_value>`,
      { tools: [readTool] }
    );
    expect(JSON.parse(toolCalls[0].function.arguments)).toEqual({ filePath: '/etc/hosts' });
  });

  it('reassembles a native call split across stream chunks', () => {
    const parser = new ToolCallStreamParser({ tools: [readTool] });
    const chunks = [
      '<tool_c',
      'all>read\n<arg_k',
      'ey>filePath</arg_key>\n<arg_val',
      'ue>"/etc/hosts"</arg_value>\n</tool_',
      'call>',
    ];
    const calls = chunks.flatMap((c) => parser.push(c).toolCalls);
    const tail = parser.flush();
    expect([...calls, ...tail.toolCalls]).toHaveLength(1);
    expect(tail.content).toBe('');
  });

  it('works without declared tools', () => {
    const { toolCalls } = parseToolCalls(
      native('read\n<arg_key>filePath</arg_key>\n<arg_value>"/etc/hosts"</arg_value>\n')
    );
    expect(toolCalls).toHaveLength(1);
    expect(toolCalls[0].function.name).toBe('read');
  });

  it('picks the right function out of a large tool set', () => {
    const many: ToolDefinition[] = ['bash', 'edit', 'glob', 'grep', 'list', 'read', 'write'].map(
      (name) => ({
        type: 'function',
        function: {
          name,
          parameters: { type: 'object', properties: { filePath: { type: 'string' } } },
        },
      })
    );
    const { toolCalls } = parseToolCalls(
      native('grep\n<arg_key>filePath</arg_key>\n<arg_value>"src/tools.ts"</arg_value>\n'),
      { tools: many }
    );
    expect(toolCalls[0].function.name).toBe('grep');
  });

  it('does not mistake prose containing angle brackets for a call', () => {
    const { toolCalls, content } = parseToolCalls(
      native('this is not a call at all\n'),
      { tools: [readTool] }
    );
    expect(toolCalls).toHaveLength(0);
    expect(content).toContain('this is not a call at all');
  });

  it('ignores a block with no arg tags even when it contains a colon', () => {
    const { toolCalls, content } = parseToolCalls(native('\nnote: not a call\n'), {
      tools: [readTool],
    });
    expect(toolCalls).toHaveLength(0);
    expect(content).toContain('note: not a call');
  });

  describe('degenerate output captured from live GLM 5.2 over E2EE', () => {
    // GLM half-blends its native template with the JSON body the prompt asks
    // for, and the tags come out lossy — a different subset survives each time.
    // These are verbatim shapes seen in production, not hypotheticals.
    const globTool: ToolDefinition = {
      type: 'function',
      function: {
        name: 'glob',
        parameters: {
          type: 'object',
          properties: { pattern: { type: 'string' }, path: { type: 'string' } },
          required: ['pattern'],
        },
      },
    };

    it('key and value run together, closed by a stray </arg_value>', () => {
      const { toolCalls } = parseToolCalls(
        '<tool_call>glob<arg_key>pattern "**/opencode.json"</arg_value></tool_call>',
        { tools: [globTool] }
      );
      expect(toolCalls).toHaveLength(1);
      expect(toolCalls[0].function.name).toBe('glob');
      expect(JSON.parse(toolCalls[0].function.arguments)).toEqual({ pattern: '**/opencode.json' });
    });

    it('opening arg_key missing, keys trailing the closing tags', () => {
      const { toolCalls } = parseToolCalls(
        '<tool_call>glob</arg_value>pattern</arg_key><arg_value>**/opencode.json</arg_value>' +
          '<arg_key>path</arg_key><arg_value>/Users/juraj/.config/opencode</arg_value></tool_call>',
        { tools: [globTool] }
      );
      expect(toolCalls).toHaveLength(1);
      expect(JSON.parse(toolCalls[0].function.arguments)).toEqual({
        pattern: '**/opencode.json',
        path: '/Users/juraj/.config/opencode',
      });
    });

    it('JSON body leaking into the arg_key tag', () => {
      const { toolCalls } = parseToolCalls(
        '<tool_call>read<arg_key>filePath":"/Users/juraj/.config/opencode/opencode.json"</arg_value></tool_call>',
        { tools: [readTool] }
      );
      expect(toolCalls).toHaveLength(1);
      expect(JSON.parse(toolCalls[0].function.arguments)).toEqual({
        filePath: '/Users/juraj/.config/opencode/opencode.json',
      });
    });

    const grepTool: ToolDefinition = {
      type: 'function',
      function: {
        name: 'grep',
        parameters: {
          type: 'object',
          properties: { pattern: { type: 'string' }, include: { type: 'string' } },
          required: ['pattern'],
        },
      },
    };

    const taskTool: ToolDefinition = {
      type: 'function',
      function: {
        name: 'task',
        parameters: {
          type: 'object',
          properties: {
            description: { type: 'string' },
            prompt: { type: 'string' },
            subagent_type: { type: 'string' },
          },
          required: ['description', 'prompt'],
        },
      },
    };






    it('recovers line-delimited calls carrying a stray arg tag', () => {
      // The orphan </arg_value> used to land on a line of its own, breaking the
      // key/value pairing so the call was dropped without a trace.
      const { toolCalls } = parseToolCalls(
        '<tool_call>grep\npattern\nstrong match|good match\n</arg_value></tool_call>' +
          '<tool_call>grep\npattern\npurple|violet\n</arg_value><arg_key>include\n' +
          '*.{ts,svelte}\n</arg_value></tool_call>',
        { tools: [grepTool] }
      );
      expect(toolCalls).toHaveLength(2);
      expect(JSON.parse(toolCalls[0].function.arguments)).toEqual({
        pattern: 'strong match|good match',
      });
      expect(JSON.parse(toolCalls[1].function.arguments)).toEqual({
        pattern: 'purple|violet',
        include: '*.{ts,svelte}',
      });
    });





    it('refuses a tagged value that could be read more than one way', () => {
      // No escaping exists in this format, so `foo</arg_value>bar` is either one
      // value containing tag text or a value plus stray text — and no rule wins
      // both that case and the ordinary multi-argument one. Reading the first
      // close truncates to `foo`; reading the last swallows later arguments.
      // Refusing is the only answer that is never silently wrong.
      const { content, toolCalls } = parseToolCalls(
        '<tool_call>grep<arg_key>pattern</arg_key><arg_value>foo</arg_value>bar</arg_value></tool_call>',
        { tools: [grepTool] }
      );
      expect(toolCalls).toHaveLength(0);
      expect(content).toContain('<tool_call>');
    });

    it('refuses a tagged value holding the opening key tag as text', () => {
      // The mirror of the case above: bounding the value at the next `<arg_key>`
      // truncates a value that contains that text.
      const { content, toolCalls } = parseToolCalls(
        '<tool_call>grep<arg_key>pattern</arg_key><arg_value>foo<arg_key>bar</arg_value></tool_call>',
        { tools: [grepTool] }
      );
      expect(toolCalls).toHaveLength(0);
      expect(content).toContain('<tool_call>');
    });

    it('still reads ordinary multi-argument tagged bodies', () => {
      // The refusals above must not cost the well-formed case they protect.
      const { toolCalls } = parseToolCalls(
        '<tool_call>grep<arg_key>pattern</arg_key><arg_value>good.?match</arg_value>' +
          '<arg_key>include</arg_key><arg_value>*.svelte</arg_value></tool_call>',
        { tools: [grepTool] }
      );
      expect(toolCalls).toHaveLength(1);
      expect(JSON.parse(toolCalls[0].function.arguments)).toEqual({
        pattern: 'good.?match',
        include: '*.svelte',
      });
    });

    it('refuses rather than re-pairs when a tag-only line sits mid-block', () => {
      // Dropping it would shift the alternation and pair `pattern` with the next
      // key's name, producing a call nobody asked for. Losing the call is fine;
      // inventing one is not.
      const { content, toolCalls } = parseToolCalls(
        '<tool_call>grep\npattern\n</arg_value>\ninclude\n</tool_call>',
        { tools: [grepTool] }
      );
      expect(toolCalls).toHaveLength(0);
      expect(content).toContain('<tool_call>');
    });

    it('leaves a value alone even when it is entirely tag-shaped', () => {
      // A value at a value position is never rewritten, so grepping for the
      // literal text of a transport tag survives. The pairing decides what is a
      // key before any tag is removed, which is what makes that safe.
      const { toolCalls } = parseToolCalls(
        '<tool_call>grep\npattern\n</arg_value>foo\ninclude\n*.ts\n</arg_value></tool_call>',
        { tools: [grepTool] }
      );
      expect(toolCalls).toHaveLength(1);
      expect(JSON.parse(toolCalls[0].function.arguments)).toEqual({
        pattern: '</arg_value>foo',
        include: '*.ts',
      });
    });

    it('leaves tag-shaped text inside a value alone', () => {
      // Searching for the literal text of a transport tag is a legitimate grep.
      // Stripping it from the pattern would produce a call that runs and returns
      // the wrong thing, which is worse than not recovering the call.
      const { toolCalls } = parseToolCalls(
        '<tool_call>grep\npattern\nfoo</arg_value>bar\n</arg_value></tool_call>',
        { tools: [grepTool] }
      );
      expect(toolCalls).toHaveLength(1);
      expect(JSON.parse(toolCalls[0].function.arguments)).toEqual({
        pattern: 'foo</arg_value>bar',
      });
    });

    it('keeps tag-shaped text in a call-syntax argument', () => {
      const editTool: ToolDefinition = {
        type: 'function',
        function: {
          name: 'edit',
          parameters: {
            type: 'object',
            properties: { filePath: { type: 'string' }, oldString: { type: 'string' } },
            required: ['filePath', 'oldString'],
          },
        },
      };
      const { toolCalls } = parseToolCalls(
        '<tool_call>edit(filePath:"/src/a.ts",oldString:"const x = \\"<arg_value>\\";")',
        { tools: [editTool] }
      );
      expect(toolCalls).toHaveLength(1);
      expect(JSON.parse(toolCalls[0].function.arguments)).toEqual({
        filePath: '/src/a.ts',
        oldString: 'const x = "<arg_value>";',
      });
    });

    it('parses call syntax with bare keys and keeps the escapes intact', () => {
      const editTool: ToolDefinition = {
        type: 'function',
        function: {
          name: 'edit',
          parameters: {
            type: 'object',
            properties: {
              filePath: { type: 'string' },
              oldString: { type: 'string' },
              newString: { type: 'string' },
            },
            required: ['filePath', 'oldString', 'newString'],
          },
        },
      };
      const { toolCalls } = parseToolCalls(
        '<tool_call>edit(filePath:"/src/Badge.svelte",' +
          'oldString:"  .band-strong {\\n    background: var(--accent-bg);\\n  }",' +
          'newString:"  /* the \\"positive\\" tier */\\n  .band-strong {\\n    background: var(--ok);\\n  }")',
        { tools: [editTool] }
      );
      expect(toolCalls).toHaveLength(1);
      expect(JSON.parse(toolCalls[0].function.arguments)).toEqual({
        filePath: '/src/Badge.svelte',
        oldString: '  .band-strong {\n    background: var(--accent-bg);\n  }',
        newString: '  /* the "positive" tier */\n  .band-strong {\n    background: var(--ok);\n  }',
      });
    });

    it('does not read a parenthesised phrase as a call', () => {
      const { toolCalls, content } = parseToolCalls('<tool_call>read(the docs first)</tool_call>', {
        tools: [readTool],
      });
      expect(toolCalls).toHaveLength(0);
      expect(content).toContain('read(the docs first)');
    });

    it('keeps an argument whose key rode along inside the value tag', () => {
      const { toolCalls } = parseToolCalls(
        '<tool_call>task<arg_key>description":"Find the badge</arg_value>' +
          '<arg_value>prompt":"Search for match strength colors</arg_value>' +
          '<arg_key>subagent_type":"explore</arg_value></tool_call>',
        { tools: [taskTool] }
      );
      expect(toolCalls).toHaveLength(1);
      // `prompt` used to be discarded outright: its tag was a value tag with no
      // key pending, so the whole argument vanished.
      expect(JSON.parse(toolCalls[0].function.arguments)).toEqual({
        description: 'Find the badge',
        prompt: 'Search for match strength colors',
        subagent_type: 'explore',
      });
    });
  });
});

describe('blocks that yield no call', () => {
  it('surfaces a closed but unparseable block as content', () => {
    // Regression: the block used to be consumed and dropped, costing the caller
    // the entire turn with nothing to show for it.
    const { content, toolCalls } = parseToolCalls(block('what even is this'));
    expect(toolCalls).toHaveLength(0);
    expect(content).toContain('what even is this');
    expect(content).toContain(TOOL_CALL_OPEN);
    expect(content).toContain(TOOL_CALL_CLOSE);
  });

  it('surfaces an unparseable block while streaming, not only at flush', () => {
    const parser = new ToolCallStreamParser();
    const pushed = parser.push(`${block('nonsense')}and then prose`);
    expect(pushed.toolCalls).toHaveLength(0);
    expect(pushed.content).toContain('nonsense');
    expect(pushed.content).toContain('and then prose');
  });

  it('keeps prose around a dropped block in order', () => {
    const { content } = parseToolCalls(`before ${block('nope')} after`);
    expect(content.indexOf('before')).toBeLessThan(content.indexOf('nope'));
    expect(content.indexOf('nope')).toBeLessThan(content.indexOf('after'));
  });
});

describe('untagged tool calls', () => {
  it('recovers a bare JSON call that names a declared tool', () => {
    const { content, toolCalls } = parseToolCalls(
      '{"name": "get_weather", "arguments": {"city": "Bratislava"}}',
      { tools: [weatherTool] }
    );
    expect(toolCalls).toHaveLength(1);
    expect(toolCalls[0].function.name).toBe('get_weather');
    expect(content).toBe('');
  });

  it('recovers a bare JSON call wrapped in a markdown fence', () => {
    const { toolCalls } = parseToolCalls(
      '```json\n{"name": "get_weather", "arguments": {"city": "Vienna"}}\n```',
      { tools: [weatherTool] }
    );
    expect(toolCalls).toHaveLength(1);
  });

  it('leaves a JSON answer alone when it names no declared tool', () => {
    const text = '{"answer": 42}';
    const { content, toolCalls } = parseToolCalls(text, { tools: [weatherTool] });
    expect(toolCalls).toHaveLength(0);
    expect(content).toBe(text);
  });

  it('does not hunt for untagged calls when no tools are declared', () => {
    const text = '{"name": "get_weather", "arguments": {"city": "Bratislava"}}';
    const { content, toolCalls } = parseToolCalls(text);
    expect(toolCalls).toHaveLength(0);
    expect(content).toBe(text);
  });

  it('streams prose unchanged when tools are declared', () => {
    const parser = new ToolCallStreamParser({ tools: [weatherTool] });
    const first = parser.push('It is sunny ');
    const second = parser.push('in Bratislava.');
    expect(first.content + second.content + parser.flush().content).toBe(
      'It is sunny in Bratislava.'
    );
  });

  it('assembles an untagged call split across chunks', () => {
    const parser = new ToolCallStreamParser({ tools: [weatherTool] });
    const chunks = ['{"name": "get_', 'weather", "argum', 'ents": {"city": "Br', 'atislava"}}'];
    const calls = chunks.flatMap((c) => parser.push(c).toolCalls);
    const tail = parser.flush();
    expect([...calls, ...tail.toolCalls]).toHaveLength(1);
    expect(tail.content).toBe('');
  });

  it('prefers the tagged form when the model uses it after prose', () => {
    const { content, toolCalls } = parseToolCalls(
      `{ is a brace. Now:\n${block('{"name":"get_weather","arguments":{"city":"Vienna"}}')}`,
      { tools: [weatherTool] }
    );
    expect(toolCalls).toHaveLength(1);
    expect(content).toContain('{ is a brace.');
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
