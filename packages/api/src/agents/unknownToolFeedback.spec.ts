import { buildUnknownToolError } from './unknownToolFeedback';

describe('invalid tool names never resolve an alias', () => {
  it('identifies the exact unknown name and suggests an authorized related tool', () => {
    const message = buildUnknownToolError('bash_terminal', ['bash_tool', 'web_search']);
    expect(message).toContain('"bash_terminal"');
    expect(message).toContain('"bash_tool"');
    expect(message).not.toContain('web_search');
    expect(message).toContain('was not executed');
  });

  it('handles the shorter bad bash alias without executing it', () => {
    const message = buildUnknownToolError('bash', ['bash_tool']);
    expect(message).toContain('"bash"');
    expect(message).toContain('"bash_tool"');
  });

  it('does not suggest tools that were not supplied by the authorized runtime', () => {
    const message = buildUnknownToolError('bash_terminal', []);
    expect(message).not.toContain('bash_tool');
    expect(message).toContain('was not executed');
  });

  it('does not leak a different MCP server tool on the generic mcp prefix', () => {
    const message = buildUnknownToolError('mcp__serverA__read', ['mcp__serverB__delete']);
    expect(message).not.toContain('serverB');
  });

  it('deduplicates suggestions and limits output to three related names', () => {
    const message = buildUnknownToolError('read_file', [
      'read_a',
      'read_c',
      'read_b',
      'read_d',
      'read_a',
      'secret_write',
    ]);
    expect(message).toContain('"read_a"');
    expect(message).toContain('"read_b"');
    expect(message).toContain('"read_c"');
    expect(message).not.toContain('"read_d"');
    expect(message).not.toContain('secret_write');
  });

  it('quotes the original requested name rather than substituting a guessed alias', () => {
    const message = buildUnknownToolError('bash_terminal\\"invalid', ['bash_tool']);
    expect(message).toContain(JSON.stringify('bash_terminal\\"invalid'));
    expect(message).toContain('was not executed');
  });
});
