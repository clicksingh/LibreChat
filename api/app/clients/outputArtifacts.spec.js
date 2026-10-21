const {
  latestAttachments,
  missingFinalArtifactResponse,
  ensureVisibleEmptyFinalResponse,
} = require('./outputArtifacts');
describe('Durable agent deliverables', () => {
  it('Aryn: previously blank completed turn receives truthful visible recovery text', () => {
    const msg = { text: '', content: [], attachments: [] };
    expect(ensureVisibleEmptyFinalResponse(msg)).toBe(true);
    expect(msg.text).toMatch(/ended before/);
    expect(msg.content).toEqual([{ type: 'text', text: msg.text }]);
    expect(ensureVisibleEmptyFinalResponse(msg)).toBe(false);
  });
  it('tool-only final without files is not persisted as an invisible turn', () => {
    const tool = { type: 'tool_call', name: 'bash_tool' };
    const msg = { text: '', content: [tool] };
    expect(ensureVisibleEmptyFinalResponse(msg)).toBe(true);
    expect(msg.content[0]).toBe(tool);
    expect(msg.content[1].text).toBe(msg.text);
  });
  it('valid structured assistant text is kept without duplication', () => {
    const msg = { text: '', content: [{ type: 'text', text: 'Document available for review' }] };
    expect(ensureVisibleEmptyFinalResponse(msg)).toBe(false);
    expect(msg.content).toHaveLength(1);
  });

  it('persists one latest revision per file_id even across many tool calls', () => {
    const result = latestAttachments([
      { file_id: 'doc', filename: 'Manual.docx', bytes: 100, status: 'pending' },
      { file_id: 'pdf', filename: 'Manual.pdf', bytes: 200 },
      { file_id: 'doc', filename: 'Manual.docx', bytes: 120, toolCallId: 'new-doc' },
      { file_id: 'pdf', filename: 'Manual.pdf', bytes: 220, toolCallId: 'new-pdf' },
      { file_id: 'doc', filename: 'Manual.docx', bytes: 130, toolCallId: 'final-doc' },
    ]);
    expect(result).toHaveLength(2);
    expect(result[0]).toMatchObject({ file_id: 'doc', bytes: 130, toolCallId: 'final-doc' });
    expect(result[1]).toMatchObject({ file_id: 'pdf', bytes: 220, toolCallId: 'new-pdf' });
  });
  it('does not dedupe unrelated attachments or hide memory artifacts', () => {
    expect(
      latestAttachments([{ type: 'memory', note: 'one' }, { type: 'memory', note: 'two' }, null]),
    ).toEqual([
      { type: 'memory', note: 'one' },
      { type: 'memory', note: 'two' },
    ]);
  });
  it('never fabricates prose if the agent answered or lacks output documents', () => {
    const answered = {
      text: 'I have finished.',
      attachments: [{ file_id: 'x', filename: 'a.docx' }],
    };
    expect(missingFinalArtifactResponse(answered)).toBe(false);
    expect(answered.text).toBe('I have finished.');
    const blank = { text: '', attachments: [{ file_id: 't', filename: 'trace.log' }] };
    expect(missingFinalArtifactResponse(blank)).toBe(false);
  });
  it('adds visible text to tool-only content and preserves tool parts', () => {
    const tool = { type: 'tool_call', name: 'bash_tool', tool_call_id: 'abc' };
    const msg = {
      text: '',
      content: [tool],
      attachments: [{ file_id: 'manual', filename: 'Manual.docx' }],
    };
    expect(missingFinalArtifactResponse(msg)).toBe(true);
    expect(msg.content).toHaveLength(2);
    expect(msg.content[0]).toBe(tool);
    expect(msg.content[1]).toEqual({ type: 'text', text: msg.text });
    expect(missingFinalArtifactResponse(msg)).toBe(false);
  });
  it('keeps meaningful structured text and avoids duplicate fallback', () => {
    const msg = {
      text: '',
      content: [{ type: 'text', text: 'Here is the manual.' }],
      attachments: [{ file_id: 'manual', filename: 'Manual.docx' }],
    };
    expect(missingFinalArtifactResponse(msg)).toBe(false);
  });
  it('adds only a truthful review instruction to an otherwise blank delivered file response', () => {
    const msg = { text: '', attachments: [{ file_id: 'x', filename: 'Manual.docx', bytes: 125 }] };
    expect(missingFinalArtifactResponse(msg)).toBe(true);
    expect(msg.text).toMatch(/review/);
    expect(msg.text).not.toMatch(/approved|complete and verified/i);
  });
});
