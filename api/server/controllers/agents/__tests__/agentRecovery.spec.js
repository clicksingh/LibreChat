const {
  classifyAgentFailure,
  classifyToolReplay,
  buildRecoveryReceipt,
  formatRecoveryContext,
  persistInterruptedRunCheckpoint,
} = require('../agentFailure');

const failure = { status: 503, code: 'ECONNRESET', message: 'api_key=provider-secret-X' };
const base = {
  error: failure,
  conversationId: 'convo-1',
  runId: 'run-1',
  model: 'glm-5.3-flash',
  provider: 'openai',
  startedAt: 1794000000000,
  failedAt: 1794000001111,
};

const call = (id, name, completed = false, extra = {}) => ({
  type: 'tool_call',
  tool_call: { id, name, ...(completed ? { output: 'done' } : {}), ...extra },
});

describe('deterministic interruption receipts', () => {
  it('records an interruption before tools without inventing a completion', () => {
    const receipt = buildRecoveryReceipt(base);
    expect(receipt.completedTools).toEqual([]);
    expect(receipt.uncertainTools).toEqual([]);
    expect(receipt.lastConfirmed).toBeNull();
    expect(receipt.failureClass).toBe('gateway_network');
    expect(receipt.sideEffectsAutoReplayed).toBe(false);
  });

  it('confirms a completed read and marks it only as read-only', () => {
    const receipt = buildRecoveryReceipt({
      ...base,
      contentParts: [call('read-1', 'mcp__Xpose__read_file', true)],
    });
    expect(receipt.completedTools).toEqual([
      { id: 'read-1', name: 'mcp__Xpose__read_file', replay: 'read_only', status: 'completed' },
    ]);
    expect(receipt.lastConfirmed.toolCallId).toBe('read-1');
  });

  it('confirms an already completed write without allowing automatic replay', () => {
    const receipt = buildRecoveryReceipt({
      ...base,
      contentParts: [call('write-1', 'mcp__Xpose__write_file', true)],
    });
    expect(receipt.completedTools[0].replay).toBe('side_effecting');
    expect(receipt.sideEffectsAutoReplayed).toBe(false);
    expect(formatRecoveryContext(receipt)).toContain('Do not automatically repeat');
  });

  it('retains a pending write as uncertain, never as completed', () => {
    const receipt = buildRecoveryReceipt({
      ...base,
      contentParts: [call('write-1', 'mcp__Xpose__write_file')],
    });
    expect(receipt.completedTools).toEqual([]);
    expect(receipt.uncertainTools[0]).toMatchObject({
      id: 'write-1', status: 'uncertain', replay: 'side_effecting',
    });
  });

  it('uses run steps to capture a pending tool not yet present in streamed content', () => {
    const receipt = buildRecoveryReceipt({
      ...base,
      runSteps: [{ stepDetails: { tool_calls: [{ id: 'side-2', name: 'powershell' }] } }],
    });
    expect(receipt.uncertainTools[0].replay).toBe('side_effecting');
  });

  it('never classifies shell, database, install or unknown actions as read-only', () => {
    for (const name of ['PowerShell', 'execute_code', 'database_query',
      'run_command', 'deploy_release', 'delete_file', 'unknown_plugin_tool']) {
      expect(classifyToolReplay(name)).not.toBe('read_only');
    }
    for (const name of ['read_file', 'list_directory', 'search_files', 'screenshot',
      'read_process_output', 'list_processes']) {
      expect(classifyToolReplay(name)).toBe('read_only');
    }
  });

  it('retains observed generated file IDs without leaking file contents', () => {
    const receipt = buildRecoveryReceipt({
      ...base,
      contentParts: [call('file-tool', 'create_file', true, {
        artifact: { files: [{ id: 'file-1', name: 'private-staff-details.txt' }] },
      })],
    });
    expect(receipt.artifactRefs).toEqual(['file-1']);
    expect(JSON.stringify(receipt)).not.toContain('private-staff-details');
  });

  it('excludes provider credentials, tool arguments and outputs from the receipt', () => {
    const receipt = buildRecoveryReceipt({
      ...base,
      error: { status: 401, message: 'api_key=provider-secret-X' },
      model: 'model?key=private',
      contentParts: [call('call-1', 'edit_file', true, {
        args: 'Authorization: Bearer private-token', output: 'password=value',
      })],
    });
    const json = JSON.stringify(receipt);
    expect(receipt.failureClass).toBe('provider_auth');
    expect(receipt.model).toBeNull();
    expect(json).not.toMatch(/provider-secret|private-token|password=value|key=private/);
  });

  it.each([
    [{ status: 429 }, 'provider_rate_limit'],
    [{ status: 402 }, 'provider_credit'],
    [{ status: 401 }, 'provider_auth'],
    [{ status: 400, code: 'invalid_request_error' }, 'malformed_request'],
    [{ name: 'AbortError' }, 'provider_abort'],
    [{ status: 504 }, 'gateway_network'],
    [{ code: 'SSE_DISCONNECTED' }, 'client_disconnect'],
  ])('classifies failure cause without raw diagnostic text', (error, cause) => {
    expect(classifyAgentFailure(error)).toBe(cause);
  });
});

describe('durable failure fallback', () => {
  function harness(parts = [], steps = []) {
    const rows = new Map();
    const saveMessage = jest.fn(async (_ctx, msg) => {
      rows.set(msg.messageId, structuredClone(msg));
      return msg;
    });
    const manager = {
      getResumeState: jest.fn(async () => ({
        userMessage: { messageId: 'user-1', text: 'Please create a report' },
        responseMessageId: 'assistant-1',
        model: 'glm-5.3-flash',
        aggregatedContent: parts,
        runSteps: steps,
      })),
    };
    const args = {
      ...base,
      manager, saveMessage, streamId: 'convo-1',
      generationCreatedAt: 1794000000000,
      reqContext: { userId: 'user-1' }, userId: 'user-1',
      conversationId: 'convo-1', responseMessageId: 'assistant-1',
    };
    return { args, rows, saveMessage, manager };
  }

  it('persists pre-tool failure as unfinished assistant message with a receipt', async () => {
    const { args, rows, saveMessage } = harness();
    const receipt = await persistInterruptedRunCheckpoint(args);
    expect(saveMessage).toHaveBeenCalledTimes(2);
    const msg = rows.get('assistant-1');
    expect(msg.unfinished).toBe(true);
    expect(msg.metadata.interruption).toEqual(receipt);
    expect(msg.content.at(-1).error).toMatch(/^MODEL_REQUEST_INTERRUPTED/);
  });

  it('saves the confirmed write once and continuation cannot duplicate it', async () => {
    const writeTool = jest.fn().mockResolvedValue('done');
    await writeTool();
    const { args, rows } = harness([
      call('write-1', 'edit_file', true),
      { type: 'text', text: 'File edited.' },
    ]);
    await persistInterruptedRunCheckpoint(args);
    const saved = rows.get('assistant-1');
    expect(saved.metadata.interruption.completedTools[0].replay).toBe('side_effecting');
    expect(saved.content.some((part) => part.text?.includes('Do not automatically repeat'))).toBe(true);
    // A new turn reads the checkpoint, not an executable queued tool command.
    const continued = structuredClone(saved.metadata.interruption);
    expect(continued.sideEffectsAutoReplayed).toBe(false);
    expect(writeTool).toHaveBeenCalledTimes(1);
  });

  it('preserves a generated artifact reference on interruption', async () => {
    const { args, rows } = harness([
      call('create-1', 'create_file', true, {
        artifact: { files: [{ id: 'file-123' }] },
      }),
    ]);
    await persistInterruptedRunCheckpoint(args);
    expect(rows.get('assistant-1').metadata.interruption.artifactRefs).toEqual(['file-123']);
  });

  it('uses the generation-fenced snapshot and refuses missing epoch snapshots', async () => {
    const { args, manager, saveMessage } = harness();
    manager.getResumeState.mockResolvedValueOnce(null);
    await expect(persistInterruptedRunCheckpoint(args)).resolves.toBeNull();
    expect(manager.getResumeState).toHaveBeenCalledWith('convo-1', 1794000000000);
    expect(saveMessage).not.toHaveBeenCalled();
  });

  it('does not persist temporary chat content', async () => {
    const { args, saveMessage } = harness();
    args.reqContext.isTemporary = true;
    expect(await persistInterruptedRunCheckpoint(args)).toBeNull();
    expect(saveMessage).not.toHaveBeenCalled();
  });

  it('rejects unconfirmed database saves instead of claiming recovery', async () => {
    const { args, saveMessage } = harness();
    saveMessage.mockResolvedValueOnce(false);
    await expect(persistInterruptedRunCheckpoint(args)).rejects.toThrow('could not be persisted');
  });
});
