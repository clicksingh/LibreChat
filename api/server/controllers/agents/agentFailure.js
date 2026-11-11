'use strict';

/**
 * Only bounded, server-authored fields enter interruption receipts. No raw
 * provider messages, tool inputs, outputs, shell commands, or URLs are stored.
 */
const safeId = (value) =>
  typeof value === 'string' && /^[A-Za-z0-9_./:-]{1,128}$/.test(value) ? value : null;
const safeTime = (value) => {
  const time = Number(value);
  return Number.isFinite(time) && time > 0 ? new Date(time).toISOString() : null;
};

function classifyAgentFailure(error) {
  const status = Number(error?.status ?? error?.response?.status ?? 0);
  const code = String(error?.code ?? error?.response?.data?.error?.code ?? '').toLowerCase();
  const name = String(error?.name ?? '').toLowerCase();
  const message = String(error?.message ?? error?.response?.data?.error?.message ?? '');
  if (code === 'agent_expected_mcp_tools_unavailable') return 'tool_configuration';
  // B1 grants are local authorization/provenance failures, not provider interruptions.
  // The normalized message must not suggest retrying an unresumable file context.
  if (
    /^(?:CODEAPI_EXECUTION_INPUT_SCOPE_UNVERIFIED|CODEAPI_EXECUTION_INPUT_DUPLICATE|CODEAPI_EXECUTION_FILES_DB_UNAVAILABLE|CODEAPI_EXECUTION_HASH_SOURCE_UNAVAILABLE|CODEAPI_EXECUTION_INPUT_CHANGED_DURING_GRANT)$/.test(
      message,
    ) ||
    /^(?:codeapi_execution_input_scope_unverified|codeapi_execution_input_duplicate|codeapi_execution_files_db_unavailable|codeapi_execution_hash_source_unavailable|codeapi_execution_input_changed_during_grant)$/.test(
      code,
    )
  )
    return 'file_scope_validation';
  if (
    [
      'context_length_exceeded',
      'context_window_exceeded',
      'prompt_too_long',
      'max_tokens_exceeded',
      'context_overflow',
    ].includes(code) ||
    (status === 400 &&
      /context (?:length|window|limit)|maximum context|prompt (?:is )?too long|too many (?:input )?tokens|exceed(?:s|ed)? (?:the )?model.*(?:token|context)/i.test(
        message,
      ))
  )
    return 'context_limit';
  if (status === 429) return 'provider_rate_limit';
  if (status === 402 || code === 'insufficient_balance') return 'provider_credit';
  if (status === 401 || status === 403) return 'provider_auth';
  if (status === 400 || /(?:invalid_tool|tool.*schema|schema.*tool)/i.test(code + ' ' + message))
    return 'malformed_request';
  if (/^(?:econnreset|econnrefused|etimedout|enotfound|eai_again|und_err_socket)$/.test(code))
    return 'gateway_network';
  if (status === 502 || status === 503 || status === 504) return 'gateway_network';
  if (code === 'client_disconnected' || code === 'sse_disconnected') return 'client_disconnect';
  if (/proxy|sse|stream.*closed/i.test(code)) return 'proxy_stream';
  if (name === 'aborterror' || code === 'abort_err' || code === 'aborted') return 'provider_abort';
  if (status >= 500) return 'provider_http';
  return 'agent_exception';
}

function normalizeAgentFailure(error) {
  const cause = classifyAgentFailure(error);
  if (cause === 'tool_configuration')
    return 'AGENT_TOOL_CONFIGURATION: This agent is configured to use MCP tools, but none are available. Verify that the MCP server is connected and this agent can access its selected tools, then try again.';
  if (cause === 'file_scope_validation')
    return 'CODE_FILE_VALIDATION: A file referenced by this conversation could not pass code-execution validation. Saved artifacts remain available, but this turn cannot proceed until file access is repaired. No tool actions were automatically replayed.';
  if (cause === 'context_limit')
    return 'MODEL_CONTEXT_LIMIT: The model could not fit this turn into its context window. No tool actions were automatically replayed. Previously saved files remain available. Continue in this chat and ask me to summarize the existing work before proceeding.';
  if (cause === 'provider_rate_limit')
    return 'MODEL_RATE_LIMIT: The model service is temporarily rate-limiting requests. Saved files remain available; retry this chat later.';
  if (cause === 'provider_credit')
    return 'MODEL_PROVIDER_CREDIT: The selected model provider could not authorize this request. Saved files remain available; contact your administrator.';
  return 'MODEL_REQUEST_INTERRUPTED: This response was interrupted. Completed work and saved files are preserved. Continue in this chat from the last confirmed step; state-changing actions will not be automatically replayed.';
}

/** Unknown names and every process/shell tool fail closed; no heuristic "safe" replay. */
function classifyToolReplay(name) {
  const toolName = safeId(name);
  if (!toolName) return 'unknown';
  const base = toolName
    .split(/__|[./:]/)
    .pop()
    .toLowerCase();
  const readOnlyNames = new Set([
    'read_file',
    'read_multiple_files',
    'list_directory',
    'get_file_info',
    'get_config',
    'read_process_output',
    'list_processes',
    'list_sessions',
    'list_searches',
    'get_more_search_results',
    'get_status',
    'status',
    'screenshot',
    'search_files',
    'search_content',
    'fetch_file',
    'inspect_file',
    'find_file',
    'discover_tools',
  ]);
  if (readOnlyNames.has(base)) return 'read_only';
  if (
    /shell|powershell|terminal|process|exec|code|script|sql|query|http|request|command|run|batch|invoke|install|deploy|publish|send|delete|remove|write|edit|update|create|patch|move|rename|set|upload|download|approve|restart|start|stop|kill|mutate|submit/.test(
      base,
    )
  )
    return 'side_effecting';
  return 'unknown';
}

function toolCallsFromContent(contentParts = [], runSteps = []) {
  const calls = new Map();
  const add = (call, completed) => {
    const id = safeId(call?.id);
    if (!id) return;
    const prior = calls.get(id);
    const name = safeId(call?.name) ?? prior?.name ?? null;
    const replay = classifyToolReplay(name);
    calls.set(id, {
      id,
      name,
      replay,
      status: completed || prior?.status === 'completed' ? 'completed' : 'uncertain',
      ...(replay !== 'read_only' && { effectOutcome: 'not_verified' }),
    });
  };
  for (const step of Array.isArray(runSteps) ? runSteps : []) {
    for (const call of step?.stepDetails?.tool_calls ?? []) add(call, false);
  }
  for (const part of Array.isArray(contentParts) ? contentParts : []) {
    const call = part?.tool_call;
    if (part?.type !== 'tool_call' || !call) continue;
    // A tool-call card can be emitted before execution. An output is confirmation.
    add(call, call.output !== undefined && call.output !== null);
  }
  return [...calls.values()].slice(-100);
}

function artifactRefs(contentParts = [], attachments = []) {
  const refs = new Set();
  const add = (file) => {
    const id = safeId(file?.file_id ?? file?.id);
    if (id) refs.add(id);
  };
  for (const file of Array.isArray(attachments) ? attachments : []) add(file);
  for (const part of Array.isArray(contentParts) ? contentParts : []) {
    const files = part?.tool_call?.artifact?.files ?? [];
    for (const file of Array.isArray(files) ? files : []) add(file);
  }
  return [...refs].slice(0, 100);
}

/** Receipts describe past confirmations, never grant execution permission. */
function buildRecoveryReceipt({
  error,
  conversationId,
  runId,
  model,
  provider,
  startedAt,
  failedAt = Date.now(),
  contentParts = [],
  runSteps = [],
  attachments = [],
}) {
  const calls = toolCallsFromContent(contentParts, runSteps);
  const completed = calls.filter((call) => call.status === 'completed');
  const uncertain = calls.filter((call) => call.status === 'uncertain');
  const last = completed[completed.length - 1] ?? null;
  const lastTextIndex = Array.isArray(contentParts)
    ? contentParts.reduce((index, part, i) => (part?.type === 'text' ? i : index), -1)
    : -1;
  return {
    version: 1,
    conversationId: safeId(conversationId),
    runId: safeId(runId),
    model: safeId(model),
    provider: safeId(provider),
    startedAt: safeTime(startedAt),
    failedAt: safeTime(failedAt),
    failureClass: classifyAgentFailure(error),
    upstreamStatus:
      Number.isInteger(Number(error?.status ?? error?.response?.status)) &&
      Number(error?.status ?? error?.response?.status) >= 100 &&
      Number(error?.status ?? error?.response?.status) <= 599
        ? Number(error?.status ?? error?.response?.status)
        : null,
    interruptedTool: uncertain[uncertain.length - 1] ?? null,
    lastConfirmed: last ? { type: 'tool', toolCallId: last.id, toolName: last.name } : null,
    lastObservedTextIndex: lastTextIndex >= 0 ? lastTextIndex : null,
    completedTools: completed,
    uncertainTools: uncertain,
    artifactRefs: artifactRefs(contentParts, attachments),
    sideEffectsAutoReplayed: false,
  };
}

function formatRecoveryContext(receipt) {
  const done = receipt.completedTools.map((call) =>
    [call.name ?? 'unknown tool', call.id, call.replay].join(' / '),
  );
  const uncertain = receipt.uncertainTools.map((call) =>
    [call.name ?? 'unknown tool', call.id, call.replay].join(' / '),
  );
  return [
    'Recovery checkpoint (server confirmed):',
    'Completed tool calls: ' + (done.join('; ') || 'none'),
    'Uncertain/in-flight tool calls: ' + (uncertain.join('; ') || 'none'),
    'Observed artifact IDs (verify saved state): ' +
      (receipt.artifactRefs.join(', ') || 'none recorded'),
    'Continue from the last confirmed step. Verify uncertain external effects first.',
    'Do not automatically repeat completed or uncertain writes, edits, deletes, sends, publishes, shell commands or other side effects.',
    'Only explicitly classified read-only calls may be retried after checking the current state.',
  ].join('\n');
}

/** Preserves error status even if SSE publication is down. */
async function persistAgentFailure(manager, streamId, error, onPublishError = () => {}) {
  const message = normalizeAgentFailure(error);
  let eventDelivered = false;
  try {
    await manager.emitError(streamId, message);
    eventDelivered = true;
  } catch (publishError) {
    onPublishError(publishError);
  } finally {
    await manager.completeJob(streamId, message);
  }
  return { message, eventDelivered };
}

module.exports = {
  normalizeAgentFailure,
  classifyAgentFailure,
  classifyToolReplay,
  buildRecoveryReceipt,
  formatRecoveryContext,
  artifactRefs,
  persistAgentFailure,
  persistInterruptedRunCheckpoint,
};
/**
 * Initialization can fail before BaseClient writes the assistant row. Persist
 * an unfinished checkpoint through the existing message model. No replay.
 */
async function persistInterruptedRunCheckpoint({
  manager,
  saveMessage,
  streamId,
  generationCreatedAt,
  reqContext,
  userId,
  conversationId,
  responseMessageId,
  model,
  provider,
  client,
  error,
}) {
  if (!generationCreatedAt || reqContext?.isTemporary) return null;
  const state = await manager.getResumeState(streamId, generationCreatedAt);
  if (!state?.userMessage?.messageId) return null;
  const parts = client?.contentParts?.length
    ? client.contentParts
    : (state.aggregatedContent ?? []);
  const receipt = buildRecoveryReceipt({
    error,
    conversationId,
    runId: state.responseMessageId ?? responseMessageId,
    model: state.model ?? model,
    provider,
    startedAt: generationCreatedAt,
    contentParts: parts,
    runSteps: state.runSteps ?? [],
    attachments: client?.options?.attachments,
  });
  const ctx = { ...reqContext, userId };
  const user = { ...state.userMessage, conversationId, user: userId, isCreatedByUser: true };
  const persistedUser = await saveMessage(ctx, user, {
    context: 'api/server/controllers/agents/agentFailure.js - interrupted user checkpoint',
  });
  if (!persistedUser) throw new Error('Interrupted user checkpoint could not be persisted');
  const response = {
    messageId: state.responseMessageId ?? responseMessageId ?? user.messageId + '_',
    conversationId,
    parentMessageId: user.messageId,
    user: userId,
    isCreatedByUser: false,
    sender: state.sender ?? client?.sender ?? 'AI',
    model: state.model ?? model,
    endpoint: client?.options?.endpoint ?? 'agents',
    unfinished: true,
    error: false,
    content: [
      ...parts,
      { type: 'text', text: formatRecoveryContext(receipt) },
      { type: 'error', error: normalizeAgentFailure(error) },
    ],
    metadata: { interruption: receipt },
  };
  const persistedResponse = await saveMessage(ctx, response, {
    context: 'api/server/controllers/agents/agentFailure.js - interrupted assistant checkpoint',
  });
  if (!persistedResponse)
    throw new Error('Interrupted assistant checkpoint could not be persisted');
  return receipt;
}
