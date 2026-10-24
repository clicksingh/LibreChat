'use strict';

/**
 * Server-owned, safe error messages for resumable agent jobs.
 * A provider throwing AbortError is not evidence that a USER pressed Stop.
 * Never re-run tool side effects automatically on an unknown provider state.
 */
function normalizeAgentFailure(error) {
  const status = Number(error?.status ?? error?.response?.status ?? 0);
  const rawCode = String(error?.code ?? error?.response?.data?.error?.code ?? '').toLowerCase();
  const rawMessage = String(error?.message ?? error?.response?.data?.error?.message ?? '');
  const explicitOverflowCode = [
    'context_length_exceeded',
    'context_window_exceeded',
    'prompt_too_long',
    'max_tokens_exceeded',
    'context_overflow',
  ].includes(rawCode);
  if (rawCode === 'agent_expected_mcp_tools_unavailable') {
    return 'AGENT_TOOL_CONFIGURATION: This agent is configured to use MCP tools, but none are available. Verify that the MCP server is connected and this agent can access its selected tools, then try again.';
  }

  const messageOverflow =
    /context (?:length|window|limit)|maximum context|prompt (?:is )?too long|too many (?:input )?tokens|exceed(?:s|ed)? (?:the )?model.*(?:token|context)/i.test(
      rawMessage,
    );
  if (status === 400 && (explicitOverflowCode || messageOverflow)) {
    return 'MODEL_CONTEXT_LIMIT: The model could not fit this turn into its context window. No tool actions were automatically replayed. Previously saved files remain available. Continue in this chat and ask me to summarize the existing work before proceeding.';
  }
  if (status === 429) {
    return 'MODEL_RATE_LIMIT: The model service is temporarily rate-limiting requests. Saved files remain available; retry this chat later.';
  }
  if (status === 402 || rawCode === 'insufficient_balance') {
    return 'MODEL_PROVIDER_CREDIT: The selected model provider could not authorize this request. Saved files remain available; contact your administrator.';
  }
  return 'MODEL_REQUEST_INTERRUPTED: This response stopped before completion. Existing saved files are preserved. Continue in this chat from the last completed step; tool actions have not been automatically replayed.';
}

/**
 * Persist the failure regardless of Redis pub/sub availability. Do not
 * falsely complete and delete a failed job when the SSE error cannot publish.
 * Both methods are awaited: late subscribers can inspect jobStore.status/error.
 */
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

module.exports = { normalizeAgentFailure, persistAgentFailure };
