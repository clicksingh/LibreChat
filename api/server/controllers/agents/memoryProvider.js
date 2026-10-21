/**
 * A primary initialized custom agent has TWO provider identities:
 * - endpoint: its original, credential-bearing configured name (e.g. CBHR AI)
 * - provider: the normalized LLM SDK adapter (e.g. openAI)
 *
 * A memory agent runs through initializeAgent for a second time. Passing the
 * normalized adapter loses the custom endpoint's centrally supplied key/URL
 * and may trigger a BYOK getUserKey lookup. Re-initialize from the ORIGINAL
 * configured endpoint and retain only the model settings, not chat tools.
 */
function createConversationMemoryAgent(initializedAgent, memoryInstructions) {
  if (!initializedAgent || typeof initializedAgent !== 'object') {
    throw new TypeError('A primary initialized agent is required for memory reuse');
  }
  const originalProvider =
    typeof initializedAgent.endpoint === 'string' && initializedAgent.endpoint.length > 0
      ? initializedAgent.endpoint
      : initializedAgent.provider;
  return {
    ...initializedAgent,
    provider: originalProvider,
    tools: [],
    tool_resources: undefined,
    model_parameters: { ...initializedAgent.model_parameters },
    instructions: memoryInstructions,
  };
}

module.exports = { createConversationMemoryAgent };
