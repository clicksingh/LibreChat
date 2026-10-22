const { logger } = require('@librechat/data-schemas');
const { loadAgent: loadAgentFn } = require('@librechat/api');
const { isAgentsEndpoint, removeNullishValues, Constants } = require('librechat-data-provider');
const { getMCPServerTools } = require('~/server/services/Config');
const db = require('~/models');
const { matchesManagedAgentPolicy } = require('~/server/middleware/enforceManagedChatEndpoint');

const loadAgent = (params) => loadAgentFn(params, { getAgent: db.getAgent, getMCPServerTools });

const buildOptions = (req, endpoint, parsedBody, endpointType) => {
  const { spec, iconURL, agent_id, chatProjectId, workspaceId, ...model_parameters } = parsedBody;
  const agentPromise = loadAgent({
    req,
    spec,
    agent_id: isAgentsEndpoint(endpoint) ? agent_id : Constants.EPHEMERAL_AGENT_ID,
    endpoint,
    model_parameters,
  }).then((agent) => {
    const approved = req.managedSavedAgentAuth;
    if (!approved) return agent;
    // Re-check the saved model after the ACL/policy lookup. A record changed
    // between reads must not become an alternate provider route.
    if (!agent || agent.id !== approved.id ||
        !matchesManagedAgentPolicy(agent, approved)) {
      throw new Error('Managed saved-agent policy changed after authorization');
    }
    const params = { ...(agent.model_parameters || {}) };
    for (const key of [
      'reasoning_effort', 'reasoningEffort', 'reasoning',
      'effort', 'thinking', 'thinkingLevel', 'thinkingBudget',
      'reasoning_mode', 'reasoning_summary', 'reasoning_context',
      'modelOptions', 'provider', 'apiKey', 'baseURL', 'key',
    ]) delete params[key];
    return { ...agent, model_parameters: params };
  }).catch((error) => {
    logger.error(`[/agents/:${agent_id}] Error retrieving agent during build options step`, error);
    return undefined;
  });

  /** @type {import('librechat-data-provider').TConversation | undefined} */
  const addedConvo = req.body?.addedConvo;

  return removeNullishValues({
    spec,
    iconURL,
    endpoint,
    agent_id,
    endpointType,
    chatProjectId,
    // 8S3D.1: only ever passed through here on the FIRST save for a new
    // conversation — saveConvo() enforces immutability once a conversation
    // already has a workspaceId (see methods/conversation.ts). Never trust
    // this as an access grant by itself: resolveWorkspaceContext() re-checks
    // membership per-request before any codeapi claim is minted from it.
    workspaceId,
    model_parameters,
    agent: agentPromise,
    addedConvo,
  });
};

module.exports = { buildOptions };
