const { logger } = require('@librechat/data-schemas');
const {
  Constants,
  EModelEndpoint,
  SystemRoles,
  isAgentsEndpoint,
  isEphemeralAgentId,
} = require('librechat-data-provider');


/**
 * Regular CBHR staff have centrally funded access, not individual BYOK keys.
 * Correct stale browser/conversation endpoint payloads before model setup or
 * generation job creation. Saved agents cannot bypass the required company default;
 * ADMIN retains independent selection.
 *
 * Fail closed if the deployment no longer provides a valid centrally funded
 * default. Never trust a caller-provided spec or arbitrary custom endpoint.
 */
function resolveFundedDefault(config) {
  const list = config?.modelSpecs?.list;
  const configured = config?.endpoints?.custom;
  const spec = Array.isArray(list) && Array.isArray(configured)
    ? list.find(entry =>
        entry?.default === true &&
        typeof entry?.name === 'string' && entry.name.length > 0 &&
        typeof entry?.preset?.endpoint === 'string' &&
        configured.some(ep => ep?.name === entry.preset.endpoint))
    : undefined;
  const custom = Array.isArray(configured)
    ? configured.find(entry => entry?.name === spec?.preset?.endpoint)
    : undefined;
  const selected = Array.isArray(custom?.models?.default)
    ? custom.models.default[0] : undefined;
  const validModel = typeof selected === 'string' &&
    /^[a-zA-Z0-9][a-zA-Z0-9_.:/@+-]{0,255}$/.test(selected);
  const apiKey = custom?.apiKey;
  const baseURL = custom?.baseURL;
  if (
    !spec ||
    typeof apiKey !== 'string' ||
    !apiKey.trim() ||
    apiKey === 'user_provided' ||
    typeof baseURL !== 'string' ||
    !baseURL.trim() ||
    baseURL === 'user_provided' ||
    !validModel
  ) {
    return null;
  }
  return { endpoint: spec.preset.endpoint, model: selected, spec: spec.name };
}

function isExplicitPersistedAgent(body) {
  return (
    isAgentsEndpoint(body.endpoint) &&
    typeof body.agent_id === 'string' &&
    body.agent_id.length > 0 &&
    !isEphemeralAgentId(body.agent_id)
  );
}

function enforceManagedChatEndpoint(req, res, next) {
  if (req.user?.role === SystemRoles.ADMIN) {
    return next();
  }

  const body = req.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json({
      error: 'Invalid chat request',
      message: 'Chat request body must be an object.',
    });
  }

  // Reasoning effort for ordinary users is organization policy, never a
  // browser-supplied parameter. The bridge injects that model's configured
  // default after routing; unsupported models receive no extra parameter.
  for (const field of [
    'reasoning_effort', 'reasoningEffort', 'thinking', 'thinkingBudget',
    'thinkingLevel', 'reasoning', 'effort',
  ]) delete body[field];

  // Saved agents may carry a persisted, privileged model selected before the
  // current central policy. Their VIEW ACL is *not* model authorization.
  // Refuse non-admin saved-agent execution until stored agent models can be
  // independently checked against the effective model policy.
  if (isExplicitPersistedAgent(body)) {
    return res.status(403).json({
      error: 'Company model required',
      message: 'This saved agent cannot run under the current company model policy.',
    });
  }

  const funded = resolveFundedDefault(req.config);
  if (!funded) {
    logger.error('[managed-endpoint] No valid centrally funded USER default configured');
    return res.status(503).json({
      error: 'Managed model unavailable',
      message: 'The company-provided model is temporarily unavailable.',
    });
  }

  const previousEndpoint = typeof body.endpoint === 'string' ? body.endpoint : '(missing)';
  const previousModel = typeof body.model === 'string' ? body.model : '(missing)';
  const oldSpec = typeof body.spec === 'string' ? body.spec : '(missing)';
  const changed =
    body.endpoint !== funded.endpoint ||
    body.model !== funded.model ||
    body.spec !== funded.spec ||
    body.endpointType !== EModelEndpoint.custom ||
    body.agent_id !== Constants.EPHEMERAL_AGENT_ID;

  // Eliminate conflicting credential/provider selections from stale client
  // state. Preserve conversation IDs, user messages, files, workspace,
  // explicit skills and UI tool flags; none confer endpoint authority.
  for (const field of [
    'apiKey',
    'baseURL',
    'key',
    'provider',
    'model_parameters',
    'modelOptions',
    'modelLabel',
    'chatGptLabel',
  ]) {
    delete body[field];
  }
  body.endpoint = funded.endpoint;
  body.endpointType = EModelEndpoint.custom;
  body.model = funded.model;
  body.spec = funded.spec;
  body.agent_id = Constants.EPHEMERAL_AGENT_ID;
  // The /chat/:endpoint route segment is client-controlled too. Keep both
  // views synchronized so future route consumers cannot revive a stale BYOK
  // selection after the body has been normalized.
  if (req.params && Object.prototype.hasOwnProperty.call(req.params, 'endpoint')) {
    req.params.endpoint = funded.endpoint;
  }

  if (changed) {
    logger.info('[managed-endpoint] Corrected USER chat model selection', {
      userId: req.user.id,
      previousEndpoint,
      previousModel,
      previousSpec: oldSpec,
      correctedEndpoint: funded.endpoint,
      correctedModel: funded.model,
    });
  }
  next();
}

/**
 * Legacy assistants use separate /api/assistants/v1|v2/chat handlers, so they
 * never pass through the normal chat endpoint normalizer. An assistant ID
 * cannot be safely converted into a CBHR AI model request; reject USER here
 * instead of attempting a personal provider key. ADMIN remains unaffected.
 */
function rejectManagedAssistantEndpoint(req, res, next) {
  if (req.user?.role !== SystemRoles.ADMIN) {
    return res.status(403).json({
      error: 'Company model required',
      message: 'Use CBHR AI to start a company-funded chat.',
    });
  }
  return next();
}

module.exports = {
  enforceManagedChatEndpoint,
  rejectManagedAssistantEndpoint,
  resolveFundedDefault,
};
