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
  const spec =
    Array.isArray(list) && Array.isArray(configured)
      ? list.find(
          (entry) =>
            entry?.default === true &&
            typeof entry?.name === 'string' &&
            entry.name.length > 0 &&
            typeof entry?.preset?.endpoint === 'string' &&
            configured.some((ep) => ep?.name === entry.preset.endpoint),
        )
      : undefined;
  // V2 owns the server-side default endpoint without requiring a legacy
  // concrete modelSpec. Never fall back to an arbitrary first endpoint.
  const v2Defaults = Array.isArray(configured)
    ? configured.filter((entry) => entry?.default === true && typeof entry.name === 'string')
    : [];
  let custom;
  if (spec) {
    custom = configured.find((entry) => entry?.name === spec.preset.endpoint);
  } else if (v2Defaults.length === 1) {
    custom = v2Defaults[0];
  }
  const selected = Array.isArray(custom?.models?.default) ? custom.models.default[0] : undefined;
  const validModel =
    typeof selected === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_.:/@+-]{0,255}$/.test(selected);
  const apiKey = custom?.apiKey;
  const baseURL = custom?.baseURL;
  if (
    !custom ||
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
  return { endpoint: custom.name, model: selected, spec: spec?.name };
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
    'reasoning_effort',
    'reasoningEffort',
    'thinking',
    'thinkingBudget',
    'thinkingLevel',
    'reasoning',
    'effort',
  ])
    delete body[field];

  // A second conversation can independently resolve a different saved agent
  // and provider. Non-admins cannot create such a graph until every model in
  // that graph can be authorized against the same effective policy.
  if (body.addedConvo != null) {
    return res.status(403).json({
      error: 'Company model required',
      message: 'Multiple-model conversations are not available for this account.',
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

  // A persisted agent must first pass the existing resource VIEW ACL.
  // We defer the model check until AFTER the access-control middleware, so
  // unauthorized callers cannot use the model guard to inspect agent data.
  if (isExplicitPersistedAgent(body)) {
    if (req.params?.endpoint && req.params.endpoint !== body.endpoint) {
      return res.status(400).json({
        error: 'Invalid agent request',
        message: 'Agent endpoint route does not match the selected agent endpoint.',
      });
    }
    req.managedSavedAgentCandidate = { id: body.agent_id };
    return next();
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
  if (funded.spec) body.spec = funded.spec;
  else delete body.spec;
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
 * The normal saved-agent VIEW ACL runs BEFORE this middleware.
 * Check the persisted model rather than trusting the browser's model.
 * A matching, single-agent record is accepted; subagent/multi-agent graphs
 * remain blocked until each nested model is independently authorized.
 *
 * An accepted agent is read a second time by buildOptions, which verifies
 * the same persisted provider/model and strips all stored effort overrides
 * from the request-scoped copy, without modifying the saved database record.
 */
function createAuthorizeManagedSavedAgent({ getAgent }) {
  if (typeof getAgent !== 'function') throw new TypeError('getAgent required');
  return async (req, res, next) => {
    if (req.user?.role === SystemRoles.ADMIN || !req.managedSavedAgentCandidate) {
      return next();
    }
    const funded = resolveFundedDefault(req.config);
    if (!funded) {
      return res.status(503).json({
        error: 'Managed model unavailable',
        message: 'The company-provided model is temporarily unavailable.',
      });
    }
    if (!req.user?.id || req.body?.agent_id !== req.managedSavedAgentCandidate.id) {
      return res.status(403).json({ error: 'Company model required' });
    }
    let agent;
    try {
      agent = await getAgent({ id: req.managedSavedAgentCandidate.id });
    } catch (err) {
      logger.error('[managed-agent] Unable to resolve saved agent after ACL', err);
      return res.status(503).json({ error: 'Saved agent temporarily unavailable' });
    }
    if (!matchesManagedAgentPolicy(agent, funded)) {
      return res.status(403).json({
        error: 'Company model required',
        message: 'This saved agent uses a model or agent graph outside company policy.',
      });
    }
    req.managedSavedAgentAuth = {
      id: agent.id,
      endpoint: funded.endpoint,
      model: funded.model,
    };
    for (const key of [
      'apiKey',
      'baseURL',
      'key',
      'provider',
      'model_parameters',
      'modelOptions',
      'modelLabel',
      'chatGptLabel',
      'effort',
      'thinking',
      'thinkingBudget',
      'thinkingLevel',
      'reasoning_effort',
    ])
      delete req.body[key];
    req.body.model = funded.model;
    return next();
  };
}

function matchesManagedAgentPolicy(agent, funded) {
  if (!agent || !funded || typeof agent.id !== 'string') return false;
  if (agent.provider !== funded.endpoint || agent.model !== funded.model) return false;
  const params = agent.model_parameters;
  if (params != null && (typeof params !== 'object' || Array.isArray(params))) return false;
  if (params?.model != null && params.model !== funded.model) return false;
  // Saved multi-agent graphs can route subsequent turns through other models.
  if (agent.agent_ids != null && (!Array.isArray(agent.agent_ids) || agent.agent_ids.length))
    return false;
  if (agent.edges != null && (!Array.isArray(agent.edges) || agent.edges.length)) return false;
  if (agent.subagents?.enabled === true || agent.subagents?.agent_ids?.length) return false;
  return true;
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

/**
 * API-key remote-agent endpoints have independent authentication and do not
 * traverse the interactive chat normalizer. Their agent VIEW/USE permission
 * alone does not prove a non-admin agent's stored model is the funded default.
 * Until remote-agent model authorization is implemented, deny non-admin use
 * after authentication and effective role/config resolution.
 */
function rejectNonAdminRemoteAgentApi(req, res, next) {
  if (req.user?.role !== SystemRoles.ADMIN) {
    return res.status(403).json({
      error: 'Company model required',
      message: 'Remote agent API access requires administrator model authorization.',
    });
  }
  return next();
}

module.exports = {
  rejectNonAdminRemoteAgentApi,
  enforceManagedChatEndpoint,
  rejectManagedAssistantEndpoint,
  resolveFundedDefault,
  createAuthorizeManagedSavedAgent,
  matchesManagedAgentPolicy,
};
