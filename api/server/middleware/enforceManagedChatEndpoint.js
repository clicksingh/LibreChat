const { logger } = require('@librechat/data-schemas');
const {
  Constants,
  EModelEndpoint,
  SystemRoles,
  isAgentsEndpoint,
  isEphemeralAgentId,
} = require('librechat-data-provider');

const FUNDED_ENDPOINT = 'CBHR AI';

/**
 * Regular CBHR staff have centrally funded access, not individual BYOK keys.
 * Correct stale browser/conversation endpoint payloads before model setup or
 * generation job creation. Authorization for explicit saved agents remains with
 * canAccessAgentFromBody (VIEW ACL); ADMIN and other roles are not rewritten.
 *
 * Fail closed if the deployment no longer provides a valid centrally funded
 * default. Never trust a caller-provided spec or arbitrary custom endpoint.
 */
function resolveFundedDefault(config) {
  const list = config?.modelSpecs?.list;
  const spec = Array.isArray(list)
    ? list.find((entry) =>
        entry?.default === true &&
        entry?.preset?.endpoint === FUNDED_ENDPOINT &&
        typeof entry?.preset?.model === 'string' &&
        entry.preset.model.length > 0,
      )
    : undefined;

  const configured = config?.endpoints?.custom;
  const custom = Array.isArray(configured)
    ? configured.find((entry) => entry?.name === FUNDED_ENDPOINT)
    : undefined;
  const apiKey = custom?.apiKey;
  const baseURL = custom?.baseURL;
  const configuredModels = custom?.models?.default;
  if (
    !spec ||
    typeof apiKey !== 'string' ||
    !apiKey.trim() ||
    apiKey === 'user_provided' ||
    typeof baseURL !== 'string' ||
    !baseURL.trim() ||
    baseURL === 'user_provided' ||
    !Array.isArray(configuredModels) ||
    !configuredModels.includes(spec.preset.model)
  ) {
    return null;
  }
  return { endpoint: FUNDED_ENDPOINT, model: spec.preset.model, spec: spec.name };
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
  if (req.user?.role !== SystemRoles.USER) {
    return next();
  }

  const body = req.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json({
      error: 'Invalid chat request',
      message: 'Chat request body must be an object.',
    });
  }

  // Non-ephemeral agents are explicitly configured resources. Their VIEW ACL
  // is independently verified downstream; do not rewrite saved agent models.
  if (isExplicitPersistedAgent(body)) {
    if (req.params?.endpoint && req.params.endpoint !== body.endpoint) {
      return res.status(400).json({
        error: 'Invalid agent request',
        message: 'Agent endpoint route does not match the selected agent endpoint.',
      });
    }
    return next();
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
    'apiKey', 'baseURL', 'key', 'provider', 'model_parameters', 'modelOptions',
    'modelLabel', 'chatGptLabel',
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

module.exports = { enforceManagedChatEndpoint, resolveFundedDefault };
