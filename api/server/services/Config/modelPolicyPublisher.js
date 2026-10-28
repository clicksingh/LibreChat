const { buildModelPolicyCommitPlan } = require('./modelPolicyProjection');

const ROLE = 'role';
const ROLE_MODEL = 'Role';
const DEFAULT_PRIORITY = { __base__: 10, USER: 20, ADMIN: 20 };

function clone(value) {
  return value == null ? value : JSON.parse(JSON.stringify(value));
}

function same(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function mergeEndpointList(current, endpointPatch) {
  const list = Array.isArray(current) ? clone(current) : [];
  const index = list.findIndex((item) => item && item.name === endpointPatch.name);
  if (index < 0) return [...list, clone(endpointPatch)];
  const existing = list[index] || {};
  list[index] = {
    ...existing,
    ...clone(endpointPatch),
    models: endpointPatch.models
      ? { ...(existing.models || {}), ...clone(endpointPatch.models) }
      : existing.models,
    customParams: endpointPatch.customParams
      ? { ...(existing.customParams || {}), ...clone(endpointPatch.customParams) }
      : existing.customParams,
  };
  return list;
}

function invalidFundedEndpoint(message) {
  const error = new Error(message);
  error.code = 'MODEL_POLICY_FUNDED_ENDPOINT_INVALID';
  error.status = 422;
  throw error;
}

function validateFundedEndpoint(existing, projection, baseAppConfig) {
  const managedPatch = projection.roles.__base__.endpoints.custom[0];
  // Credentials are owned by the validated server/YAML base configuration.
  // The Config projection need not (and must not) duplicate the API key.
  const configured = baseAppConfig?.endpoints?.custom;
  const trusted = Array.isArray(configured)
    ? configured.filter((ep) => ep?.name === managedPatch.name)
    : [];
  if (trusted.length !== 1) {
    invalidFundedEndpoint('Managed endpoint must exist in validated server configuration');
  }

  const baseEntries = existing.__base__?.overrides?.endpoints?.custom;
  const userEntries = existing.USER?.overrides?.endpoints?.custom;
  for (const entries of [baseEntries, userEntries]) {
    if (
      entries != null &&
      (!Array.isArray(entries) ||
        entries.some((ep) => !ep || typeof ep !== 'object' || typeof ep.name !== 'string'))
    ) {
      invalidFundedEndpoint('Invalid role endpoint overrides');
    }
  }

  // Use the same keyed merge precedence as the actual Config resolver:
  // validated YAML -> __base__ role -> V2 base patch -> USER role.
  const mergedBase = (baseEntries || []).reduce(
    (entries, override) => mergeEndpointList(entries, override),
    configured,
  );
  const projectedBase = mergeEndpointList(mergedBase, managedPatch);
  const effective = (userEntries || []).reduce(
    (entries, override) => mergeEndpointList(entries, override),
    projectedBase,
  );
  const defaults = effective.filter((ep) => ep?.default === true);
  if (defaults.length !== 1 || defaults[0].name !== managedPatch.name) {
    invalidFundedEndpoint('Managed USER default endpoint is ambiguous or overridden');
  }

  const selected = defaults[0];
  const requiredModel = managedPatch.models.default[0];
  if (
    !Array.isArray(selected.models?.default) ||
    selected.models.default.length !== 1 ||
    selected.models.default[0] !== requiredModel
  ) {
    invalidFundedEndpoint('USER override conflicts with published managed model');
  }

  const configuredEndpoint = trusted[0];
  if (
    typeof configuredEndpoint.apiKey !== 'string' ||
    !configuredEndpoint.apiKey.trim() ||
    configuredEndpoint.apiKey === 'user_provided' ||
    typeof configuredEndpoint.baseURL !== 'string' ||
    !configuredEndpoint.baseURL.trim() ||
    configuredEndpoint.baseURL === 'user_provided' ||
    selected.apiKey !== configuredEndpoint.apiKey ||
    selected.baseURL !== configuredEndpoint.baseURL
  ) {
    invalidFundedEndpoint('Managed endpoint requires unchanged server-owned credentials');
  }
  try {
    const url = new URL(configuredEndpoint.baseURL);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
      invalidFundedEndpoint('Managed endpoint URL is invalid');
    }
  } catch (error) {
    if (error?.code === 'MODEL_POLICY_FUNDED_ENDPOINT_INVALID') throw error;
    invalidFundedEndpoint('Managed endpoint URL is invalid');
  }
}

async function applyProjectionInSession(projection, deps, session) {
  const { findConfigByPrincipal, patchConfigFields, tenantId, baseAppConfig } = deps;
  const ids = ['__base__', 'USER', 'ADMIN'];
  const existing = Object.fromEntries(
    await Promise.all(
      ids.map(async (id) => [
        id,
        await findConfigByPrincipal(ROLE, id, { includeInactive: true, tenantId }, session),
      ]),
    ),
  );
  const writes = [];

  // Validate the *effective* USER endpoint before the transaction can
  // advance the canonical revision, not only the new base projection.
  validateFundedEndpoint(existing, projection, baseAppConfig);

  for (const id of ids) {
    const current = existing[id];
    // Do not advance the canonical policy when an owned effective Config is disabled.
    if (current?.isActive === false) {
      const error = new Error('Managed-model projection is inactive');
      error.code = 'MODEL_POLICY_INACTIVE_PROJECTION';
      error.status = 409;
      throw error;
    }
    const fields = {};
    const rolePatch = projection.roles[id];

    if (
      rolePatch.interface &&
      current?.overrides?.interface?.modelSelect !== rolePatch.interface.modelSelect
    ) {
      fields['interface.modelSelect'] = rolePatch.interface.modelSelect;
    }

    const endpointPatch = rolePatch.endpoints?.custom?.[0];
    if (endpointPatch) {
      const next = mergeEndpointList(current?.overrides?.endpoints?.custom, endpointPatch);
      if (!same(current?.overrides?.endpoints?.custom || [], next)) {
        fields['endpoints.custom'] = next;
      }
    }

    if (Object.keys(fields).length === 0) continue;
    await patchConfigFields(
      ROLE,
      id,
      ROLE_MODEL,
      fields,
      current?.priority ?? DEFAULT_PRIORITY[id],
      session,
      tenantId,
    );
    writes.push({ principalId: id, fields: Object.keys(fields) });
  }

  return writes;
}

async function commitManagedModelPolicy(input, deps) {
  const {
    findConfigByPrincipal,
    patchConfigFields,
    commitModelPolicyRevision,
    invalidateConfigCaches,
    startSession,
    tenantId,
  } = deps || {};

  if (
    typeof findConfigByPrincipal !== 'function' ||
    typeof patchConfigFields !== 'function' ||
    typeof commitModelPolicyRevision !== 'function' ||
    typeof invalidateConfigCaches !== 'function' ||
    typeof startSession !== 'function'
  ) {
    throw new TypeError('model-policy commit dependencies are required');
  }

  // The bearer token is an instance-level service identity. It must be bound
  // to one explicitly configured tenant, never to the caller's request body.
  if (typeof tenantId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(tenantId)) {
    const error = new Error('Model policy tenant is not configured');
    error.code = 'MODEL_POLICY_TENANT_REQUIRED';
    error.status = 503;
    throw error;
  }
  const plan = buildModelPolicyCommitPlan(input);
  const session = await startSession();
  let result;

  try {
    await session.withTransaction(async () => {
      const canonical = await commitModelPolicyRevision(
        plan.candidate,
        {
          expectedVersion: plan.expectedVersion,
          actor: plan.actor,
          source: plan.source,
        },
        session,
      );

      const writes = await applyProjectionInSession(plan.projection, deps, session);
      let transition = 'advance';
      if (canonical.noop) {
        transition = 'noop';
      } else if (plan.expectedVersion === 0) {
        transition = 'create';
      }

      result = {
        policyVersion: canonical.version,
        transition,
        policyNoop: canonical.noop,
        refreshConfigCaches: plan.refreshConfigCaches,
        writes,
        noop: canonical.noop && writes.length === 0,
      };
    });
  } finally {
    await session.endSession();
  }

  if (!result) throw new Error('Model policy transaction completed without a result');
  if (result.writes.length > 0 || result.refreshConfigCaches === true)
    await invalidateConfigCaches(tenantId);
  return result;
}

module.exports = {
  mergeEndpointList,
  applyProjectionInSession,
  commitManagedModelPolicy,
};
