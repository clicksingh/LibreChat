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

function validateFundedEndpoint(existing, projection) {
  const managedPatch = projection.roles.__base__.endpoints.custom[0];
  const baseEntries = existing.__base__?.overrides?.endpoints?.custom;
  if (
    !Array.isArray(baseEntries) ||
    baseEntries.filter((ep) => ep?.name === managedPatch.name).length !== 1
  ) {
    invalidFundedEndpoint('Managed endpoint must already exist in base Config');
  }

  // Mirror the keyed endpoint merge in the config resolver: the USER role
  // is higher priority than __base__, so its persisted overrides also matter.
  const currentManaged = baseEntries.find((ep) => ep?.name === managedPatch.name);
  const projectedBase = mergeEndpointList(baseEntries, managedPatch);
  const userEntries = existing.USER?.overrides?.endpoints?.custom;
  if (
    userEntries != null &&
    (!Array.isArray(userEntries) ||
      userEntries.some((ep) => !ep || typeof ep !== 'object' || typeof ep.name !== 'string'))
  ) {
    invalidFundedEndpoint('Invalid USER endpoint overrides');
  }
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
  // A higher-priority USER override may not silently replace centrally
  // funded provider credentials with a different or personal destination.
  if (selected.apiKey !== currentManaged.apiKey || selected.baseURL !== currentManaged.baseURL) {
    invalidFundedEndpoint('USER override changes company-funded credentials');
  }
  if (
    typeof selected.apiKey !== 'string' ||
    !selected.apiKey.trim() ||
    selected.apiKey === 'user_provided' ||
    typeof selected.baseURL !== 'string' ||
    !selected.baseURL.trim() ||
    selected.baseURL === 'user_provided'
  ) {
    invalidFundedEndpoint('Managed endpoint requires server credentials and base URL');
  }
  try {
    const url = new URL(selected.baseURL);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
      invalidFundedEndpoint('Managed endpoint URL is invalid');
    }
  } catch (error) {
    if (error?.code === 'MODEL_POLICY_FUNDED_ENDPOINT_INVALID') throw error;
    invalidFundedEndpoint('Managed endpoint URL is invalid');
  }
}

async function applyProjectionInSession(projection, deps, session) {
  const { findConfigByPrincipal, patchConfigFields, tenantId } = deps;
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
  validateFundedEndpoint(existing, projection);

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
