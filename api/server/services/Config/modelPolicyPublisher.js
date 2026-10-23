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
  };
  return list;
}

async function applyProjectionInSession(projection, deps, session) {
  const { findConfigByPrincipal, patchConfigFields } = deps;
  const ids = ['__base__', 'USER', 'ADMIN'];
  const existing = Object.fromEntries(
    await Promise.all(
      ids.map(async (id) => [
        id,
        await findConfigByPrincipal(ROLE, id, { includeInactive: true }, session),
      ]),
    ),
  );
  const writes = [];

  for (const id of ids) {
    const current = existing[id];
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
        writes,
        noop: canonical.noop && writes.length === 0,
      };
    });
  } finally {
    await session.endSession();
  }

  if (!result) throw new Error('Model policy transaction completed without a result');
  if (result.writes.length > 0) await invalidateConfigCaches();
  return result;
}

module.exports = {
  mergeEndpointList,
  applyProjectionInSession,
  commitManagedModelPolicy,
};
