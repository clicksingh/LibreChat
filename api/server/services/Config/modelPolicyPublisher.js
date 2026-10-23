const crypto = require('crypto');
const { buildModelPolicyProjection } = require('./modelPolicyProjection');

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

function digestProjection(projection) {
  const canonical = {
    endpointName: projection.endpointName,
    companyDefault: projection.companyDefault,
    adminModels: projection.adminModels,
    roles: projection.roles,
  };
  return crypto.createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
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

async function publishModelPolicyProjection(input, deps) {
  const {
    findConfigByPrincipal,
    patchConfigFields,
    claimModelPolicyPublication,
    invalidateConfigCaches,
    startSession,
  } = deps || {};
  if (
    typeof findConfigByPrincipal !== 'function' ||
    typeof patchConfigFields !== 'function' ||
    typeof claimModelPolicyPublication !== 'function' ||
    typeof invalidateConfigCaches !== 'function' ||
    typeof startSession !== 'function'
  ) {
    throw new TypeError('model-policy publisher dependencies are required');
  }

  const projection = buildModelPolicyProjection(input);
  const digest = digestProjection(projection);
  const session = await startSession();
  let result;

  try {
    await session.withTransaction(async () => {
      const claimed = await claimModelPolicyPublication(
        { policyVersion: projection.policyVersion, digest },
        session,
      );
      if (claimed.transition === 'noop') {
        result = {
          policyVersion: projection.policyVersion,
          digest,
          transition: 'noop',
          writes: [],
          noop: true,
        };
        return;
      }
      const writes = await applyProjectionInSession(projection, deps, session);
      result = {
        policyVersion: projection.policyVersion,
        digest,
        transition: claimed.transition,
        writes,
        noop: false,
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
  digestProjection,
  mergeEndpointList,
  applyProjectionInSession,
  publishModelPolicyProjection,
};
