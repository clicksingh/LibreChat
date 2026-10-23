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

async function applyModelPolicyProjection(input, deps) {
  const { findConfigByPrincipal, patchConfigFields, invalidateConfigCaches } = deps || {};
  if (
    typeof findConfigByPrincipal !== 'function' ||
    typeof patchConfigFields !== 'function' ||
    typeof invalidateConfigCaches !== 'function'
  ) {
    throw new TypeError('model-policy publisher dependencies are required');
  }
  const projection = buildModelPolicyProjection(input);
  const ids = ['__base__', 'USER', 'ADMIN'];
  const existing = Object.fromEntries(
    await Promise.all(
      ids.map(async (id) => [id, await findConfigByPrincipal(ROLE, id, { includeInactive: true })]),
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
      if (!same(current?.overrides?.endpoints?.custom || [], next))
        fields['endpoints.custom'] = next;
    }
    if (Object.keys(fields).length === 0) continue;
    await patchConfigFields(
      ROLE,
      id,
      ROLE_MODEL,
      fields,
      current?.priority ?? DEFAULT_PRIORITY[id],
    );
    writes.push({ principalId: id, fields: Object.keys(fields) });
  }

  if (writes.length > 0) await invalidateConfigCaches();
  return { policyVersion: projection.policyVersion, writes, noop: writes.length === 0 };
}

module.exports = { applyModelPolicyProjection, mergeEndpointList };
