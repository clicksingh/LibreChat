const { applyModelPolicyProjection } = require('./modelPolicyPublisher');

function fakeDeps(seed) {
  const docs = JSON.parse(JSON.stringify(seed));
  const writes = [];
  let invalidations = 0;
  return {
    docs,
    writes,
    invalidations: () => invalidations,
    findConfigByPrincipal: async (_type, id) => docs[id] || null,
    patchConfigFields: async (_type, id, _model, fields, priority) => {
      const doc = docs[id] || { principalType: 'role', principalId: id, overrides: {}, priority };
      doc.overrides ||= {};
      for (const [path, value] of Object.entries(fields)) {
        if (path === 'interface.modelSelect') {
          doc.overrides.interface ||= {};
          doc.overrides.interface.modelSelect = value;
        } else if (path === 'endpoints.custom') {
          doc.overrides.endpoints ||= {};
          doc.overrides.endpoints.custom = value;
        }
      }
      docs[id] = doc;
      writes.push({ id, fields, priority });
      return doc;
    },
    invalidateConfigCaches: async () => {
      invalidations += 1;
    },
  };
}

const input = {
  policyVersion: 7,
  endpointName: 'CBHR AI',
  companyDefault: 'model-b',
  adminModels: ['model-b', 'model-a'],
};

describe('model policy publisher', () => {
  test('preserves unrelated config while updating only managed role projection', async () => {
    const deps = fakeDeps({
      __base__: {
        priority: 10,
        overrides: {
          endpoints: {
            custom: [
              { name: 'Other API', baseURL: 'internal-other' },
              {
                name: 'CBHR AI',
                baseURL: 'internal-bridge',
                tokenConfig: { old: true },
                models: { default: ['old'] },
              },
            ],
          },
        },
      },
      USER: { priority: 20, overrides: { interface: { modelSelect: true, fileSearch: true } } },
      ADMIN: {
        priority: 20,
        overrides: {
          endpoints: {
            custom: [
              {
                name: 'CBHR AI',
                customParams: { reasoningProfiles: { legacy: {} } },
                models: { default: ['old'] },
              },
            ],
          },
        },
      },
    });
    const result = await applyModelPolicyProjection(input, deps);
    expect(result.noop).toBe(false);
    expect(result.writes).toHaveLength(3);
    expect(deps.invalidations()).toBe(1);
    const baseList = deps.docs.__base__.overrides.endpoints.custom;
    expect(baseList.find((x) => x.name === 'Other API').baseURL).toBe('internal-other');
    const baseManaged = baseList.find((x) => x.name === 'CBHR AI');
    expect(baseManaged.baseURL).toBe('internal-bridge');
    expect(baseManaged.tokenConfig).toEqual({ old: true });
    expect(baseManaged.models.default).toEqual(['model-b']);
    expect(deps.docs.USER.overrides.interface).toEqual({ modelSelect: false, fileSearch: true });
    const adminManaged = deps.docs.ADMIN.overrides.endpoints.custom[0];
    expect(adminManaged.customParams).toEqual({ reasoningProfiles: { legacy: {} } });
    expect(adminManaged.models.default).toEqual(['model-b', 'model-a']);
    expect(deps.docs.ADMIN.overrides.interface.modelSelect).toBe(true);
  });

  test('reapplying the same projection is a no-op and does not invalidate caches again', async () => {
    const deps = fakeDeps({});
    await applyModelPolicyProjection(input, deps);
    expect(deps.invalidations()).toBe(1);
    deps.writes.length = 0;
    const second = await applyModelPolicyProjection(input, deps);
    expect(second).toEqual({ policyVersion: 7, writes: [], noop: true });
    expect(deps.writes).toHaveLength(0);
    expect(deps.invalidations()).toBe(1);
  });

  test('invalid projection fails before any persistence or cache invalidation', async () => {
    const deps = fakeDeps({});
    await expect(
      applyModelPolicyProjection({ ...input, companyDefault: 'not-in-catalogue' }, deps),
    ).rejects.toMatchObject({ code: 'MODEL_POLICY_PROJECTION_INVALID' });
    expect(deps.writes).toHaveLength(0);
    expect(deps.invalidations()).toBe(0);
  });
});
