const {
  digestProjection,
  publishModelPolicyProjection,
} = require('./modelPolicyPublisher');

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function fakeDeps(seed) {
  let docs = clone(seed);
  let publication = null;
  const writes = [];
  let invalidations = 0;

  function makeSession() {
    let snapshotDocs;
    let snapshotPublication;
    return {
      async withTransaction(fn) {
        snapshotDocs = clone(docs);
        snapshotPublication = publication ? { ...publication } : null;
        try {
          await fn();
        } catch (error) {
          docs = snapshotDocs;
          publication = snapshotPublication;
          throw error;
        }
      },
      async endSession() {},
    };
  }

  return {
    get docs() {
      return docs;
    },
    get publication() {
      return publication;
    },
    writes,
    invalidations: () => invalidations,
    startSession: async () => makeSession(),
    findConfigByPrincipal: async (_type, id) => docs[id] || null,
    patchConfigFields: async (_type, id, _model, fields, priority, session) => {
      if (!session) throw Error('session required');
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
    claimModelPolicyPublication: async ({ policyVersion, digest }, session) => {
      if (!session) throw Error('session required');
      if (!publication) {
        if (policyVersion !== 1) {
          const error = Error('First publication must be revision 1');
          error.code = 'MODEL_POLICY_PUBLICATION_CONFLICT';
          throw error;
        }
        publication = { key: 'managed-models', policyVersion, digest };
        return { publication, transition: 'create' };
      }
      if (policyVersion === publication.policyVersion) {
        if (digest !== publication.digest) {
          const error = Error('Revision replayed with different content');
          error.code = 'MODEL_POLICY_PUBLICATION_CONFLICT';
          throw error;
        }
        return { publication, transition: 'noop' };
      }
      if (policyVersion !== publication.policyVersion + 1) {
        const error = Error('Revision gap');
        error.code = 'MODEL_POLICY_PUBLICATION_CONFLICT';
        throw error;
      }
      publication = { ...publication, policyVersion, digest };
      return { publication, transition: 'advance' };
    },
    invalidateConfigCaches: async () => {
      invalidations += 1;
    },
    failPatchFor(id) {
      const original = this.patchConfigFields;
      this.patchConfigFields = async (...args) => {
        if (args[1] === id) throw Error('synthetic config write failure');
        return original(...args);
      };
    },
  };
}

const firstInput = {
  policyVersion: 1,
  endpointName: 'CBHR AI',
  companyDefault: 'model-b',
  adminModels: ['model-b', 'model-a'],
};

describe('transactional model policy publisher', () => {
  test('digest is deterministic and excludes policy version', () => {
    const a = digestProjection({
      ...firstInput,
      roles: { a: 1 },
    });
    const b = digestProjection({
      ...firstInput,
      policyVersion: 99,
      roles: { a: 1 },
    });
    expect(a).toBe(b);
    expect(a).toMatch(/^[a-f0-9]{64}$/);
  });

  test('preserves unrelated config and writes all managed role projection in one transaction', async () => {
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

    const result = await publishModelPolicyProjection(firstInput, deps);
    expect(result.transition).toBe('create');
    expect(result.noop).toBe(false);
    expect(result.writes).toHaveLength(3);
    expect(deps.publication.policyVersion).toBe(1);
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

  test('same revision and digest is an idempotent no-op without cache invalidation', async () => {
    const deps = fakeDeps({});
    await publishModelPolicyProjection(firstInput, deps);
    expect(deps.invalidations()).toBe(1);
    deps.writes.length = 0;

    const second = await publishModelPolicyProjection(firstInput, deps);
    expect(second.transition).toBe('noop');
    expect(second.noop).toBe(true);
    expect(second.writes).toEqual([]);
    expect(deps.writes).toHaveLength(0);
    expect(deps.invalidations()).toBe(1);
  });

  test('failed config write rolls back publication revision and earlier config writes', async () => {
    const deps = fakeDeps({});
    deps.failPatchFor('ADMIN');

    await expect(publishModelPolicyProjection(firstInput, deps)).rejects.toThrow(
      'synthetic config write failure',
    );

    expect(deps.publication).toBeNull();
    expect(deps.docs).toEqual({});
    expect(deps.invalidations()).toBe(0);
  });

  test('next exact revision advances and stale/gapped replay is rejected', async () => {
    const deps = fakeDeps({});
    await publishModelPolicyProjection(firstInput, deps);

    const next = {
      ...firstInput,
      policyVersion: 2,
      companyDefault: 'model-a',
      adminModels: ['model-a', 'model-b'],
    };
    const advanced = await publishModelPolicyProjection(next, deps);
    expect(advanced.transition).toBe('advance');
    expect(deps.publication.policyVersion).toBe(2);
    expect(deps.docs.__base__.overrides.endpoints.custom[0].models.default).toEqual(['model-a']);

    await expect(
      publishModelPolicyProjection({ ...firstInput, policyVersion: 1 }, deps),
    ).rejects.toMatchObject({ code: 'MODEL_POLICY_PUBLICATION_CONFLICT' });
    await expect(
      publishModelPolicyProjection({ ...next, policyVersion: 4 }, deps),
    ).rejects.toMatchObject({ code: 'MODEL_POLICY_PUBLICATION_CONFLICT' });
  });

  test('invalid projection fails before opening persistence transaction', async () => {
    const deps = fakeDeps({});
    let sessions = 0;
    deps.startSession = async () => {
      sessions += 1;
      throw Error('must not start');
    };

    await expect(
      publishModelPolicyProjection({ ...firstInput, companyDefault: 'not-in-catalogue' }, deps),
    ).rejects.toMatchObject({ code: 'MODEL_POLICY_PROJECTION_INVALID' });
    expect(sessions).toBe(0);
    expect(deps.invalidations()).toBe(0);
  });
});
