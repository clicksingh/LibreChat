const { commitManagedModelPolicy } = require('./modelPolicyPublisher');

const AUDIENCES = {
  USER: 'locked-current-default',
  ADMIN: 'managed-catalog',
};

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function makeInput({
  expectedVersion = 0,
  defaultDeploymentId = 'deployment-b',
  refreshConfigCaches = false,
  deployments = [
    {
      deploymentId: 'deployment-b',
      model: 'model-b',
      reasoning: {
        transport: 'chat.completions.reasoning_effort',
        options: ['low', 'high', 'max'],
        default: 'high',
      },
    },
    { deploymentId: 'deployment-a', model: 'model-a' },
  ],
} = {}) {
  return {
    expectedVersion,
    endpointName: 'CBHR AI',
    actor: 'admin@example.invalid',
    source: 'cbhr-admin',
    refreshConfigCaches,
    policy: {
      companyDefaultDeploymentId: defaultDeploymentId,
      deployments,
      audiences: AUDIENCES,
    },
  };
}

const validBaseConfig = {
  priority: 10,
  isActive: true,
  overrides: {
    endpoints: {
      custom: [
        {
          name: 'CBHR AI',
          default: true,
          apiKey: 'company-service-key',
          baseURL: 'http://litellm:4000/v1',
          models: { default: ['previous-model'] },
        },
      ],
    },
  },
};

const validBaseAppConfig = {
  endpoints: {
    custom: [
      {
        name: 'CBHR AI',
        apiKey: 'company-service-key',
        baseURL: 'http://litellm:4000/v1',
        models: { default: ['previous-model'] },
      },
    ],
  },
};

function fakeDeps(seed = {}) {
  let docs = clone({ __base__: validBaseConfig, ...seed });
  let headVersion = 0;
  let revision = null;
  const writes = [];
  let invalidations = 0;

  function makeSession() {
    let snapshotDocs;
    let snapshotHeadVersion;
    let snapshotRevision;
    return {
      async withTransaction(fn) {
        snapshotDocs = clone(docs);
        snapshotHeadVersion = headVersion;
        snapshotRevision = revision ? clone(revision) : null;
        try {
          await fn();
        } catch (error) {
          docs = snapshotDocs;
          headVersion = snapshotHeadVersion;
          revision = snapshotRevision;
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
    get headVersion() {
      return headVersion;
    },
    get revision() {
      return revision;
    },
    writes,
    invalidations: () => invalidations,
    startSession: async () => makeSession(),
    tenantId: 'test-tenant',
    baseAppConfig: clone(validBaseAppConfig),
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
    commitModelPolicyRevision: async (candidate, options, session) => {
      if (!session) throw Error('session required');
      if (options.expectedVersion !== headVersion) {
        const error = Error('Managed-model policy changed; reload and retry');
        error.code = 'MODEL_POLICY_REVISION_CONFLICT';
        error.status = 409;
        throw error;
      }

      if (
        revision &&
        revision.companyDefaultDeploymentId === candidate.companyDefaultDeploymentId &&
        JSON.stringify(revision.activeDeploymentIds) ===
          JSON.stringify(candidate.activeDeploymentIds) &&
        revision.audiences.USER === candidate.audiences.USER &&
        revision.audiences.ADMIN === candidate.audiences.ADMIN
      ) {
        return { version: headVersion, revision, noop: true };
      }

      headVersion += 1;
      revision = {
        ...clone(candidate),
        version: headVersion,
        parentVersion: options.expectedVersion,
        publishedBy: options.actor,
        source: options.source,
      };
      return { version: headVersion, revision, noop: false };
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

describe('transactional model policy publisher', () => {
  test('does not open a session when the authenticated instance has no explicit tenant', async () => {
    const deps = fakeDeps({});
    delete deps.tenantId;
    await expect(commitManagedModelPolicy(makeInput(), deps)).rejects.toMatchObject({
      code: 'MODEL_POLICY_TENANT_REQUIRED',
      status: 503,
    });
    expect(deps.headVersion).toBe(0);
  });

  test('scopes every Config read and write to the fixed instance tenant', async () => {
    const deps = fakeDeps({});
    const reads = [];
    const writes = [];
    const originalFind = deps.findConfigByPrincipal;
    const originalPatch = deps.patchConfigFields;
    deps.findConfigByPrincipal = async (...args) => {
      reads.push(args[2]?.tenantId);
      return originalFind(...args);
    };
    deps.patchConfigFields = async (...args) => {
      writes.push(args[6]);
      return originalPatch(...args);
    };
    await commitManagedModelPolicy(makeInput(), deps);
    expect(reads).toEqual(['test-tenant', 'test-tenant', 'test-tenant']);
    expect(writes).toEqual(['test-tenant', 'test-tenant', 'test-tenant']);
  });

  test('rolls back the canonical policy if an owned projection is inactive', async () => {
    const deps = fakeDeps({
      USER: { isActive: false, priority: 20, overrides: {} },
    });
    await expect(commitManagedModelPolicy(makeInput(), deps)).rejects.toMatchObject({
      code: 'MODEL_POLICY_INACTIVE_PROJECTION',
      status: 409,
    });
    expect(deps.headVersion).toBe(0);
    expect(deps.invalidations()).toBe(0);
  });

  test('inherits company API credentials from validated YAML when role Config stores none', async () => {
    const base = clone(validBaseConfig);
    delete base.overrides.endpoints.custom[0].apiKey;
    const deps = fakeDeps({ __base__: base });
    const result = await commitManagedModelPolicy(makeInput(), deps);
    expect(result.transition).toBe('create');
    expect(result.policyVersion).toBe(1);
    expect(deps.docs.__base__.overrides.endpoints.custom[0].apiKey).toBeUndefined();
    expect(deps.docs.__base__.overrides.endpoints.custom[0].models.default).toEqual(['model-b']);
  });

  test('creates a scoped role projection without copying YAML credentials into Mongo', async () => {
    const deps = fakeDeps({ __base__: null });
    const result = await commitManagedModelPolicy(makeInput(), deps);
    expect(result.policyVersion).toBe(1);
    expect(deps.docs.__base__.overrides.endpoints.custom[0].apiKey).toBeUndefined();
  });

  test('rejects a USER tombstone deleting the published managed endpoint', async () => {
    const deps = fakeDeps({
      USER: { priority: 20, tombstones: ['endpoints.custom'], overrides: {} },
    });
    await expect(commitManagedModelPolicy(makeInput(), deps)).rejects.toMatchObject({
      code: 'MODEL_POLICY_FUNDED_ENDPOINT_INVALID',
      status: 422,
    });
    expect(deps.headVersion).toBe(0);
    expect(deps.invalidations()).toBe(0);
  });

  test('rejects a base tombstone that would suppress effective managed endpoints', async () => {
    const base = clone(validBaseConfig);
    base.tombstones = ['endpoints.custom'];
    const deps = fakeDeps({ __base__: base });
    await expect(commitManagedModelPolicy(makeInput(), deps)).rejects.toMatchObject({
      code: 'MODEL_POLICY_FUNDED_ENDPOINT_INVALID',
    });
    expect(deps.headVersion).toBe(0);
  });

  test('rejects publication to a new endpoint with no configured company credentials', async () => {
    const deps = fakeDeps();
    const input = makeInput();
    input.endpointName = 'Unconfigured Endpoint';
    await expect(commitManagedModelPolicy(input, deps)).rejects.toMatchObject({
      code: 'MODEL_POLICY_FUNDED_ENDPOINT_INVALID',
      status: 422,
    });
    expect(deps.headVersion).toBe(0);
    expect(deps.invalidations()).toBe(0);
  });

  test('rejects a stale higher-priority USER model override rather than publishing a false default', async () => {
    const deps = fakeDeps({
      USER: {
        priority: 20,
        overrides: {
          endpoints: { custom: [{ name: 'CBHR AI', models: { default: ['stale-model'] } }] },
        },
      },
    });
    await expect(commitManagedModelPolicy(makeInput(), deps)).rejects.toMatchObject({
      code: 'MODEL_POLICY_FUNDED_ENDPOINT_INVALID',
    });
    expect(deps.headVersion).toBe(0);
    expect(deps.writes).toHaveLength(0);
  });

  test('rejects ambiguous centrally marked defaults before advancing the canonical version', async () => {
    const base = clone(validBaseConfig);
    base.overrides.endpoints.custom.push({
      name: 'Second Default',
      default: true,
      apiKey: 'company-service-key',
      baseURL: 'http://litellm:4000/v1',
      models: { default: ['other-model'] },
    });
    const deps = fakeDeps({ __base__: base });
    await expect(commitManagedModelPolicy(makeInput(), deps)).rejects.toMatchObject({
      code: 'MODEL_POLICY_FUNDED_ENDPOINT_INVALID',
    });
    expect(deps.headVersion).toBe(0);
  });

  test('rejects a USER override that redirects company credentials to a different provider', async () => {
    const deps = fakeDeps({
      USER: {
        priority: 20,
        overrides: {
          endpoints: { custom: [{ name: 'CBHR AI', baseURL: 'https://untrusted.invalid/v1' }] },
        },
      },
    });
    await expect(commitManagedModelPolicy(makeInput(), deps)).rejects.toMatchObject({
      code: 'MODEL_POLICY_FUNDED_ENDPOINT_INVALID',
    });
    expect(deps.headVersion).toBe(0);
    expect(deps.invalidations()).toBe(0);
  });

  test('commits canonical deployment policy and preserves unrelated LibreChat config', async () => {
    const deps = fakeDeps({
      __base__: {
        priority: 10,
        overrides: {
          endpoints: {
            custom: [
              { name: 'Other API', baseURL: 'internal-other' },
              {
                name: 'CBHR AI',
                baseURL: 'http://internal-bridge:4000/v1',
                apiKey: 'company-service-key',
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
                customParams: { unrelatedFlag: true, reasoningProfiles: { legacy: {} } },
                models: { default: ['old'] },
              },
            ],
          },
        },
      },
    });

    deps.baseAppConfig.endpoints.custom[0].baseURL = 'http://internal-bridge:4000/v1';
    const result = await commitManagedModelPolicy(makeInput(), deps);

    expect(result).toMatchObject({
      policyVersion: 1,
      transition: 'create',
      policyNoop: false,
      noop: false,
    });
    expect(result.writes).toHaveLength(3);
    expect(deps.headVersion).toBe(1);
    expect(deps.revision.companyDefaultDeploymentId).toBe('deployment-b');
    expect(deps.revision.activeDeploymentIds).toEqual(['deployment-b', 'deployment-a']);
    expect(deps.invalidations()).toBe(1);

    const baseList = deps.docs.__base__.overrides.endpoints.custom;
    expect(baseList.find((item) => item.name === 'Other API').baseURL).toBe('internal-other');
    const baseManaged = baseList.find((item) => item.name === 'CBHR AI');
    expect(baseManaged.baseURL).toBe('http://internal-bridge:4000/v1');
    expect(baseManaged.tokenConfig).toEqual({ old: true });
    expect(baseManaged.models.default).toEqual(['model-b']);
    expect(deps.docs.USER.overrides.interface).toEqual({ modelSelect: false, fileSearch: true });

    const adminManaged = deps.docs.ADMIN.overrides.endpoints.custom[0];
    expect(adminManaged.customParams).toEqual({
      unrelatedFlag: true,
      reasoningProfiles: {
        'model-b': {
          transport: 'chat.completions.reasoning_effort',
          options: ['low', 'high', 'max'],
          default: 'high',
        },
      },
    });
    expect(adminManaged.models.default).toEqual(['model-b', 'model-a']);
    expect(deps.docs.ADMIN.overrides.interface.modelSelect).toBe(true);
  });

  test('same canonical policy at the current expected version is a complete no-op', async () => {
    const deps = fakeDeps({});
    await commitManagedModelPolicy(makeInput(), deps);
    expect(deps.invalidations()).toBe(1);
    deps.writes.length = 0;

    const second = await commitManagedModelPolicy(makeInput({ expectedVersion: 1 }), deps);

    expect(second).toMatchObject({
      policyVersion: 1,
      transition: 'noop',
      policyNoop: true,
      noop: true,
      writes: [],
    });
    expect(deps.headVersion).toBe(1);
    expect(deps.writes).toHaveLength(0);
    expect(deps.invalidations()).toBe(1);
  });

  test('explicit cache refresh invalidates even when canonical policy and projection are unchanged', async () => {
    const deps = fakeDeps({});
    await commitManagedModelPolicy(makeInput(), deps);
    expect(deps.invalidations()).toBe(1);

    const second = await commitManagedModelPolicy(
      makeInput({ expectedVersion: 1, refreshConfigCaches: true }),
      deps,
    );

    expect(second).toMatchObject({
      policyVersion: 1,
      transition: 'noop',
      policyNoop: true,
      noop: true,
      refreshConfigCaches: true,
    });
    expect(second.writes).toEqual([]);
    expect(deps.invalidations()).toBe(2);
  });

  test('failed config projection rolls back canonical revision and earlier role writes together', async () => {
    const deps = fakeDeps({});
    deps.failPatchFor('ADMIN');

    await expect(commitManagedModelPolicy(makeInput(), deps)).rejects.toThrow(
      'synthetic config write failure',
    );

    expect(deps.headVersion).toBe(0);
    expect(deps.revision).toBeNull();
    expect(deps.docs).toEqual({ __base__: validBaseConfig });
    expect(deps.invalidations()).toBe(0);
  });

  test('next exact revision advances while stale or gapped expected versions are rejected', async () => {
    const deps = fakeDeps({});
    await commitManagedModelPolicy(makeInput(), deps);

    const next = makeInput({
      expectedVersion: 1,
      defaultDeploymentId: 'deployment-a',
      deployments: [
        { deploymentId: 'deployment-a', model: 'model-a' },
        { deploymentId: 'deployment-b', model: 'model-b' },
      ],
    });
    const advanced = await commitManagedModelPolicy(next, deps);

    expect(advanced.transition).toBe('advance');
    expect(advanced.policyVersion).toBe(2);
    expect(deps.headVersion).toBe(2);
    expect(deps.revision.companyDefaultDeploymentId).toBe('deployment-a');
    expect(deps.docs.__base__.overrides.endpoints.custom[0].models.default).toEqual(['model-a']);

    await expect(
      commitManagedModelPolicy(makeInput({ expectedVersion: 1 }), deps),
    ).rejects.toMatchObject({ code: 'MODEL_POLICY_REVISION_CONFLICT' });
    await expect(
      commitManagedModelPolicy(makeInput({ expectedVersion: 4 }), deps),
    ).rejects.toMatchObject({ code: 'MODEL_POLICY_REVISION_CONFLICT' });
  });

  test('invalid commit payload fails before a Mongo session is opened', async () => {
    const deps = fakeDeps({});
    let sessions = 0;
    deps.startSession = async () => {
      sessions += 1;
      throw Error('must not start');
    };

    const invalid = makeInput({ defaultDeploymentId: 'missing' });
    await expect(commitManagedModelPolicy(invalid, deps)).rejects.toMatchObject({
      code: 'MODEL_POLICY_PROJECTION_INVALID',
    });
    expect(sessions).toBe(0);
    expect(deps.invalidations()).toBe(0);
  });
});
