const {
  AUDIENCES,
  buildModelPolicyProjection,
  buildModelPolicyCommitPlan,
} = require('./modelPolicyProjection');

describe('managed-model config projection', () => {
  test('projects vendor-neutral USER and ADMIN policy without modelSpec authority', () => {
    const out = buildModelPolicyProjection({
      policyVersion: 42,
      endpointName: 'CBHR AI',
      companyDefault: 'provider-x/model:fast',
      adminModels: ['provider-x/model:fast', 'unrelated-vendor/deep_model'],
    });
    expect(out.roles.__base__.endpoints.custom[0].models.default).toEqual([
      'provider-x/model:fast',
    ]);
    expect(out.roles.USER.interface.modelSelect).toBe(false);
    expect(out.roles.ADMIN.interface.modelSelect).toBe(true);
    expect(out.roles.ADMIN.endpoints.custom[0].models.default).toEqual([
      'provider-x/model:fast',
      'unrelated-vendor/deep_model',
    ]);
    expect(out.roles.__base__).not.toHaveProperty('modelSpecs');
  });

  test('commit plan binds deployment IDs and model IDs into one canonical/projection input', () => {
    const out = buildModelPolicyCommitPlan({
      expectedVersion: 7,
      endpointName: 'CBHR AI',
      actor: 'admin@example.invalid',
      source: 'cbhr-admin',
      refreshConfigCaches: true,
      policy: {
        companyDefaultDeploymentId: 'deployment-b',
        deployments: [
          {
            deploymentId: 'deployment-b',
            model: 'provider-x/model:fast',
            reasoning: {
              transport: 'chat.completions.reasoning_effort',
              options: ['low', 'high', 'max'],
              default: 'high',
            },
          },
          { deploymentId: 'deployment-a', model: 'unrelated-vendor/deep_model' },
        ],
        audiences: AUDIENCES,
      },
    });

    expect(out.expectedVersion).toBe(7);
    expect(out.refreshConfigCaches).toBe(true);
    expect(out.candidate).toEqual({
      schemaVersion: 1,
      companyDefaultDeploymentId: 'deployment-b',
      activeDeploymentIds: ['deployment-b', 'deployment-a'],
      routing: {
        endpointName: 'CBHR AI',
        deployments: [
          {
            deploymentId: 'deployment-b',
            model: 'provider-x/model:fast',
            reasoning: {
              transport: 'chat.completions.reasoning_effort',
              options: ['low', 'high', 'max'],
              default: 'high',
            },
          },
          { deploymentId: 'deployment-a', model: 'unrelated-vendor/deep_model', reasoning: null },
        ],
      },
      audiences: AUDIENCES,
    });
    expect(out.projection.companyDefault).toBe('provider-x/model:fast');
    expect(out.projection.adminModels).toEqual([
      'provider-x/model:fast',
      'unrelated-vendor/deep_model',
    ]);
    expect(out.projection.roles.ADMIN.endpoints.custom[0].customParams.reasoningProfiles).toEqual({
      'provider-x/model:fast': {
        transport: 'chat.completions.reasoning_effort',
        options: ['low', 'high', 'max'],
        default: 'high',
      },
    });
  });

  test('rejects malformed reasoning capability metadata', () => {
    const base = {
      expectedVersion: 0,
      endpointName: 'CBHR AI',
      actor: 'admin@example.invalid',
      policy: {
        companyDefaultDeploymentId: 'd1',
        deployments: [
          {
            deploymentId: 'd1',
            model: 'model-a',
            reasoning: {
              transport: 'chat.completions.reasoning_effort',
              options: ['low', 'high'],
              default: 'max',
            },
          },
        ],
        audiences: AUDIENCES,
      },
    };
    expect(() => buildModelPolicyCommitPlan(base)).toThrow(/Reasoning default/);
    expect(() =>
      buildModelPolicyCommitPlan({
        ...base,
        policy: {
          ...base.policy,
          deployments: [
            {
              deploymentId: 'd1',
              model: 'model-a',
              reasoning: { transport: 'vendor.magic', options: ['high'], default: 'high' },
            },
          ],
        },
      }),
    ).toThrow(/Unsupported reasoning transport/);
  });

  test('rejects duplicate deployment IDs or model IDs instead of silently collapsing them', () => {
    const base = {
      expectedVersion: 0,
      endpointName: 'CBHR AI',
      actor: 'admin@example.invalid',
      policy: {
        companyDefaultDeploymentId: 'd1',
        deployments: [
          { deploymentId: 'd1', model: 'model-a' },
          { deploymentId: 'd2', model: 'model-b' },
        ],
        audiences: AUDIENCES,
      },
    };
    expect(() =>
      buildModelPolicyCommitPlan({
        ...base,
        policy: {
          ...base.policy,
          deployments: [
            { deploymentId: 'd1', model: 'model-a' },
            { deploymentId: 'd1', model: 'model-b' },
          ],
        },
      }),
    ).toThrow(/Deployment ids must be unique/);
    expect(() =>
      buildModelPolicyCommitPlan({
        ...base,
        policy: {
          ...base.policy,
          deployments: [
            { deploymentId: 'd1', model: 'model-a' },
            { deploymentId: 'd2', model: 'model-a' },
          ],
        },
      }),
    ).toThrow(/Managed model ids must be unique/);
  });

  test('fails closed for invalid revision/default/catalogue/audience and endpoint identifiers', () => {
    expect(() =>
      buildModelPolicyProjection({
        policyVersion: 0,
        endpointName: 'CBHR AI',
        companyDefault: 'model-a',
        adminModels: ['model-a'],
      }),
    ).toThrow(/policyVersion/);
    expect(() =>
      buildModelPolicyProjection({
        policyVersion: 1,
        endpointName: 'CBHR AI',
        companyDefault: 'missing',
        adminModels: ['model-a'],
      }),
    ).toThrow(/Company default/);
    expect(() =>
      buildModelPolicyCommitPlan({
        expectedVersion: 0,
        endpointName: 'bad/name',
        actor: 'admin@example.invalid',
        policy: {
          companyDefaultDeploymentId: 'd1',
          deployments: [{ deploymentId: 'd1', model: 'model-a' }],
          audiences: AUDIENCES,
        },
      }),
    ).toThrow(/endpoint/);
    expect(() =>
      buildModelPolicyCommitPlan({
        expectedVersion: 0,
        endpointName: 'CBHR AI',
        actor: 'admin@example.invalid',
        policy: {
          companyDefaultDeploymentId: 'missing',
          deployments: [{ deploymentId: 'd1', model: 'model-a' }],
          audiences: AUDIENCES,
        },
      }),
    ).toThrow(/default deployment must be active/);
  });
});
