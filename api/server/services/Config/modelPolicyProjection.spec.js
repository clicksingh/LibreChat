const { buildModelPolicyProjection } = require('./modelPolicyProjection');

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

  test('deduplicates ADMIN models while retaining order', () => {
    const out = buildModelPolicyProjection({
      policyVersion: 1,
      endpointName: 'Managed AI',
      companyDefault: 'model-b',
      adminModels: ['model-b', 'model-a', 'model-b'],
    });
    expect(out.adminModels).toEqual(['model-b', 'model-a']);
  });

  test('fails closed for invalid revision, default, catalogue, and endpoint identifiers', () => {
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
      buildModelPolicyProjection({
        policyVersion: 1,
        endpointName: 'bad/name',
        companyDefault: 'model-a',
        adminModels: ['model-a'],
      }),
    ).toThrow(/endpoint/);
  });
});
