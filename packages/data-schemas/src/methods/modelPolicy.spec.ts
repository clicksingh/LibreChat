import {
  MODEL_POLICY_AUDIENCES,
  ModelPolicyInvalidError,
  normalizeModelPolicyCandidate,
  sameModelPolicyCandidate,
  createModelPolicyMethods,
} from './modelPolicy';
import { modelPolicyHeadSchema, modelPolicyRevisionSchema } from '../schema/modelPolicy';

const candidate = {
  schemaVersion: 1,
  companyDefaultDeploymentId: 'deployment-b',
  activeDeploymentIds: ['deployment-b', 'deployment-a'],
  audiences: MODEL_POLICY_AUDIENCES,
};

describe('canonical managed-model policy validation', () => {
  test('normalizes a vendor-neutral ordered deployment policy', () => {
    expect(normalizeModelPolicyCandidate(candidate)).toEqual(candidate);
  });

  test('requires the default deployment to be active', () => {
    expect(() =>
      normalizeModelPolicyCandidate({
        ...candidate,
        companyDefaultDeploymentId: 'missing',
      }),
    ).toThrow(ModelPolicyInvalidError);
  });

  test('rejects duplicate, unsafe, empty, and oversized deployment catalogues', () => {
    expect(() =>
      normalizeModelPolicyCandidate({
        ...candidate,
        activeDeploymentIds: ['deployment-a', 'deployment-a'],
      }),
    ).toThrow(ModelPolicyInvalidError);
    expect(() =>
      normalizeModelPolicyCandidate({
        ...candidate,
        activeDeploymentIds: ['bad deployment id'],
      }),
    ).toThrow(ModelPolicyInvalidError);
    expect(() =>
      normalizeModelPolicyCandidate({
        ...candidate,
        activeDeploymentIds: [],
      }),
    ).toThrow(ModelPolicyInvalidError);
  });

  test('audience modes and schema version are fixed contracts', () => {
    expect(() =>
      normalizeModelPolicyCandidate({
        ...candidate,
        schemaVersion: 2,
      }),
    ).toThrow(ModelPolicyInvalidError);
    expect(() =>
      normalizeModelPolicyCandidate({
        ...candidate,
        audiences: { USER: 'free-choice' as never, ADMIN: 'managed-catalog' },
      }),
    ).toThrow(ModelPolicyInvalidError);
  });

  test('same-candidate comparison includes deployment order and default', () => {
    const revision = {
      ...candidate,
      version: 3,
      parentVersion: 2,
      publishedBy: 'test',
      publishedAt: new Date(),
      source: 'test',
    };
    expect(sameModelPolicyCandidate(revision, candidate)).toBe(true);
    expect(
      sameModelPolicyCandidate(revision, {
        ...candidate,
        activeDeploymentIds: ['deployment-a', 'deployment-b'],
      }),
    ).toBe(false);
    expect(
      sameModelPolicyCandidate(revision, {
        ...candidate,
        companyDefaultDeploymentId: 'deployment-a',
      }),
    ).toBe(false);
  });
});

describe('canonical model-policy tenant boundaries', () => {
  test('head and revision indexes are uniquely scoped by tenant, not globally by version', () => {
    const headUnique = modelPolicyHeadSchema.indexes().filter(([, options]) => options.unique);
    const revisionUnique = modelPolicyRevisionSchema
      .indexes()
      .filter(([, options]) => options.unique);
    expect(headUnique).toEqual([
      [{ tenantId: 1, key: 1 }, expect.objectContaining({ unique: true })],
    ]);
    expect(revisionUnique).toEqual([
      [{ tenantId: 1, version: 1 }, expect.objectContaining({ unique: true })],
    ]);
    expect(modelPolicyHeadSchema.path('tenantId')?.options?.required).toBeTruthy();
    expect(modelPolicyRevisionSchema.path('tenantId')?.options?.required).toBeTruthy();
  });
});

describe('canonical model-policy method tenant-bound queries', () => {
  test('filters head and revision reads by tenant and rejects absent tenants', async () => {
    const headQuery = {
      session: jest.fn().mockReturnThis(),
      lean: jest.fn().mockResolvedValue(null),
    };
    const revisionQuery = {
      session: jest.fn().mockReturnThis(),
      lean: jest.fn().mockResolvedValue(null),
    };
    const headModel = { findOne: jest.fn(() => headQuery) };
    const revisionModel = { findOne: jest.fn(() => revisionQuery) };
    const mongoose = {
      models: { ModelPolicyHead: headModel, ModelPolicyRevision: revisionModel },
    } as unknown as typeof import('mongoose');
    const methods = createModelPolicyMethods(mongoose);
    await methods.getModelPolicyHead('tenant-a');
    await methods.getModelPolicyRevision('tenant-b', 42);
    expect(headModel.findOne).toHaveBeenCalledWith({
      tenantId: 'tenant-a',
      key: 'managed-models',
    });
    expect(revisionModel.findOne).toHaveBeenCalledWith({ tenantId: 'tenant-b', version: 42 });
    await expect(methods.getModelPolicyHead('')).rejects.toMatchObject({
      code: 'MODEL_POLICY_INVALID',
    });
    await expect(methods.getModelPolicyRevision('', 1)).rejects.toMatchObject({
      code: 'MODEL_POLICY_INVALID',
    });
  });

  test('first CAS write creates both canonical records under the authorized tenant', async () => {
    const headModel = {
      findOne: jest.fn(() => ({
        session: jest.fn().mockReturnThis(),
        lean: jest.fn().mockResolvedValue(null),
      })),
      create: jest.fn().mockResolvedValue([{}]),
    };
    const revisionModel = {
      create: jest.fn(async (rows) => [{ toObject: () => rows[0] }]),
    };
    const mongoose = {
      models: { ModelPolicyHead: headModel, ModelPolicyRevision: revisionModel },
    } as unknown as typeof import('mongoose');
    const methods = createModelPolicyMethods(mongoose);
    const result = await methods.commitModelPolicyRevision(candidate, {
      tenantId: 'tenant-a',
      expectedVersion: 0,
    });
    expect(result).toMatchObject({ version: 1, noop: false });
    expect(revisionModel.create).toHaveBeenCalledWith(
      [expect.objectContaining({ tenantId: 'tenant-a', version: 1 })],
      undefined,
    );
    expect(headModel.create).toHaveBeenCalledWith(
      [{ tenantId: 'tenant-a', key: 'managed-models', version: 1, schemaVersion: 1 }],
      undefined,
    );
  });
});
