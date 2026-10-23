import {
  MODEL_POLICY_AUDIENCES,
  ModelPolicyInvalidError,
  normalizeModelPolicyCandidate,
  sameModelPolicyCandidate,
} from './modelPolicy';

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
