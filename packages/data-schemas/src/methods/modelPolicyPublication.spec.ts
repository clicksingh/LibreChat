import {
  decideModelPolicyPublicationTransition,
  ModelPolicyPublicationConflictError,
  ModelPolicyPublicationInvalidError,
} from './modelPolicyPublication';

const digestA = 'a'.repeat(64);
const digestB = 'b'.repeat(64);

describe('model-policy publication revision guard', () => {
  test('requires revision 1 for the first publication', () => {
    expect(
      decideModelPolicyPublicationTransition(null, { policyVersion: 1, digest: digestA }),
    ).toBe('create');
    expect(() =>
      decideModelPolicyPublicationTransition(null, { policyVersion: 2, digest: digestA }),
    ).toThrow(ModelPolicyPublicationConflictError);
  });

  test('same revision and digest is an idempotent no-op', () => {
    expect(
      decideModelPolicyPublicationTransition(
        { policyVersion: 4, digest: digestA },
        { policyVersion: 4, digest: digestA },
      ),
    ).toBe('noop');
  });

  test('same revision with different content is rejected', () => {
    expect(() =>
      decideModelPolicyPublicationTransition(
        { policyVersion: 4, digest: digestA },
        { policyVersion: 4, digest: digestB },
      ),
    ).toThrow(ModelPolicyPublicationConflictError);
  });

  test('stale and skipped revisions are rejected; exact next revision advances', () => {
    expect(() =>
      decideModelPolicyPublicationTransition(
        { policyVersion: 4, digest: digestA },
        { policyVersion: 3, digest: digestA },
      ),
    ).toThrow(ModelPolicyPublicationConflictError);
    expect(() =>
      decideModelPolicyPublicationTransition(
        { policyVersion: 4, digest: digestA },
        { policyVersion: 6, digest: digestB },
      ),
    ).toThrow(ModelPolicyPublicationConflictError);
    expect(
      decideModelPolicyPublicationTransition(
        { policyVersion: 4, digest: digestA },
        { policyVersion: 5, digest: digestB },
      ),
    ).toBe('advance');
  });

  test('invalid revision and digest fail before persistence', () => {
    expect(() =>
      decideModelPolicyPublicationTransition(null, { policyVersion: 0, digest: digestA }),
    ).toThrow(ModelPolicyPublicationInvalidError);
    expect(() =>
      decideModelPolicyPublicationTransition(null, { policyVersion: 1, digest: 'not-a-digest' }),
    ).toThrow(ModelPolicyPublicationInvalidError);
  });
});
