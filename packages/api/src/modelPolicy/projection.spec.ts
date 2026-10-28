import { buildModelPolicyCommitPlan } from './projection';

const input = {
  expectedVersion: 0,
  endpointName: 'CBHR AI',
  actor: 'qa@example.invalid',
  policy: {
    companyDefaultDeploymentId: 'deployment-a',
    deployments: [
      {
        deploymentId: 'deployment-a',
        model: 'provider-a/model-one',
        reasoning: {
          transport: 'chat.completions.reasoning_effort',
          options: ['low', 'high'],
          default: 'high',
        },
      },
    ],
    audiences: { USER: 'locked-current-default', ADMIN: 'managed-catalog' },
  },
};

describe('managed model policy canonical routing identity', () => {
  it('stores endpoint, model, and reasoning metadata in immutable candidate', () => {
    const planned = buildModelPolicyCommitPlan(input);
    expect(planned.candidate.routing).toEqual({
      endpointName: 'CBHR AI',
      deployments: [
        {
          deploymentId: 'deployment-a',
          model: 'provider-a/model-one',
          reasoning: {
            transport: 'chat.completions.reasoning_effort',
            options: ['low', 'high'],
            default: 'high',
          },
        },
      ],
    });
  });

  it('distinguishes same deployment ID with another concrete model', () => {
    const first = buildModelPolicyCommitPlan(input);
    const second = buildModelPolicyCommitPlan({
      ...input,
      policy: {
        ...input.policy,
        deployments: [{ ...input.policy.deployments[0], model: 'provider-a/model-two' }],
      },
    });
    expect(second.candidate.activeDeploymentIds).toEqual(first.candidate.activeDeploymentIds);
    expect(second.candidate.routing).not.toEqual(first.candidate.routing);
  });

  it('distinguishes endpoint reassignment with unchanged deployment IDs', () => {
    const first = buildModelPolicyCommitPlan(input);
    const second = buildModelPolicyCommitPlan({ ...input, endpointName: 'Managed Second' });
    expect(second.candidate.routing).not.toEqual(first.candidate.routing);
  });
});
