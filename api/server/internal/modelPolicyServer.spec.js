jest.mock(
  '@librechat/data-schemas',
  () => ({
    logger: { error: jest.fn(), info: jest.fn() },
    runAsSystem: async (fn) => fn(),
  }),
  { virtual: true },
);
jest.mock('../../models', () => ({}));
jest.mock('../services/Config', () => ({ invalidateConfigCaches: jest.fn() }));

const request = require('supertest');
const { createModelPolicyInternalApp } = require('./modelPolicyServer');

const SECRET = '0123456789abcdef0123456789abcdef';

function appWith(publish) {
  return createModelPolicyInternalApp({
    loadExpectedToken: async () => SECRET,
    publish,
  });
}

describe('internal model-policy publisher listener', () => {
  test('rejects requests without the service token before publication', async () => {
    const publish = jest.fn();
    const response = await request(appWith(publish)).post('/publish').send({
      policyVersion: 1,
    });
    expect(response.status).toBe(401);
    expect(publish).not.toHaveBeenCalled();
  });

  test('publishes only through authenticated service identity', async () => {
    const publish = jest.fn(async () => ({
      policyVersion: 1,
      digest: 'a'.repeat(64),
      transition: 'create',
      noop: false,
      writes: [{ principalId: '__base__', fields: ['endpoints.custom'] }],
    }));
    const response = await request(appWith(publish))
      .post('/publish')
      .set('Authorization', 'Bearer ' + SECRET)
      .send({
        policyVersion: 1,
        endpointName: 'CBHR AI',
        companyDefault: 'model-a',
        adminModels: ['model-a'],
      });

    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({
      ok: true,
      policyVersion: 1,
      transition: 'create',
      noop: false,
    });
    expect(publish).toHaveBeenCalledTimes(1);
  });

  test('returns deterministic policy conflicts without exposing internal data', async () => {
    const error = new Error('Stale policy revision');
    error.code = 'MODEL_POLICY_PUBLICATION_CONFLICT';
    error.status = 409;
    const response = await request(appWith(async () => Promise.reject(error)))
      .post('/publish')
      .set('Authorization', 'Bearer ' + SECRET)
      .send({ policyVersion: 1 });

    expect(response.status).toBe(409);
    expect(response.body).toEqual({
      ok: false,
      code: 'MODEL_POLICY_PUBLICATION_CONFLICT',
      error: 'Stale policy revision',
    });
  });

  test('unknown failures return a generic 500 response', async () => {
    const response = await request(
      appWith(async () => {
        throw new Error('mongo connection includes sensitive internal detail');
      }),
    )
      .post('/publish')
      .set('Authorization', 'Bearer ' + SECRET)
      .send({ policyVersion: 1 });

    expect(response.status).toBe(500);
    expect(response.body).toEqual({
      ok: false,
      code: 'MODEL_POLICY_PUBLICATION_FAILED',
      error: 'Model policy publication failed',
    });
    expect(JSON.stringify(response.body)).not.toContain('sensitive internal detail');
  });
});
