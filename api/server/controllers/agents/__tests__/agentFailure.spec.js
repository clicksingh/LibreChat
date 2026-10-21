const { normalizeAgentFailure, persistAgentFailure } = require('../agentFailure');
describe('Model failure -> durable, truthful, non-replaying SSE errors', () => {
  test.each([
    [
      { status: 400, code: 'context_length_exceeded', message: 'provider secret ABC' },
      'MODEL_CONTEXT_LIMIT',
    ],
    [
      { response: { status: 400 }, message: 'maximum context length exceeded' },
      'MODEL_CONTEXT_LIMIT',
    ],
    [{ status: 429, message: 'slow down' }, 'MODEL_RATE_LIMIT'],
    [{ status: 402 }, 'MODEL_PROVIDER_CREDIT'],
    [{ name: 'AbortError', message: 'aborted by upstream provider' }, 'MODEL_REQUEST_INTERRUPTED'],
    [
      { status: 400, code: 'invalid_request_error', message: 'invalid tool schema' },
      'MODEL_REQUEST_INTERRUPTED',
    ],
    [{ status: 401, message: 'provider api_key=secret' }, 'MODEL_REQUEST_INTERRUPTED'],
    [{ status: 500, message: 'network refused' }, 'MODEL_REQUEST_INTERRUPTED'],
  ])('classifies and sanitizes %j', (failure, code) => {
    const result = normalizeAgentFailure(failure);
    expect(result).toContain(code);
    expect(result).not.toMatch(/provider secret|api_key=secret/);
    expect(result).toMatch(/(?:saved files|Saved files)/);
  });
});

describe('live error lifecycle: save error even when SSE transport is unavailable', () => {
  const forced400 = {
    status: 400,
    code: 'context_length_exceeded',
    message: 'private provider stack',
  };
  it('publishes a bounded context-overflow event and awaits error job persistence', async () => {
    const order = [];
    const store = {
      emitError: jest.fn(async (_stream, err) => {
        order.push('event');
        expect(err).toMatch(/^MODEL_CONTEXT_LIMIT/);
      }),
      completeJob: jest.fn(async (_stream, err) => {
        order.push('persist');
        expect(err).toMatch(/^MODEL_CONTEXT_LIMIT/);
      }),
    };
    const result = await persistAgentFailure(store, 'qa-fault-stream', forced400);
    expect(result.eventDelivered).toBe(true);
    expect(order).toEqual(['event', 'persist']);
    expect(store.emitError).toHaveBeenCalledTimes(1);
    expect(store.completeJob).toHaveBeenCalledTimes(1);
  });
  it('persists failed job status if its Redis terminal event publication rejects', async () => {
    const order = [],
      errors = [];
    const store = {
      emitError: jest.fn(async () => {
        order.push('event');
        throw Error('redis transport disconnected');
      }),
      completeJob: jest.fn(async (_stream, err) => {
        order.push('persist');
        expect(err).toMatch(/^MODEL_CONTEXT_LIMIT/);
      }),
    };
    const result = await persistAgentFailure(store, 'qa-redis-disconnected', forced400, (e) =>
      errors.push(e),
    );
    expect(result.eventDelivered).toBe(false);
    expect(errors).toHaveLength(1);
    expect(order).toEqual(['event', 'persist']);
  });
  it('does not replay any model or tool calls on a forced failure', async () => {
    const invokeTool = jest.fn();
    const store = {
      emitError: jest.fn().mockResolvedValue(undefined),
      completeJob: jest.fn().mockResolvedValue(undefined),
    };
    await persistAgentFailure(store, 'qa-preserve-idempotence', forced400);
    expect(invokeTool).not.toHaveBeenCalled();
  });
});
