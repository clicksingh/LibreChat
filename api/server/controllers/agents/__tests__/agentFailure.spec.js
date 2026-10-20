const { normalizeAgentFailure } = require('../agentFailure');
describe('Model failure -> durable, truthful, non-replaying SSE errors', () => {
  test.each([
    [{ status: 400, code: 'context_length_exceeded', message: 'provider secret ABC' }, 'MODEL_CONTEXT_LIMIT'],
    [{ response: { status: 400 }, message: 'maximum context length exceeded' }, 'MODEL_CONTEXT_LIMIT'],
    [{ status: 429, message: 'slow down' }, 'MODEL_RATE_LIMIT'],
    [{ status: 402 }, 'MODEL_PROVIDER_CREDIT'],
    [{ name: 'AbortError', message: 'aborted by upstream provider' }, 'MODEL_REQUEST_INTERRUPTED'],
    [{ status: 400, code: 'invalid_request_error', message: 'invalid tool schema' }, 'MODEL_REQUEST_INTERRUPTED'],
    [{ status: 401, message: 'provider api_key=secret' }, 'MODEL_REQUEST_INTERRUPTED'],
    [{ status: 500, message: 'network refused' }, 'MODEL_REQUEST_INTERRUPTED'],
  ])('classifies and sanitizes %j', (failure, code) => {
    const result = normalizeAgentFailure(failure);
    expect(result).toContain(code);
    expect(result).not.toMatch(/provider secret|api_key=secret/);
    expect(result).toMatch(/(?:saved files|Saved files)/);
  });
});
