const { Readable } = require('node:stream');

const mockLogAxiosError = jest.fn();
jest.mock('@librechat/data-schemas', () => ({
  logger: { warn: jest.fn() },
}));
jest.mock('@librechat/agents', () => ({
  getCodeBaseURL: jest.fn(() => 'http://test-codeapi'),
}));
jest.mock('@librechat/api', () => ({
  createAxiosInstance: jest.fn(() => ({ get: jest.fn(), post: jest.fn() })),
  getCodeApiAuthHeaders: jest.fn(),
  logAxiosError: (...args) => mockLogAxiosError(...args),
}));

const { handleProxyError } = require('./proxy');

const response = () => {
  const res = { status: jest.fn(), json: jest.fn() };
  res.status.mockReturnValue(res);
  // Express' res.json serializes its payload; emulate that failure mode.
  res.json.mockImplementation((body) => {
    JSON.stringify(body);
    return res;
  });
  return res;
};

describe('Workspace proxy HTTP error mapping', () => {
  beforeEach(() => jest.clearAllMocks());

  it('preserves upstream denied download status without serializing or leaking an Axios stream', () => {
    const stream = Readable.from([Buffer.from('private upstream detail')]);
    stream.self = stream; // IncomingMessage/socket streams contain cycles.
    const res = response();
    expect(() =>
      handleProxyError(
        res,
        {
          response: { status: 404, data: stream },
        },
        'personal download failed',
      ),
    ).not.toThrow();
    expect(stream.destroyed).toBe(true);
    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.json).toHaveBeenCalledWith({ error: 'personal download failed' });
  });

  it('keeps an upstream 403 denial and never sends stream contents to clients', () => {
    const stream = Readable.from([Buffer.from('NEVER_EXPOSE_THIS_BODY')]);
    const res = response();
    handleProxyError(res, { response: { status: 403, data: stream } }, 'project download failed');
    expect(stream.destroyed).toBe(true);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ error: 'project download failed' });
  });

  it('retains valid plain JSON upstream errors and local malformed-key status', () => {
    const res = response();
    handleProxyError(res, { response: { status: 409, data: { error: 'collision' } } }, 'fallback');
    expect(res.status).toHaveBeenCalledWith(409);
    expect(res.json).toHaveBeenCalledWith({ error: 'collision' });
    const malformed = response();
    handleProxyError(
      malformed,
      { status: 400, message: 'invalid file identifier' },
      'personal download failed',
    );
    expect(malformed.status).toHaveBeenCalledWith(400);
    expect(malformed.json).toHaveBeenCalledWith({ error: 'personal download failed' });
  });
});
