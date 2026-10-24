const {
  parseBearer,
  tokenMatches,
  createModelPolicyServiceAuth,
} = require('./modelPolicyServiceAuth');

const SECRET = '0123456789abcdef0123456789abcdef';

function response() {
  return {
    statusCode: null,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    },
  };
}

describe('model policy service authentication', () => {
  test('parses bearer tokens only', () => {
    expect(parseBearer('Bearer abc')).toBe('abc');
    expect(parseBearer('Basic abc')).toBeNull();
    expect(parseBearer(undefined)).toBeNull();
  });

  test('comparison requires the exact strong configured secret', () => {
    expect(tokenMatches(SECRET, SECRET)).toBe(true);
    expect(tokenMatches(SECRET.slice(0, -1) + 'x', SECRET)).toBe(false);
    expect(tokenMatches('short', 'short')).toBe(false);
  });

  test('valid token admits the service request', async () => {
    const middleware = createModelPolicyServiceAuth({ loadExpectedToken: async () => SECRET });
    const req = { get: () => 'Bearer ' + SECRET };
    const res = response();
    const next = jest.fn();
    await middleware(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(req.modelPolicyService).toEqual({ authenticated: true });
  });

  test('missing token is 401 and unavailable secret fails closed with 503', async () => {
    const next = jest.fn();
    let res = response();
    await createModelPolicyServiceAuth({ loadExpectedToken: async () => SECRET })(
      { get: () => undefined },
      res,
      next,
    );
    expect(res.statusCode).toBe(401);
    res = response();
    await createModelPolicyServiceAuth({ loadExpectedToken: async () => 'too-short' })(
      { get: () => 'Bearer ' + SECRET },
      res,
      next,
    );
    expect(res.statusCode).toBe(503);
    expect(next).not.toHaveBeenCalled();
  });
});
