import type { Response } from 'express';
import type { ServerRequest } from '~/types';
import { createXposePairingHandlers } from './handlers';

const SECRET_TEXT = 'eHBvc2UtcG9ydGFsLXRlc3Qtc2VjcmV0LTAxMjM0NTY3ODlhYmNkZWY';
const VALID_ENV = {
  XPOSE_PAIRING_URL: 'https://xpose.example.com',
  XPOSE_PAIRING_PORTAL_SECRET: SECRET_TEXT,
  XPOSE_PAIRING_FLEET_ID: 'fleet-1',
};

type MockFetch = jest.Mock & typeof fetch;

function upstreamFetch(status: number, body: unknown): MockFetch {
  return jest.fn(async () => ({ status, json: async () => body })) as unknown as MockFetch;
}

function failingFetch(error: unknown): MockFetch {
  return jest.fn(async () => {
    throw error;
  }) as unknown as MockFetch;
}

interface MockRes {
  statusCode: number;
  body: unknown;
  headers: Record<string, string>;
  set: jest.Mock;
  status: jest.Mock;
  json: jest.Mock;
}

function mockRes() {
  const res: MockRes = {
    statusCode: 200,
    body: undefined,
    headers: {},
    set: jest.fn((name: string, value: string) => {
      res.headers[name.toLowerCase()] = value;
      return res;
    }),
    status: jest.fn((code: number) => {
      res.statusCode = code;
      return res;
    }),
    json: jest.fn((data: unknown) => {
      res.body = data;
      return res;
    }),
  };
  return res as Partial<Response> as Response & MockRes;
}

function mockReq(overrides = {}) {
  return {
    user: { email: 'user@example.com' },
    params: {},
    query: {},
    body: { code: 'ABC-123' },
    ...overrides,
  } as unknown as ServerRequest;
}

function createHandlers(overrides = {}) {
  return createXposePairingHandlers({
    env: VALID_ENV,
    now: () => 1700000000000,
    randomNonce: () => 'abcdefghijklmnopqrstuv',
    ...overrides,
  });
}

describe('createXposePairingHandlers', () => {
  const successBody = {
    ok: true,
    sessionId: 's1',
    deviceId: 'dev-1',
    state: 'claimed',
    fleetId: 'fleet-1',
    publicKeyDigest: 'digest',
    expiresAt: 1700000000000,
    actorId: 'user@example.com',
  };

  it('rejects a missing or malformed authenticated email without contacting upstream', async () => {
    const users = [
      undefined,
      {},
      { email: '' },
      { email: 'not-an-email' },
      { email: 'a@b\n@c' },
      { email: `${'a'.repeat(200)}@example.com` },
    ];
    for (const user of users) {
      const fetchImpl = upstreamFetch(200, successBody);
      const res = mockRes();
      await createHandlers({ fetch: fetchImpl }).claimDevice(mockReq({ user }), res);
      expect(res.statusCode).toBe(403);
      expect(res.body).toEqual({ ok: false, code: 'xpose_pairing_identity_invalid' });
      expect(fetchImpl).not.toHaveBeenCalled();
    }
  });

  it('rejects any browser-supplied actor, fleet, owner, or extra field', async () => {
    const bodies = [
      { code: 'ABC-123', actorId: 'evil@example.com' },
      { code: 'ABC-123', connectionOwnerId: 'evil@example.com' },
      { code: 'ABC-123', fleetId: 'evil-fleet' },
      { code: 'ABC-123', alias: 'my phone' },
      { code: 'ABC-123', nested: { actorId: 'evil@example.com' } },
    ];
    for (const body of bodies) {
      const fetchImpl = upstreamFetch(200, successBody);
      const res = mockRes();
      await createHandlers({ fetch: fetchImpl }).claimDevice(mockReq({ body }), res);
      expect(res.statusCode).toBe(400);
      expect(res.body).toEqual({ ok: false, code: 'xpose_pairing_request_invalid' });
      expect(fetchImpl).not.toHaveBeenCalled();
    }
  });

  it('rejects a missing, empty, oversized, or newline pairing code', async () => {
    const bodies = [
      {},
      { code: '' },
      { code: 'A'.repeat(33) },
      { code: 'AB\r\nCD' },
      { code: 42 },
      { code: 'AB\n' },
    ];
    for (const body of bodies) {
      const fetchImpl = upstreamFetch(200, successBody);
      const res = mockRes();
      await createHandlers({ fetch: fetchImpl }).claimDevice(mockReq({ body }), res);
      expect(res.statusCode).toBe(400);
      expect(res.body).toEqual({ ok: false, code: 'xpose_pairing_code_invalid' });
      expect(fetchImpl).not.toHaveBeenCalled();
    }
  });

  it('rejects non-object bodies', async () => {
    for (const body of [null, undefined, 'code', ['ABC-123'], 7]) {
      const fetchImpl = upstreamFetch(200, successBody);
      const res = mockRes();
      await createHandlers({ fetch: fetchImpl }).claimDevice(mockReq({ body }), res);
      expect(res.statusCode).toBe(400);
      expect(res.body).toEqual({ ok: false, code: 'xpose_pairing_request_invalid' });
      expect(fetchImpl).not.toHaveBeenCalled();
    }
  });

  it('derives actor and owner from the authenticated email and fleet from server env', async () => {
    const fetchImpl = upstreamFetch(200, successBody);
    const res = mockRes();
    await createHandlers({ fetch: fetchImpl }).claimDevice(
      mockReq({ user: { email: ' User@Example.COM ' } }),
      res,
    );

    expect(res.statusCode).toBe(200);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const init = fetchImpl.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(init.body as string)).toEqual({
      code: 'ABC-123',
      actorId: 'user@example.com',
      connectionOwnerId: 'user@example.com',
      fleetId: 'fleet-1',
    });
  });

  it('projects only an explicit allowlist of success fields and never the secret or signature', async () => {
    const fetchImpl = upstreamFetch(200, successBody);
    const res = mockRes();
    await createHandlers({ fetch: fetchImpl }).claimDevice(mockReq(), res);

    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ ok: true, state: 'claimed', deviceId: 'dev-1' });

    const serialized = JSON.stringify(res.body);
    expect(serialized).not.toContain(SECRET_TEXT);
    expect(serialized).not.toContain('signature');
    expect(serialized).not.toContain('sessionId');
    expect(serialized).not.toContain('publicKeyDigest');
    expect(serialized).not.toContain('fleet-1');
    expect(serialized).not.toContain('actorId');
  });

  it('maps upstream error statuses conservatively and preserves bounded error codes', async () => {
    const cases: Array<{
      status: number;
      body: unknown;
      expectedStatus: number;
      expectedCode: string;
    }> = [
      {
        status: 404,
        body: { ok: false, code: 'pairing_not_found' },
        expectedStatus: 404,
        expectedCode: 'pairing_not_found',
      },
      {
        status: 400,
        body: { ok: false, code: 'pairing_code_invalid' },
        expectedStatus: 400,
        expectedCode: 'pairing_code_invalid',
      },
      {
        status: 429,
        body: { ok: false, code: 'pairing_rate_limited' },
        expectedStatus: 429,
        expectedCode: 'pairing_rate_limited',
      },
      {
        status: 500,
        body: { ok: false, code: 'pairing_storage_unavailable' },
        expectedStatus: 502,
        expectedCode: 'pairing_storage_unavailable',
      },
      {
        status: 200,
        body: { ok: false, code: 'pairing_not_claimed' },
        expectedStatus: 502,
        expectedCode: 'pairing_not_claimed',
      },
      {
        status: 418,
        body: 'not json',
        expectedStatus: 502,
        expectedCode: 'xpose_pairing_upstream_error',
      },
      {
        status: 502,
        body: { ok: false, code: 'has spaces and is not bounded' },
        expectedStatus: 502,
        expectedCode: 'xpose_pairing_upstream_error',
      },
    ];
    for (const testCase of cases) {
      const res = mockRes();
      await createHandlers({ fetch: upstreamFetch(testCase.status, testCase.body) }).claimDevice(
        mockReq(),
        res,
      );
      expect(res.statusCode).toBe(testCase.expectedStatus);
      expect(res.body).toEqual({ ok: false, code: testCase.expectedCode });
    }
  });

  it('maps aborts to 504 and other network failures to 502', async () => {
    const abortError = new Error('aborted');
    abortError.name = 'AbortError';

    const timeoutRes = mockRes();
    await createHandlers({ fetch: failingFetch(abortError) }).claimDevice(mockReq(), timeoutRes);
    expect(timeoutRes.statusCode).toBe(504);
    expect(timeoutRes.body).toEqual({ ok: false, code: 'xpose_pairing_unavailable' });

    const networkRes = mockRes();
    await createHandlers({ fetch: failingFetch(new Error('econnrefused')) }).claimDevice(
      mockReq(),
      networkRes,
    );
    expect(networkRes.statusCode).toBe(502);
    expect(networkRes.body).toEqual({ ok: false, code: 'xpose_pairing_unavailable' });
  });

  it('fails closed with 503 when the pairing backend is unconfigured', async () => {
    const fetchImpl = upstreamFetch(200, successBody);
    const res = mockRes();
    await createHandlers({ fetch: fetchImpl, env: {} }).claimDevice(mockReq(), res);
    expect(res.statusCode).toBe(503);
    expect(res.body).toEqual({ ok: false, code: 'xpose_pairing_unconfigured' });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('sets no-store cache control on every response', async () => {
    const okRes = mockRes();
    await createHandlers({ fetch: upstreamFetch(200, successBody) }).claimDevice(mockReq(), okRes);
    expect(okRes.headers['cache-control']).toBe('no-store');

    const badRes = mockRes();
    await createHandlers({ fetch: upstreamFetch(500, {}) }).claimDevice(mockReq(), badRes);
    expect(badRes.headers['cache-control']).toBe('no-store');
  });
});
