'use strict';

const {
  signProjectFallback,
  verifyProjectFallback,
  authorizeProjectFallback,
} = require('./fallbackGrant');

describe('project CodeAPI fallback grants', () => {
  const previousSecret = process.env.JWT_SECRET;
  const requester = { user: { id: 'member-a', tenantId: 'tenant-a' } };
  const outputScope = { kind: 'project', id: 'project-a' };
  const target = { sessionId: 'session-a', fileId: 'file-a' };
  const issue = (overrides = {}) =>
    signProjectFallback({
      req: requester,
      outputScope,
      ...target,
      expiresAt: Date.now() + 60_000,
      ...overrides,
    });
  const verify = (token, overrides = {}) =>
    verifyProjectFallback({ token, req: requester, ...target, ...overrides });

  beforeEach(() => {
    process.env.JWT_SECRET = 'synthetic-pr35-isolated-test-secret-only-64-characters-long';
  });
  afterAll(() => {
    if (previousSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = previousSecret;
  });

  test('resolves only the server-signed project and never caller query kind/id', () => {
    const token = issue();
    expect(verify(token)).toEqual({ kind: 'project', id: 'project-a' });
  });

  test('rejects a different authenticated user or tenant', () => {
    const token = issue();
    expect(() =>
      verify(token, {
        req: { user: { id: 'member-b', tenantId: 'tenant-a' } },
      }),
    ).toThrow('CODE_PROJECT_FALLBACK_DENIED');
    expect(() =>
      verify(token, {
        req: { user: { id: 'member-a', tenantId: 'tenant-b' } },
      }),
    ).toThrow('CODE_PROJECT_FALLBACK_DENIED');
  });

  test('rejects a different execution session or file even with same user', () => {
    const token = issue();
    expect(() => verify(token, { sessionId: 'session-b' })).toThrow('CODE_PROJECT_FALLBACK_DENIED');
    expect(() => verify(token, { fileId: 'file-b' })).toThrow('CODE_PROJECT_FALLBACK_DENIED');
  });

  test('rejects tampering, wrong signature, malformed token and multiple query values', () => {
    const token = issue();
    const [body, signature] = token.split('.');
    const alternate = issue({ outputScope: { kind: 'project', id: 'project-b' } });
    expect(() => verify(alternate.split('.')[0] + '.' + signature)).toThrow(
      'CODE_PROJECT_FALLBACK_DENIED',
    );
    const flipped = (signature[0] === 'A' ? 'B' : 'A') + signature.slice(1);
    expect(() => verify(body + '.' + flipped)).toThrow('CODE_PROJECT_FALLBACK_DENIED');
    expect(() => verify(['token', token])).toThrow('CODE_PROJECT_FALLBACK_DENIED');
    expect(() => verify('malformed')).toThrow('CODE_PROJECT_FALLBACK_DENIED');
  });

  test('rejects expired tokens and excessive lifetime before signing', () => {
    const token = issue({ expiresAt: Date.now() + 500 });
    const now = jest.spyOn(Date, 'now');
    try {
      now.mockReturnValue(Date.now() + 1000);
      expect(() => verify(token)).toThrow('CODE_PROJECT_FALLBACK_DENIED');
    } finally {
      now.mockRestore();
    }
    expect(() =>
      issue({
        expiresAt: Date.now() + 2 * 24 * 60 * 60 * 1000,
      }),
    ).toThrow('CODE_PROJECT_FALLBACK_DENIED');
  });

  test('refuses unsigned project grants or missing signing secret', () => {
    expect(() => issue({ outputScope: { kind: 'user', id: 'member-a' } })).toThrow(
      'CODE_PROJECT_FALLBACK_DENIED',
    );
    delete process.env.JWT_SECRET;
    expect(() => issue()).toThrow('CODE_PROJECT_FALLBACK_SIGNING_UNAVAILABLE');
  });

  test('authorizes only the exact active project returned by live membership check', async () => {
    const req = { user: { id: 'member-a', tenantId: 'tenant-a' } };
    const resolver = jest.fn().mockResolvedValue({ kind: 'project', workspaceId: 'project-a' });
    const token = issue();
    await expect(
      authorizeProjectFallback({
        token,
        req,
        ...target,
        resolveWorkspaceContextExplicit: resolver,
      }),
    ).resolves.toEqual({ kind: 'project', id: 'project-a' });
    expect(resolver).toHaveBeenCalledWith(req, 'project-a');
    expect(req.workspaceContext).toEqual({ kind: 'project', workspaceId: 'project-a' });
  });

  test('fails closed on revoked or archived workspace and never binds a project context', async () => {
    const token = issue();
    for (const deniedStatus of [403, 404]) {
      const req = { user: { id: 'member-a', tenantId: 'tenant-a' } };
      const resolver = jest
        .fn()
        .mockRejectedValue(Object.assign(new Error('Denied'), { status: deniedStatus }));
      await expect(
        authorizeProjectFallback({
          token,
          req,
          ...target,
          resolveWorkspaceContextExplicit: resolver,
        }),
      ).rejects.toMatchObject({ status: deniedStatus });
      expect(req.workspaceContext).toBeUndefined();
    }
  });

  test('rejects a resolver that changes project scope rather than confirming it', async () => {
    const req = { user: { id: 'member-a', tenantId: 'tenant-a' } };
    const resolver = jest.fn().mockResolvedValue({ kind: 'project', workspaceId: 'project-b' });
    await expect(
      authorizeProjectFallback({
        token: issue(),
        req,
        ...target,
        resolveWorkspaceContextExplicit: resolver,
      }),
    ).rejects.toThrow('CODE_PROJECT_FALLBACK_DENIED');
    expect(req.workspaceContext).toBeUndefined();
  });

  test('tenantless personal context cannot be confused with tenant-scoped project', () => {
    const token = issue();
    expect(() => verify(token, { req: { user: { id: 'member-a' } } })).toThrow(
      'CODE_PROJECT_FALLBACK_DENIED',
    );
  });
});
