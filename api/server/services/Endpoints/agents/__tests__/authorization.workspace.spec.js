/**
 * 8S3D.1 — project workspace authorization regression tests.
 *
 * Pins the fail-closed contract for resolveWorkspaceContext /
 * resolveWorkspaceContextExplicit: membership is re-checked EVERY request
 * (never trusted from a conversation's stored workspaceId), a workspace
 * that no longer exists or is archived is denied, and denial throws rather
 * than silently falling back to the personal workspace.
 */
const mockGetConvo = jest.fn();
const mockGetWorkspace = jest.fn();
jest.mock('~/models', () => ({
  getConvo: (...args) => mockGetConvo(...args),
  getWorkspace: (...args) => mockGetWorkspace(...args),
}));

const mockCheckPermission = jest.fn();
jest.mock('~/server/services/PermissionService', () => ({
  checkPermission: (...args) => mockCheckPermission(...args),
}));

const {
  resolveWorkspaceContext,
  resolveWorkspaceContextExplicit,
} = require('../authorization');

function makeReq(overrides = {}) {
  return { user: { id: 'user_1', role: 'USER' }, body: {}, ...overrides };
}

describe('resolveWorkspaceContext (8S3D.1)', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('returns undefined (personal fallback) when no conversation/workspace is referenced', async () => {
    const req = makeReq({ body: { conversationId: 'new' } });
    await expect(resolveWorkspaceContext(req)).resolves.toBeUndefined();
    expect(req.workspaceContext).toBeUndefined();
    expect(mockGetWorkspace).not.toHaveBeenCalled();
  });

  it('returns undefined when there is no authenticated user', async () => {
    const req = { body: {} };
    await expect(resolveWorkspaceContext(req)).resolves.toBeUndefined();
  });

  it('resolves an existing conversation workspace when the user is still a member (EDIT)', async () => {
    mockGetConvo.mockResolvedValue({ workspaceId: 'ws_1' });
    mockGetWorkspace.mockResolvedValue({ _id: 'ws_1', state: 'active' });
    mockCheckPermission.mockResolvedValue(true);

    const req = makeReq({ body: { conversationId: 'convo_1' } });
    const ctx = await resolveWorkspaceContext(req);
    expect(ctx).toEqual({ kind: 'project', workspaceId: 'ws_1' });
    expect(req.workspaceContext).toEqual(ctx);
  });

  it('FAILS CLOSED (throws 403) when the user is no longer a member — never silently falls back to personal', async () => {
    mockGetConvo.mockResolvedValue({ workspaceId: 'ws_1' });
    mockGetWorkspace.mockResolvedValue({ _id: 'ws_1', state: 'active' });
    mockCheckPermission.mockResolvedValue(false); // removed member

    const req = makeReq({ body: { conversationId: 'convo_1' } });
    await expect(resolveWorkspaceContext(req)).rejects.toMatchObject({ status: 403 });
    expect(req.workspaceContext).toBeUndefined();
  });

  it('throws 404 for an archived workspace, even for the owner', async () => {
    mockGetConvo.mockResolvedValue({ workspaceId: 'ws_1' });
    mockGetWorkspace.mockResolvedValue({ _id: 'ws_1', state: 'archived' });
    mockCheckPermission.mockResolvedValue(true);

    const req = makeReq({ body: { conversationId: 'convo_1' } });
    await expect(resolveWorkspaceContext(req)).rejects.toMatchObject({ status: 404 });
  });

  it('throws 404 for a workspace that does not exist (forged id)', async () => {
    mockGetConvo.mockResolvedValue({ workspaceId: 'ws_forged' });
    mockGetWorkspace.mockResolvedValue(null);

    const req = makeReq({ body: { conversationId: 'convo_1' } });
    await expect(resolveWorkspaceContext(req)).rejects.toMatchObject({ status: 404 });
    expect(mockCheckPermission).not.toHaveBeenCalled();
  });

  it('resolves an explicit workspaceId for a brand-new (not-yet-persisted) conversation', async () => {
    mockGetWorkspace.mockResolvedValue({ _id: 'ws_2', state: 'active' });
    mockCheckPermission.mockResolvedValue(true);

    const req = makeReq({ body: { conversationId: 'new', workspaceId: 'ws_2' } });
    const ctx = await resolveWorkspaceContext(req);
    expect(ctx).toEqual({ kind: 'project', workspaceId: 'ws_2' });
    expect(mockGetConvo).not.toHaveBeenCalled(); // "new" is never looked up as an existing convo
  });

  it('a stale/existing conversation workspaceId takes precedence over a body workspaceId (no silent switch)', async () => {
    mockGetConvo.mockResolvedValue({ workspaceId: 'ws_original' });
    mockGetWorkspace.mockResolvedValue({ _id: 'ws_original', state: 'active' });
    mockCheckPermission.mockResolvedValue(true);

    // Attacker/bug tries to smuggle a different workspaceId in the body for
    // an EXISTING conversation — the conversation's own stored id must win.
    const req = makeReq({ body: { conversationId: 'convo_1', workspaceId: 'ws_attacker' } });
    const ctx = await resolveWorkspaceContext(req);
    expect(ctx.workspaceId).toBe('ws_original');
    expect(mockGetWorkspace).toHaveBeenCalledWith('ws_original');
  });

  it('caches the resolution on req — a second call in the same request does not re-query', async () => {
    mockGetConvo.mockResolvedValue({ workspaceId: 'ws_1' });
    mockGetWorkspace.mockResolvedValue({ _id: 'ws_1', state: 'active' });
    mockCheckPermission.mockResolvedValue(true);

    const req = makeReq({ body: { conversationId: 'convo_1' } });
    await resolveWorkspaceContext(req);
    await resolveWorkspaceContext(req);
    expect(mockGetConvo).toHaveBeenCalledTimes(1);
    expect(mockCheckPermission).toHaveBeenCalledTimes(1);
  });
});

describe('resolveWorkspaceContextExplicit (8S3D.1 — REST file-browser callers)', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('requires authentication', async () => {
    await expect(resolveWorkspaceContextExplicit({}, 'ws_1')).rejects.toMatchObject({ status: 401 });
  });

  it('allows a current member (EDIT)', async () => {
    mockGetWorkspace.mockResolvedValue({ _id: 'ws_1', state: 'active' });
    mockCheckPermission.mockResolvedValue(true);
    const ctx = await resolveWorkspaceContextExplicit(makeReq(), 'ws_1');
    expect(ctx).toEqual({ kind: 'project', workspaceId: 'ws_1' });
  });

  it('denies a nonmember (403), does not leak whether membership was ever granted', async () => {
    mockGetWorkspace.mockResolvedValue({ _id: 'ws_1', state: 'active' });
    mockCheckPermission.mockResolvedValue(false);
    await expect(resolveWorkspaceContextExplicit(makeReq(), 'ws_1')).rejects.toMatchObject({ status: 403 });
  });

  it('denies a forged/nonexistent workspace id (404)', async () => {
    mockGetWorkspace.mockResolvedValue(null);
    await expect(resolveWorkspaceContextExplicit(makeReq(), 'ws_forged')).rejects.toMatchObject({ status: 404 });
  });
});
