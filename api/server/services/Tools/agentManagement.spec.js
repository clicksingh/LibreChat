const { Tools, Permissions, ResourceType, PrincipalType, PermissionBits, PermissionTypes } =
  require('librechat-data-provider');

const mockCheckAccessWithRequestCache = jest.fn();
jest.mock('@librechat/api', () => ({
  checkAccessWithRequestCache: (...args) => mockCheckAccessWithRequestCache(...args),
}));

const mockCheckPermission = jest.fn();
const mockGrantPermission = jest.fn();
const mockFindAccessibleResources = jest.fn();
const mockBulkUpdateResourcePermissions = jest.fn();
jest.mock('~/server/services/PermissionService', () => ({
  checkPermission: (...args) => mockCheckPermission(...args),
  grantPermission: (...args) => mockGrantPermission(...args),
  findAccessibleResources: (...args) => mockFindAccessibleResources(...args),
  bulkUpdateResourcePermissions: (...args) => mockBulkUpdateResourcePermissions(...args),
}));

const mockGetRoleByName = jest.fn();
const mockFindUser = jest.fn();
const mockGetAgent = jest.fn();
const mockCreateAgent = jest.fn();
const mockUpdateAgent = jest.fn();
const mockArchiveAgent = jest.fn();
const mockRestoreAgent = jest.fn();
const mockDiffAgentVersions = jest.fn();
const mockGetListAgentsByAccess = jest.fn();
jest.mock('~/models', () => ({
  getRoleByName: (...args) => mockGetRoleByName(...args),
  findUser: (...args) => mockFindUser(...args),
  getAgent: (...args) => mockGetAgent(...args),
  createAgent: (...args) => mockCreateAgent(...args),
  updateAgent: (...args) => mockUpdateAgent(...args),
  archiveAgent: (...args) => mockArchiveAgent(...args),
  restoreAgent: (...args) => mockRestoreAgent(...args),
  diffAgentVersions: (...args) => mockDiffAgentVersions(...args),
  getListAgentsByAccess: (...args) => mockGetListAgentsByAccess(...args),
}));

const mockFilterAuthorizedTools = jest.fn();
jest.mock('~/server/controllers/agents/v1', () => ({
  filterAuthorizedTools: (...args) => mockFilterAuthorizedTools(...args),
}));

const mockGetCachedTools = jest.fn();
jest.mock('~/server/services/Config', () => ({
  getCachedTools: (...args) => mockGetCachedTools(...args),
}));

jest.mock('nanoid', () => ({ nanoid: () => 'testid123' }));

const { createAgentManagementTool } = require('./agentManagement');

const OWNER = { id: 'user_owner', role: 'USER' };
const ATTACKER = { id: 'user_attacker', role: 'USER' };
const AGENT_DB_ID = 'mongo_id_abc';
const AGENT_ID = 'agent_abc';

function buildTool(user) {
  return createAgentManagementTool({ req: { user } });
}

/** Grants global PermissionTypes.AGENTS.{USE,CREATE} — the "may use the
 *  tool at all" gate, distinct from per-resource ACL and distinct from
 *  PermissionTypes.RUN_CODE (the 8S3C.2 gate). */
function grantGlobalAgents({ use = true, create = true } = {}) {
  mockCheckAccessWithRequestCache.mockImplementation(({ permissionType, permissions }) => {
    if (permissionType === PermissionTypes.AGENTS) {
      return Promise.resolve(
        permissions.every((p) => (p === Permissions.USE ? use : p === Permissions.CREATE ? create : false)),
      );
    }
    if (permissionType === PermissionTypes.RUN_CODE) {
      return Promise.resolve(false); // default: RUN_CODE denied unless a test overrides
    }
    return Promise.resolve(false);
  });
}

function grantRunCode(allowed) {
  mockCheckAccessWithRequestCache.mockImplementation(({ permissionType, permissions }) => {
    if (permissionType === PermissionTypes.AGENTS) {
      return Promise.resolve(true);
    }
    if (permissionType === PermissionTypes.RUN_CODE) {
      return Promise.resolve(allowed);
    }
    return Promise.resolve(false);
  });
}

beforeEach(() => {
  jest.clearAllMocks();
  grantGlobalAgents();
  mockGetAgent.mockResolvedValue({
    _id: AGENT_DB_ID,
    id: AGENT_ID,
    name: 'Existing Agent',
    tools: [],
    versions: [{ name: 'v1' }],
  });
  mockFilterAuthorizedTools.mockImplementation(({ tools }) => Promise.resolve(tools || []));
  mockGetCachedTools.mockResolvedValue({});
});

describe('agent_management tool — actor identity', () => {
  it('has no owner_id/user_id field anywhere in its input schema', () => {
    const tool = buildTool(OWNER);
    const schemaStr = JSON.stringify(tool.schema);
    expect(schemaStr).not.toMatch(/owner_id/i);
    expect(schemaStr).not.toMatch(/"user_id"/i);
  });

  it('returns AGENT_ACCESS_DENIED and never dispatches when req.user is absent', async () => {
    const tool = createAgentManagementTool({ req: {} });
    const out = await tool.invoke({ action: 'list' });
    expect(out).toMatch(/^\[AGENT_ACCESS_DENIED\]/);
    expect(mockCheckAccessWithRequestCache).not.toHaveBeenCalled();
    expect(mockGetListAgentsByAccess).not.toHaveBeenCalled();
  });

  it('always uses req.user.id as the actor for create — never a model-supplied field', async () => {
    mockCreateAgent.mockResolvedValue({ id: AGENT_ID, _id: AGENT_DB_ID, tools: [], versions: [] });
    const tool = buildTool(OWNER);
    await tool.invoke({ action: 'create', name: 'x', owner_id: 'someone_else' });
    expect(mockCreateAgent).toHaveBeenCalledWith(
      expect.objectContaining({ author: OWNER.id }),
    );
    expect(mockGrantPermission).toHaveBeenCalledWith(
      expect.objectContaining({ principalId: OWNER.id, grantedBy: OWNER.id }),
    );
  });
});

describe('agent_management tool — unknown action', () => {
  it('rejects an action outside the fixed allowlist at the schema layer, before the handler ever runs', async () => {
    const tool = buildTool(OWNER);
    // The `action` enum is enforced by the tool's own JSON schema (a
    // defense-in-depth layer ahead of the ACTIONS-map lookup in func());
    // an out-of-enum action never reaches the handler at all.
    await expect(tool.invoke({ action: 'delete', agent_id: AGENT_ID })).rejects.toThrow();
    expect(mockGetAgent).not.toHaveBeenCalled();
  });

  it('the func() ACTIONS-map lookup itself also fails closed for an unrecognized action (belt-and-suspenders, bypassing schema validation)', async () => {
    // Exercise the handler's own defense directly, since the schema layer
    // above would otherwise mask a regression in this second guard.
    const agentManagement = require('./agentManagement');
    const rawTool = agentManagement.createAgentManagementTool({ req: { user: OWNER } });
    // `.func` is the raw handler DynamicStructuredTool wraps with schema
    // validation; call it directly to bypass that validation layer.
    const out = await rawTool.func({ action: 'delete', agent_id: AGENT_ID });
    expect(out).toMatch(/^\[AGENT_ACTION_UNKNOWN\]/);
    expect(mockGetAgent).not.toHaveBeenCalled();
  });

  it('has no hard-delete action in the schema enum', () => {
    const tool = buildTool(OWNER);
    expect(tool.schema.properties.action.enum).not.toContain('delete');
    expect(tool.schema.properties.action.enum).toEqual([
      'list',
      'get',
      'create',
      'update',
      'versions',
      'diff',
      'archive',
      'restore',
      'share',
      'unshare',
    ]);
  });
});

describe('agent_management tool — per-action permission enforcement', () => {
  it('list requires AGENTS.USE; denies and never queries when missing', async () => {
    grantGlobalAgents({ use: false });
    const tool = buildTool(ATTACKER);
    const out = await tool.invoke({ action: 'list' });
    expect(out).toMatch(/AGENT_ACCESS_DENIED/);
    expect(mockGetListAgentsByAccess).not.toHaveBeenCalled();
  });

  it('get requires AGENTS.USE globally AND resource VIEW; denies on missing resource VIEW without ever calling getAgent update path', async () => {
    mockCheckPermission.mockResolvedValue(false);
    const tool = buildTool(ATTACKER);
    const out = await tool.invoke({ action: 'get', agent_id: AGENT_ID });
    expect(out).toMatch(/AGENT_ACCESS_DENIED/);
    expect(mockCheckPermission).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: ATTACKER.id,
        resourceType: ResourceType.AGENT,
        resourceId: AGENT_DB_ID,
        requiredPermission: PermissionBits.VIEW,
      }),
    );
  });

  it('create requires AGENTS.CREATE; denies without ever calling createAgent', async () => {
    grantGlobalAgents({ use: true, create: false });
    const tool = buildTool(ATTACKER);
    const out = await tool.invoke({ action: 'create', name: 'x' });
    expect(out).toMatch(/AGENT_ACCESS_DENIED/);
    expect(mockCreateAgent).not.toHaveBeenCalled();
  });

  it('update requires resource EDIT; denies without ever calling updateAgent (cross-user attack)', async () => {
    mockCheckPermission.mockResolvedValue(false);
    const tool = buildTool(ATTACKER);
    const out = await tool.invoke({ action: 'update', agent_id: AGENT_ID, name: 'hijacked' });
    expect(out).toMatch(/AGENT_ACCESS_DENIED/);
    expect(mockCheckPermission).toHaveBeenCalledWith(
      expect.objectContaining({ requiredPermission: PermissionBits.EDIT }),
    );
    expect(mockUpdateAgent).not.toHaveBeenCalled();
  });

  it('archive requires resource EDIT; denies without calling archiveAgent', async () => {
    mockCheckPermission.mockResolvedValue(false);
    const tool = buildTool(ATTACKER);
    const out = await tool.invoke({ action: 'archive', agent_id: AGENT_ID });
    expect(out).toMatch(/AGENT_ACCESS_DENIED/);
    expect(mockArchiveAgent).not.toHaveBeenCalled();
  });

  it('restore requires resource EDIT; denies without calling restoreAgent', async () => {
    mockCheckPermission.mockResolvedValue(false);
    const tool = buildTool(ATTACKER);
    const out = await tool.invoke({ action: 'restore', agent_id: AGENT_ID });
    expect(out).toMatch(/AGENT_ACCESS_DENIED/);
    expect(mockRestoreAgent).not.toHaveBeenCalled();
  });

  it('versions requires resource VIEW; denies without ever reading versions', async () => {
    mockCheckPermission.mockResolvedValue(false);
    const tool = buildTool(ATTACKER);
    const out = await tool.invoke({ action: 'versions', agent_id: AGENT_ID });
    expect(out).toMatch(/AGENT_ACCESS_DENIED/);
  });

  it('diff requires resource VIEW; denies without calling diffAgentVersions', async () => {
    mockCheckPermission.mockResolvedValue(false);
    const tool = buildTool(ATTACKER);
    const out = await tool.invoke({ action: 'diff', agent_id: AGENT_ID, from: 0 });
    expect(out).toMatch(/AGENT_ACCESS_DENIED/);
    expect(mockDiffAgentVersions).not.toHaveBeenCalled();
  });

  it('share requires SHARE — EDIT alone is NOT sufficient', async () => {
    // Simulate a user who has EDIT but not SHARE on the resource.
    mockCheckPermission.mockImplementation(({ requiredPermission }) =>
      Promise.resolve(requiredPermission === PermissionBits.EDIT),
    );
    const tool = buildTool(ATTACKER);
    const out = await tool.invoke({
      action: 'share',
      agent_id: AGENT_ID,
      recipient_email: 'someone@example.com',
    });
    expect(out).toMatch(/AGENT_ACCESS_DENIED/);
    expect(mockCheckPermission).toHaveBeenCalledWith(
      expect.objectContaining({ requiredPermission: PermissionBits.SHARE }),
    );
    expect(mockBulkUpdateResourcePermissions).not.toHaveBeenCalled();
  });

  it('unshare requires SHARE — EDIT alone is NOT sufficient', async () => {
    mockCheckPermission.mockImplementation(({ requiredPermission }) =>
      Promise.resolve(requiredPermission === PermissionBits.EDIT),
    );
    const tool = buildTool(ATTACKER);
    const out = await tool.invoke({
      action: 'unshare',
      agent_id: AGENT_ID,
      recipient_email: 'someone@example.com',
    });
    expect(out).toMatch(/AGENT_ACCESS_DENIED/);
    expect(mockBulkUpdateResourcePermissions).not.toHaveBeenCalled();
  });

  it('a positive-permission user succeeds on get (positive control)', async () => {
    mockCheckPermission.mockResolvedValue(true);
    const tool = buildTool(OWNER);
    const out = await tool.invoke({ action: 'get', agent_id: AGENT_ID });
    expect(out).not.toMatch(/^\[/);
    expect(JSON.parse(out).agent_id).toBe(AGENT_ID);
  });
});

describe('agent_management tool — 8S3C.2 RUN_CODE.USE regression class', () => {
  it('create rejects execute_code in the final tool list for a user without RUN_CODE.USE', async () => {
    grantRunCode(false);
    mockFilterAuthorizedTools.mockResolvedValue([Tools.execute_code, 'web_search']);
    const tool = buildTool(ATTACKER);
    const out = await tool.invoke({ action: 'create', name: 'x', tools: [Tools.execute_code] });
    expect(out).toMatch(/AGENT_CAPABILITY_NOT_ALLOWED/);
    expect(mockCreateAgent).not.toHaveBeenCalled();
  });

  it('create allows execute_code for a user WITH RUN_CODE.USE (positive control)', async () => {
    grantRunCode(true);
    mockFilterAuthorizedTools.mockResolvedValue([Tools.execute_code]);
    mockCreateAgent.mockResolvedValue({ id: AGENT_ID, _id: AGENT_DB_ID, tools: [Tools.execute_code], versions: [] });
    const tool = buildTool(OWNER);
    const out = await tool.invoke({ action: 'create', name: 'x', tools: [Tools.execute_code] });
    expect(out).not.toMatch(/^\[/);
    expect(mockCreateAgent).toHaveBeenCalled();
  });

  it('update rejects bash_tool in the FINAL merged tool list for a user without RUN_CODE.USE, even if only unrelated fields changed', async () => {
    grantRunCode(false);
    mockCheckPermission.mockResolvedValue(true);
    // Existing agent already has bash_tool configured (e.g. author's RUN_CODE.USE was later revoked).
    mockGetAgent.mockResolvedValue({
      _id: AGENT_DB_ID,
      id: AGENT_ID,
      name: 'Existing Agent',
      tools: [Tools.bash_tool],
      versions: [{ name: 'v1' }],
    });
    const tool = buildTool(ATTACKER);
    // Editor only changes `name` — does not touch `tools` — but the full
    // resulting config (existing.tools) still carries bash_tool and must
    // be re-validated on every save, not just the diff.
    const out = await tool.invoke({ action: 'update', agent_id: AGENT_ID, name: 'renamed' });
    expect(out).toMatch(/AGENT_CAPABILITY_NOT_ALLOWED/);
    expect(mockUpdateAgent).not.toHaveBeenCalled();
  });

  it('update rejects execute_code when the editor explicitly adds it without RUN_CODE.USE', async () => {
    grantRunCode(false);
    mockCheckPermission.mockResolvedValue(true);
    mockFilterAuthorizedTools.mockResolvedValue([Tools.execute_code]);
    const tool = buildTool(ATTACKER);
    const out = await tool.invoke({
      action: 'update',
      agent_id: AGENT_ID,
      tools: [Tools.execute_code],
    });
    expect(out).toMatch(/AGENT_CAPABILITY_NOT_ALLOWED/);
    expect(mockUpdateAgent).not.toHaveBeenCalled();
  });
});

describe('agent_management tool — optimistic concurrency (expected_version)', () => {
  it('rejects update with AGENT_VERSION_CONFLICT when expected_version does not match', async () => {
    mockCheckPermission.mockResolvedValue(true);
    mockGetAgent.mockResolvedValue({
      _id: AGENT_DB_ID,
      id: AGENT_ID,
      tools: [],
      versions: [{ name: 'v1' }, { name: 'v2' }],
    });
    const tool = buildTool(OWNER);
    const out = await tool.invoke({
      action: 'update',
      agent_id: AGENT_ID,
      name: 'x',
      expected_version: 1,
    });
    expect(out).toMatch(/AGENT_VERSION_CONFLICT/);
    expect(mockUpdateAgent).not.toHaveBeenCalled();
  });

  it('allows update when expected_version matches current version count', async () => {
    mockCheckPermission.mockResolvedValue(true);
    mockGetAgent.mockResolvedValue({
      _id: AGENT_DB_ID,
      id: AGENT_ID,
      tools: [],
      versions: [{ name: 'v1' }, { name: 'v2' }],
    });
    mockUpdateAgent.mockResolvedValue({ id: AGENT_ID, tools: [], versions: [{}, {}, {}] });
    const tool = buildTool(OWNER);
    const out = await tool.invoke({
      action: 'update',
      agent_id: AGENT_ID,
      name: 'x',
      expected_version: 2,
    });
    expect(out).not.toMatch(/^\[/);
    expect(mockUpdateAgent).toHaveBeenCalled();
  });

  it('allows update when expected_version is omitted (last-write-wins preserved for legacy callers)', async () => {
    mockCheckPermission.mockResolvedValue(true);
    mockUpdateAgent.mockResolvedValue({ id: AGENT_ID, tools: [], versions: [{}] });
    const tool = buildTool(OWNER);
    const out = await tool.invoke({ action: 'update', agent_id: AGENT_ID, name: 'x' });
    expect(out).not.toMatch(/^\[/);
    expect(mockUpdateAgent).toHaveBeenCalled();
  });
});

describe('agent_management tool — search input handling', () => {
  it('regex-escapes a malicious search string instead of evaluating it as a live regex', async () => {
    mockGetListAgentsByAccess.mockResolvedValue({ data: [] });
    const tool = buildTool(OWNER);
    const out = await tool.invoke({ action: 'list', search: '.*(evil' });
    expect(out).not.toMatch(/^\[/);
    const call = mockGetListAgentsByAccess.mock.calls[0][0];
    const namePattern = call.otherParams.$or[0].name;
    expect(namePattern.source).toBe('\\.\\*\\(evil');
  });

  it('caps search length to prevent unbounded regex construction', async () => {
    mockGetListAgentsByAccess.mockResolvedValue({ data: [] });
    const tool = buildTool(OWNER);
    const longSearch = 'a'.repeat(500);
    await tool.invoke({ action: 'list', search: longSearch });
    const call = mockGetListAgentsByAccess.mock.calls[0][0];
    const namePattern = call.otherParams.$or[0].name;
    expect(namePattern.source.length).toBeLessThanOrEqual(100);
  });
});

describe('agent_management tool — error surface hygiene', () => {
  it('returns a bracketed [CODE] message for a coded error, never a raw stack trace', async () => {
    mockCheckPermission.mockResolvedValue(false);
    const tool = buildTool(ATTACKER);
    const out = await tool.invoke({ action: 'get', agent_id: AGENT_ID });
    expect(out).toMatch(/^\[[A-Z_]+\] /);
    expect(out).not.toMatch(/at .*\(.*:\d+:\d+\)/); // no stack-trace-shaped line
  });

  it('returns a generic bracketed error for an unexpected internal failure, not the raw exception object', async () => {
    mockCheckPermission.mockResolvedValue(true);
    mockGetAgent.mockImplementation(() => {
      throw new Error('ECONNREFUSED 127.0.0.1:27017');
    });
    const tool = buildTool(OWNER);
    const out = await tool.invoke({ action: 'get', agent_id: AGENT_ID });
    expect(out).toMatch(/^\[AGENT_MANAGEMENT_ERROR\]/);
    expect(typeof out).toBe('string');
  });
});

describe('agent_management tool — share/unshare principal correctness', () => {
  it('share resolves recipient by email and grants via ResourceType.AGENT / PrincipalType.USER only', async () => {
    mockCheckPermission.mockResolvedValue(true);
    mockFindUser.mockResolvedValue({ _id: 'recipient_id', email: 'friend@example.com' });
    const tool = buildTool(OWNER);
    const out = await tool.invoke({
      action: 'share',
      agent_id: AGENT_ID,
      recipient_email: 'FRIEND@example.com',
      access: 'edit',
    });
    expect(out).not.toMatch(/^\[/);
    expect(mockBulkUpdateResourcePermissions).toHaveBeenCalledWith(
      expect.objectContaining({
        resourceType: ResourceType.AGENT,
        resourceId: AGENT_DB_ID,
        updatedPrincipals: [
          expect.objectContaining({ type: PrincipalType.USER, id: 'recipient_id' }),
        ],
        grantedBy: OWNER.id,
      }),
    );
  });

  it('share fails closed with AGENT_RECIPIENT_NOT_FOUND for an unknown email, without granting anything', async () => {
    mockCheckPermission.mockResolvedValue(true);
    mockFindUser.mockResolvedValue(null);
    const tool = buildTool(OWNER);
    const out = await tool.invoke({
      action: 'share',
      agent_id: AGENT_ID,
      recipient_email: 'nobody@example.com',
    });
    expect(out).toMatch(/AGENT_RECIPIENT_NOT_FOUND/);
    expect(mockBulkUpdateResourcePermissions).not.toHaveBeenCalled();
  });
});
