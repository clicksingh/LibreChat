const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const { Constants } = require('librechat-data-provider');
const { agentSchema } = require('@librechat/data-schemas');
const { MongoMemoryServer } = require('mongodb-memory-server');

/**
 * 8S5 — controller-level tests for: expected_version optimistic
 * concurrency, the capability-ceiling 403 translation, and the
 * archived-agent default-hide list filter. Mirrors the existing real-DB
 * + selectively-mocked-collaborators pattern from
 * filterAuthorizedTools.spec.js (real Agent model + real db.* methods via
 * `~/models`, only PermissionService/MCP/Config/Files mocked) — this file
 * additionally mocks `@librechat/api`'s `checkAccessWithRequestCache` so
 * the RUN_CODE.USE outcome is directly controllable per test without
 * needing to seed a real Role document.
 */

const mockGetAllServerConfigs = jest.fn();
const mockUserCanUseMCPServers = jest.fn();
const mockCheckAccessWithRequestCache = jest.fn();

jest.mock('~/server/services/Config', () => ({
  getCachedTools: jest.fn().mockResolvedValue({
    web_search: true,
    execute_code: true,
    bash_tool: true,
    file_search: true,
  }),
}));

jest.mock('~/config', () => ({
  getMCPServersRegistry: jest.fn(() => ({
    getAllServerConfigs: mockGetAllServerConfigs,
  })),
}));

jest.mock('~/server/services/MCP', () => ({
  resolveConfigServers: jest.fn().mockResolvedValue({}),
  createMCPPermissionContext: jest.fn((req) => ({
    canUseServers: (user) => mockUserCanUseMCPServers(user, req),
  })),
  userCanUseMCPServers: (...args) => mockUserCanUseMCPServers(...args),
}));

jest.mock('~/server/services/Files/strategies', () => ({
  getStrategyFunctions: jest.fn(),
}));
jest.mock('~/server/services/Files/images/avatar', () => ({
  resizeAvatar: jest.fn(),
}));
jest.mock('~/server/services/Files/process', () => ({
  filterFile: jest.fn(),
}));

jest.mock('~/server/services/PermissionService', () => ({
  findAccessibleResources: jest.fn().mockResolvedValue([]),
  findPubliclyAccessibleResources: jest.fn().mockResolvedValue([]),
  grantPermission: jest.fn(),
  hasPublicPermission: jest.fn().mockResolvedValue(false),
  checkPermission: jest.fn().mockResolvedValue(true),
}));

jest.mock('~/models', () => {
  const mongoose = require('mongoose');
  const { createModels, createMethods } = require('@librechat/data-schemas');
  createModels(mongoose);
  const methods = createMethods(mongoose);
  return {
    ...methods,
    getCategoriesWithCounts: jest.fn(),
    deleteFileByFilter: jest.fn(),
  };
});

jest.mock('~/cache', () => ({
  getLogStores: jest.fn(() => ({
    get: jest.fn(),
    set: jest.fn(),
    delete: jest.fn(),
  })),
}));

jest.mock('@librechat/api', () => ({
  ...jest.requireActual('@librechat/api'),
  checkAccessWithRequestCache: (...args) => mockCheckAccessWithRequestCache(...args),
}));

const {
  createAgent: createAgentHandler,
  updateAgent: updateAgentHandler,
  getListAgents: getListAgentsHandler,
} = require('./v1');
const { findAccessibleResources } = require('~/server/services/PermissionService');

let Agent;

describe('8S5 controller lifecycle: expected_version, capability ceiling, archived filter', () => {
  let mongoServer;
  let mockReq;
  let mockRes;

  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create();
    const mongoUri = mongoServer.getUri();
    await mongoose.connect(mongoUri);
    Agent = mongoose.models.Agent || mongoose.model('Agent', agentSchema);
  }, 20000);

  afterAll(async () => {
    await mongoose.disconnect();
    await mongoServer.stop();
  });

  beforeEach(async () => {
    await Agent.deleteMany({});
    jest.clearAllMocks();

    mockGetAllServerConfigs.mockResolvedValue({});
    mockUserCanUseMCPServers.mockResolvedValue(true);
    // Default: AGENTS.* checks pass; RUN_CODE.USE denied unless a test grants it.
    mockCheckAccessWithRequestCache.mockImplementation(({ permissionType }) => {
      if (permissionType === 'RUN_CODE') return Promise.resolve(false);
      return Promise.resolve(true);
    });

    mockReq = {
      user: { id: new mongoose.Types.ObjectId().toString(), role: 'USER' },
      body: {},
      params: {},
      query: {},
      app: { locals: { fileStrategy: 'local' } },
    };
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
  });

  describe('updateAgentHandler — expected_version optimistic concurrency', () => {
    let agentId;
    let authorId;

    beforeEach(async () => {
      authorId = new mongoose.Types.ObjectId();
      const agent = await Agent.create({
        id: `agent_${uuidv4()}`,
        name: 'V1',
        provider: 'openai',
        model: 'gpt-4',
        author: authorId,
        tools: [],
        versions: [
          { name: 'V1', provider: 'openai', model: 'gpt-4', tools: [], createdAt: new Date(), updatedAt: new Date() },
          { name: 'V2', provider: 'openai', model: 'gpt-4', tools: [], createdAt: new Date(), updatedAt: new Date() },
        ],
      });
      agentId = agent.id;
    });

    test('returns 409 AGENT_VERSION_CONFLICT when expected_version does not match current', async () => {
      mockReq.user.id = authorId.toString();
      mockReq.params.id = agentId;
      mockReq.body = { name: 'Renamed', expected_version: 1 };

      await updateAgentHandler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(409);
      const payload = mockRes.json.mock.calls[0][0];
      expect(payload.code).toBe('AGENT_VERSION_CONFLICT');
      expect(payload.details).toEqual({ expectedVersion: 1, currentVersion: 2 });

      const stillOriginal = await Agent.findOne({ id: agentId });
      expect(stillOriginal.name).toBe('V1');
    });

    test('succeeds when expected_version matches current version count', async () => {
      mockReq.user.id = authorId.toString();
      mockReq.params.id = agentId;
      mockReq.body = { name: 'Renamed', expected_version: 2 };

      await updateAgentHandler(mockReq, mockRes);

      expect(mockRes.status).not.toHaveBeenCalledWith(409);
      expect(mockRes.json).toHaveBeenCalled();
      const payload = mockRes.json.mock.calls[0][0];
      expect(payload.name).toBe('Renamed');
    });

    test('succeeds when expected_version is omitted (legacy last-write-wins callers unaffected)', async () => {
      mockReq.user.id = authorId.toString();
      mockReq.params.id = agentId;
      mockReq.body = { name: 'Renamed No Version' };

      await updateAgentHandler(mockReq, mockRes);

      expect(mockRes.status).not.toHaveBeenCalledWith(409);
      const payload = mockRes.json.mock.calls[0][0];
      expect(payload.name).toBe('Renamed No Version');
    });
  });

  describe('capability ceiling (8S3C.2 class) — REST controller integration', () => {
    test('createAgentHandler returns 403 AGENT_CAPABILITY_NOT_ALLOWED when creating with execute_code and no RUN_CODE.USE', async () => {
      mockReq.body = {
        name: 'New Agent',
        provider: 'openai',
        model: 'gpt-4',
        tools: ['execute_code'],
      };

      await createAgentHandler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(403);
      const payload = mockRes.json.mock.calls[0][0];
      expect(payload.code).toBe('AGENT_CAPABILITY_NOT_ALLOWED');

      const created = await Agent.findOne({ name: 'New Agent' });
      expect(created).toBeNull();
    });

    test('createAgentHandler succeeds with execute_code when RUN_CODE.USE is granted (positive control)', async () => {
      mockCheckAccessWithRequestCache.mockResolvedValue(true);
      mockReq.body = {
        name: 'Allowed Agent',
        provider: 'openai',
        model: 'gpt-4',
        tools: ['execute_code'],
      };

      await createAgentHandler(mockReq, mockRes);

      expect(mockRes.status).not.toHaveBeenCalledWith(403);
      const created = await Agent.findOne({ name: 'Allowed Agent' });
      expect(created).not.toBeNull();
    });

    test('updateAgentHandler returns 403 when adding execute_code without RUN_CODE.USE', async () => {
      const authorId = new mongoose.Types.ObjectId();
      const agent = await Agent.create({
        id: `agent_${uuidv4()}`,
        name: 'Plain',
        provider: 'openai',
        model: 'gpt-4',
        author: authorId,
        tools: [],
        versions: [{ name: 'Plain', provider: 'openai', model: 'gpt-4', tools: [], createdAt: new Date(), updatedAt: new Date() }],
      });

      mockReq.user.id = authorId.toString();
      mockReq.params.id = agent.id;
      mockReq.body = { tools: ['execute_code'] };

      await updateAgentHandler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(403);
      const payload = mockRes.json.mock.calls[0][0];
      expect(payload.code).toBe('AGENT_CAPABILITY_NOT_ALLOWED');

      const stillPlain = await Agent.findOne({ id: agent.id });
      expect(stillPlain.tools).toEqual([]);
    });

    test('updateAgentHandler re-validates the FULL resulting tool set even when execute_code is untouched by this edit', async () => {
      // Agent already carries execute_code from before RUN_CODE.USE was revoked.
      const authorId = new mongoose.Types.ObjectId();
      const agent = await Agent.create({
        id: `agent_${uuidv4()}`,
        name: 'HasCode',
        provider: 'openai',
        model: 'gpt-4',
        author: authorId,
        tools: ['execute_code'],
        versions: [{ name: 'HasCode', provider: 'openai', model: 'gpt-4', tools: ['execute_code'], createdAt: new Date(), updatedAt: new Date() }],
      });

      mockReq.user.id = authorId.toString();
      mockReq.params.id = agent.id;
      mockReq.body = { name: 'Renamed Only' }; // tools not sent at all

      await updateAgentHandler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(403);
      const stillOriginalName = await Agent.findOne({ id: agent.id });
      expect(stillOriginalName.name).toBe('HasCode');
    });
  });

  describe('getListAgentsHandler — archived agents hidden by default', () => {
    let authorId;

    beforeEach(async () => {
      authorId = new mongoose.Types.ObjectId();
      const active = await Agent.create({
        id: `agent_${uuidv4()}`,
        name: 'Active Agent',
        provider: 'openai',
        model: 'gpt-4',
        author: authorId,
        tools: [],
        lifecycle_state: 'active',
        versions: [{ name: 'Active Agent', provider: 'openai', model: 'gpt-4', tools: [], createdAt: new Date(), updatedAt: new Date() }],
      });
      const archived = await Agent.create({
        id: `agent_${uuidv4()}`,
        name: 'Archived Agent',
        provider: 'openai',
        model: 'gpt-4',
        author: authorId,
        tools: [],
        lifecycle_state: 'archived',
        archivedAt: new Date(),
        archivedBy: authorId,
        versions: [{ name: 'Archived Agent', provider: 'openai', model: 'gpt-4', tools: [], createdAt: new Date(), updatedAt: new Date() }],
      });
      // ACL is out of scope for this describe block — grant VIEW on both via
      // the mock so only the lifecycle_state filter is under test here.
      findAccessibleResources.mockResolvedValue([active._id, archived._id]);
    });

    test('excludes archived agents by default', async () => {
      mockReq.user.id = authorId.toString();
      mockReq.query = {};

      await getListAgentsHandler(mockReq, mockRes);

      const payload = mockRes.json.mock.calls[0][0];
      const names = payload.data.map((a) => a.name);
      expect(names).toContain('Active Agent');
      expect(names).not.toContain('Archived Agent');
    });


    test('includes archived agents when includeArchived=1', async () => {
      mockReq.user.id = authorId.toString();
      mockReq.query = { includeArchived: '1' };

      await getListAgentsHandler(mockReq, mockRes);

      const payload = mockRes.json.mock.calls[0][0];
      const names = payload.data.map((a) => a.name);
      expect(names).toContain('Active Agent');
      expect(names).toContain('Archived Agent');
    });
  });
});
