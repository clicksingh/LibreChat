/**
 * 8S5 — archived-agent new-conversation block. A minimal, isolated spec
 * (does not extend initialize.spec.js's DB-backed ACL suite) that stubs
 * `endpointOption.agent` directly, since the archived-state check reads
 * only `primaryAgent.lifecycle_state` and `req.body.conversationId` —
 * no ACL/DB round trip is involved in the check itself.
 */
const mockInitializeAgent = jest.fn();
const mockValidateAgentModel = jest.fn();

jest.mock('@librechat/agents', () => ({
  ...jest.requireActual('@librechat/agents'),
  createContentAggregator: jest.fn(() => ({ contentParts: [], aggregateContent: jest.fn() })),
}));

jest.mock('@librechat/api', () => ({
  ...jest.requireActual('@librechat/api'),
  initializeAgent: (...args) => mockInitializeAgent(...args),
  validateAgentModel: (...args) => mockValidateAgentModel(...args),
  GenerationJobManager: { setCollectedUsage: jest.fn() },
  getCustomEndpointConfig: jest.fn(),
  createSequentialChainEdges: jest.fn(),
}));

jest.mock('~/server/controllers/agents/callbacks', () => ({
  createToolEndCallback: jest.fn(() => jest.fn()),
  getDefaultHandlers: jest.fn(() => ({})),
}));

jest.mock('~/server/services/ToolService', () => ({
  loadAgentTools: jest.fn(),
  loadToolsForExecution: jest.fn(),
}));

jest.mock('~/server/controllers/ModelController', () => ({
  getModelsConfig: jest.fn().mockResolvedValue({}),
}));

let agentClientArgs;
jest.mock('~/server/controllers/agents/client', () => {
  return jest.fn().mockImplementation((args) => {
    agentClientArgs = args;
    return {};
  });
});

jest.mock('./addedConvo', () => ({
  processAddedConvo: jest.fn().mockResolvedValue({ userMCPAuthMap: undefined }),
}));

jest.mock('~/cache', () => ({
  logViolation: jest.fn(),
}));

// No ACL/DB path is exercised by this suite, so ~/models is fully mocked
// (unlike initialize.spec.js, which needs real createAgent/AclEntry).
jest.mock('~/models', () => ({
  getMultiplier: jest.fn(),
  getCacheMultiplier: jest.fn(),
  findAccessibleResources: jest.fn().mockResolvedValue([]),
  getConvo: jest.fn().mockResolvedValue(null),
}));
jest.mock('~/server/services/PermissionService', () => ({
  findAccessibleResources: jest.fn().mockResolvedValue([]),
}));

const { initializeClient } = require('./initialize');

const PRIMARY_ID = 'agent_primary';

function makeReq(conversationId) {
  return {
    user: { id: 'user_1', role: 'USER' },
    body: { conversationId, files: [] },
    config: { endpoints: {} },
    _resumableStreamId: null,
  };
}

function makeEndpointOption({ lifecycle_state } = {}) {
  return {
    agent: Promise.resolve({
      id: PRIMARY_ID,
      name: 'Primary',
      provider: 'openai',
      model: 'gpt-4',
      tools: [],
      lifecycle_state,
    }),
    model_parameters: { model: 'gpt-4' },
    endpoint: 'agents',
  };
}

function makePrimaryConfig() {
  return {
    id: PRIMARY_ID,
    endpoint: 'agents',
    edges: [],
    toolDefinitions: [],
    toolRegistry: new Map(),
    userMCPAuthMap: null,
    tool_resources: {},
    resendFiles: true,
    maxContextTokens: 4096,
  };
}

describe('initializeClient — archived-agent new-conversation block (8S5)', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    agentClientArgs = undefined;
    mockValidateAgentModel.mockResolvedValue({ isValid: true });
    mockInitializeAgent.mockResolvedValue(makePrimaryConfig());
  });

  it('rejects starting a brand-new conversation (no conversationId) with an archived agent', async () => {
    await expect(
      initializeClient({
        req: makeReq(undefined),
        res: {},
        signal: new AbortController().signal,
        endpointOption: makeEndpointOption({ lifecycle_state: 'archived' }),
      }),
    ).rejects.toMatchObject({ status: 400 });
    expect(mockInitializeAgent).not.toHaveBeenCalled();
  });

  it('rejects conversationId === "new" with an archived agent', async () => {
    await expect(
      initializeClient({
        req: makeReq('new'),
        res: {},
        signal: new AbortController().signal,
        endpointOption: makeEndpointOption({ lifecycle_state: 'archived' }),
      }),
    ).rejects.toMatchObject({ status: 400 });
    expect(mockInitializeAgent).not.toHaveBeenCalled();
  });

  it('allows continuing an EXISTING conversation with an archived agent (history is not broken)', async () => {
    await initializeClient({
      req: makeReq('conv_existing_123'),
      res: {},
      signal: new AbortController().signal,
      endpointOption: makeEndpointOption({ lifecycle_state: 'archived' }),
    });
    expect(mockInitializeAgent).toHaveBeenCalledTimes(1);
  });

  it('allows a brand-new conversation with an active agent (positive control)', async () => {
    await initializeClient({
      req: makeReq(undefined),
      res: {},
      signal: new AbortController().signal,
      endpointOption: makeEndpointOption({ lifecycle_state: 'active' }),
    });
    expect(mockInitializeAgent).toHaveBeenCalledTimes(1);
  });

  it('allows a brand-new conversation with an ephemeral/default agent that has no lifecycle_state at all', async () => {
    await initializeClient({
      req: makeReq(undefined),
      res: {},
      signal: new AbortController().signal,
      endpointOption: makeEndpointOption({ lifecycle_state: undefined }),
    });
    expect(mockInitializeAgent).toHaveBeenCalledTimes(1);
  });
});
