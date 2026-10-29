const { Constants, EModelEndpoint, SystemRoles } = require('librechat-data-provider');
const {
  enforceManagedChatEndpoint,
  rejectManagedAssistantEndpoint,
  resolveFundedDefault,
  createAuthorizeManagedSavedAgent,
  matchesManagedAgentPolicy,
  rejectNonAdminRemoteAgentApi,
} = require('./enforceManagedChatEndpoint');

jest.mock('~/server/services/Config', () => ({ getAppConfig: jest.fn() }));
const { getAppConfig } = require('~/server/services/Config');

const COMPANY_ENDPOINT = 'CBHR AI';
const COMPANY_MODEL = 'zai/glm-5.3-flash';
const COMPANY_SPEC = 'cbhr-managed-default';

const makeConfig = () => ({
  modelSpecs: {
    prioritize: true,
    enforce: false,
    list: [
      {
        name: COMPANY_SPEC,
        default: true,
        preset: { endpoint: COMPANY_ENDPOINT, model: COMPANY_MODEL },
      },
    ],
  },
  endpoints: {
    custom: [
      {
        name: COMPANY_ENDPOINT,
        apiKey: '$' + '{LITELLM_MASTER_KEY}',
        baseURL: 'http://litellm:4000/v1',
        models: { default: [COMPANY_MODEL] },
      },
    ],
  },
});

const makeReq = (body, role = SystemRoles.USER, config = makeConfig()) => ({
  user: { id: '6ace7a2699c5e3e643d7548e', role },
  config,
  body,
});

const invoke = (req) => {
  const res = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
  };
  const next = jest.fn();
  enforceManagedChatEndpoint(req, res, next);
  return { res, next };
};

describe('V2 active USER runtime authority against later user/group override drift', () => {
  let previousPort;
  beforeEach(() => {
    previousPort = process.env.MODEL_POLICY_INTERNAL_PORT;
    process.env.MODEL_POLICY_INTERNAL_PORT = '29099';
    jest.clearAllMocks();
  });
  afterEach(() => {
    if (previousPort === undefined) delete process.env.MODEL_POLICY_INTERNAL_PORT;
    else process.env.MODEL_POLICY_INTERNAL_PORT = previousPort;
  });

  async function invokePublished(req) {
    const res = { status: jest.fn().mockReturnThis(), json: jest.fn().mockReturnThis() };
    const next = jest.fn();
    await enforceManagedChatEndpoint(req, res, next);
    return { res, next };
  }

  it('admits the company default when tenant role-only and user-effective configs agree', async () => {
    const roleConfig = makeConfig();
    roleConfig.endpoints.custom[0].default = true;
    getAppConfig.mockResolvedValue(roleConfig);
    const req = makeReq({ endpoint: 'forged', model: 'forged', text: 'hi' });
    req.user.tenantId = 'tenant-qa';
    req.config = JSON.parse(JSON.stringify(roleConfig));
    const { res, next } = await invokePublished(req);
    expect(next).toHaveBeenCalledTimes(1);
    expect(res.status).not.toHaveBeenCalled();
    expect(getAppConfig).toHaveBeenCalledWith({ role: SystemRoles.USER, tenantId: 'tenant-qa' });
    expect(req.body.model).toBe(COMPANY_MODEL);
  });

  it('rejects stale user/group models even after successful publication', async () => {
    const roleConfig = makeConfig();
    roleConfig.endpoints.custom[0].default = true;
    getAppConfig.mockResolvedValue(roleConfig);
    const userConfig = JSON.parse(JSON.stringify(roleConfig));
    userConfig.endpoints.custom[0].models.default = ['stale-user-model'];
    const req = makeReq(
      { endpoint: 'forged', model: 'stale-user-model' },
      SystemRoles.USER,
      userConfig,
    );
    req.user.tenantId = 'tenant-qa';
    const { res, next } = await invokePublished(req);
    expect(res.status).toHaveBeenCalledWith(503);
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects later endpoint addParams.model overriding the same funded model', async () => {
    const roleConfig = makeConfig();
    roleConfig.endpoints.custom[0].default = true;
    getAppConfig.mockResolvedValue(roleConfig);
    const userConfig = JSON.parse(JSON.stringify(roleConfig));
    userConfig.endpoints.custom[0].addParams = { model: 'unfunded-model' };
    const req = makeReq(
      { endpoint: COMPANY_ENDPOINT, model: COMPANY_MODEL },
      SystemRoles.USER,
      userConfig,
    );
    req.user.tenantId = 'tenant-qa';
    const { res, next } = await invokePublished(req);
    expect(res.status).toHaveBeenCalledWith(503);
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects user/group API key or URL replacement with unchanged model', async () => {
    const roleConfig = makeConfig();
    roleConfig.endpoints.custom[0].default = true;
    getAppConfig.mockResolvedValue(roleConfig);
    const userConfig = JSON.parse(JSON.stringify(roleConfig));
    userConfig.endpoints.custom[0].baseURL = 'http://alternate.invalid/v1';
    const req = makeReq(
      { endpoint: COMPANY_ENDPOINT, model: COMPANY_MODEL },
      SystemRoles.USER,
      userConfig,
    );
    req.user.tenantId = 'tenant-qa';
    const { res, next } = await invokePublished(req);
    expect(res.status).toHaveBeenCalledWith(503);
    expect(next).not.toHaveBeenCalled();
  });
});

describe('server-enforced company-funded endpoint for ordinary USER chats', () => {
  it.each([
    ['openAI', 'gpt-4o'],
    ['anthropic', 'claude-sonnet-4-5'],
    ['google', 'gemini-2.5-pro'],
    ['HiddenBYOK', 'private-model'],
    [null, 'missing-model'],
    [{ malicious: true }, 'bad-model'],
  ])('repairs stale or hidden %p endpoint before generation', (endpoint, model) => {
    const req = makeReq({
      endpoint,
      endpointType: 'openAI',
      agent_id: Constants.EPHEMERAL_AGENT_ID,
      model,
      spec: 'old-model-spec',
      text: 'hi',
      conversationId: 'new',
      files: [{ file_id: 'f1' }],
      workspaceId: 'w1',
      ephemeralAgent: { skills: true },
      apiKey: 'should-not-leak',
      baseURL: 'https://untrusted.invalid',
      provider: 'anthropic',
      model_parameters: { model: 'gpt-4o' },
    });
    const { res, next } = invoke(req);

    expect(next).toHaveBeenCalledTimes(1);
    expect(res.status).not.toHaveBeenCalled();
    expect(req.body).toMatchObject({
      endpoint: COMPANY_ENDPOINT,
      endpointType: EModelEndpoint.custom,
      agent_id: Constants.EPHEMERAL_AGENT_ID,
      model: COMPANY_MODEL,
      spec: COMPANY_SPEC,
      text: 'hi',
      conversationId: 'new',
      files: [{ file_id: 'f1' }],
      ephemeralAgent: { skills: true },
      workspaceId: 'w1',
    });
    for (const key of ['apiKey', 'baseURL', 'provider', 'model_parameters']) {
      expect(req.body).not.toHaveProperty(key);
    }
  });

  it('synchronizes client-controlled route endpoint with the corrected body', () => {
    const req = makeReq({ endpoint: 'openAI', model: 'gpt-4o', text: 'hi' });
    req.params = { endpoint: 'openAI' };
    const { next } = invoke(req);
    expect(next).toHaveBeenCalledTimes(1);
    expect(req.params.endpoint).toBe(COMPANY_ENDPOINT);
    expect(req.body.endpoint).toBe(COMPANY_ENDPOINT);
    expect(req.body.model).toBe(COMPANY_MODEL);
  });

  it('refuses inconsistent explicit saved-agent route parameters', () => {
    const req = makeReq({ endpoint: 'agents', agent_id: 'agent_protected', text: 'hi' });
    req.params = { endpoint: 'openAI' };
    const { res, next } = invoke(req);
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(400);
    expect(req.body.agent_id).toBe('agent_protected');
  });

  it('uses the CURRENT principal-scoped default, not a stale YAML modelSpec model', () => {
    const config = makeConfig();
    // These strings deliberately differ from current production provider/model.
    // The first available model is the current admin selection after role merge.
    config.modelSpecs.list[0].preset.model = 'old-irrelevant-provider/old-model';
    config.endpoints.custom[0].models.default = ['new-provider/new-model', 'second-provider/beta'];
    const req = makeReq(
      {
        endpoint: COMPANY_ENDPOINT,
        model: COMPANY_MODEL,
        text: 'hi',
      },
      SystemRoles.USER,
      config,
    );
    const { next, res } = invoke(req);
    expect(next).toHaveBeenCalledTimes(1);
    expect(res.status).not.toHaveBeenCalled();
    expect(req.body.model).toBe('new-provider/new-model');
  });

  it('fails closed when there is no effective model to choose', () => {
    const config = makeConfig();
    config.endpoints.custom[0].models.default = [];
    const { next, res } = invoke(makeReq({ text: 'hi' }, SystemRoles.USER, config));
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(503);
  });

  it('resynchronizes stale model/spec even on an already selected company endpoint', () => {
    const req = makeReq({
      endpoint: COMPANY_ENDPOINT,
      endpointType: EModelEndpoint.custom,
      model: 'gpt-4o',
      spec: 'external-byo-key',
      agent_id: Constants.EPHEMERAL_AGENT_ID,
      text: 'hi',
    });
    const { next } = invoke(req);
    expect(next).toHaveBeenCalledTimes(1);
    expect(req.body.model).toBe(COMPANY_MODEL);
    expect(req.body.spec).toBe(COMPANY_SPEC);
  });

  it('preserves an already valid company selection', () => {
    const body = {
      endpoint: COMPANY_ENDPOINT,
      endpointType: EModelEndpoint.custom,
      agent_id: Constants.EPHEMERAL_AGENT_ID,
      model: COMPANY_MODEL,
      spec: COMPANY_SPEC,
      text: 'hi',
    };
    const req = makeReq({ ...body });
    const { next } = invoke(req);
    expect(next).toHaveBeenCalledTimes(1);
    expect(req.body).toEqual(body);
  });

  it('defers compatible saved-agent review until after resource ACL', () => {
    const req = makeReq({ endpoint: 'agents', agent_id: 'agent_approved' });
    const { next, res } = invoke(req);
    expect(next).toHaveBeenCalledTimes(1);
    expect(res.status).not.toHaveBeenCalled();
    expect(req.managedSavedAgentCandidate).toEqual({ id: 'agent_approved' });
  });

  it('rejects addedConvo multi-agent model bypasses for staff', () => {
    const req = makeReq({
      endpoint: COMPANY_ENDPOINT,
      addedConvo: {
        endpoint: 'agents',
        agent_id: 'agent_other',
        model: 'unfunded',
      },
    });
    const { next, res } = invoke(req);
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it('does not treat an ephemeral agents endpoint as saved-agent authorization', () => {
    const req = makeReq({
      endpoint: 'agents',
      agent_id: Constants.EPHEMERAL_AGENT_ID,
      model: 'gpt-4o',
    });
    const { next } = invoke(req);
    expect(next).toHaveBeenCalledTimes(1);
    expect(req.body.endpoint).toBe(COMPANY_ENDPOINT);
    expect(req.body.model).toBe(COMPANY_MODEL);
  });

  it('does not preserve malformed or missing agent ID as a privileged saved agent', () => {
    const req = makeReq({ endpoint: 'agents', agent_id: { id: 'agent_hidden' }, model: 'gpt-4o' });
    const { next } = invoke(req);
    expect(next).toHaveBeenCalledTimes(1);
    expect(req.body.agent_id).toBe(Constants.EPHEMERAL_AGENT_ID);
    expect(req.body.endpoint).toBe(COMPANY_ENDPOINT);
  });

  it.each([SystemRoles.ADMIN])('does not modify %s selection', (role) => {
    const body = { endpoint: 'openAI', model: 'gpt-4o', spec: 'admin-model' };
    const req = makeReq({ ...body }, role);
    const { next } = invoke(req);
    expect(next).toHaveBeenCalledTimes(1);
    expect(req.body).toEqual(body);
  });

  it('refuses malformed top-level bodies before any job creation', () => {
    const req = makeReq([]);
    const { res, next } = invoke(req);
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(400);
  });

  it.each([
    [{ ...makeConfig(), modelSpecs: { list: [] } }, 'no-admin-default'],
    [{ ...makeConfig(), endpoints: { custom: [] } }, 'no-managed-endpoint'],
    [
      {
        ...makeConfig(),
        endpoints: {
          custom: [
            {
              name: COMPANY_ENDPOINT,
              apiKey: 'user_provided',
              baseURL: 'http://litellm:4000/v1',
              models: { default: [COMPANY_MODEL] },
            },
          ],
        },
      },
      'BYOK-not-funded',
    ],
    [
      {
        ...makeConfig(),
        endpoints: {
          custom: [
            {
              name: COMPANY_ENDPOINT,
              apiKey: '$' + '{LITELLM_MASTER_KEY}',
              baseURL: 'http://litellm:4000/v1',
              models: { default: [] },
            },
          ],
        },
      },
      'model-not-in-funded-catalog',
    ],
  ])('fails closed when company funding is not configured: %s', (config) => {
    const req = makeReq({ endpoint: 'openAI', text: 'hi' }, SystemRoles.USER, config);
    const { res, next } = invoke(req);
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(503);
  });

  it('admits the unique funded V2 default without a legacy modelSpec', () => {
    const config = makeConfig();
    delete config.modelSpecs;
    config.endpoints.custom[0].default = true;
    const req = makeReq(
      { endpoint: 'openAI', model: 'unfunded', spec: 'forged' },
      SystemRoles.USER,
      config,
    );
    const { next, res } = invoke(req);
    expect(next).toHaveBeenCalledTimes(1);
    expect(res.status).not.toHaveBeenCalled();
    expect(req.body).toMatchObject({
      endpoint: COMPANY_ENDPOINT,
      model: COMPANY_MODEL,
      endpointType: EModelEndpoint.custom,
    });
    expect(req.body).not.toHaveProperty('spec');
    expect(resolveFundedDefault(config)).toEqual({
      endpoint: COMPANY_ENDPOINT,
      model: COMPANY_MODEL,
      spec: undefined,
    });
  });

  it('refuses ambiguous or uncredentialed V2 defaults without a legacy modelSpec', () => {
    const config = makeConfig();
    delete config.modelSpecs;
    config.endpoints.custom[0].default = true;
    config.endpoints.custom.push({
      ...config.endpoints.custom[0],
      name: 'Second Central Endpoint',
    });
    expect(resolveFundedDefault(config)).toBeNull();
    config.endpoints.custom[1].default = false;
    config.endpoints.custom[0].apiKey = 'user_provided';
    expect(resolveFundedDefault(config)).toBeNull();
  });

  it('gives the server-marked funded default precedence over a conflicting legacy preset', () => {
    const config = makeConfig();
    config.endpoints.custom[0].default = true;
    config.endpoints.custom.push({
      name: 'Legacy Privileged Endpoint',
      apiKey: 'server-key',
      baseURL: 'http://legacy.internal/v1',
      models: { default: ['old-model'] },
    });
    config.modelSpecs.list[0].preset.endpoint = 'Legacy Privileged Endpoint';
    config.modelSpecs.list[0].preset.model = 'old-model';
    expect(resolveFundedDefault(config)).toEqual({
      endpoint: COMPANY_ENDPOINT,
      model: COMPANY_MODEL,
      spec: undefined,
    });
    const req = makeReq(
      { endpoint: 'Legacy Privileged Endpoint', model: 'old-model', spec: COMPANY_SPEC },
      SystemRoles.USER,
      config,
    );
    const { next } = invoke(req);
    expect(next).toHaveBeenCalledTimes(1);
    expect(req.body.endpoint).toBe(COMPANY_ENDPOINT);
    expect(req.body.model).toBe(COMPANY_MODEL);
    expect(req.body).not.toHaveProperty('spec');
  });

  it('refuses multiple marked defaults even if a legacy preset selects one', () => {
    const config = makeConfig();
    config.endpoints.custom[0].default = true;
    config.endpoints.custom.push({
      name: 'Another Default',
      default: true,
      apiKey: 'server-key',
      baseURL: 'http://another.internal/v1',
      models: { default: ['other-model'] },
    });
    expect(resolveFundedDefault(config)).toBeNull();
  });

  it('only uses the configured default spec and centrally authenticated endpoint', () => {
    expect(resolveFundedDefault(makeConfig())).toEqual({
      endpoint: COMPANY_ENDPOINT,
      model: COMPANY_MODEL,
      spec: COMPANY_SPEC,
    });
  });
});

describe('legacy assistants outside the ordinary managed chat route', () => {
  it('rejects a USER assistant call before any personal key lookup', () => {
    const req = makeReq({ endpoint: 'assistants', assistant_id: 'asst_1' });
    const res = { status: jest.fn().mockReturnThis(), json: jest.fn().mockReturnThis() };
    const next = jest.fn();
    rejectManagedAssistantEndpoint(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        message: 'Use CBHR AI to start a company-funded chat.',
      }),
    );
  });

  it('leaves ADMIN assistant endpoint access unchanged', () => {
    const req = makeReq({ endpoint: 'assistants', assistant_id: 'asst_1' }, SystemRoles.ADMIN);
    const res = { status: jest.fn().mockReturnThis(), json: jest.fn().mockReturnThis() };
    const next = jest.fn();
    rejectManagedAssistantEndpoint(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(res.status).not.toHaveBeenCalled();
  });
});

describe('saved-agent model checks, after existing resource VIEW ACL', () => {
  const allowed = {
    id: 'agent_approved',
    provider: COMPANY_ENDPOINT,
    model: COMPANY_MODEL,
    model_parameters: { model: COMPANY_MODEL, reasoning_effort: 'xhigh' },
  };

  async function checkAgent(saved = allowed, role = SystemRoles.USER) {
    const req = makeReq(
      {
        endpoint: 'agents',
        agent_id: 'agent_approved',
        model: 'forged',
        model_parameters: { apiKey: 'forged' },
        reasoning_effort: 'xhigh',
      },
      role,
    );
    const preflight = invoke(req);
    const response = { status: jest.fn().mockReturnThis(), json: jest.fn().mockReturnThis() };
    const next = jest.fn();
    const getAgent = jest.fn().mockResolvedValue(saved);
    const authorize = createAuthorizeManagedSavedAgent({ getAgent });
    await authorize(req, response, next);
    return { req, preflight, response, next, getAgent };
  }

  it('accepts matching single-agent record and strips request overrides', async () => {
    const { req, next, response, getAgent } = await checkAgent();
    expect(next).toHaveBeenCalledTimes(1);
    expect(response.status).not.toHaveBeenCalled();
    expect(getAgent).toHaveBeenCalledWith({ id: 'agent_approved' });
    expect(req.managedSavedAgentAuth).toEqual({
      id: 'agent_approved',
      model: COMPANY_MODEL,
      endpoint: COMPANY_ENDPOINT,
    });
    expect(req.body.model).toBe(COMPANY_MODEL);
    expect(req.body).not.toHaveProperty('model_parameters');
    expect(req.body).not.toHaveProperty('reasoning_effort');
    expect(req.body.agent_id).toBe('agent_approved');
  });

  it.each([
    [{ ...allowed, provider: 'another-endpoint' }, 'wrong-provider'],
    [{ ...allowed, model: 'unauthorized-model' }, 'wrong-model'],
    [{ ...allowed, model_parameters: { model: 'unauthorized-model' } }, 'parameter-model'],
    [{ ...allowed, edges: [{ source: 'start', target: 'other' }] }, 'graph'],
    [{ ...allowed, agent_ids: ['agent_other'] }, 'legacy-chain'],
    [{ ...allowed, agent_ids: 'malformed-nested-agent' }, 'malformed-chain'],
    [{ ...allowed, subagents: { enabled: true, agent_ids: ['agent_other'] } }, 'subagents'],
    [null, 'missing-agent'],
  ])('denies a saved agent with %s (%s)', async (saved) => {
    const { req, next, response } = await checkAgent(saved);
    expect(next).not.toHaveBeenCalled();
    expect(response.status).toHaveBeenCalledWith(403);
    expect(req.managedSavedAgentAuth).toBeUndefined();
  });

  it('does not query saved agents before VIEW ACL completes', () => {
    const req = makeReq({ endpoint: 'agents', agent_id: 'agent_approved' });
    const getAgent = jest.fn();
    const authorize = createAuthorizeManagedSavedAgent({ getAgent });
    const { next } = invoke(req);
    expect(next).toHaveBeenCalledTimes(1);
    expect(getAgent).not.toHaveBeenCalled();
    expect(typeof authorize).toBe('function');
  });

  it('does not query/alter admin saved-agent model selection', async () => {
    const req = makeReq({ endpoint: 'agents', agent_id: 'agent_admin' }, SystemRoles.ADMIN);
    const getAgent = jest.fn();
    const res = { status: jest.fn().mockReturnThis(), json: jest.fn() };
    const next = jest.fn();
    await createAuthorizeManagedSavedAgent({ getAgent })(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(getAgent).not.toHaveBeenCalled();
  });

  it('checks persisted model using any configured provider and slug', () => {
    const config = makeConfig();
    config.modelSpecs.list[0].preset.endpoint = 'Project Engine';
    config.endpoints.custom[0].name = 'Project Engine';
    config.endpoints.custom[0].models.default = ['manufacturer-q/model-7'];
    const funded = resolveFundedDefault(config);
    expect(
      matchesManagedAgentPolicy(
        {
          id: 'agent_q',
          provider: 'Project Engine',
          model: 'manufacturer-q/model-7',
        },
        funded,
      ),
    ).toBe(true);
    expect(
      matchesManagedAgentPolicy(
        {
          id: 'agent_q',
          provider: 'Project Engine',
          model: 'another-model',
        },
        funded,
      ),
    ).toBe(false);
  });
});

describe('API-key remote-agent alternate request path', () => {
  it.each([SystemRoles.USER, 'E2E_NOCODE', undefined])(
    'denies non-admin role %s after remote authentication',
    (role) => {
      const req = makeReq({ model: 'different-agent-id' }, role);
      const res = { status: jest.fn().mockReturnThis(), json: jest.fn() };
      const next = jest.fn();
      rejectNonAdminRemoteAgentApi(req, res, next);
      expect(res.status).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();
    },
  );

  it('preserves authenticated ADMIN access without rewriting agent identifier', () => {
    const req = makeReq({ model: 'approved-agent-id' }, SystemRoles.ADMIN);
    const res = { status: jest.fn().mockReturnThis(), json: jest.fn() };
    const next = jest.fn();
    rejectNonAdminRemoteAgentApi(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(res.status).not.toHaveBeenCalled();
    expect(req.body.model).toBe('approved-agent-id');
  });
});
