const { Constants, EModelEndpoint, SystemRoles } = require('librechat-data-provider');
const { enforceManagedChatEndpoint, resolveFundedDefault } = require('./enforceManagedChatEndpoint');

const COMPANY_ENDPOINT = 'CBHR AI';
const COMPANY_MODEL = 'zai/glm-5.3-flash';
const COMPANY_SPEC = 'cbhr-managed-default';

const makeConfig = () => ({
  modelSpecs: {
    prioritize: true,
    enforce: false,
    list: [{
      name: COMPANY_SPEC,
      default: true,
      preset: { endpoint: COMPANY_ENDPOINT, model: COMPANY_MODEL },
    }],
  },
  endpoints: {
    custom: [{
      name: COMPANY_ENDPOINT,
      apiKey: '$' + '{LITELLM_MASTER_KEY}',
      baseURL: 'http://litellm:4000/v1',
    }],
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
      endpoint: COMPANY_ENDPOINT, endpointType: EModelEndpoint.custom,
      agent_id: Constants.EPHEMERAL_AGENT_ID,
      model: COMPANY_MODEL, spec: COMPANY_SPEC, text: 'hi',
    };
    const req = makeReq({ ...body });
    const { next } = invoke(req);
    expect(next).toHaveBeenCalledTimes(1);
    expect(req.body).toEqual(body);
  });

  it('preserves an explicitly selected persisted agent for existing VIEW ACL checks', () => {
    const body = { endpoint: 'agents', agent_id: 'agent_approved', model: 'my-model', spec: 'saved-agent' };
    const req = makeReq({ ...body });
    const { next } = invoke(req);
    expect(next).toHaveBeenCalledTimes(1);
    expect(req.body).toEqual(body);
  });

  it('does not treat an ephemeral agents endpoint as saved-agent authorization', () => {
    const req = makeReq({ endpoint: 'agents', agent_id: Constants.EPHEMERAL_AGENT_ID, model: 'gpt-4o' });
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

  it.each([SystemRoles.ADMIN, 'SPECIAL_ROLE'])('does not modify %s selection', (role) => {
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
    [{
      ...makeConfig(),
      endpoints: { custom: [{ name: COMPANY_ENDPOINT, apiKey: 'user_provided', baseURL: 'http://litellm:4000/v1' }] },
    }, 'BYOK-not-funded'],
  ])('fails closed when company funding is not configured: %s', (config) => {
    const req = makeReq({ endpoint: 'openAI', text: 'hi' }, SystemRoles.USER, config);
    const { res, next } = invoke(req);
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(503);
  });

  it('only uses the configured default spec and centrally authenticated endpoint', () => {
    expect(resolveFundedDefault(makeConfig())).toEqual({
      endpoint: COMPANY_ENDPOINT, model: COMPANY_MODEL, spec: COMPANY_SPEC,
    });
  });
});
