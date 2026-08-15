import { MAX_SUBAGENTS } from 'librechat-data-provider';
import { agentCreateSchema, agentUpdateSchema, agentSubagentsSchema } from './validation';

describe('agentSubagentsSchema', () => {
  it('accepts enabled:true with a list within the cap', () => {
    const result = agentSubagentsSchema.safeParse({
      enabled: true,
      allowSelf: false,
      agent_ids: ['agent_1', 'agent_2'],
    });
    expect(result.success).toBe(true);
  });

  it('accepts the feature-off shape (enabled:false, no agents)', () => {
    const result = agentSubagentsSchema.safeParse({ enabled: false });
    expect(result.success).toBe(true);
  });

  it('rejects agent_ids longer than MAX_SUBAGENTS', () => {
    const oversized = Array.from({ length: MAX_SUBAGENTS + 1 }, (_, i) => `agent_${i}`);
    const result = agentSubagentsSchema.safeParse({
      enabled: true,
      agent_ids: oversized,
    });
    expect(result.success).toBe(false);
  });

  it('accepts exactly MAX_SUBAGENTS entries', () => {
    const atCap = Array.from({ length: MAX_SUBAGENTS }, (_, i) => `agent_${i}`);
    const result = agentSubagentsSchema.safeParse({
      enabled: true,
      agent_ids: atCap,
    });
    expect(result.success).toBe(true);
  });
});

describe('agentCreateSchema with subagents', () => {
  const base = {
    provider: 'openAI',
    model: 'gpt-4o-mini',
    tools: [],
  };

  it('passes with subagents omitted', () => {
    const result = agentCreateSchema.safeParse(base);
    expect(result.success).toBe(true);
  });

  it('passes with a valid subagents config', () => {
    const result = agentCreateSchema.safeParse({
      ...base,
      subagents: { enabled: true, allowSelf: true, agent_ids: [] },
    });
    expect(result.success).toBe(true);
  });

  it('rejects when subagents.agent_ids exceeds the cap', () => {
    const oversized = Array.from({ length: MAX_SUBAGENTS + 1 }, (_, i) => `agent_${i}`);
    const result = agentCreateSchema.safeParse({
      ...base,
      subagents: { enabled: true, agent_ids: oversized },
    });
    expect(result.success).toBe(false);
  });
});

describe('agentUpdateSchema with subagents', () => {
  it('accepts a partial update with only the disabled flag set', () => {
    const result = agentUpdateSchema.safeParse({
      subagents: { enabled: false, allowSelf: true, agent_ids: [] },
    });
    expect(result.success).toBe(true);
  });

  it('rejects oversized agent_ids on update', () => {
    const oversized = Array.from({ length: MAX_SUBAGENTS + 3 }, (_, i) => `agent_${i}`);
    const result = agentUpdateSchema.safeParse({
      subagents: { enabled: true, agent_ids: oversized },
    });
    expect(result.success).toBe(false);
  });
});

import { validateAgentModel } from './validation';
import { ErrorTypes, ViolationTypes } from 'librechat-data-provider';
import type { Agent, TModelsConfig } from 'librechat-data-provider';
import type { AppConfig } from '@librechat/data-schemas';
import type { Response } from 'express';

describe('validateAgentModel default-model resolver', () => {
  const endpoint = 'cbhr-ai';
  const logViolation = jest.fn().mockResolvedValue(undefined);
  const res = {} as Response;

  function appConfigWithDefault(defaultModel: string | { name: string }): AppConfig {
    return {
      endpoints: {
        custom: [{ name: 'CBHR AI', models: { default: [defaultModel] } }],
      },
    } as unknown as AppConfig;
  }

  function makeAgent(model: string): Agent {
    return { provider: endpoint, model, tools: [] } as unknown as Agent;
  }

  function makeReq(config?: AppConfig) {
    return { config } as unknown as Parameters<typeof validateAgentModel>[0]['req'];
  }

  it('resolves the admin default when a request arrives without a model', async () => {
    const agent = makeAgent('');
    const result = await validateAgentModel({
      req: makeReq(appConfigWithDefault('deepseek-v4-flash')),
      res,
      agent,
      modelsConfig: { [endpoint]: ['deepseek-v4-flash', 'glm-5-turbo'] },
      logViolation,
    });

    expect(result.isValid).toBe(true);
    expect(agent.model).toBe('deepseek-v4-flash');
  });

  it('accepts an object-form model item in models.default', async () => {
    const agent = makeAgent('');
    const result = await validateAgentModel({
      req: makeReq(appConfigWithDefault({ name: 'deepseek-v4-flash' })),
      res,
      agent,
      modelsConfig: { [endpoint]: ['deepseek-v4-flash'] },
      logViolation,
    });

    expect(result.isValid).toBe(true);
    expect(agent.model).toBe('deepseek-v4-flash');
  });

  it('falls back to the first permitted model when the configured default is unavailable', async () => {
    const agent = makeAgent('');
    const result = await validateAgentModel({
      req: makeReq(appConfigWithDefault('removed-model')),
      res,
      agent,
      modelsConfig: { [endpoint]: ['glm-5-turbo', 'deepseek-v4-flash'] },
      logViolation,
    });

    expect(result.isValid).toBe(true);
    expect(agent.model).toBe('glm-5-turbo');
  });

  it('returns MISSING_MODEL when there is no app config to resolve a default from', async () => {
    const agent = makeAgent('');
    const result = await validateAgentModel({
      req: makeReq(),
      res,
      agent,
      modelsConfig: { [endpoint]: ['deepseek-v4-flash'] },
      logViolation,
    });

    expect(result.isValid).toBe(false);
    expect(result.error?.message).toContain(ErrorTypes.MISSING_MODEL);
  });

  it('returns MODELS_NOT_LOADED when the catalog is absent', async () => {
    const agent = makeAgent('');
    const result = await validateAgentModel({
      req: makeReq(appConfigWithDefault('deepseek-v4-flash')),
      res,
      agent,
      modelsConfig: undefined as unknown as TModelsConfig,
      logViolation,
    });

    expect(result.isValid).toBe(false);
    expect(result.error?.message).toContain(ErrorTypes.MODELS_NOT_LOADED);
  });

  it('returns ENDPOINT_MODELS_NOT_LOADED when the endpoint has no usable models', async () => {
    const agent = makeAgent('');
    const result = await validateAgentModel({
      req: makeReq(appConfigWithDefault('deepseek-v4-flash')),
      res,
      agent,
      modelsConfig: { [endpoint]: [] },
      logViolation,
    });

    expect(result.isValid).toBe(false);
    expect(result.error?.message).toContain(ErrorTypes.ENDPOINT_MODELS_NOT_LOADED);
  });

  it('keeps an explicit valid model untouched', async () => {
    const agent = makeAgent('glm-5-turbo');
    const result = await validateAgentModel({
      req: makeReq(appConfigWithDefault('deepseek-v4-flash')),
      res,
      agent,
      modelsConfig: { [endpoint]: ['deepseek-v4-flash', 'glm-5-turbo'] },
      logViolation,
    });

    expect(result.isValid).toBe(true);
    expect(agent.model).toBe('glm-5-turbo');
  });

  it('keeps ILLEGAL_MODEL_REQUEST for an explicit model outside the catalog', async () => {
    const agent = makeAgent('forbidden-model');
    const result = await validateAgentModel({
      req: makeReq(appConfigWithDefault('deepseek-v4-flash')),
      res,
      agent,
      modelsConfig: { [endpoint]: ['deepseek-v4-flash'] },
      logViolation,
    });

    expect(result.isValid).toBe(false);
    expect(result.error?.message).toContain(ViolationTypes.ILLEGAL_MODEL_REQUEST);
    expect(logViolation).toHaveBeenCalled();
  });
});
