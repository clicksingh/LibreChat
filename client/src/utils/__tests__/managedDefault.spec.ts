import { Constants, EModelEndpoint, LocalStorageKeys } from 'librechat-data-provider';
import type {
  TStartupConfig,
  TEndpointsConfig,
  TModelsConfig,
  TConversation,
  TPreset,
} from 'librechat-data-provider';
import {
  getManagedNewChatPreset,
  applyManagedNewChatPreset,
  reconcileManagedDraftModel,
} from '../managedDefault';

const managedSpec = {
  name: 'cbhr-managed-default',
  label: 'CBHR AI',
  default: true,
  preset: {
    endpoint: 'CBHR AI',
    model: 'glm-5.3-flash',
  },
};
const staleSpec = {
  name: 'other-personal-key-provider',
  label: 'Legacy Provider',
  preset: { endpoint: EModelEndpoint.openAI, model: 'model-needing-key' },
};
const config = {
  modelSpecs: { list: [staleSpec, managedSpec], prioritize: true },
} as TStartupConfig;
const endpoints = {
  'CBHR AI': { type: EModelEndpoint.custom },
  openAI: { type: EModelEndpoint.openAI },
} as unknown as TEndpointsConfig;
const models = { 'CBHR AI': ['glm-5.3-flash'] } as TModelsConfig;
const managedNew = (template: Partial<TConversation> = {}) =>
  getManagedNewChatPreset({
    isManagedUser: true,
    conversationId: Constants.NEW_CONVO as string,
    template,
    startupConfig: config,
    endpointsConfig: endpoints,
    modelsConfig: models,
  });

describe('Managed USER company-provided model default', () => {
  beforeEach(() => localStorage.clear());

  it('selects CBHR AI even if localStorage contains stale personal-key provider and spec', () => {
    localStorage.setItem(
      LocalStorageKeys.LAST_CONVO_SETUP + '_0',
      JSON.stringify({ endpoint: EModelEndpoint.openAI, model: 'model-needing-key' }),
    );
    localStorage.setItem(
      LocalStorageKeys.LAST_MODEL,
      JSON.stringify({ openAI: 'model-needing-key' }),
    );
    const preset = managedNew({ endpoint: EModelEndpoint.openAI, model: 'model-needing-key' });
    expect(preset).toMatchObject({
      endpoint: 'CBHR AI',
      model: 'glm-5.3-flash',
      spec: 'cbhr-managed-default',
    });
  });

  it('normalizes the endpoint type, model, agent ID, and spec instead of mixing old provider state', () => {
    const convo = {
      conversationId: Constants.NEW_CONVO as string,
      endpoint: EModelEndpoint.openAI,
      endpointType: EModelEndpoint.openAI,
      model: 'model-needing-key',
      spec: 'old',
      agent_id: 'stale-agent',
    } as TConversation;
    const selected = applyManagedNewChatPreset(convo, managedNew() as Partial<TPreset>, endpoints);
    expect(selected).toMatchObject({
      endpoint: 'CBHR AI',
      endpointType: EModelEndpoint.custom,
      model: 'glm-5.3-flash',
      spec: 'cbhr-managed-default',
    });
    expect(selected.agent_id).toBeUndefined();
  });

  it('leaves explicitly selected agents or assistants alone', () => {
    expect(managedNew({ endpoint: EModelEndpoint.agents, agent_id: 'chosen' })).toBeUndefined();
    expect(
      managedNew({ endpoint: EModelEndpoint.assistants, assistant_id: 'chosen' }),
    ).toBeUndefined();
  });

  it('does not silently change provider of existing conversation or admin/new advanced user', () => {
    expect(
      getManagedNewChatPreset({
        isManagedUser: true,
        conversationId: 'old-saved-conversation',
        startupConfig: config,
        endpointsConfig: endpoints,
      }),
    ).toBeUndefined();
    expect(
      getManagedNewChatPreset({
        isManagedUser: false,
        conversationId: Constants.NEW_CONVO as string,
        startupConfig: config,
        endpointsConfig: endpoints,
      }),
    ).toBeUndefined();
  });

  it('uses advertised CBHR AI models if admin modelSpec is unavailable', () => {
    expect(
      getManagedNewChatPreset({
        isManagedUser: true,
        conversationId: Constants.NEW_CONVO as string,
        startupConfig: { modelSpecs: { list: [] } } as unknown as TStartupConfig,
        endpointsConfig: endpoints,
        modelsConfig: models,
      }),
    ).toMatchObject({
      endpoint: 'CBHR AI',
      model: 'glm-5.3-flash',
      endpointType: EModelEndpoint.custom,
    });
  });

  it('does not pretend CBHR AI exists if server does not advertise it', () => {
    expect(
      getManagedNewChatPreset({
        isManagedUser: true,
        conversationId: Constants.NEW_CONVO as string,
        startupConfig: { modelSpecs: { list: [] } } as unknown as TStartupConfig,
        endpointsConfig: { openAI: {} } as unknown as TEndpointsConfig,
        modelsConfig: models,
      }),
    ).toBeUndefined();
  });
});

describe('live company default refresh', () => {
  const current = {
    conversationId: Constants.NEW_CONVO as string,
    endpoint: 'CBHR AI',
    model: 'old-default',
    spec: 'cbhr-managed-default',
    chatProjectId: 'saved-project',
    workspaceId: 'saved-workspace',
    title: 'New Chat',
    createdAt: '',
    updatedAt: '',
  } as unknown as TConversation;
  const next = { model: 'glm-5.3-flash', spec: 'cbhr-managed-default' };
  it('updates the blank managed draft without losing project/workspace context', () => {
    expect(reconcileManagedDraftModel(current, next, true)).toEqual({
      ...current,
      model: 'glm-5.3-flash',
    });
  });
  it('is stable once the draft reflects the new company default', () => {
    const changed = reconcileManagedDraftModel(current, next, true) as TConversation;
    expect(reconcileManagedDraftModel(changed, next, true)).toBe(changed);
  });
  it('never changes existing chats, admins, or explicit agent drafts', () => {
    expect(
      reconcileManagedDraftModel({ ...current, conversationId: 'saved' }, next, true)?.model,
    ).toBe('old-default');
    expect(reconcileManagedDraftModel(current, next, false)).toBe(current);
    expect(
      reconcileManagedDraftModel({ ...current, agent_id: 'selected' }, next, true)?.model,
    ).toBe('old-default');
  });
});
