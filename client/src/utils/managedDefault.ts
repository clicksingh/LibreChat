import {
  Constants,
  EModelEndpoint,
  isAgentsEndpoint,
  isAssistantsEndpoint,
} from 'librechat-data-provider';
import type {
  TConversation,
  TPreset,
  TStartupConfig,
  TEndpointsConfig,
  TModelsConfig,
} from 'librechat-data-provider';
import { getModelSpecPreset } from './endpoints';

export const MANAGED_ENDPOINT = 'CBHR AI';

type ManagedDefaultParams = {
  isManagedUser: boolean;
  conversationId?: string | null;
  template?: Partial<TConversation>;
  startupConfig?: TStartupConfig;
  endpointsConfig?: TEndpointsConfig;
  modelsConfig?: TModelsConfig;
};

/**
 * A company-managed new chat must not inherit a personal-key provider from
 * LAST_CONVO_SETUP, LAST_SPEC, LAST_MODEL, URL query settings, or presets.
 * Explicit agent/assistant selection is retained only when it is carried by
 * the caller's *template* (agent picker); a preset alone can be restored
 * automatically from stale browser state and is not proof of user intent.
 *
 * Does not modify an existing conversation, which must retain its historical
 * identity until the user consciously changes the model.
 */
export function getManagedNewChatPreset({
  isManagedUser,
  conversationId,
  template,
  startupConfig,
  endpointsConfig,
  modelsConfig,
}: ManagedDefaultParams): Partial<TPreset> | undefined {
  if (!isManagedUser || conversationId !== Constants.NEW_CONVO) {
    return;
  }
  if (
    template?.agent_id ||
    template?.assistant_id ||
    isAgentsEndpoint(template?.endpoint) ||
    isAssistantsEndpoint(template?.endpoint)
  ) {
    return;
  }

  const specs = startupConfig?.modelSpecs?.list ?? [];
  const managedSpec =
    specs.find((spec) => spec.default && spec.preset?.endpoint === MANAGED_ENDPOINT) ??
    specs.find(
      (spec) => spec.name === 'cbhr-managed-default' && spec.preset?.endpoint === MANAGED_ENDPOINT,
    );
  if (managedSpec) {
    return getModelSpecPreset(managedSpec);
  }

  // A missing spec must never silently fall back to a locally remembered
  // personal-key endpoint. The managed endpoint is only usable when it is
  // actually advertised by the server, and the model comes from its models
  // response (never a browser-stored last-selected provider).
  if (!endpointsConfig?.[MANAGED_ENDPOINT]) {
    return;
  }
  return {
    endpoint: MANAGED_ENDPOINT as EModelEndpoint,
    endpointType: EModelEndpoint.custom,
    model: modelsConfig?.[MANAGED_ENDPOINT]?.[0] ?? '',
  };
}

/** Normalize the new chat's active state as well as its preset. */
export function applyManagedNewChatPreset(
  conversation: TConversation,
  managedPreset: Partial<TPreset>,
  endpointsConfig?: TEndpointsConfig,
): TConversation {
  return {
    ...conversation,
    endpoint: (managedPreset.endpoint as EModelEndpoint | undefined) ?? null,
    endpointType: ((managedPreset.endpoint && endpointsConfig?.[managedPreset.endpoint]?.type) ??
      managedPreset.endpointType) as EModelEndpoint | undefined,
    model: managedPreset.model,
    spec: managedPreset.spec,
    agent_id: undefined,
    assistant_id: undefined,
  };
}

/** Refresh an unsent managed USER draft after the company default changes.
 * Never silently rewrite a saved conversation, admin selection or tool agent. */
export function reconcileManagedDraftModel(
  conversation: TConversation | null | undefined,
  preset: Partial<TPreset> | undefined,
  isManagedUser: boolean,
): TConversation | null | undefined {
  if (
    !isManagedUser ||
    !conversation ||
    conversation.conversationId !== Constants.NEW_CONVO ||
    String(conversation.endpoint ?? '') !== MANAGED_ENDPOINT ||
    !preset?.model ||
    conversation.agent_id ||
    conversation.assistant_id
  ) {
    return conversation;
  }
  if (conversation.model === preset.model && conversation.spec === preset.spec) {
    return conversation;
  }
  return { ...conversation, model: preset.model, spec: preset.spec };
}
