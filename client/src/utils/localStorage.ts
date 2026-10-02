import { LocalStorageKeys, TConversation, isUUID } from 'librechat-data-provider';

function parseStoredJson<T>(value: string, fallback: T): T {
  if (!value) {
    return fallback;
  }
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

export function getLocalStorageItems() {
  const items = {
    lastSelectedModel: localStorage.getItem(LocalStorageKeys.LAST_MODEL) ?? '',
    lastSelectedTools: localStorage.getItem(LocalStorageKeys.LAST_TOOLS) ?? '',
    lastConversationSetup: localStorage.getItem(LocalStorageKeys.LAST_CONVO_SETUP + '_0') ?? '',
  };

  const lastSelectedModel = parseStoredJson<Record<string, string | undefined> | null>(
    items.lastSelectedModel,
    {},
  );
  const lastSelectedTools = parseStoredJson<string[] | null>(items.lastSelectedTools, []);
  const lastConversationSetup = parseStoredJson<Partial<TConversation> | null>(
    items.lastConversationSetup,
    {},
  );

  return {
    lastSelectedModel,
    lastSelectedTools,
    lastConversationSetup,
  };
}

export function clearLocalStorage(skipFirst?: boolean) {
  const keys = Object.keys(localStorage);
  keys.forEach((key) => {
    if (skipFirst === true && key.endsWith('0')) {
      return;
    }
    if (
      key.startsWith(LocalStorageKeys.LAST_MCP_) ||
      key.startsWith(LocalStorageKeys.LAST_CODE_TOGGLE_) ||
      key.startsWith(LocalStorageKeys.ASST_ID_PREFIX) ||
      key.startsWith(LocalStorageKeys.AGENT_ID_PREFIX) ||
      key.startsWith(LocalStorageKeys.LAST_CONVO_SETUP) ||
      key === LocalStorageKeys.LAST_SPEC ||
      key === LocalStorageKeys.LAST_TOOLS ||
      key === LocalStorageKeys.LAST_MODEL ||
      key === LocalStorageKeys.FILES_TO_DELETE
    ) {
      localStorage.removeItem(key);
    }
  });
}

export function clearConversationStorage(conversationId?: string | null) {
  if (!conversationId) {
    return;
  }
  if (!isUUID.safeParse(conversationId)?.success) {
    console.warn(
      `Conversation ID ${conversationId} is not a valid UUID. Skipping local storage cleanup.`,
    );
    return;
  }
  const keys = Object.keys(localStorage);
  keys.forEach((key) => {
    if (key.includes(conversationId)) {
      localStorage.removeItem(key);
    }
  });
}
export function clearAllConversationStorage() {
  const keys = Object.keys(localStorage);
  keys.forEach((key) => {
    if (
      key.startsWith(LocalStorageKeys.LAST_MCP_) ||
      key.startsWith(LocalStorageKeys.LAST_CODE_TOGGLE_) ||
      key.startsWith(LocalStorageKeys.TEXT_DRAFT) ||
      key.startsWith(LocalStorageKeys.ASST_ID_PREFIX) ||
      key.startsWith(LocalStorageKeys.AGENT_ID_PREFIX) ||
      key.startsWith(LocalStorageKeys.LAST_CONVO_SETUP)
    ) {
      localStorage.removeItem(key);
    }
  });
}
