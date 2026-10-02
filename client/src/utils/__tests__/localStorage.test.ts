import { LocalStorageKeys } from 'librechat-data-provider';
import { getLocalStorageItems } from '../localStorage';

describe('getLocalStorageItems', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('parses valid stored conversation state', () => {
    localStorage.setItem(LocalStorageKeys.LAST_MODEL, JSON.stringify({ 'CBHR AI': 'glm-5.1' }));
    localStorage.setItem(LocalStorageKeys.LAST_TOOLS, JSON.stringify(['tool-a']));
    localStorage.setItem(
      LocalStorageKeys.LAST_CONVO_SETUP + '_0',
      JSON.stringify({ conversationId: 'new', model: 'glm-5.1' }),
    );

    expect(getLocalStorageItems()).toEqual({
      lastSelectedModel: { 'CBHR AI': 'glm-5.1' },
      lastSelectedTools: ['tool-a'],
      lastConversationSetup: { conversationId: 'new', model: 'glm-5.1' },
    });
  });

  it('falls back safely when legacy storage contains malformed JSON', () => {
    localStorage.setItem(LocalStorageKeys.LAST_MODEL, 'glm-5.1');
    localStorage.setItem(LocalStorageKeys.LAST_TOOLS, 'not-json');
    localStorage.setItem(LocalStorageKeys.LAST_CONVO_SETUP + '_0', '{broken');

    expect(getLocalStorageItems()).toEqual({
      lastSelectedModel: {},
      lastSelectedTools: [],
      lastConversationSetup: {},
    });
  });
});
