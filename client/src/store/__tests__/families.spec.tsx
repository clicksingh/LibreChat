import { useEffect } from 'react';
import { render, waitFor } from '@testing-library/react';
import { RecoilRoot, useSetRecoilState } from 'recoil';
import type { TConversation } from 'librechat-data-provider';
import store from '../families';

const baseConversation = {
  conversationId: 'new',
  createdAt: '',
  updatedAt: '',
  endpoint: 'CBHR AI',
  model: 'zai/glm-5.3-flash',
  title: 'New Chat',
} as unknown as TConversation;

function ConversationWriter({ effort }: { effort: string }) {
  const setConversation = useSetRecoilState(store.conversationByIndex(0));

  useEffect(() => {
    setConversation({
      ...baseConversation,
      reasoning_effort: effort,
    } as TConversation);
  }, [effort, setConversation]);

  return null;
}

describe('conversationByIndex blank-chat URL effect', () => {
  beforeEach(() => {
    window.history.replaceState(
      {},
      '',
      '/c/new?endpoint=CBHR+AI&model=zai%2Fglm-5.3-flash&reasoning_effort=high',
    );
  });

  afterEach(() => {
    jest.restoreAllMocks();
    window.history.replaceState({}, '', '/');
  });

  it('does not push duplicate history when settings already match the current URL', async () => {
    const pushState = jest.spyOn(window.history, 'pushState');

    const { rerender } = render(
      <RecoilRoot>
        <ConversationWriter effort="max" />
      </RecoilRoot>,
    );

    await waitFor(() => expect(pushState).not.toHaveBeenCalled());

    rerender(
      <RecoilRoot>
        <ConversationWriter effort="high" />
      </RecoilRoot>,
    );

    await waitFor(() => expect(pushState).not.toHaveBeenCalled());
  });
});
