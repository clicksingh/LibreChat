import { Constants } from 'librechat-data-provider';
import type { EventSubmission, TMessage } from 'librechat-data-provider';
import {
  buildCreatedInitialResponse,
  getExistingConversationAbortMessages,
  isInitialNewConversationSubmission,
  mergeRegenerateFinalMessages,
  reconcileStreamFailureMessages,
} from '~/hooks/SSE/useEventHandlers';

describe('buildCreatedInitialResponse', () => {
  const userMessage = {
    messageId: 'server-user-message',
    conversationId: 'conversation-1',
    isCreatedByUser: true,
    text: 'Hello',
    sender: 'User',
  } as TMessage;

  const initialResponse = {
    messageId: 'prelim-response',
    parentMessageId: 'original-user-message',
    conversationId: 'conversation-1',
    isCreatedByUser: false,
    text: '',
    sender: 'Assistant',
  } as TMessage;

  it('uses the created user message id for new turns', () => {
    expect(
      buildCreatedInitialResponse({
        initialResponse,
        userMessage,
        isRegenerate: false,
      }),
    ).toEqual(
      expect.objectContaining({
        messageId: 'server-user-message_',
        parentMessageId: 'server-user-message',
      }),
    );
  });

  it('preserves the regenerated prelim response id and parent', () => {
    expect(
      buildCreatedInitialResponse({
        initialResponse,
        userMessage,
        isRegenerate: true,
      }),
    ).toEqual(
      expect.objectContaining({
        messageId: 'prelim-response',
        parentMessageId: 'original-user-message',
      }),
    );
  });
});

describe('isInitialNewConversationSubmission', () => {
  it('treats a root user message as an optimistic new chat', () => {
    expect(
      isInitialNewConversationSubmission({
        userMessage: {
          messageId: 'user-1',
          parentMessageId: Constants.NO_PARENT,
        } as TMessage,
      } as EventSubmission),
    ).toBe(true);
  });

  it('does not treat follow-up turns as optimistic new chats', () => {
    expect(
      isInitialNewConversationSubmission({
        userMessage: {
          messageId: 'user-2',
          parentMessageId: 'assistant-1',
        } as TMessage,
      } as EventSubmission),
    ).toBe(false);
  });
});

describe('mergeRegenerateFinalMessages', () => {
  const userMessage = (messageId: string, parentMessageId: string = Constants.NO_PARENT) =>
    ({
      messageId,
      parentMessageId,
      conversationId: 'conversation-1',
      isCreatedByUser: true,
      sender: 'User',
      text: messageId,
    }) as TMessage;

  const assistantMessage = (messageId: string, parentMessageId: string) =>
    ({
      messageId,
      parentMessageId,
      conversationId: 'conversation-1',
      isCreatedByUser: false,
      sender: 'Assistant',
      text: messageId,
    }) as TMessage;

  it('keeps the original branch siblings when a non-tail regenerate finalizes', () => {
    const rootUser = userMessage('user-1');
    const originalResponse = assistantMessage('assistant-1', rootUser.messageId);
    const followUpUser = userMessage('user-2', originalResponse.messageId);
    const followUpResponse = assistantMessage('assistant-2', followUpUser.messageId);
    const finalResponse = assistantMessage('assistant-3', rootUser.messageId);

    expect(
      mergeRegenerateFinalMessages({
        messages: [rootUser, originalResponse, followUpUser, followUpResponse],
        responseMessage: finalResponse,
        initialResponseId: 'assistant-1_',
      }).map((message) => message.messageId),
    ).toEqual([
      rootUser.messageId,
      originalResponse.messageId,
      followUpUser.messageId,
      followUpResponse.messageId,
      finalResponse.messageId,
    ]);
  });

  it('replaces the streamed preliminary response when it is present', () => {
    const rootUser = userMessage('user-1');
    const preliminaryResponse = assistantMessage('assistant-1_', rootUser.messageId);
    const finalResponse = assistantMessage('assistant-3', rootUser.messageId);

    expect(
      mergeRegenerateFinalMessages({
        messages: [rootUser, preliminaryResponse],
        responseMessage: finalResponse,
        initialResponseId: preliminaryResponse.messageId,
      }).map((message) => message.messageId),
    ).toEqual([rootUser.messageId, finalResponse.messageId]);
  });
});

describe('getExistingConversationAbortMessages', () => {
  const message = (messageId: string) =>
    ({
      messageId,
      conversationId: 'conversation-1',
      text: messageId,
    }) as TMessage;

  it('restores the full pre-regenerate branch on early abort', () => {
    const originalMessages = [message('user-1'), message('assistant-1'), message('user-2')];
    const scopedRegenerateMessages = [message('user-1')];
    const currentStreamMessages = [message('user-1'), message('assistant-1_')];

    expect(
      getExistingConversationAbortMessages({
        messages: scopedRegenerateMessages,
        currentMessages: currentStreamMessages,
        regenerateMessages: originalMessages,
        isRegenerate: true,
      }).map(({ messageId }) => messageId),
    ).toEqual(['user-1', 'assistant-1', 'user-2']);
  });

  it('keeps the existing non-regenerate abort rollback behavior', () => {
    const submissionMessages = [message('user-1')];
    const currentMessages = [message('user-1'), message('assistant-1')];

    expect(
      getExistingConversationAbortMessages({
        messages: submissionMessages,
        currentMessages,
      }).map(({ messageId }) => messageId),
    ).toEqual(['user-1']);
  });
});

describe('reconcileStreamFailureMessages', () => {
  const message = (id: string, isCreatedByUser: boolean, parentMessageId = '') =>
    ({
      messageId: id,
      parentMessageId,
      conversationId: 'conv-1',
      isCreatedByUser,
      text: '',
    }) as TMessage;

  it('keeps streamed content and appends a visible error instead of resetting the turn', () => {
    const user = message('user-1', true);
    const partial = {
      ...message('response-1', false, user.messageId),
      content: [{ type: 'text', text: 'Work completed before disconnect' }],
    } as TMessage;
    const error = { ...message('error-1', false, user.messageId), text: 'terminated' };
    const messages = reconcileStreamFailureMessages({
      messages: [],
      currentMessages: [user, partial],
      userMessage: user,
      errorMessage: error,
    });

    expect(messages).toHaveLength(2);
    expect(messages[1]).toEqual(
      expect.objectContaining({
        messageId: partial.messageId,
        unfinished: true,
        content: [
          { type: 'text', text: 'Work completed before disconnect' },
          { type: 'error', error: 'terminated' },
        ],
      }),
    );
  });

  it('does not mix another conversation into a failed response', () => {
    const user = message('user-1', true);
    const unrelated = {
      ...message('response-2', false, 'user-2'),
      conversationId: 'other-conversation',
      content: [{ type: 'text', text: 'Unrelated' }],
    } as TMessage;
    const error = { ...message('error-1', false, user.messageId), text: 'terminated' };

    const messages = reconcileStreamFailureMessages({
      messages: [],
      currentMessages: [unrelated],
      userMessage: user,
      errorMessage: error,
    });
    expect(messages.map((msg) => msg.messageId)).toEqual(['user-1', 'error-1']);
  });
});
