import { expect, test } from '@playwright/test';
import { withMongo } from './db';
import {
  MOCK_ENDPOINTS,
  NEW_CHAT_PATH,
  messagesView,
  selectMockEndpoint,
  sendMessage,
} from './helpers';

test.describe('generation finalization invariant', () => {
  test('preserves an interrupted assistant checkpoint without reporting a successful completion', async ({
    page,
  }) => {
    test.setTimeout(90_000);
    const label = `completion-error-${Date.now()}`;

    await page.goto(NEW_CHAT_PATH, { timeout: 10000 });
    await selectMockEndpoint(page, MOCK_ENDPOINTS[0]);

    // This is deliberately NOT sendMessageAndWaitForCompletion: a failed
    // generation retains unfinished:true with an error content part, rather
    // than masquerading as a successful, fully finalized model answer.
    const admission = await sendMessage(page, `E2E_FORCED_ERROR:${label}`);
    expect(admission.ok()).toBeTruthy();
    const { conversationId } = (await admission.json()) as { conversationId?: string };
    expect(conversationId).toMatch(/^[0-9a-f-]{36}$/);

    const persistedFailure = async () =>
      withMongo(async (db) => {
        const user = await db.collection('messages').findOne({
          conversationId,
          isCreatedByUser: true,
          text: `E2E_FORCED_ERROR:${label}`,
        });
        const assistant = await db.collection('messages').findOne({
          conversationId,
          isCreatedByUser: false,
          'content.type': 'error',
        });
        const errorPart = assistant?.content?.find(
          (part: { type?: string }) => part.type === 'error',
        );
        const receipt = assistant?.metadata?.interruption;
        return {
          hasUser: !!user,
          correctParent: !!user && assistant?.parentMessageId === user.messageId,
          unfinished: assistant?.unfinished === true,
          notSuccess: assistant?.error !== true,
          hasBoundedError:
            typeof errorPart?.error === 'string' &&
            errorPart.error.startsWith('MODEL_REQUEST_INTERRUPTED:') &&
            !errorPart.error.includes('E2E forced stream error'),
          receiptFailureClass: receipt?.failureClass ?? null,
          noCompletedTools:
            Array.isArray(receipt?.completedTools) && receipt.completedTools.length === 0,
          noUncertainTools:
            Array.isArray(receipt?.uncertainTools) && receipt.uncertainTools.length === 0,
          sideEffectsNotReplayed: receipt?.sideEffectsAutoReplayed === false,
        };
      });

    const expected = {
      hasUser: true,
      correctParent: true,
      unfinished: true,
      notSuccess: true,
      hasBoundedError: true,
      receiptFailureClass: 'agent_exception',
      noCompletedTools: true,
      noUncertainTools: true,
      sideEffectsNotReplayed: true,
    };
    await expect.poll(persistedFailure, { timeout: 40_000 }).toEqual(expected);
    await expect(
      messagesView(page).getByRole('alert').filter({ hasText: 'MODEL_REQUEST_INTERRUPTED:' }),
    ).toBeVisible();
    await page.reload();
    await expect(
      messagesView(page).getByRole('alert').filter({ hasText: 'MODEL_REQUEST_INTERRUPTED:' }),
    ).toBeVisible();
    expect(await persistedFailure()).toEqual(expected);
  });
});
