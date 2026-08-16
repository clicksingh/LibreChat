/**
 * 8S3C.1 — J3 negative user, RUN_CODE.USE:false (directive item E, journey 3).
 *
 * (a) Browser: the Run Code toggle is hidden (canRunCode), and the outgoing
 *     request carries NO execute_code / document_visual_qa.
 * (b) Host-side forged flag at the chat path: recorded observation, NOT
 *     asserted as denial — codeEnvAvailable is global for all users and the
 *     chat path trusts the client flag (the honest task-F finding).
 * (c) Direct tool-call endpoint: the platform's RUN_CODE gate HOLD — 403
 *     "Forbidden: Insufficient permissions" for a real nocode-owned message.
 */

import { test, expect } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { loginAs } from '../utils/browser';
import { chatRequest, directToolCall, insertMessage, deleteMessage } from '../utils/api';
import { USERS } from '../utils/constants';

test.describe('J3 — negative user (RUN_CODE.USE:false)', () => {
  test('(a) UI hides Run Code toggle; outgoing request carries no capability flags', async ({
    page,
    context,
  }) => {
    const session = await loginAs(context, USERS.nocode.id);
    try {
      const outgoing: any[] = [];
      page.on('request', (req) => {
        if (req.method() === 'POST' && req.url().includes('/api/agents/chat/')) {
          try {
            outgoing.push(JSON.parse(req.postData() || '{}'));
          } catch {
            /* ignore non-JSON */
          }
        }
      });

      await page.goto('/c/new');
      await expect(page).toHaveURL(/\/c\//, { timeout: 60_000 });

      const toolsBtn = page.locator('#tools-dropdown-button').first();
      await expect(toolsBtn).toBeVisible({ timeout: 60_000 });
      await toolsBtn.click();
      const runCodeItem = page.locator('#tools-dropdown-menu div:has-text("Run Code")').first();
      await expect(runCodeItem).not.toBeVisible({ timeout: 5_000 });
      await page.keyboard.press('Escape').catch(() => {});

      const textarea = page.locator('textarea[data-testid="message-input"], textarea').first();
      await textarea.click();
      await textarea.fill('hello');
      await page.keyboard.press('Enter');

      await expect.poll(() => outgoing.length, { timeout: 90_000 }).toBeGreaterThan(0);
      const agent = outgoing[0]?.ephemeralAgent ?? {};
      expect(
        agent.execute_code ?? false,
        `no-code user request must not set execute_code, got ${JSON.stringify(agent)}`,
      ).toBe(false);
      expect(agent.document_visual_qa ?? false).toBe(false);
    } finally {
      await session.cleanup();
    }
  });

  test('(b) forged flag at chat path — recorded observation', async () => {
    const r = await chatRequest(USERS.nocode.id, {
      execute_code: true,
      document_visual_qa: true,
    });
    expect(r.postStatus, `POST should be 200, got ${r.postStatus} (${r.postBody})`).toBe(200);
    test.info().annotations.push({
      type: 'finding',
      description: `chat-path forged flag for nocode user registered tools: [${r.toolTokenCounts.join(', ')}] — chat path trusts client flag; RUN_CODE.USE enforced at UI toggle + direct endpoint only. Recorded for task F, not auto-healed.`,
    });
  });

  test('(c) direct tool-call endpoint enforces RUN_CODE — 403', async () => {
    const messageId = randomUUID();
    await insertMessage(USERS.nocode.id, messageId);
    try {
      const r = await directToolCall(USERS.nocode.id, messageId, null);
      expect(
        r.status,
        `RUN_CODE gate must hold at direct endpoint for nocode user, got ${r.status} ${r.body}`,
      ).toBe(403);
    } finally {
      await deleteMessage(messageId);
    }
  });
});
