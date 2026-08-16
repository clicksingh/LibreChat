/**
 * 8S3C.1 — J1 normal enabled user (directive item E, journey 1).
 *
 * The REAL UI path: a user with Run Code enabled opens a fresh conversation,
 * toggles Run Code, sends a message, and the outgoing request couples
 * document_visual_qa onto execute_code (task B proof through the browser).
 *
 * Selectors mirror verify-browser-ui-path.js (task A), which proved this path
 * pre-fix. The classifier asserted pre-fix is now the coupling assertion.
 */

import { test, expect } from '@playwright/test';
import { loginAs } from '../utils/browser';
import { USERS } from '../utils/constants';

test.describe('J1 — normal enabled user', () => {
  test('Run Code toggle visible → on → outgoing request couples document_visual_qa', async ({
    page,
    context,
  }) => {
    const session = await loginAs(context, USERS.enabled.id);
    try {
      // Capture the outgoing agent-chat request(s) — the request-state surface.
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

      // Tools dropdown + Run Code item visible for a RUN_CODE.USE user.
      const toolsBtn = page.locator('#tools-dropdown-button').first();
      await expect(toolsBtn).toBeVisible({ timeout: 60_000 });
      await toolsBtn.click();
      const runCodeItem = page.locator('#tools-dropdown-menu div:has-text("Run Code")').first();
      await expect(runCodeItem).toBeVisible({ timeout: 10_000 });

      // Snapshot toggle state BEFORE clicking so the persistence assertion proves
      // the click flipped it (the app pre-seeds LAST_CODE_TOGGLE_pinned:"false"
      // and also writes a _TIMESTAMP key on toggle).
      const readToggleKeys = () => {
        const out: Record<string, string> = {};
        for (let i = 0; i < localStorage.length; i++) {
          const k = localStorage.key(i);
          if (k && k.startsWith('LAST_CODE_TOGGLE_')) out[k] = localStorage.getItem(k) ?? '';
        }
        return out;
      };
      const preToggle = await page.evaluate(readToggleKeys);
      await runCodeItem.click();
      await page.keyboard.press('Escape').catch(() => {});
      const postToggle = await page.evaluate(readToggleKeys);

      // Toggle persisted: some LAST_CODE_TOGGLE_* key moved to 'true' on click.
      const flippedTrue = Object.entries(postToggle).some(
        ([k, v]) => v === 'true' && preToggle[k] !== 'true',
      );
      expect(
        flippedTrue,
        `Run Code click must flip a LAST_CODE_TOGGLE_* to 'true'. pre=${JSON.stringify(preToggle)} post=${JSON.stringify(postToggle)}`,
      ).toBe(true);

      // Send a message through the real composer.
      const textarea = page.locator('textarea[data-testid="message-input"], textarea').first();
      await textarea.click();
      await textarea.fill('Use bash to run python3 -c "print(2+2)" and reply with just the number.');
      await page.keyboard.press('Enter');

      // The coupling proof: applyVisualQaToRequest (task B) adds
      // document_visual_qa to any agent carrying execute_code.
      await expect.poll(() => outgoing.length, { timeout: 90_000 }).toBeGreaterThan(0);
      const agent = outgoing[0]?.ephemeralAgent ?? {};
      expect(agent.execute_code, 'execute_code must be true').toBe(true);
      expect(
        agent.document_visual_qa,
        `document_visual_qa must be true (coupled by applyVisualQaToRequest), got ${JSON.stringify(agent)}`,
      ).toBe(true);
    } finally {
      await session.cleanup();
    }
  });
});
