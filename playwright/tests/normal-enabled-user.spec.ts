/**
 * CBHR managed USER acceptance.
 *
 * Regular users receive the approved model/tool policy automatically. The UI
 * intentionally hides model/tool/MCP selectors so staff cannot accidentally
 * disable document handling or web research.
 */

import { test, expect } from '@playwright/test';
import { loginAs } from '../utils/browser';
import { USERS } from '../utils/constants';

test.describe('CBHR managed regular user', () => {
  test('hidden controls, forced model, and approved tools are active by default', async ({
    page,
    context,
  }) => {
    const session = await loginAs(context, USERS.enabled.id);
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

      // Simulate the exact legacy failure mode: this browser previously saved
      // every user-facing tool toggle OFF and no MCP selection.
      await page.addInitScript(() => {
        const suffix = '__defaults__';
        const poisoned: Record<string, string> = {
          ['LAST_CODE_TOGGLE_' + suffix]: 'false',
          ['LAST_FILE_SEARCH_TOGGLE_' + suffix]: 'false',
          ['LAST_WEB_SEARCH_TOGGLE_' + suffix]: 'false',
          ['LAST_ARTIFACTS_TOGGLE_' + suffix]: 'false',
          ['LAST_SKILLS_TOGGLE_' + suffix]: 'false',
          ['LAST_MCP_' + suffix]: '[]',
        };
        const now = Date.now().toString();
        for (const [key, value] of Object.entries(poisoned)) {
          localStorage.setItem(key, value);
          localStorage.setItem(key + '_TIMESTAMP', now);
        }
        localStorage.setItem('lastSelectedModel', 'glm-5.1');
      });

      await page.goto('/c/new');
      await expect(page).toHaveURL(/\/c\//, { timeout: 60_000 });

      // Managed USER UX: no model picker and no tool/MCP controls.
      await expect(page.locator('#tools-dropdown-button')).toHaveCount(0);
      await expect(page.getByRole('button', { name: /select model/i })).toHaveCount(0);
      await expect(page.getByText('UltraSearch', { exact: true })).toHaveCount(0);

      // Hiding tool controls must not hide the document/file entry point.
      await expect(page.getByRole('button', { name: /attach file options/i })).toBeVisible();

      // Send through the real composer and inspect the actual request-state surface.
      const textarea = page.locator('textarea[data-testid="message-input"], textarea').first();
      await textarea.click();
      await textarea.fill('Reply with the word ready.');
      await page.keyboard.press('Enter');

      await expect.poll(() => outgoing.length, { timeout: 90_000 }).toBeGreaterThan(0);
      const body = outgoing[0] ?? {};
      const agent = body.ephemeralAgent ?? {};

      expect(agent.execute_code, JSON.stringify(agent)).toBe(true);
      expect(agent.document_visual_qa, JSON.stringify(agent)).toBe(true);
      expect(agent.file_search, JSON.stringify(agent)).toBe(true);
      expect(agent.skills, JSON.stringify(agent)).toBe(true);
      expect(agent.artifacts, JSON.stringify(agent)).toBe('default');
      expect(agent.web_search ?? false, JSON.stringify(agent)).toBe(false);
      expect(agent.mcp, JSON.stringify(agent)).toEqual(['ultrasearch']);

      // Hidden model value must be the current managed default, not browser history.
      expect(body.model).toBe('zai/glm-5.3-flash');
    } finally {
      await session.cleanup();
    }
  });
});
