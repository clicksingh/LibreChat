import { test, expect } from '@playwright/test';
import { loginAs } from '../utils/browser';
import { USERS } from '../utils/constants';
import { parseStream, type ParsedStream } from '../utils/stream';

test.describe('Files v2 managed-user publication boundary', () => {
  test.setTimeout(240_000);

  test('working file stays private while outputs/ result surfaces and tool detail stays collapsed', async ({
    page,
    context,
  }) => {
    const session = await loginAs(context, USERS.enabled.id);
    const stamp = Date.now().toString();
    const scratchName = `scratch_${stamp}.txt`;
    const finalName = `filesv2_final_${stamp}.txt`;

    async function sendAndCapture(text: string): Promise<ParsedStream> {
      const streamRespPromise = page.waitForResponse(
        (r) => r.url().includes('/api/agents/chat/stream/') && r.status() === 200,
        { timeout: 180_000 },
      );
      const textarea = page.locator('textarea[data-testid="message-input"], textarea').first();
      await textarea.click();
      await textarea.fill(text);
      await page.keyboard.press('Enter');
      const streamResp = await streamRespPromise;
      const raw = await streamResp.text();
      await page.waitForTimeout(1500);
      return parseStream(raw);
    }

    try {
      await page.goto('/c/new');
      await expect(page).toHaveURL(/\/c\//, { timeout: 60_000 });

      await expect(page.locator('#tools-dropdown-button')).toHaveCount(0);
      await expect(page.getByRole('button', { name: /select model/i })).toHaveCount(0);

      const turn = await sendAndCapture(
        `Run Python code now. In the persistent workspace create a private working file named "${scratchName}" containing "private working state". Also create the final user deliverable at "outputs/${finalName}" containing "published result". Do not delete either file. Then reply briefly that the result is ready.`,
      );

      expect(turn.toolCalls, JSON.stringify(turn.toolCalls)).toContain('bash_tool');

      const workDone = page.getByRole('button', { name: 'Work completed' }).last();
      await expect(workDone).toBeVisible({ timeout: 30_000 });
      await expect(workDone).toHaveAttribute('aria-expanded', 'false');

      const filesNav = page.getByRole('button', { name: 'Files', exact: true }).first();
      await expect(filesNav).toBeVisible({ timeout: 30_000 });
      await filesNav.click();

      const panel = page.getByTestId('workspace-panel');
      await expect(panel).toBeVisible({ timeout: 30_000 });

      const finalCell = panel.getByText(finalName).first();
      await finalCell.scrollIntoViewIfNeeded({ timeout: 30_000 });
      await expect(finalCell).toBeVisible({ timeout: 20_000 });

      await expect(panel.getByText(scratchName)).toHaveCount(0);

      const row = panel.locator('tr', { hasText: finalName }).first();
      await row.getByRole('button', { name: /move .* to trash/i }).click();
      await expect(panel.getByText(finalName).first()).not.toBeVisible({ timeout: 20_000 });

      await page.getByRole('button', { name: 'Trash', exact: true }).click();
      const trashRow = panel.locator('tr', { hasText: finalName }).first();
      await expect(trashRow).toBeVisible({ timeout: 20_000 });
      await trashRow.getByRole('button', { name: /permanently delete/i }).click();
      await expect(page.getByText('Permanently delete this file?')).toBeVisible({ timeout: 10_000 });
      await page.getByRole('button', { name: 'Permanently delete' }).click();
      await expect(panel.getByText(finalName).first()).not.toBeVisible({ timeout: 20_000 });

      await filesNav.click().catch(() => {});
      const cleanup = await sendAndCapture(
        `Run Python code to delete "${scratchName}" from the persistent workspace if it exists. Print CLEANED when done.`,
      );
      expect(cleanup.toolCalls, JSON.stringify(cleanup.toolCalls)).toContain('bash_tool');
      expect(cleanup.finalText).toMatch(/clean|done|removed|deleted/i);
    } finally {
      await session.cleanup();
    }
  });
});
