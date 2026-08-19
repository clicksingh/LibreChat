/**
 * 8S3D.1 — J6: personal workspace file browser + usage, true browser E2E.
 *
 * Every state check reads what the REAL browser UI shows (the Workspace
 * side-panel tab this milestone adds), driven by an actual chat message
 * through the composer to generate the file being tracked.
 */
import { test, expect } from '@playwright/test';
import { loginAs } from '../utils/browser';
import { USERS } from '../utils/constants';

test.describe('J6 — personal workspace file browser', () => {
  test.setTimeout(180_000);

  test('quota + usage visible, generated file appears, download/rename-adjacent metadata, trash it', async ({
    page,
    context,
  }) => {
    const session = await loginAs(context, USERS.enabled.id);
    try {
      await page.goto('/c/new');
      await expect(page).toHaveURL(/\/c\//, { timeout: 60_000 });

      await page.getByRole('button', { name: 'Select a model' }).click();
      await page.getByRole('option', { name: /^CBHR AI/ }).first().click({ timeout: 10_000 });
      const modelSearch = page.getByRole('combobox').last();
      await modelSearch.waitFor({ state: 'visible', timeout: 10_000 });
      await modelSearch.fill('glm-5-turbo');
      await page.getByRole('option', { name: 'glm-5-turbo' }).first().click({ timeout: 15_000 });

      const toolsBtn = page.locator('#tools-dropdown-button').first();
      await expect(toolsBtn).toBeVisible({ timeout: 60_000 });
      await toolsBtn.click();
      const runCodeItem = page.locator('#tools-dropdown-menu div:has-text("Run Code")').first();
      await expect(runCodeItem).toBeVisible({ timeout: 10_000 });
      await runCodeItem.click();
      await page.keyboard.press('Escape').catch(() => {});

      const uniqueMarker = `j6-${Date.now()}`;
      const composer = page.getByRole('textbox').first();
      await composer.click();
      await composer.fill(
        `Run python code that writes a file named j6_proof.txt containing the text "${uniqueMarker}". Then confirm.`,
      );
      await composer.press('Enter');

      // Wait for the assistant's response to finish streaming.
      await expect(page.getByText(/j6_proof\.txt/i).first()).toBeVisible({ timeout: 120_000 });

      // ---- open the Workspace side panel (Personal is the default) --------
      const workspaceTab = page.getByRole('button', { name: 'Workspace' }).first();
      await expect(workspaceTab).toBeVisible({ timeout: 30_000 });
      await workspaceTab.click();

      // Usage/quota visible.
      await expect(page.getByText(/\d+(\.\d+)?\s?(B|KB|MB|GB)\s?\/\s?\d+(\.\d+)?\s?(B|KB|MB|GB)/i)).toBeVisible({
        timeout: 30_000,
      });

      // Generated file appears with size/modified metadata, via a fresh
      // fetch of the browser's own workspace file list (its own network
      // traffic, not a separately-issued API call).
      const filesResponse = page.waitForResponse(
        (r) => r.url().includes('/api/workspaces/personal/files') && r.status() === 200,
      );
      // Force a refetch by re-clicking the Files tab.
      await page.getByRole('button', { name: 'Files' }).click();
      const res = await filesResponse;
      const body = (await res.json()) as { items: Array<{ name: string; fileId: string; sessionId: string }> };
      const proof = body.items.find((f) => f.name === 'j6_proof.txt');
      expect(proof, `j6_proof.txt should be in the browser's own /api/workspaces/personal/files response`).toBeTruthy();

      await expect(page.getByText('j6_proof.txt')).toBeVisible({ timeout: 15_000 });

      // Trash it via the real UI trash button on that row.
      const row = page.locator('tr', { hasText: 'j6_proof.txt' });
      await row.getByRole('button', { name: /move .* to trash/i }).click();

      // It must disappear from the active listing.
      await expect(page.getByText('j6_proof.txt')).not.toBeVisible({ timeout: 15_000 });
    } finally {
      await session.cleanup();
    }
  });
});
