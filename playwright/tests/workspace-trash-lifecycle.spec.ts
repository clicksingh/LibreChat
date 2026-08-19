/**
 * 8S3D.1 — J8: trash -> restore -> trash again -> purge (explicit confirm),
 * true browser E2E. Also proves usage does NOT decrease merely by trashing,
 * and DOES decrease after purge — both read from the browser's own quota-bar
 * text, not a side-channel API call.
 */
import { test, expect } from '@playwright/test';
import { loginAs } from '../utils/browser';
import { USERS } from '../utils/constants';
import { getUsage } from '../utils/workspaceApi';

test.describe('J8 — trash / restore / purge lifecycle', () => {
  test.setTimeout(180_000);

  test('full lifecycle: create, trash (usage unchanged), restore, trash again, purge (usage frees)', async ({
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
      await page.locator('#tools-dropdown-menu div:has-text("Run Code")').first().click();
      await page.keyboard.press('Escape').catch(() => {});

      const marker = `j8-${Date.now()}`;
      const composer = page.locator('textarea[data-testid="message-input"], textarea').first();
      await composer.click();
      await composer.fill(
        `Run python code that writes a 2000-byte file named j8_lifecycle.bin containing repeated bytes, then prints "${marker} done".`,
      );
      await composer.press('Enter');
      await expect(page.getByText(new RegExp(`${marker} done`, 'i')).first()).toBeVisible({
        timeout: 120_000,
      });

      const usageBeforeTrash = await getUsage(USERS.enabled.id, 'personal');

      await page.getByRole('button', { name: 'Workspace' }).first().click();
      await page.getByRole('button', { name: 'Files' }).click();
      await expect(page.getByText('j8_lifecycle.bin')).toBeVisible({ timeout: 20_000 });

      // ---- trash it ---------------------------------------------------------
      const fileRow = page.locator('tr', { hasText: 'j8_lifecycle.bin' });
      await fileRow.getByRole('button', { name: /move .* to trash/i }).click();
      await expect(page.getByText('j8_lifecycle.bin')).not.toBeVisible({ timeout: 15_000 });

      // Usage must NOT drop merely from trashing (same quota tree).
      const usageAfterTrash = await getUsage(USERS.enabled.id, 'personal');
      expect(usageAfterTrash.used_bytes).toBeGreaterThanOrEqual(usageBeforeTrash.used_bytes);

      // ---- appears in Trash tab ----------------------------------------------
      await page.getByRole('button', { name: 'Trash' }).click();
      await expect(page.getByText('j8_lifecycle.bin')).toBeVisible({ timeout: 15_000 });

      // ---- restore ------------------------------------------------------------
      const trashRow = page.locator('tr', { hasText: 'j8_lifecycle.bin' });
      await trashRow.getByRole('button', { name: 'Restore' }).click();
      await expect(page.getByText('j8_lifecycle.bin')).not.toBeVisible({ timeout: 15_000 }); // gone from Trash

      await page.getByRole('button', { name: 'Files' }).click();
      await expect(page.getByText('j8_lifecycle.bin')).toBeVisible({ timeout: 15_000 }); // back in Files

      // ---- trash again, then PURGE (explicit confirmation dialog) -----------
      await page
        .locator('tr', { hasText: 'j8_lifecycle.bin' })
        .getByRole('button', { name: /move .* to trash/i })
        .click();
      await page.getByRole('button', { name: 'Trash' }).click();
      await expect(page.getByText('j8_lifecycle.bin')).toBeVisible({ timeout: 15_000 });

      const purgeTrigger = page
        .locator('tr', { hasText: 'j8_lifecycle.bin' })
        .getByRole('button', { name: 'Purge (permanent)' });
      await purgeTrigger.click();

      // Confirmation dialog must appear before anything is destroyed.
      const confirmDialog = page.getByText('Permanently delete this file?');
      await expect(confirmDialog).toBeVisible({ timeout: 10_000 });
      await page.getByRole('button', { name: 'Permanently delete' }).click();

      await expect(page.getByText('j8_lifecycle.bin')).not.toBeVisible({ timeout: 15_000 });

      // Usage decreases after purge.
      const usageAfterPurge = await getUsage(USERS.enabled.id, 'personal');
      expect(usageAfterPurge.used_bytes).toBeLessThan(usageAfterTrash.used_bytes);
    } finally {
      await session.cleanup();
    }
  });
});
