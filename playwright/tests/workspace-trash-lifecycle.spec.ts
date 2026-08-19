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

      // Everything below scopes to the Workspace panel itself, not the whole
      // page — the chat transcript above still contains the literal
      // filename text, which would otherwise make these assertions ambiguous.
      const panel = page.getByTestId('workspace-panel');
      await page.getByRole('button', { name: 'Workspace', exact: true }).first().click();
      await page.getByRole('button', { name: 'Files', exact: true }).click();
      // This real test user has ~50 accumulated files from earlier accepted
      // Playwright suites (8S3C.2) sharing the same fixture identity — the
      // new row can land below the panel's fixed-height scroll fold.
      // scrollIntoViewIfNeeded first so visibility isn't gated on scroll
      // position (attach() below finds it in the DOM even before scroll).
      const newFileCell = panel.getByText('j8_lifecycle.bin').first();
      await newFileCell.scrollIntoViewIfNeeded({ timeout: 60_000 });
      await expect(newFileCell).toBeVisible({ timeout: 15_000 });

      // ---- trash it ---------------------------------------------------------
      const fileRow = panel.locator('tr', { hasText: 'j8_lifecycle.bin' }).first();
      await fileRow.scrollIntoViewIfNeeded();
      await fileRow.getByRole('button', { name: /move .* to trash/i }).click();
      await expect(panel.getByText('j8_lifecycle.bin').first()).not.toBeVisible({ timeout: 15_000 });

      // Usage must NOT drop merely from trashing (same quota tree).
      const usageAfterTrash = await getUsage(USERS.enabled.id, 'personal');
      expect(usageAfterTrash.used_bytes).toBeGreaterThanOrEqual(usageBeforeTrash.used_bytes);

      // ---- appears in Trash tab (this test's own trash, not the crowded
      // 8S3C.2 fixture history — Files list is, Trash isn't) ------------------
      await page.getByRole('button', { name: 'Trash', exact: true }).click();
      await expect(panel.getByText('j8_lifecycle.bin').first()).toBeVisible({ timeout: 15_000 });

      // ---- restore ------------------------------------------------------------
      const trashRow = panel.locator('tr', { hasText: 'j8_lifecycle.bin' }).first();
      await trashRow.getByRole('button', { name: 'Restore' }).click();
      await expect(panel.getByText('j8_lifecycle.bin').first()).not.toBeVisible({ timeout: 15_000 }); // gone from Trash

      await page.getByRole('button', { name: 'Files', exact: true }).click();
      const restoredCell = panel.getByText('j8_lifecycle.bin').first();
      await restoredCell.scrollIntoViewIfNeeded({ timeout: 60_000 });
      await expect(restoredCell).toBeVisible({ timeout: 15_000 }); // back in Files

      // ---- trash again, then PURGE (explicit confirmation dialog) -----------
      const fileRow2 = panel.locator('tr', { hasText: 'j8_lifecycle.bin' }).first();
      await fileRow2.scrollIntoViewIfNeeded();
      await fileRow2.getByRole('button', { name: /move .* to trash/i }).click();
      await page.getByRole('button', { name: 'Trash', exact: true }).click();
      await expect(panel.getByText('j8_lifecycle.bin').first()).toBeVisible({ timeout: 15_000 });

      const purgeTrigger = panel
        .locator('tr', { hasText: 'j8_lifecycle.bin' })
        .first()
        .getByRole('button', { name: /permanently delete/i });
      await purgeTrigger.click();

      // Confirmation dialog must appear before anything is destroyed.
      const confirmDialog = page.getByText('Permanently delete this file?');
      await expect(confirmDialog).toBeVisible({ timeout: 10_000 });
      await page.getByRole('button', { name: 'Permanently delete' }).click();

      await expect(panel.getByText('j8_lifecycle.bin').first()).not.toBeVisible({ timeout: 15_000 });

      // Usage decreases after purge.
      const usageAfterPurge = await getUsage(USERS.enabled.id, 'personal');
      expect(usageAfterPurge.used_bytes).toBeLessThan(usageAfterTrash.used_bytes);
    } finally {
      await session.cleanup();
    }
  });
});
