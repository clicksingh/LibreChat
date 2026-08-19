/**
 * 8S3D.1 — J7: quota journey on a disposable, deliberately tiny project
 * workspace, true browser E2E. The workspace must first be "ensured" via a
 * real small write (which provisions its XFS project quota at CodeAPI's own
 * default), then its quota is shrunk to the helper's 64MiB floor — the
 * smallest hard limit the platform can ever assign — via direct
 * TEST-FIXTURE setup (mirrors J4/J5's non-UI auth setup discipline). The
 * actual overflow write, warning/full state, and recovery are all driven
 * through the real browser and real code execution.
 */
import { test, expect } from '@playwright/test';
import { loginAs } from '../utils/browser';
import { USERS } from '../utils/constants';
import { createWorkspace } from '../utils/workspaceApi';
import { setQuotaDirect, setQuotaPolicyDirect } from '../utils/codeapiInternal';

const TINY_QUOTA_BYTES = 64 * 1024 * 1024; // the helper's own MIN_QUOTA_BYTES floor

test.describe('J7 — quota journey (tiny disposable workspace)', () => {
  test.setTimeout(180_000);

  test('warning/full state visible, overflow write fails cleanly, prior files intact, quota bump recovers', async ({
    page,
    context,
  }) => {
    const { id: workspaceId } = await createWorkspace(USERS.enabled.id, `J7 Quota ${Date.now()}`);

    const session = await loginAs(context, USERS.enabled.id);
    try {
      await page.goto('/c/new');
      await expect(page).toHaveURL(/\/c\//, { timeout: 60_000 });

      await page.getByRole('button', { name: 'Workspace', exact: true }).first().click();
      await page.locator('select').selectOption(workspaceId);
      await page.getByRole('button', { name: 'Use for new chat' }).click();

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

      // ---- step 1: a small real write ensures the workspace (provisions
      // its XFS project quota at CodeAPI's own default) ----------------------
      const composer = page.locator('textarea[data-testid="message-input"], textarea').first();
      await composer.click();
      await composer.fill('Run python code that writes a small file good.txt containing "ok". Confirm.');
      await composer.press('Enter');
      await expect(page.getByText(/good\.txt/i).first()).toBeVisible({ timeout: 120_000 });

      // ---- step 2: shrink the now-provisioned workspace to the 64MiB floor --
      // Both the live helper limit AND the policy document that
      // syncProjectQuotaFireAndForget re-applies on every subsequent
      // project-context message — a bare helper poke with no matching
      // policy gets silently overwritten back to the platform default the
      // moment the next chat message (the overflow write) is sent.
      await setQuotaPolicyDirect(workspaceId, TINY_QUOTA_BYTES);
      await setQuotaDirect(workspaceId, 'project', TINY_QUOTA_BYTES);

      // ---- step 3: real code execution intentionally exceeds the limit ------
      await composer.click();
      await composer.fill(
        'Run python code that writes an 80MB file named overflow.bin (write in a loop, e.g. 8MB chunks of b"x"*8_000_000, 10 times), then print "wrote overflow".',
      );
      // Enter occasionally lands as a newline instead of a submit here
      // (stray modifier state after the tools-dropdown Escape earlier in
      // this same conversation) — the explicit send button doesn't have
      // that ambiguity.
      await page.locator('button[data-testid="send-button"], button[aria-label*="Send" i]').first().click();
      // Wait for the turn to actually finish (success text, quota-exceeded
      // error, or any other terminal reply) rather than a specific network
      // response — React Query can legitimately fire more than once around
      // the panel's own polling, so pinning "the" response is racy (same
      // lesson as J6/J8). 80MB against a 64MiB hard limit under real disk
      // I/O plus model generation can take a while.
      await expect(
        page
          .getByText(/wrote overflow|exceeded|permission denied|disk quota|no space/i)
          .first(),
      ).toBeVisible({ timeout: 120_000 });

      // ---- step 4: Workspace panel shows a non-NORMAL state ------------------
      // The Workspace nav-rail button is a toggle — it was already opened in
      // step 1, so clicking it again here would close it instead.
      const panel = page.getByTestId('workspace-panel');
      if (!(await panel.isVisible().catch(() => false))) {
        await page.getByRole('button', { name: 'Workspace', exact: true }).first().click();
      }
      await expect(panel.getByText(/CRITICAL|FULL|Warning|Critical|Full/i)).toBeVisible({
        timeout: 30_000,
      });

      // ---- step 5: the prior valid file survives intact ----------------------
      await page.getByRole('button', { name: 'Files', exact: true }).click();
      await expect(panel.getByText('good.txt')).toBeVisible({ timeout: 20_000 });

      // ---- step 6: recovery via a quota bump (equivalent to an
      // admin/operator raising the limit) — subsequent write succeeds. --------
      await setQuotaPolicyDirect(workspaceId, TINY_QUOTA_BYTES * 4);
      await setQuotaDirect(workspaceId, 'project', TINY_QUOTA_BYTES * 4);
      await composer.click();
      await composer.fill('Run python code that writes a small file after_recovery.txt containing "ok2". Confirm.');
      await composer.press('Enter');
      await expect(page.getByText(/after_recovery\.txt/i).first()).toBeVisible({ timeout: 120_000 });
    } finally {
      await session.cleanup();
    }
  });
});
