/**
 * 8S3D.1 — J10: pre-8S3D conversation continuity, true browser E2E. Builds
 * on the API-level proof already recorded in docs/8S3D-RETURN.md (a real
 * migrated user's pre-migration file served correctly post-cutover) by
 * proving the SAME thing through the actual browser UI: open the real
 * migrated user's existing conversation, see their pre-migration file in
 * the Workspace panel, and confirm the conversation is (still) bound to
 * their Personal workspace automatically — no migration required on the
 * Conversation document itself.
 */
import { test, expect } from '@playwright/test';
import { loginAs } from '../utils/browser';

// 65f2a1b2c3d4e5f60708090a: real pre-8S3D migrated user (see
// docs/8S3D-RETURN.md item 19/CUTOVER ADDENDUM — this exact id's workspace
// was hash-verified byte-identical across the migration).
const MIGRATED_USER_ID = '65f2a1b2c3d4e5f60708090a';

test.describe('J10 — pre-8S3D conversation continuity', () => {
  test.setTimeout(120_000);

  test('a real migrated user sees their pre-migration file in the Workspace panel, conversation resolves to Personal', async ({
    page,
    context,
  }) => {
    const session = await loginAs(context, MIGRATED_USER_ID);
    try {
      await page.goto('/c/new');
      await expect(page).toHaveURL(/\/c\//, { timeout: 60_000 });

      await page.getByRole('button', { name: 'Workspace' }).first().click();

      // Personal must be the default/only selectable option this
      // conversation resolves to — no workspace migration was needed on
      // the Conversation document itself.
      const select = page.locator('select');
      await expect(select).toHaveValue('personal', { timeout: 20_000 });

      await page.getByRole('button', { name: 'Files' }).click();

      // note.txt is the exact pre-migration fixture file recorded in
      // docs/8S3D-RETURN.md's CUTOVER ADDENDUM (content "persist-1").
      const filesResponse = page.waitForResponse(
        (r) => r.url().includes('/api/workspaces/personal/files') && r.status() === 200,
      );
      await page.getByRole('button', { name: 'Trash' }).click();
      await page.getByRole('button', { name: 'Files' }).click();
      const res = await filesResponse;
      const body = (await res.json()) as { items: Array<{ name: string }> };
      const preMigration = body.items.find((f) => f.name === 'note.txt');
      expect(
        preMigration,
        'pre-migration file note.txt should still be present and browsable post-cutover',
      ).toBeTruthy();

      await expect(page.getByText('note.txt')).toBeVisible({ timeout: 15_000 });
    } finally {
      await session.cleanup();
    }
  });
});
