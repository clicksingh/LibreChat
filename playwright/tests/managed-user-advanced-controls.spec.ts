import { test, expect } from '@playwright/test';
import { loginAs } from '../utils/browser';
import { USERS } from '../utils/constants';

test('managed user hides advanced model and tool plumbing', async ({ page, context }) => {
  const session = await loginAs(context, USERS.enabled.id);
  try {
    await page.goto('/c/new');
    await page.locator('textarea').first().waitFor({ state: 'visible', timeout: 30_000 });

    await expect(page.locator('#attach-file')).toHaveCount(1);
    await expect(page.locator('#tools-dropdown-button')).toHaveCount(0);
    await expect(page.getByRole('button', { name: /select model/i })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Parameters', exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'MCP Settings', exact: true })).toHaveCount(0);
  } finally {
    await session.cleanup();
  }
});
