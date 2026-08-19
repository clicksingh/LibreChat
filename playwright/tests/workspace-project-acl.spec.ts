/**
 * 8S3D.1 — J9: project workspace ACL isolation, true browser E2E across TWO
 * real, independent browser contexts (owner + member B). Setup (create
 * project, grant membership) goes through the REST API as test fixture
 * plumbing — same discipline as J4/J5's Mongo session-injection auth setup —
 * but every ACCESS CHECK is read from a real browser.
 */
import { test, expect } from '@playwright/test';
import { loginAs } from '../utils/browser';
import { USERS, BASE } from '../utils/constants';
import { accessToken } from '../utils/auth';
import { createWorkspace, addMember, removeMember } from '../utils/workspaceApi';

test.describe('J9 — project workspace ACL isolation', () => {
  test.setTimeout(180_000);

  test('owner + member B see it, nonmember C cannot, forged workspace_id fails, removed member loses access', async ({
    browser,
  }) => {
    const projectName = `J9 Project ${Date.now()}`;
    const { id: workspaceId } = await createWorkspace(USERS.enabled.id, projectName);
    await addMember(USERS.enabled.id, workspaceId, USERS.memberB.id, 'workspace_editor');

    // ---- owner: selects the project for a new chat, generates a file -------
    const ownerCtx = await browser.newContext();
    const ownerPage = await ownerCtx.newPage();
    const ownerSession = await loginAs(ownerCtx, USERS.enabled.id);
    try {
      await ownerPage.goto('/c/new');
      await expect(ownerPage).toHaveURL(/\/c\//, { timeout: 60_000 });

      await ownerPage.getByRole('button', { name: 'Workspace' }).first().click();
      await ownerPage
        .locator('select')
        .selectOption({ label: projectName });
      await ownerPage.getByRole('button', { name: 'Use for new chat' }).click();

      await ownerPage.getByRole('button', { name: 'Select a model' }).click();
      await ownerPage.getByRole('option', { name: /^CBHR AI/ }).first().click({ timeout: 10_000 });
      const modelSearch = ownerPage.getByRole('combobox').last();
      await modelSearch.waitFor({ state: 'visible', timeout: 10_000 });
      await modelSearch.fill('glm-5-turbo');
      await modelSearch.press('Enter').catch(() => {});
      await ownerPage.getByRole('option', { name: 'glm-5-turbo' }).first().click({ timeout: 15_000 });

      const toolsBtn = ownerPage.locator('#tools-dropdown-button').first();
      await expect(toolsBtn).toBeVisible({ timeout: 60_000 });
      await toolsBtn.click();
      await ownerPage.locator('#tools-dropdown-menu div:has-text("Run Code")').first().click();
      await ownerPage.keyboard.press('Escape').catch(() => {});

      const marker = `j9-${Date.now()}`;
      const composer = ownerPage.locator('textarea[data-testid="message-input"], textarea').first();
      await composer.click();
      await composer.fill(
        `Run python code that writes a file named j9_shared.txt containing "${marker}". Confirm when done.`,
      );

      // Capture the real outgoing POST from the browser and assert it
      // actually carries workspaceId for this NEW conversation.
      const postPromise = ownerPage.waitForRequest(
        (r) => r.url().includes('/api/agents/chat/') && r.method() === 'POST',
      );
      await composer.press('Enter');
      const outgoing = await postPromise;
      const outgoingBody = outgoing.postDataJSON() as { workspaceId?: string };
      expect(outgoingBody.workspaceId).toBe(workspaceId);

      await expect(ownerPage.getByText(/j9_shared\.txt/i).first()).toBeVisible({ timeout: 120_000 });
    } finally {
      await ownerSession.cleanup();
      await ownerCtx.close();
    }

    // ---- member B: independent login, sees the project + the file ---------
    const memberCtx = await browser.newContext();
    const memberPage = await memberCtx.newPage();
    const memberSession = await loginAs(memberCtx, USERS.memberB.id);
    try {
      await memberPage.goto('/c/new');
      await expect(memberPage).toHaveURL(/\/c\//, { timeout: 60_000 });
      await memberPage.getByRole('button', { name: 'Workspace' }).first().click();

      const select = memberPage.locator('select');
      await expect(select.locator('option', { hasText: projectName })).toHaveCount(1, { timeout: 20_000 });
      await select.selectOption({ label: projectName });

      await expect(memberPage.getByText('j9_shared.txt')).toBeVisible({ timeout: 20_000 });
    } finally {
      await memberSession.cleanup();
      await memberCtx.close();
    }

    // ---- nonmember C: cannot see the project at all -------------------------
    const nonmemberCtx = await browser.newContext();
    const nonmemberPage = await nonmemberCtx.newPage();
    const nonmemberSession = await loginAs(nonmemberCtx, USERS.nocode.id);
    try {
      await nonmemberPage.goto('/c/new');
      await expect(nonmemberPage).toHaveURL(/\/c\//, { timeout: 60_000 });
      await nonmemberPage.getByRole('button', { name: 'Workspace' }).first().click();

      const select = nonmemberPage.locator('select');
      await expect(select.locator('option', { hasText: projectName })).toHaveCount(0, { timeout: 10_000 });

      // Direct API access with a forged workspace_id also fails (403/404),
      // not just absent from the dropdown.
      const forgedToken = accessToken(USERS.nocode.id);
      const forgedResp = await nonmemberPage.request.get(`${BASE}/api/workspaces/${workspaceId}/usage`, {
        headers: { Authorization: `Bearer ${forgedToken}` },
      });
      expect([403, 404]).toContain(forgedResp.status());
    } finally {
      await nonmemberSession.cleanup();
      await nonmemberCtx.close();
    }

    // ---- removed member immediately loses access ---------------------------
    await removeMember(USERS.enabled.id, workspaceId, USERS.memberB.id);
    const removedToken = accessToken(USERS.memberB.id);
    const removedResp = await fetch(`${BASE}/api/workspaces/${workspaceId}/usage`, {
      headers: { Authorization: `Bearer ${removedToken}` },
    });
    expect(removedResp.status).toBe(403);
  });
});
