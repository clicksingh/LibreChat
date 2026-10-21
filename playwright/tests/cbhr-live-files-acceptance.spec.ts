/**
 * CBHR Files user-facing acceptance. Run ONLY against an authorized staging
 * deployment with dedicated E2E accounts and its temporary session cleanup.
 * It never reads staff/Kim documents or sends text to a model.
 *
 * Required:
 *   CBHR_ACCEPTANCE_MODE=staging
 *   LC_BASE=<isolated staging base URL>
 *   CBHR_E2E_HOST_ENV=<staging secret env file path>
 *   MONGO_HOST_OVERRIDE=<isolated staging MongoDB endpoint>
 *   CBHR_E2E_OWNER_ID=<24-hex fixture owner id>
 *   CBHR_E2E_OUTSIDER_ID=<24-hex fixture nonmember id>
 * Run: playwright test playwright/tests/cbhr-live-files-acceptance.spec.ts
 *
 * This test is intentionally skipped in normal CI. Do NOT count skip as PASS.
 */
import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { loginAs } from '../utils/browser';
import { accessToken } from '../utils/auth';

test.describe('CBHR Files authenticated legacy reuse and ACL', () => {
  test.setTimeout(120_000);

  test('retained legacy file downloads, reattaches without upload; outsider is denied', async ({
    browser,
  }) => {
    test.skip(
      process.env.CBHR_ACCEPTANCE_MODE !== 'staging',
      'Requires authorized isolated staging and dedicated E2E account',
    );
    const ownerId = process.env.CBHR_E2E_OWNER_ID;
    const outsiderId = process.env.CBHR_E2E_OUTSIDER_ID;
    expect(process.env.LC_BASE, 'Explicit isolated staging URL is required').toBeTruthy();
    expect(
      process.env.CBHR_E2E_HOST_ENV,
      'Explicit staging signer environment is required',
    ).toBeTruthy();
    expect(
      process.env.MONGO_HOST_OVERRIDE,
      'Explicit staging Mongo endpoint is required',
    ).toBeTruthy();
    expect(ownerId, 'Dedicated staging owner fixture ID is required').toMatch(/^[0-9a-f]{24}$/i);
    expect(outsiderId, 'Dedicated staging outsider fixture ID is required').toMatch(
      /^[0-9a-f]{24}$/i,
    );
    expect(ownerId).not.toBe(outsiderId);

    const ownerCtx = await browser.newContext({ acceptDownloads: true });
    const otherCtx = await browser.newContext();
    const ownerSession = await loginAs(ownerCtx, ownerId!);
    const otherSession = await loginAs(otherCtx, outsiderId!);
    try {
      const owner = await ownerCtx.newPage();
      const outsider = await otherCtx.newPage();
      const requests: string[] = [];
      owner.on('request', (r) => {
        if (r.method() === 'POST' && /\/api\/files\/upload(?:\/|$)/.test(new URL(r.url()).pathname))
          requests.push('browser-file-upload');
      });

      await owner.goto('/c/new');
      await expect(
        owner.locator('textarea[data-testid="message-input"],textarea').first(),
      ).toBeVisible({ timeout: 45_000 });
      await owner.getByRole('button', { name: 'Files', exact: true }).first().click();
      const rows = owner.locator('table tbody tr');
      await expect(rows.first()).toBeVisible({ timeout: 30_000 });

      // Select a retained *legacy* entry: the UI has no Uploaded/Created label
      // when CodeAPI's metadata.role was never recorded. No fixed filename.
      let row = rows.first();
      let selected = false;
      const n = Math.min(await rows.count(), 150);
      for (let i = 0; i < n; i++) {
        const candidate = rows.nth(i);
        const label = await candidate.innerText();
        if (
          !/\bUploaded\b|\bCreated by ChatGPT\b/i.test(label) &&
          (await candidate.getByRole('button', { name: /^Download / }).count())
        ) {
          row = candidate;
          selected = true;
          break;
        }
      }
      expect(selected, 'A role-less E2E legacy fixture is required').toBe(true);
      const path = await row.locator('td[title]').first().getAttribute('title');
      expect(path).toMatch(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/);
      const [sessionId, fileId] = path!.split('/');
      const downloadButton = row.getByRole('button', { name: /^Download / });
      const filename = (await downloadButton.getAttribute('aria-label'))!.replace(/^Download /, '');

      const [download] = await Promise.all([
        owner.waitForEvent('download', { timeout: 30_000 }),
        downloadButton.click(),
      ]);
      const stored = await readFile((await download.path())!);
      expect(stored.length).toBeGreaterThan(0);
      expect(download.suggestedFilename()).toBe(filename);
      const pendingUploads = requests.length;
      const [attachResp] = await Promise.all([
        owner.waitForResponse(
          (r) =>
            r.request().method() === 'POST' &&
            new URL(r.url()).pathname === '/api/workspaces/personal/files/attach',
          { timeout: 30_000 },
        ),
        row.getByRole('button', { name: 'Attach ' + filename + ' to chat' }).click(),
      ]);
      expect(attachResp.status(), 'Owner reattach must create a new chat file').toBe(201);
      await expect(owner.locator('main').getByText(filename, { exact: true }).first()).toBeVisible({
        timeout: 15_000,
      });
      expect(requests.length, 'Existing Files object must not reupload from browser').toBe(
        pendingUploads,
      );

      await outsider.goto('/c/new');
      await expect(
        outsider.locator('textarea[data-testid="message-input"],textarea').first(),
      ).toBeVisible({ timeout: 45_000 });
      const forbiddenDownload = await outsider.request.get(
        '/api/workspaces/personal/files/' + sessionId + '/' + fileId + '/download',
        {
          headers: { Authorization: 'Bearer ' + accessToken(outsiderId!) },
        },
      );
      const forbiddenAttach = await outsider.request.post('/api/workspaces/personal/files/attach', {
        headers: { Authorization: 'Bearer ' + accessToken(outsiderId!) },
        data: { session_id: sessionId, file_id: fileId },
      });
      expect([403, 404], 'Other user download must deny, not return 500').toContain(
        forbiddenDownload.status(),
      );
      expect([403, 404], 'Other user cannot attach opaque owner file').toContain(
        forbiddenAttach.status(),
      );

      console.log(
        'CBHR_FILES_STAGING_ACCEPTANCE_PASS ' +
          JSON.stringify({
            ownerDownloadBytes: stored.length,
            ownerAttachStatus: attachResp.status(),
            outsiderDownloadStatus: forbiddenDownload.status(),
            outsiderAttachStatus: forbiddenAttach.status(),
            browserReuploads: requests.length - pendingUploads,
          }),
      );
    } finally {
      await ownerSession.cleanup();
      await otherSession.cleanup();
      await ownerCtx.close();
      await otherCtx.close();
    }
  });
});
