import { defineConfig } from '@playwright/test';

/**
 * 8S3C.1 acceptance browser E2E — task D/E.
 *
 * Targets the DEPLOYED LibreChat instance (compose project `librechat`,
 * 127.0.0.1:3080). Browser-test users live in the deployed Mongo
 * (e2e-enabled / e2e-nocode); their credentials are in /tmp/e2e-user-creds.env
 * (0600, NEVER committed). Auth is session injection — the exact `sessions`
 * doc + refreshToken cookie a real login produces — so /api/auth/login is
 * never called (login rate-limiter ban).
 *
 * RUNNING (this host's system Chromium crashes on the authenticated dashboard
 * in the media/compositor path; the canonical runner is a Playwright docker
 * image with a working Chromium):
 *   scripts/e2e-browser/run-e2e.sh
 * Set PW_CHROMIUM to a working chromium only if the host browser is reliable.
 *
 * Test agents (official constitution model): the Planner wrote
 * playwright/specs/8s3c1-browser-e2e.md (journeys + pass criteria), the
 * Generator produced these specs from live execution, and the Healer may only
 * classify TEST_DRIFT — never a product/security expectation.
 */
export default defineConfig({
  testDir: './playwright/tests',
  timeout: 180_000,
  expect: { timeout: 30_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list'], ['html', { open: 'never', outputFolder: 'playwright/.report' }]],
  outputDir: 'playwright/.test-results',
  use: {
    baseURL: process.env.LC_BASE ?? 'http://127.0.0.1:3080',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    // @playwright/test 1.56.1 wants chromium rev 1194; only 1234 is installed
    // on this host and is proven against this app by verify-browser-ui-path.js.
    launchOptions: {
      executablePath:
        process.env.PW_CHROMIUM ??
        '/home/ai/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome',
    },
  },
});
