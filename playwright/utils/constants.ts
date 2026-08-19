/**
 * 8S3C.1 browser E2E — shared constants.
 *
 * Browser-test users live ONLY in the deployed LibreChat Mongo (this worktree's
 * repo does NOT contain their passwords). Credentials are in
 * /tmp/e2e-user-creds.env (0600, gitignored, never committed). The tests
 * authenticate with the safe session-injection pattern (the exact Session doc
 * POST /api/auth/login creates) so they never hammer /api/auth/login — the
 * LibreChat login rate-limiter bans scripted logins (see the librechat-login-ban
 * memory).
 */

export const BASE = process.env.LC_BASE ?? 'http://127.0.0.1:3080';

/** Browser-test users (created in deployed Mongo by the E2E provisioning). */
export const USERS = {
  /** Role USER — RUN_CODE.USE:true. */
  enabled: { id: '6a812639c7164cdbc39df8a4', email: 'e2e-enabled@kelownarealestate.com', role: 'USER' },
  /** Role E2E_NOCODE — RUN_CODE.USE:false. */
  nocode: { id: '6a812639c7164cdbc39df8a5', email: 'e2e-nocode@kelownarealestate.com', role: 'E2E_NOCODE' },
  /** 8S3D.1: second RUN_CODE-enabled user, used as project workspace "member B"
   *  in J9 (cross-user project ACL). Provisioned directly in Mongo (same shape
   *  as `enabled`/`nocode`), see docs/8S3D.1-RETURN.md. */
  memberB: { id: '6a812639c7164cdbc39df8a6', email: 'e2e-member-b@kelownarealestate.com', role: 'USER' },
} as const;

export const CHAT_ENDPOINT = 'CBHR AI';

/** Host .env for JWT_REFRESH_SECRET (session injection) + JWT_SECRET (host-side API). */
export const HOST_ENV = '/opt/cbhr-ai/LibreChat/.env';

/** Chromium executable installed for the host Playwright (wt-r3 wants rev 1194;
 *  1234 is present and proven against this app by verify-browser-ui-path.js). */
export const CHROMIUM_PATH =
  process.env.PW_CHROMIUM ?? '/home/ai/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome';
