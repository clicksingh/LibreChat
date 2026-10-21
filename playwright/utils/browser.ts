/**
 * 8S3C.1 browser E2E — safe authenticated browser state.
 *
 * Injects a refreshToken cookie for a freshly created `sessions` doc (the exact
 * artifact POST /api/auth/login produces). The client's silent-refresh
 * exchanges it for an access token. NO password, NO login hammering — this
 * never trips the LibreChat login rate-limiter ban.
 */

import type { BrowserContext } from '@playwright/test';
import { createSession, cleanupSession, refreshTokenCookie } from './auth';

export interface BrowserSession {
  sessionId: string;
  cleanup: () => Promise<void>;
}

export async function loginAs(context: BrowserContext, userId: string): Promise<BrowserSession> {
  const session = await createSession(userId);
  await context.addCookies(refreshTokenCookie(session.refreshToken));
  return { sessionId: session.sessionId, cleanup: () => cleanupSession(session.sessionId) };
}
