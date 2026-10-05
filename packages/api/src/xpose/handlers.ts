import { randomBytes } from 'node:crypto';
import { logger } from '@librechat/data-schemas';
import type { Response } from 'express';
import type { ServerRequest } from '~/types';
import {
  loadXposePairingConfig,
  mapUpstreamStatus,
  requestPortalClaim,
  XPOSE_MAX_CODE_LENGTH,
} from './pairing';

const ALLOWED_BROWSER_BODY_KEYS: Record<string, true> = { code: true };
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+$/;
const MAX_EMAIL_LENGTH = 160;
const MAX_STATE_LENGTH = 64;
const MAX_DEVICE_ID_LENGTH = 128;
const UPSTREAM_CODE_PATTERN = /^[A-Za-z0-9_.-]{1,64}$/;

type BrowserRequestBodyResult =
  | { ok: true; code: string }
  | { ok: false; code: 'xpose_pairing_request_invalid' | 'xpose_pairing_code_invalid' };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Browser body is an explicit allowlist: `{ code }` and nothing else. Actor/fleet/owner
 * identifiers are server-derived and any attempt to supply them is rejected outright.
 */
function parseBrowserRequestBody(raw: unknown): BrowserRequestBodyResult {
  if (!isRecord(raw)) {
    return { ok: false, code: 'xpose_pairing_request_invalid' };
  }

  const keys = Object.keys(raw);
  if (keys.some((key) => ALLOWED_BROWSER_BODY_KEYS[key] !== true)) {
    return { ok: false, code: 'xpose_pairing_request_invalid' };
  }

  const code = raw.code;
  if (
    typeof code !== 'string' ||
    code.length === 0 ||
    code.length > XPOSE_MAX_CODE_LENGTH ||
    /[\r\n]/.test(code)
  ) {
    return { ok: false, code: 'xpose_pairing_code_invalid' };
  }

  return { ok: true, code };
}

/** Allowlist projection: never spread the Xpose response into the browser payload. */
function projectClaimSuccess(body: Record<string, unknown>): {
  ok: true;
  state?: string;
  deviceId?: string;
} {
  const projected: { ok: true; state?: string; deviceId?: string } = { ok: true };
  if (
    typeof body.state === 'string' &&
    body.state.length > 0 &&
    body.state.length <= MAX_STATE_LENGTH
  ) {
    projected.state = body.state;
  }
  if (
    typeof body.deviceId === 'string' &&
    body.deviceId.length > 0 &&
    body.deviceId.length <= MAX_DEVICE_ID_LENGTH
  ) {
    projected.deviceId = body.deviceId;
  }
  return projected;
}

export interface XposePairingHandlerDeps {
  /** Injectable for deterministic tests; defaults to the global `fetch`. */
  fetch?: typeof fetch;
  now?: () => number;
  randomNonce?: () => string;
  env?: Record<string, string | undefined>;
}

export interface XposePairingHandlers {
  claimDevice: (req: ServerRequest, res: Response) => Promise<Response>;
}

/**
 * Authenticated browser -> LibreChat -> Xpose portal claim.
 *
 * The browser only supplies a pairing code. `actorId`/`connectionOwnerId` come from the
 * authenticated email, `fleetId` and the HMAC secret come from server-only env, and the
 * Xpose response is projected through an allowlist so no secret, bearer, key, or grant can
 * reach the browser.
 */
export function createXposePairingHandlers(
  deps: XposePairingHandlerDeps = {},
): XposePairingHandlers {
  const fetchImpl = deps.fetch ?? globalThis.fetch;
  const now = deps.now ?? Date.now;
  const randomNonce = deps.randomNonce ?? (() => randomBytes(16).toString('base64url'));
  const env = deps.env ?? process.env;

  async function claimDevice(req: ServerRequest, res: Response): Promise<Response> {
    res.set('Cache-Control', 'no-store');

    const rawEmail = req.user?.email;
    const email = typeof rawEmail === 'string' ? rawEmail.trim().toLowerCase() : '';
    if (
      email.length === 0 ||
      email.length > MAX_EMAIL_LENGTH ||
      !EMAIL_PATTERN.test(email) ||
      /[\r\n]/.test(email)
    ) {
      return res.status(403).json({ ok: false, code: 'xpose_pairing_identity_invalid' });
    }

    const configResult = loadXposePairingConfig(env);
    if (!configResult.ok) {
      logger.error('[XposePairing] portal claim rejected: pairing backend is not configured');
      return res.status(503).json({ ok: false, code: configResult.code });
    }

    const bodyResult = parseBrowserRequestBody(req.body);
    if (!bodyResult.ok) {
      return res.status(400).json({ ok: false, code: bodyResult.code });
    }

    const transport = await requestPortalClaim(
      configResult.config,
      {
        code: bodyResult.code,
        actorId: email,
        connectionOwnerId: email,
        fleetId: configResult.config.fleetId,
      },
      { fetch: fetchImpl, now, randomNonce },
    );

    if (!transport.ok) {
      logger.error('[XposePairing] portal claim transport failure:', transport.reason);
      return res
        .status(transport.reason === 'timeout' ? 504 : 502)
        .json({ ok: false, code: 'xpose_pairing_unavailable' });
    }

    if (
      transport.status >= 200 &&
      transport.status < 300 &&
      isRecord(transport.body) &&
      transport.body.ok === true
    ) {
      return res.status(200).json(projectClaimSuccess(transport.body));
    }

    const status = mapUpstreamStatus(transport.status);
    const code =
      isRecord(transport.body) &&
      typeof transport.body.code === 'string' &&
      UPSTREAM_CODE_PATTERN.test(transport.body.code)
        ? transport.body.code
        : 'xpose_pairing_upstream_error';
    logger.error(
      `[XposePairing] portal claim upstream status ${transport.status} mapped to ${status}`,
    );
    return res.status(status).json({ ok: false, code });
  }

  return { claimDevice };
}
