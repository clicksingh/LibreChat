import { createHash, createHmac } from 'node:crypto';

/** Pathname bound into the portal-claim signature. Xpose verifies this exact value. */
export const XPOSE_PORTAL_CLAIM_PATH = '/pairing/portal-claim';
/** Signature scheme/version tag, first line of the canonical string. */
export const XPOSE_PORTAL_SIGNATURE_VERSION = 'xpose-pairing-portal-v1';
/** Bounded upstream timeout for a single portal-claim request. */
export const XPOSE_PORTAL_TIMEOUT_MS = 10_000;
/** Xpose rejects browser pairing codes longer than this. */
export const XPOSE_MAX_CODE_LENGTH = 32;

const SECRET_PATTERN = /^[A-Za-z0-9_-]+$/;
const FLEET_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;
const MIN_SECRET_BYTES = 32;
const PASS_THROUGH_STATUSES: Record<number, true> = {
  400: true,
  401: true,
  403: true,
  404: true,
  409: true,
  410: true,
  429: true,
};

export interface XposePairingConfig {
  /** Absolute https portal-claim endpoint (origin + fixed path, no query/hash). */
  endpoint: string;
  /** Server-only fleet identifier asserted to Xpose. Never browser-supplied. */
  fleetId: string;
  /** Decoded HMAC secret bytes. Never serialized, returned, or logged. */
  secret: Buffer;
}

export type XposePairingConfigResult =
  | { ok: true; config: XposePairingConfig }
  | { ok: false; code: 'xpose_pairing_unconfigured' };

export interface XposePortalClaimBody {
  code: string;
  actorId: string;
  connectionOwnerId: string;
  fleetId: string;
}

export interface PortalClaimSignatureInput {
  /** Decimal `Date.now()` milliseconds as a string. */
  timestamp: string;
  nonce: string;
  bodyHash: string;
}

export interface PortalClaimSignedHeaders {
  bodyHash: string;
  signature: string;
}

/** Result of the signed server-to-server call. Network failures are tagged, never thrown. */
export type XposePortalClaimTransport =
  | { ok: true; status: number; body: unknown }
  | { ok: false; reason: 'timeout' | 'unreachable' };

export interface PortalClaimRequestDeps {
  fetch: typeof fetch;
  now: () => number;
  /** Fresh base64url nonce, 22–128 chars. Must be unique per request. */
  randomNonce: () => string;
}

/**
 * Strict base64url decode that fails closed on malformed input.
 * Node's `Buffer.from(..., 'base64url')` silently ignores invalid characters, so the
 * pattern is validated first and the decoded secret must be at least 32 bytes.
 */
export function decodePortalSecret(value: string): Buffer | null {
  if (typeof value !== 'string' || value.length === 0 || !SECRET_PATTERN.test(value)) {
    return null;
  }
  if (value.length % 4 === 1) {
    return null;
  }
  const bytes = Buffer.from(value, 'base64url');
  return bytes.length >= MIN_SECRET_BYTES ? bytes : null;
}

/**
 * Resolve and validate the server-only Xpose pairing configuration.
 * Normalizes `XPOSE_PAIRING_URL` to its origin and binds the request to the exact
 * `/pairing/portal-claim` pathname; any configured path/query/hash is dropped so the
 * signed and requested pathname always match the Xpose verifier.
 */
export function loadXposePairingConfig(
  env: Record<string, string | undefined> = process.env,
): XposePairingConfigResult {
  const rawUrl = typeof env.XPOSE_PAIRING_URL === 'string' ? env.XPOSE_PAIRING_URL.trim() : '';
  const rawSecret =
    typeof env.XPOSE_PAIRING_PORTAL_SECRET === 'string'
      ? env.XPOSE_PAIRING_PORTAL_SECRET.trim()
      : '';
  const rawFleet =
    typeof env.XPOSE_PAIRING_FLEET_ID === 'string' ? env.XPOSE_PAIRING_FLEET_ID.trim() : '';

  if (!rawUrl || !rawSecret || !rawFleet) {
    return { ok: false, code: 'xpose_pairing_unconfigured' };
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { ok: false, code: 'xpose_pairing_unconfigured' };
  }
  if (parsed.protocol !== 'https:' || !parsed.hostname) {
    return { ok: false, code: 'xpose_pairing_unconfigured' };
  }

  const secret = decodePortalSecret(rawSecret);
  if (!secret) {
    return { ok: false, code: 'xpose_pairing_unconfigured' };
  }

  if (!FLEET_PATTERN.test(rawFleet)) {
    return { ok: false, code: 'xpose_pairing_unconfigured' };
  }

  parsed.pathname = XPOSE_PORTAL_CLAIM_PATH;
  parsed.search = '';
  parsed.hash = '';

  return { ok: true, config: { endpoint: parsed.toString(), fleetId: rawFleet, secret } };
}

export function hashPortalClaimBody(bodyText: string): string {
  return createHash('sha256').update(bodyText, 'utf8').digest('base64url');
}

export function buildPortalClaimCanonicalString(input: PortalClaimSignatureInput): string {
  return [
    XPOSE_PORTAL_SIGNATURE_VERSION,
    'POST',
    XPOSE_PORTAL_CLAIM_PATH,
    String(input.timestamp),
    String(input.nonce),
    String(input.bodyHash),
  ].join('\n');
}

/** Serialize the claim body once so the signed bytes are exactly the transmitted bytes. */
export function serializePortalClaimBody(body: XposePortalClaimBody): string {
  return JSON.stringify({
    code: body.code,
    actorId: body.actorId,
    connectionOwnerId: body.connectionOwnerId,
    fleetId: body.fleetId,
  });
}

export function signPortalClaim(input: {
  secret: Buffer;
  timestamp: string;
  nonce: string;
  bodyText: string;
}): PortalClaimSignedHeaders {
  const bodyHash = hashPortalClaimBody(input.bodyText);
  const canonical = buildPortalClaimCanonicalString({
    timestamp: input.timestamp,
    nonce: input.nonce,
    bodyHash,
  });
  const signature = createHmac('sha256', input.secret)
    .update(canonical, 'utf8')
    .digest('base64url');
  return { bodyHash, signature };
}

/** Conservative upstream status mapping: 5xx/timeouts never surface as a success path. */
export function mapUpstreamStatus(status: number): number {
  return PASS_THROUGH_STATUSES[status] === true ? status : 502;
}

/**
 * Signed POST to Xpose `/pairing/portal-claim`. The JSON body is transmitted as the exact
 * string that was hashed and signed; the secret never leaves this process.
 */
export async function requestPortalClaim(
  config: XposePairingConfig,
  body: XposePortalClaimBody,
  deps: PortalClaimRequestDeps,
  timeoutMs: number = XPOSE_PORTAL_TIMEOUT_MS,
): Promise<XposePortalClaimTransport> {
  const bodyText = serializePortalClaimBody(body);
  const timestamp = String(deps.now());
  const nonce = deps.randomNonce();
  const { signature } = signPortalClaim({
    secret: config.secret,
    timestamp,
    nonce,
    bodyText,
  });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await deps.fetch(config.endpoint, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-xpose-portal-timestamp': timestamp,
        'x-xpose-portal-nonce': nonce,
        'x-xpose-portal-signature': signature,
      },
      body: bodyText,
      signal: controller.signal,
    });

    let parsed: unknown = null;
    try {
      parsed = await response.json();
    } catch {
      parsed = null;
    }
    return { ok: true, status: response.status, body: parsed };
  } catch (error) {
    const aborted =
      typeof error === 'object' && error !== null && 'name' in error && error.name === 'AbortError';
    return { ok: false, reason: aborted ? 'timeout' : 'unreachable' };
  } finally {
    clearTimeout(timer);
  }
}
