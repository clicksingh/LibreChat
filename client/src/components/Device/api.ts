/**
 * The panel's ONLY network surface.
 *
 * Every request this module makes passes through `assertPanelMayCall`, which checks the path
 * against `ALLOWED_PANEL_ENDPOINTS`. That allowlist contains exactly two entries:
 *
 *   GET  /api/devices/current          read lease status
 *   POST /api/devices/pairing/approve  redeem a six-digit code
 *
 * WHY THIS IS A SECURITY BOUNDARY, NOT A STYLE CHOICE
 * - Renewal (`POST /api/devices/current/renew`) needs fresh LOCAL confirmation on the PC
 *   (docs/ARCHITECTURE.md boundary 7) and owner identity lives only in the backend (D007).
 *   If this page could renew, a stolen browser session would be enough to keep device access
 *   alive indefinitely. So the panel does not merely avoid the call — the path is not on the
 *   allowlist, and no exported function targets it. Renewal is a NUDGE: `RenewalNudge.tsx`
 *   tells the employee to approve in the tray app.
 * - `POST /api/devices/pairing/complete` is DEVICE-authenticated. The PC polls it; the panel
 *   never calls it and must not, or the browser would stand in for the endpoint's proof.
 * - `POST /api/devices/pairing/challenge` and `/pairing/issue` are authenticated by the PC's
 *   Ed25519 key material and a signature over a server-minted challenge. The browser holds no
 *   key and must never be asked for one, so those legs are out of scope for this surface.
 *
 * The panel also sends no identity: the approve body is built by `buildApproveBody`, which
 * emits exactly `{ code }` and refuses anything that is not six digits.
 */

import { apiBaseUrl, request } from 'librechat-data-provider';
import { ALLOWED_PANEL_ENDPOINTS, DEVICE_ENDPOINTS, SIX_DIGIT_CODE_PATTERN } from './constants';
import type { DeviceApiError, DeviceStatusPayload, PairingApprovePayload } from './types';

/** Raised when a caller tries to reach outside the panel's allowlist, or to send a bad body. */
export class PanelBoundaryError extends Error {
  readonly code = 'PANEL_BOUNDARY_VIOLATION';

  constructor(message: string) {
    super(message);
    this.name = 'PanelBoundaryError';
  }
}

const ALLOWED_ENDPOINT_SET: ReadonlySet<string> = new Set(ALLOWED_PANEL_ENDPOINTS);

/**
 * Fail-closed guard: a path outside the allowlist never reaches the network.
 *
 * Exported only so the boundary spec can assert it throws for every non-allowlisted path — it is
 * not a public API and every request in this module already runs through it.
 */
export function assertPanelMayCall(path: string): void {
  if (!ALLOWED_ENDPOINT_SET.has(path)) {
    throw new PanelBoundaryError(
      `The My Computer panel may not call ${path}. Renewal needs local confirmation on the PC and pairing completion belongs to the device.`,
    );
  }
}

/**
 * The approve body, built from an allowlist of one field. No owner, device or tenant value can
 * travel from the browser, because nothing but the six digits is ever put in the object.
 */
function buildApproveBody(code: string): { code: string } {
  if (!SIX_DIGIT_CODE_PATTERN.test(code)) {
    throw new PanelBoundaryError('The panel only submits a well-formed six-digit code');
  }
  return { code };
}

interface ErrorWithResponse {
  response?: { status?: unknown; data?: unknown };
}

function readHttpStatus(error: unknown): number | null {
  const candidate = error as ErrorWithResponse | null;
  const status = candidate?.response?.status;
  return typeof status === 'number' ? status : null;
}

function readErrorCode(error: unknown): string | null {
  const candidate = error as ErrorWithResponse | null;
  const body = candidate?.response?.data;
  if (body === null || typeof body !== 'object') {
    return null;
  }
  const code = (body as { code?: unknown }).code;
  return typeof code === 'string' && code.length > 0 ? code : null;
}

/** Normalizes an axios failure (or anything else) into the panel's error shape. */
export function toDeviceApiError(error: unknown): DeviceApiError {
  if (error instanceof PanelBoundaryError) {
    return { kind: 'malformed', status: null, code: error.code };
  }
  const status = readHttpStatus(error);
  if (status === null) {
    return { kind: 'network', status: null, code: null };
  }
  return { kind: 'http', status, code: readErrorCode(error) };
}

/**
 * Reads the authenticated user's current device. The request carries no body, no query and no
 * parameters: the backend resolves tenant, owner and device from the session alone.
 */
export async function fetchCurrentDevice(signal?: AbortSignal): Promise<DeviceStatusPayload> {
  assertPanelMayCall(DEVICE_ENDPOINTS.currentStatus);
  const url = `${apiBaseUrl()}${DEVICE_ENDPOINTS.currentStatus}`;
  return request.get<DeviceStatusPayload>(url, signal ? { signal } : undefined);
}

/**
 * Redeems a six-digit pairing code for the authenticated owner (the frozen LP-2 leg).
 *
 * This is where the panel's job ends: the server binds `pendingOwnerId` and moves the session
 * to `claim_pending`. No authority or lease is granted here — the PC's own poll of
 * `pairing/complete` lands the lease, and the panel learns about it from `GET /current`.
 */
export async function approvePairingCode(code: string): Promise<PairingApprovePayload> {
  assertPanelMayCall(DEVICE_ENDPOINTS.pairingApprove);
  const url = `${apiBaseUrl()}${DEVICE_ENDPOINTS.pairingApprove}`;
  const body = buildApproveBody(code);
  return (await request.post(url, body)) as PairingApprovePayload;
}
