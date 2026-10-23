/**
 * Frozen constants for the "My Computer" panel (GM plan W3).
 *
 * The panel is a READ-AND-APPROVE surface. It reads lease status and redeems a six-digit
 * pairing code. It never grants, renews or extends authority — see `api.ts` for the two-endpoint
 * allowlist that enforces this mechanically.
 */

import type { DeviceEndpointPath } from './types';

/** Six digits, single use, 300 s TTL — frozen product constraint (AGENTS.md, GM-2). */
export const PAIRING_CODE_LENGTH = 6;
export const PAIRING_CODE_TTL_MS = 300_000;

/** GM-3: the tray app warns at T-2h before expiry; the panel mirrors that window. */
export const RENEWAL_DUE_WINDOW_MS = 2 * 60 * 60 * 1000;

/** Status polling: calm when idle, brisk while a claim is landing (GM-2 device poll). */
export const STATUS_POLL_INTERVAL_MS = 15_000;
export const CLAIM_POLL_INTERVAL_MS = 5_000;

/** Digits-only filtering, and the exact shape the backend accepts (`/^\d{6}$/`). */
export const NON_DIGIT_PATTERN = /[^0-9]/g;
export const SIX_DIGIT_CODE_PATTERN = /^[0-9]{6}$/;

/**
 * The COMPLETE set of device endpoints this panel may call.
 *
 * Deliberately absent, and never to be added here:
 * - `/api/devices/current/renew` — renewal requires fresh LOCAL confirmation on the PC
 *   (docs/ARCHITECTURE.md boundary 7) and owner identity is confined to the backend (D007).
 *   A stolen browser session must not be able to extend device access. The panel nudges the
 *   employee to the tray prompt and nothing more (GM-12 / GM-3).
 * - `/api/devices/pairing/complete` — device-authenticated; the DEVICE calls it, not the panel.
 * - `/api/devices/pairing/challenge` and `/api/devices/pairing/issue` — endpoint-authenticated
 *   with the PC's own Ed25519 key material and signature. The browser holds no key and must
 *   never be asked for one, so those two legs belong to the Tauri app, not to this panel.
 */
export const DEVICE_ENDPOINTS = {
  currentStatus: '/api/devices/current',
  pairingApprove: '/api/devices/pairing/approve',
} as const satisfies Record<string, DeviceEndpointPath>;

/** Runtime allowlist consulted by `api.ts` before every request. */
export const ALLOWED_PANEL_ENDPOINTS: readonly DeviceEndpointPath[] = [
  DEVICE_ENDPOINTS.currentStatus,
  DEVICE_ENDPOINTS.pairingApprove,
];
