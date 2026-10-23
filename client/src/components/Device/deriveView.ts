/**
 * Pure derivations for the "My Computer" panel.
 *
 * Everything here is a pure function of server truth plus the current clock, so the panel's
 * security-relevant rules are readable in one place and testable without React:
 *
 * 1. `toLeaseSnapshot` copies only the four lease fields out of the wire body. `tenantId` and
 *    `deviceId` are never copied, so no component can render an identity value.
 * 2. `classifyLease` reaches `connected` only for `identityState === 'active'` AND
 *    `leaseState === 'active'` AND a readable expiry strictly in the future. Every other shape
 *    — including "looks active but the expiry is unreadable" — maps to a distinct non-connected
 *    state. There is no fallthrough to `connected`.
 * 3. `now` never means `Date.now()`. `serverClockOffset` turns the body's `serverTime` plus the
 *    local instant it arrived into `offset = serverTime - localNowAtFetch`, and every expiry test
 *    and countdown runs on `localNow + offset`. Without a server time the lease reads `unverified`
 *    — the panel fails closed to a non-green state rather than guess.
 */

import { toDeviceApiError } from './api';
import { NON_DIGIT_PATTERN, RENEWAL_DUE_WINDOW_MS } from './constants';
import type { DeviceApiError, DeviceStatusPayload, LeaseSnapshot, StatusView } from './types';

export interface DurationUnits {
  hour: string;
  minute: string;
  second: string;
}

export interface LeaseClassification {
  kind: 'connected' | 'expired' | 'revoked' | 'paired-incomplete' | 'unverified';
  renewalDue: boolean;
  remainingMs: number | null;
}

/** Parses an ISO-8601 instant (or epoch millis) into millis; `null` when unreadable. */
export function parseInstant(value: unknown): number | null {
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : null;
  }
  if (typeof value !== 'string' || value.length === 0) {
    return null;
  }
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
}

function parseEpoch(value: unknown): number | null {
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : null;
  }
  if (typeof value === 'string' && value.length > 0) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

/**
 * How far this browser's clock sits from the server's, in milliseconds (`server - local`).
 *
 * The status body carries the server's own reading (`serverTime`) and the panel records the local
 * reading taken when that body arrived (`localNowAtFetch`). Their difference is the only honest
 * way to place "now": a snapshot-restored VM or a domain-drifted clock can be hours off, so
 * comparing `expiresAt` against raw `Date.now()` can show a green "Connected" for a lease the
 * server expired an hour ago.
 *
 * `null` means the server did not state a readable time (or no fetch instant is known), so this
 * browser cannot judge an expiry at all — callers fail closed rather than assume.
 */
export function serverClockOffset(
  payload: DeviceStatusPayload,
  localNowAtFetch: number,
): number | null {
  const serverTime = parseInstant(payload.serverTime);
  if (serverTime === null || !Number.isFinite(localNowAtFetch) || localNowAtFetch <= 0) {
    return null;
  }
  return serverTime - localNowAtFetch;
}

/**
 * The panel's view of the lease. Identity values on the wire are deliberately dropped here —
 * this function is the choke point that keeps them out of the render tree.
 */
export function toLeaseSnapshot(payload: DeviceStatusPayload): LeaseSnapshot {
  return {
    identityState: typeof payload.identityState === 'string' ? payload.identityState : null,
    leaseState: typeof payload.leaseState === 'string' ? payload.leaseState : null,
    epoch: parseEpoch(payload.epoch),
    expiresAt: parseInstant(payload.expiresAt),
  };
}

/**
 * Classifies a lease snapshot. The single place that may answer "connected".
 *
 * `now` must be SERVER-anchored time (`localNow + serverClockOffset`), or `null` when no server
 * clock reading is available. A `null` clock can never produce `connected`: without a trustworthy
 * "now", "unexpired" is not knowable, and the panel's rule is to never claim green on a guess.
 */
export function classifyLease(lease: LeaseSnapshot, now: number | null): LeaseClassification {
  if (lease.identityState === 'retired' || lease.leaseState === 'revoked') {
    return { kind: 'revoked', renewalDue: false, remainingMs: null };
  }
  if (lease.leaseState === 'expired') {
    return { kind: 'expired', renewalDue: false, remainingMs: null };
  }
  if (lease.expiresAt === null) {
    if (lease.leaseState === 'never' || lease.identityState === 'pending') {
      return { kind: 'paired-incomplete', renewalDue: false, remainingMs: null };
    }
    // Active-looking states but no readable expiry: never claim connected.
    return { kind: 'unverified', renewalDue: false, remainingMs: null };
  }
  if (now === null || !Number.isFinite(now)) {
    // The server never stated its time: the expiry cannot be judged here. Fail closed.
    return { kind: 'unverified', renewalDue: false, remainingMs: null };
  }
  const remainingMs = lease.expiresAt - now;
  if (remainingMs <= 0) {
    return { kind: 'expired', renewalDue: false, remainingMs: 0 };
  }
  if (lease.identityState === 'active' && lease.leaseState === 'active') {
    return {
      kind: 'connected',
      renewalDue: remainingMs <= RENEWAL_DUE_WINDOW_MS,
      remainingMs,
    };
  }
  return { kind: 'paired-incomplete', renewalDue: false, remainingMs };
}

export interface DeriveStatusViewInput {
  /** The query error, if the most recent poll failed. */
  error: unknown;
  /** The most recent successful body, if any. A missing body with no error means "loading". */
  payload: DeviceStatusPayload | undefined;
  /** Current local tick (`Date.now()` via `useNow`), for the live countdown. */
  now: number;
  /**
   * Local `Date.now()` captured when `payload` arrived (React Query's `dataUpdatedAt`). The
   * server-clock offset is anchored here, not at render time, so the countdown advances at the
   * same rate as the server rather than freezing or drifting.
   */
  fetchedAt: number;
}

/**
 * Maps the query result onto the panel's status view.
 *
 * A failed poll WINS over last-known data: if the page cannot reach the server it must not keep
 * showing "Connected" from a stale response, because that is exactly the false-connected state
 * the panel is required never to display.
 *
 * The lease clock is the SERVER's: `expiresAt` is compared against `now + offset`, where
 * `offset = serverTime - localNowAtFetch`. A local clock that is two hours slow can therefore no
 * longer turn an expired lease green, and a fast clock can no longer misfire the T-2h renewal
 * window. If the server's time is missing or unreadable, the lease reads `unverified`.
 */
export function deriveStatusView({
  error,
  payload,
  now,
  fetchedAt,
}: DeriveStatusViewInput): StatusView {
  if (error != null) {
    const apiError: DeviceApiError = toDeviceApiError(error);
    if (apiError.kind === 'http' && apiError.status === 401) {
      return { kind: 'session-expired' };
    }
    if (
      apiError.kind === 'http' &&
      apiError.status === 400 &&
      apiError.code === 'REQUEST_SUPPLIED_IDENTITY_REJECTED'
    ) {
      return { kind: 'request-rejected' };
    }
    if (apiError.kind === 'http' && apiError.status === 404 && apiError.code === 'UNKNOWN_DEVICE') {
      return { kind: 'no-device' };
    }
    return { kind: 'relay-error', error: apiError };
  }
  if (payload == null) {
    return { kind: 'loading' };
  }
  if (payload.ok !== true) {
    return { kind: 'relay-error', error: { kind: 'malformed', status: null, code: null } };
  }

  const lease = toLeaseSnapshot(payload);
  const offsetMs = serverClockOffset(payload, fetchedAt);
  const serverNow = offsetMs === null ? null : now + offsetMs;
  const classification = classifyLease(lease, serverNow);
  if (
    classification.kind === 'connected' &&
    classification.remainingMs !== null &&
    offsetMs !== null
  ) {
    return {
      kind: 'connected',
      lease,
      renewalDue: classification.renewalDue,
      remainingMs: classification.remainingMs,
      serverNowOffsetMs: offsetMs,
    };
  }
  if (classification.kind === 'expired') {
    return { kind: 'expired', lease };
  }
  if (classification.kind === 'revoked') {
    return { kind: 'revoked', lease };
  }
  if (classification.kind === 'unverified') {
    return { kind: 'unverified', lease };
  }
  return { kind: 'paired-incomplete', lease };
}

/** Remaining milliseconds, clamped at zero. */
export function remainingUntil(deadline: number | null, now: number): number | null {
  if (deadline === null) {
    return null;
  }
  return Math.max(0, deadline - now);
}

/** Digits only, at most six — the only user input the panel accepts. */
export function filterCodeInput(raw: string, maxLength: number): string {
  return raw.replace(NON_DIGIT_PATTERN, '').slice(0, maxLength);
}

/** Human duration built from localized unit suffixes: `4m 59s`, `47h 59m`, `12s`. */
export function formatDuration(remainingMs: number, units: DurationUnits): string {
  const totalSeconds = Number.isFinite(remainingMs)
    ? Math.max(0, Math.floor(remainingMs / 1000))
    : 0;
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  if (hours > 0) {
    return `${hours}${units.hour} ${minutes}${units.minute}`;
  }
  if (minutes > 0) {
    return `${minutes}${units.minute} ${seconds}${units.second}`;
  }
  return `${seconds}${units.second}`;
}

/**
 * Renders a server state word using the panel's plain-language map. Unknown values render as
 * the caller's fallback — the panel never invents "Active".
 */
export function describeState(
  labels: Record<string, string>,
  value: string | null,
  fallback: string,
): string {
  if (value === null) {
    return fallback;
  }
  return labels[value] ?? fallback;
}
