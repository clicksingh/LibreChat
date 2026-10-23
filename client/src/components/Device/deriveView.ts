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

/** Classifies a lease snapshot. The single place that may answer "connected". */
export function classifyLease(lease: LeaseSnapshot, now: number): LeaseClassification {
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
  now: number;
}

/**
 * Maps the query result onto the panel's status view.
 *
 * A failed poll WINS over last-known data: if the page cannot reach the server it must not keep
 * showing "Connected" from a stale response, because that is exactly the false-connected state
 * the panel is required never to display.
 */
export function deriveStatusView({ error, payload, now }: DeriveStatusViewInput): StatusView {
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
  const classification = classifyLease(lease, now);
  if (classification.kind === 'connected' && classification.remainingMs !== null) {
    return {
      kind: 'connected',
      lease,
      renewalDue: classification.renewalDue,
      remainingMs: classification.remainingMs,
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
