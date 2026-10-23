/**
 * Wire and view-model types for the "My Computer" panel (GM plan W3).
 *
 * NOTE ON IDENTITY: `GET /api/devices/current` also returns `tenantId` and `deviceId` on the
 * wire, and `POST /api/devices/pairing/approve` also returns `pairingSessionId` and
 * `deviceKeyId`. None of them are modelled below, on purpose: if the panel's types cannot
 * express an identity value, no component can render one, log one, or echo one back. The panel
 * accepts no identity input either — the only user input is six digits.
 */

/** The two — and only two — device endpoints the panel is permitted to call. */
export type DeviceEndpointPath = '/api/devices/current' | '/api/devices/pairing/approve';

/** `GET /api/devices/current` — the fields the panel actually uses. */
export interface DeviceStatusPayload {
  ok?: boolean;
  identityState?: string | null;
  leaseState?: string | null;
  epoch?: number | string | null;
  expiresAt?: string | null;
  /**
   * The server's own wall clock at response time (ISO-8601), or `null`/absent when the server
   * could not state it. The panel anchors lease expiry to this reading, never to the browser's
   * clock: a snapshot-restored VM or a domain-drifted clock can be hours off, and a slow local
   * clock must not be able to turn an expired lease green. No identity, no authority.
   */
  serverTime?: string | null;
}

/** `POST /api/devices/pairing/approve` — the fields the panel actually uses. */
export interface PairingApprovePayload {
  ok?: boolean;
  state?: string | null;
  expiresAt?: string | null;
}

/**
 * Normalized failure. `kind` separates "the server answered and said no" (`http`) from
 * "the request never produced a trustworthy answer" (`network`/`malformed`); the panel maps
 * those to distinct, non-authority-implying states.
 */
export type DeviceApiErrorKind = 'network' | 'http' | 'malformed';

export interface DeviceApiError {
  kind: DeviceApiErrorKind;
  status: number | null;
  code: string | null;
}

/** What the panel knows about the lease — and nothing that identifies an owner or a device. */
export interface LeaseSnapshot {
  identityState: string | null;
  leaseState: string | null;
  epoch: number | null;
  expiresAt: number | null;
}

/**
 * The panel's single source of truth for what to show about the lease.
 *
 * `connected` is only reachable from `identityState === 'active' && leaseState === 'active'`
 * with a readable expiry in the future. Everything else is a distinct, honest non-connected
 * state.
 */
export type StatusView =
  | { kind: 'loading' }
  | { kind: 'relay-error'; error: DeviceApiError }
  | { kind: 'session-expired' }
  | { kind: 'request-rejected' }
  | { kind: 'no-device' }
  | {
      kind: 'connected';
      lease: LeaseSnapshot;
      renewalDue: boolean;
      remainingMs: number;
      /**
       * `serverTime - localNowAtFetch` at the moment the status body arrived. The card renders the
       * countdown from `now + serverNowOffsetMs` so the number on screen matches the server's
       * clock, not this browser's (which may be hours off).
       */
      serverNowOffsetMs: number;
    }
  | { kind: 'paired-incomplete'; lease: LeaseSnapshot }
  | { kind: 'expired'; lease: LeaseSnapshot }
  | { kind: 'revoked'; lease: LeaseSnapshot }
  | { kind: 'unverified'; lease: LeaseSnapshot };

/**
 * Local claim window: set only after the server accepted a code. The panel uses it to keep
 * showing "waiting for your PC" while `GET /current` still reports no device, and to close
 * that message honestly when the window passes without the lease landing (GM-2).
 */
export interface ClaimWindow {
  approvedAt: number;
  deadline: number;
}
