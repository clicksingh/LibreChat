/**
 * DOM-free specs for the panel's pure derivations.
 *
 * These import `deriveView.ts` (which imports `api.ts` only for `toDeviceApiError`) and exercise
 * plain functions: no React, no rendering, no fake DOM. The `librechat-data-provider` import in
 * `api.ts` is mocked virtually because the workspace package is unbuilt in this lab checkout.
 *
 * Runner: `cd client && npx jest src/components/Device/__tests__ --coverage=false`
 */

jest.mock(
  'librechat-data-provider',
  () => ({
    apiBaseUrl: () => 'http://localhost:3080',
    request: { get: jest.fn(), post: jest.fn() },
  }),
  { virtual: true },
);

import { RENEWAL_DUE_WINDOW_MS } from '../constants';
import { deriveStatusView, serverClockOffset } from '../deriveView';
import type { DeviceStatusPayload } from '../types';

const TRUE_NOW = 1_800_000_000_000; // An arbitrary instant; nothing here reads the real clock.
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

/** A live-looking body as the server would send it at `serverNow`. */
function body(overrides: Partial<DeviceStatusPayload> = {}): DeviceStatusPayload {
  return {
    ok: true,
    identityState: 'active',
    leaseState: 'active',
    epoch: 3,
    expiresAt: new Date(TRUE_NOW + HOUR).toISOString(),
    serverTime: new Date(TRUE_NOW).toISOString(),
    ...overrides,
  };
}

describe('error beats stale data (failed poll wins over a cached success)', () => {
  // A previous poll succeeded and left a green-looking body in the query cache.
  const staleSuccess = body({ expiresAt: new Date(TRUE_NOW + 24 * HOUR).toISOString() });

  it('control: without an error the cached body really would render connected', () => {
    const view = deriveStatusView({
      error: null,
      payload: staleSuccess,
      now: TRUE_NOW,
      fetchedAt: TRUE_NOW,
    });
    expect(view.kind).toBe('connected');
  });

  it('a 401 wins over stale success data and renders session-expired', () => {
    const view = deriveStatusView({
      error: { response: { status: 401 } },
      payload: staleSuccess,
      now: TRUE_NOW,
      fetchedAt: TRUE_NOW,
    });
    expect(view.kind).toBe('session-expired');
    expect(view.kind).not.toBe('connected');
  });

  it('an unknown-device 404 wins over stale success data and renders no-device', () => {
    const view = deriveStatusView({
      error: { response: { status: 404, data: { code: 'UNKNOWN_DEVICE' } } },
      payload: staleSuccess,
      now: TRUE_NOW,
      fetchedAt: TRUE_NOW,
    });
    expect(view.kind).toBe('no-device');
  });

  it('an identity-rejected 400 wins over stale success data and renders request-rejected', () => {
    const view = deriveStatusView({
      error: { response: { status: 400, data: { code: 'REQUEST_SUPPLIED_IDENTITY_REJECTED' } } },
      payload: staleSuccess,
      now: TRUE_NOW,
      fetchedAt: TRUE_NOW,
    });
    expect(view.kind).toBe('request-rejected');
  });

  it('an HTTP failure wins over stale success data and renders relay-error', () => {
    const view = deriveStatusView({
      error: { response: { status: 502, data: { code: 'RELAY_UNAVAILABLE' } } },
      payload: staleSuccess,
      now: TRUE_NOW,
      fetchedAt: TRUE_NOW,
    });
    expect(view.kind).toBe('relay-error');
    if (view.kind === 'relay-error') {
      expect(view.error).toEqual({ kind: 'http', status: 502, code: 'RELAY_UNAVAILABLE' });
    }
  });

  it('a transport failure (no response) wins over stale success data', () => {
    const view = deriveStatusView({
      error: new Error('socket hang up'),
      payload: staleSuccess,
      now: TRUE_NOW,
      fetchedAt: TRUE_NOW,
    });
    expect(view.kind).toBe('relay-error');
    if (view.kind === 'relay-error') {
      expect(view.error.kind).toBe('network');
    }
  });

  it('a malformed body is a relay-error even with no error object', () => {
    const view = deriveStatusView({
      error: null,
      payload: { ...body(), ok: false },
      now: TRUE_NOW,
      fetchedAt: TRUE_NOW,
    });
    expect(view.kind).toBe('relay-error');
  });
});

describe('server-clock anchoring (clock skew must not produce a false Connected)', () => {
  it('derives offset = serverTime - localNowAtFetch', () => {
    const offset = serverClockOffset(
      body({ serverTime: new Date(TRUE_NOW).toISOString() }),
      TRUE_NOW - 2 * HOUR,
    );
    expect(offset).toBe(2 * HOUR);
  });

  it('returns null when serverTime is absent, null or unparseable', () => {
    expect(serverClockOffset(body({ serverTime: undefined }), TRUE_NOW)).toBeNull();
    expect(serverClockOffset(body({ serverTime: null }), TRUE_NOW)).toBeNull();
    expect(serverClockOffset(body({ serverTime: 'not-a-timestamp' }), TRUE_NOW)).toBeNull();
    expect(serverClockOffset(body(), 0)).toBeNull();
  });

  it('a 2-hour-slow local clock with an expired lease renders expired, NOT connected', () => {
    const localSkew = -2 * HOUR;
    const localNowAtFetch = TRUE_NOW + localSkew;
    // The lease truly expired an hour ago on the server.
    const expired = body({
      expiresAt: new Date(TRUE_NOW - HOUR).toISOString(),
      serverTime: new Date(TRUE_NOW).toISOString(),
    });

    // The defect this test pins: raw local arithmetic says there is still an hour left.
    const rawLocalRemaining = Date.parse(String(expired.expiresAt)) - localNowAtFetch;
    expect(rawLocalRemaining).toBe(HOUR); // verifier's demonstrated `remainingMs=3600000`

    const view = deriveStatusView({
      error: null,
      payload: expired,
      now: localNowAtFetch,
      fetchedAt: localNowAtFetch,
    });

    expect(view.kind).not.toBe('connected');
    expect(view.kind).toBe('expired');
  });

  it('a 2-hour-fast local clock does not misfire the T-2h renewal window', () => {
    const localSkew = 2 * HOUR;
    const localNowAtFetch = TRUE_NOW + localSkew;
    // Three hours of lease left on the server: outside the T-2h window.
    const live = body({ expiresAt: new Date(TRUE_NOW + 3 * HOUR).toISOString() });

    // Raw local arithmetic would put it at one hour left, inside the window (the misfire).
    const rawLocalRemaining = Date.parse(String(live.expiresAt)) - localNowAtFetch;
    expect(rawLocalRemaining).toBeLessThan(RENEWAL_DUE_WINDOW_MS);

    const view = deriveStatusView({
      error: null,
      payload: live,
      now: localNowAtFetch,
      fetchedAt: localNowAtFetch,
    });

    expect(view.kind).toBe('connected');
    if (view.kind === 'connected') {
      expect(view.renewalDue).toBe(false);
      expect(view.remainingMs).toBe(3 * HOUR);
      expect(view.serverNowOffsetMs).toBe(-2 * HOUR);
    }
  });

  it('advances the countdown on server time as the local tick moves', () => {
    const localSkew = -2 * HOUR;
    const localNowAtFetch = TRUE_NOW + localSkew;
    const live = body({ expiresAt: new Date(TRUE_NOW + HOUR).toISOString() });

    const first = deriveStatusView({
      error: null,
      payload: live,
      now: localNowAtFetch,
      fetchedAt: localNowAtFetch,
    });
    const later = deriveStatusView({
      error: null,
      payload: live,
      now: localNowAtFetch + 10 * MINUTE,
      fetchedAt: localNowAtFetch,
    });

    expect(first.kind).toBe('connected');
    expect(later.kind).toBe('connected');
    if (first.kind === 'connected' && later.kind === 'connected') {
      expect(first.remainingMs).toBe(HOUR);
      expect(later.remainingMs).toBe(HOUR - 10 * MINUTE);
    }
  });

  it('fails closed to unverified when the server states no time', () => {
    for (const serverTime of [undefined, null, 'not-a-timestamp']) {
      const view = deriveStatusView({
        error: null,
        payload: body({
          expiresAt: new Date(TRUE_NOW + 24 * HOUR).toISOString(),
          serverTime: serverTime as DeviceStatusPayload['serverTime'],
        }),
        now: TRUE_NOW,
        fetchedAt: TRUE_NOW,
      });
      expect(view.kind).toBe('unverified');
      expect(view.kind).not.toBe('connected');
    }
  });

  it('still reports connected when the local clock agrees with the server', () => {
    const view = deriveStatusView({
      error: null,
      payload: body(),
      now: TRUE_NOW,
      fetchedAt: TRUE_NOW,
    });
    expect(view.kind).toBe('connected');
  });

  it('marks a lease inside the T-2h window as renewal-due on server time', () => {
    const view = deriveStatusView({
      error: null,
      payload: body({ expiresAt: new Date(TRUE_NOW + HOUR).toISOString() }),
      now: TRUE_NOW,
      fetchedAt: TRUE_NOW,
    });
    expect(view.kind).toBe('connected');
    if (view.kind === 'connected') {
      expect(view.renewalDue).toBe(true);
    }
  });
});
