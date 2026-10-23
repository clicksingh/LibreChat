/**
 * DOM-free spec for the panel's network boundary.
 *
 * Pins the two-entry allowlist and proves `assertPanelMayCall` refuses every other path — renewal,
 * pairing completion and the device-key legs included. No React, no rendering.
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

import { ALLOWED_PANEL_ENDPOINTS, DEVICE_ENDPOINTS } from '../constants';
import { PanelBoundaryError, approvePairingCode, assertPanelMayCall } from '../api';

/**
 * The spec reads the mocked request client through `jest.requireMock` rather than importing it:
 * the scoped eslint override forbids this directory from importing `request` at all (api.ts is the
 * only exception), and the spec should obey the rule it pins.
 */
const mockedRequest = (jest.requireMock('librechat-data-provider') as { request: unknown })
  .request as { get: jest.Mock; post: jest.Mock };

beforeEach(() => {
  mockedRequest.get.mockReset();
  mockedRequest.post.mockReset();
});

describe('the panel allowlist has exactly two entries', () => {
  it('is exactly the status read and the pairing approve', () => {
    expect(ALLOWED_PANEL_ENDPOINTS).toHaveLength(2);
    expect([...ALLOWED_PANEL_ENDPOINTS]).toEqual([
      '/api/devices/current',
      '/api/devices/pairing/approve',
    ]);
    expect(DEVICE_ENDPOINTS.currentStatus).toBe('/api/devices/current');
    expect(DEVICE_ENDPOINTS.pairingApprove).toBe('/api/devices/pairing/approve');
    expect(Object.keys(DEVICE_ENDPOINTS)).toHaveLength(2);
  });

  it('does not contain the renewal path or any device-authenticated leg', () => {
    for (const forbidden of [
      '/api/devices/current/renew',
      '/api/devices/current/retire',
      '/api/devices/pairing/complete',
      '/api/devices/pairing/challenge',
      '/api/devices/pairing/issue',
    ]) {
      expect(ALLOWED_PANEL_ENDPOINTS).not.toContain(forbidden);
    }
  });
});

describe('assertPanelMayCall', () => {
  it('permits both allowlisted paths', () => {
    expect(() => assertPanelMayCall('/api/devices/current')).not.toThrow();
    expect(() => assertPanelMayCall('/api/devices/pairing/approve')).not.toThrow();
  });

  it.each([
    '/api/devices/current/renew',
    '/api/devices/current/retire',
    '/api/devices/pairing/complete',
    '/api/devices/pairing/challenge',
    '/api/devices/pairing/issue',
    '/api/devices/current?deviceId=x',
    '/api/devices/current/',
    '',
  ])('throws PanelBoundaryError for %s', (path) => {
    expect(() => assertPanelMayCall(path)).toThrow(PanelBoundaryError);
    expect(() => assertPanelMayCall(path)).toThrow(/may not call/);
  });

  it('the error carries the boundary code, not an HTTP status', () => {
    try {
      assertPanelMayCall('/api/devices/current/renew');
      throw new Error('expected assertPanelMayCall to throw');
    } catch (error) {
      expect(error).toBeInstanceOf(PanelBoundaryError);
      expect((error as PanelBoundaryError).code).toBe('PANEL_BOUNDARY_VIOLATION');
    }
  });
});

describe('the two exported callers stay inside the allowlist', () => {
  it('fetchCurrentDevice only ever GETs the status path', async () => {
    const { fetchCurrentDevice } = await import('../api');
    mockedRequest.get.mockResolvedValueOnce({ ok: true });
    await fetchCurrentDevice();
    expect(mockedRequest.get).toHaveBeenCalledTimes(1);
    expect(mockedRequest.get.mock.calls[0][0]).toBe('http://localhost:3080/api/devices/current');
    expect(mockedRequest.post).not.toHaveBeenCalled();
  });

  it('approvePairingCode only ever POSTs the approve path with six digits', async () => {
    mockedRequest.post.mockResolvedValueOnce({ ok: true });
    await approvePairingCode('123456');
    expect(mockedRequest.post).toHaveBeenCalledTimes(1);
    expect(mockedRequest.post.mock.calls[0][0]).toBe(
      'http://localhost:3080/api/devices/pairing/approve',
    );
    expect(mockedRequest.post.mock.calls[0][1]).toEqual({ code: '123456' });
    expect(mockedRequest.get).not.toHaveBeenCalled();
  });

  it('a malformed code is refused before any request is sent', async () => {
    await expect(approvePairingCode('12ab56')).rejects.toBeInstanceOf(PanelBoundaryError);
    expect(mockedRequest.post).not.toHaveBeenCalled();
  });
});
