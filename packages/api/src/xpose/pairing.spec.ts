import {
  buildPortalClaimCanonicalString,
  decodePortalSecret,
  hashPortalClaimBody,
  loadXposePairingConfig,
  mapUpstreamStatus,
  requestPortalClaim,
  serializePortalClaimBody,
  signPortalClaim,
} from './pairing';

/**
 * Frozen vector: computed independently with `node:crypto` from the exact Xpose contract.
 * If the canonical string or serialization order drifts, these assertions fail.
 */
const SECRET_TEXT = 'eHBvc2UtcG9ydGFsLXRlc3Qtc2VjcmV0LTAxMjM0NTY3ODlhYmNkZWY';
const TIMESTAMP = '1700000000000';
const NONCE = 'abcdefghijklmnopqrstuv';
const BODY = {
  code: 'ABC-123',
  actorId: 'user@example.com',
  connectionOwnerId: 'user@example.com',
  fleetId: 'fleet-1',
};
const BODY_TEXT =
  '{"code":"ABC-123","actorId":"user@example.com","connectionOwnerId":"user@example.com","fleetId":"fleet-1"}';
const BODY_HASH = 'Jaqx6-ODVk8f_Rz3zmCMETY7gl_cGKTYsckA7c1X1GE';
const CANONICAL =
  'xpose-pairing-portal-v1\nPOST\n/pairing/portal-claim\n1700000000000\nabcdefghijklmnopqrstuv\nJaqx6-ODVk8f_Rz3zmCMETY7gl_cGKTYsckA7c1X1GE';
const SIGNATURE = 'R8rgT39mAxBkb0zFi840beRarK5kyUiyKO8dVpPcSpg';

const VALID_ENV = {
  XPOSE_PAIRING_URL: 'https://xpose.example.com',
  XPOSE_PAIRING_PORTAL_SECRET: SECRET_TEXT,
  XPOSE_PAIRING_FLEET_ID: 'fleet-1',
};

describe('decodePortalSecret', () => {
  it('accepts base64url that decodes to at least 32 bytes', () => {
    const bytes = decodePortalSecret(SECRET_TEXT);
    expect(bytes).not.toBeNull();
    expect(bytes?.length).toBe(41);
  });

  it('rejects short, malformed, and non-canonical secrets', () => {
    expect(decodePortalSecret('')).toBeNull();
    expect(decodePortalSecret('QUJD')).toBeNull(); // 3 bytes
    expect(decodePortalSecret('not base64url!!')).toBeNull();
    expect(decodePortalSecret('AAAAA')).toBeNull(); // length % 4 === 1
    expect(decodePortalSecret('QUJD====')).toBeNull(); // padding not allowed
  });
});

describe('loadXposePairingConfig', () => {
  it('fails closed when any env var is missing or invalid', () => {
    expect(loadXposePairingConfig({}).ok).toBe(false);
    expect(loadXposePairingConfig({ ...VALID_ENV, XPOSE_PAIRING_URL: '' }).ok).toBe(false);
    expect(
      loadXposePairingConfig({ ...VALID_ENV, XPOSE_PAIRING_URL: 'http://xpose.example.com' }).ok,
    ).toBe(false);
    expect(loadXposePairingConfig({ ...VALID_ENV, XPOSE_PAIRING_URL: 'not-a-url' }).ok).toBe(false);
    expect(loadXposePairingConfig({ ...VALID_ENV, XPOSE_PAIRING_PORTAL_SECRET: 'QUJD' }).ok).toBe(
      false,
    );
    expect(loadXposePairingConfig({ ...VALID_ENV, XPOSE_PAIRING_FLEET_ID: 'bad fleet!' }).ok).toBe(
      false,
    );
  });

  it('normalizes to the exact portal-claim pathname and exposes decoded bytes', () => {
    const result = loadXposePairingConfig({
      ...VALID_ENV,
      XPOSE_PAIRING_URL: 'https://xpose.example.com/some/prefix?token=1#frag',
    });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.config.endpoint).toBe('https://xpose.example.com/pairing/portal-claim');
    expect(result.config.fleetId).toBe('fleet-1');
    expect(result.config.secret.length).toBe(41);
  });
});

describe('signPortalClaim', () => {
  it('matches the frozen signature vector', () => {
    expect(serializePortalClaimBody(BODY)).toBe(BODY_TEXT);
    const secret = decodePortalSecret(SECRET_TEXT);
    expect(secret).not.toBeNull();
    if (!secret) {
      return;
    }
    const bodyHash = hashPortalClaimBody(BODY_TEXT);
    expect(bodyHash).toBe(BODY_HASH);
    expect(buildPortalClaimCanonicalString({ timestamp: TIMESTAMP, nonce: NONCE, bodyHash })).toBe(
      CANONICAL,
    );
    expect(
      signPortalClaim({ secret, timestamp: TIMESTAMP, nonce: NONCE, bodyText: BODY_TEXT }),
    ).toEqual({
      bodyHash: BODY_HASH,
      signature: SIGNATURE,
    });
  });
});

describe('mapUpstreamStatus', () => {
  it('passes through conservative statuses and maps everything else to 502', () => {
    for (const status of [400, 401, 403, 404, 409, 410, 429]) {
      expect(mapUpstreamStatus(status)).toBe(status);
    }
    expect(mapUpstreamStatus(200)).toBe(502);
    expect(mapUpstreamStatus(418)).toBe(502);
    expect(mapUpstreamStatus(500)).toBe(502);
    expect(mapUpstreamStatus(503)).toBe(502);
  });
});

describe('requestPortalClaim', () => {
  const config = loadXposePairingConfig(VALID_ENV);

  function requireConfig() {
    if (!config.ok) {
      throw new Error('test config unexpectedly invalid');
    }
    return config.config;
  }

  const deps = { now: () => Number(TIMESTAMP), randomNonce: () => NONCE };

  it('signs and transmits the exact serialized body with the contract headers', async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fetchImpl = (async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      return { status: 200, json: async () => ({ ok: true, state: 'claimed', deviceId: 'dev-1' }) };
    }) as unknown as typeof fetch;

    const result = await requestPortalClaim(requireConfig(), BODY, { ...deps, fetch: fetchImpl });

    expect(result).toEqual({
      ok: true,
      status: 200,
      body: { ok: true, state: 'claimed', deviceId: 'dev-1' },
    });
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe('https://xpose.example.com/pairing/portal-claim');
    expect(calls[0].init.method).toBe('POST');
    expect(calls[0].init.body).toBe(BODY_TEXT);
    const headers = calls[0].init.headers as Record<string, string>;
    expect(headers['content-type']).toBe('application/json');
    expect(headers['x-xpose-portal-timestamp']).toBe(TIMESTAMP);
    expect(headers['x-xpose-portal-nonce']).toBe(NONCE);
    expect(headers['x-xpose-portal-signature']).toBe(SIGNATURE);
  });

  it('tags network failures as unreachable', async () => {
    const fetchImpl = jest
      .fn()
      .mockRejectedValue(new Error('econnrefused')) as unknown as typeof fetch;
    const result = await requestPortalClaim(requireConfig(), BODY, { ...deps, fetch: fetchImpl });
    expect(result).toEqual({ ok: false, reason: 'unreachable' });
  });

  it('tags aborts as timeout and respects the abort signal', async () => {
    const fetchImpl = ((_url: string, init: RequestInit) =>
      new Promise((_resolve, reject) => {
        init.signal?.addEventListener('abort', () => {
          const error = new Error('aborted');
          error.name = 'AbortError';
          reject(error);
        });
      })) as unknown as typeof fetch;

    const result = await requestPortalClaim(
      requireConfig(),
      BODY,
      { ...deps, fetch: fetchImpl },
      5,
    );
    expect(result).toEqual({ ok: false, reason: 'timeout' });
  });
});
