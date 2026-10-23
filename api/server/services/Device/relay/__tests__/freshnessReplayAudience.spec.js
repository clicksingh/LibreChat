'use strict';

/**
 * W2 spec — audience binding, freshness in BOTH directions, the deadline bound, and replay.
 *
 * Frozen law under test:
 *   - `audience` is field 14, bound INSIDE the signature.
 *   - freshness is dual: `|now - issuedAt| <= 60 000` (endpoint) / `<= 120 000` (relay), AND
 *     `now <= deadlineMs`, with `deadlineMs` inside the signature so it cannot be extended.
 *   - the replay ring is keyed `(grantId, nonce)`, so a grant rotation starts a fresh ring.
 */

const {
  relay,
  WORKED_EXAMPLE_CORE,
  T0,
  makeTestKeypair,
  makeCustodySeam,
} = require('./_fixtures.cjs');

const keypair = makeTestKeypair();
const verifier = relay.createEnvelopeVerifier({ publicKeySpkiB64u: keypair.publicKeySpkiB64u });

function coreAt({ issuedAt = T0, deadlineMs = T0 + 60000, ...overrides } = {}) {
  return {
    ...WORKED_EXAMPLE_CORE,
    issuedAt: String(issuedAt),
    deadlineMs: String(deadlineMs),
    ...overrides,
  };
}

/**
 * Signs a core and returns the signed envelope.
 *
 * Relay-audience cores are ENDPOINT-signed in production; the backend signing primitive refuses
 * them by default (GM-48 m3), so this reference-verifier spec opts in explicitly in order to have a
 * relay-audience envelope to verify at all. The default refusal is asserted in
 * `defectFixes.spec.js`.
 */
async function sign(core) {
  const signer = relay.createEnvelopeSigner(makeCustodySeam(keypair), {
    allowRelayAudience: true,
  });
  return signer.signCore(core);
}

describe('audience binding', () => {
  it('rejects an endpoint-audience envelope presented to a relay-audience receiver', async () => {
    const signed = await sign(coreAt({ audience: 'endpoint' }));

    const result = await relay.verifyEnvelope({
      signed,
      verifier,
      expectedAudience: 'relay',
      now: T0,
    });

    expect(result.ok).toBe(false);
    expect(result.error.code).toBe('ENVELOPE_AUDIENCE_MISMATCH');
  });

  it('rejects a relay-audience envelope presented to an endpoint-audience receiver', async () => {
    const signed = await sign(coreAt({ audience: 'relay', deadlineMs: T0 + 120000 }));

    const result = await relay.verifyEnvelope({
      signed,
      verifier,
      expectedAudience: 'endpoint',
      now: T0,
    });

    expect(result.ok).toBe(false);
    expect(result.error.code).toBe('ENVELOPE_AUDIENCE_MISMATCH');
  });

  it('accepts each audience at its own receiver', async () => {
    const endpointFrame = await sign(coreAt({ audience: 'endpoint' }));
    const relayFrame = await sign(coreAt({ audience: 'relay', deadlineMs: T0 + 120000 }));

    const asEndpoint = await relay.verifyEnvelope({
      signed: endpointFrame,
      verifier,
      expectedAudience: 'endpoint',
      now: T0,
    });
    const asRelay = await relay.verifyEnvelope({
      signed: relayFrame,
      verifier,
      expectedAudience: 'relay',
      now: T0,
    });

    expect(asEndpoint.ok).toBe(true);
    expect(asRelay.ok).toBe(true);
    expect(asRelay.windowMs).toBe(120000);
  });

  it('cannot be flipped without invalidating the signature', async () => {
    const signed = await sign(coreAt({ audience: 'endpoint' }));
    const flipped = {
      core: { ...signed.core, audience: 'relay' },
      signatureB64u: signed.signatureB64u,
      keyId: signed.keyId,
    };

    const result = await relay.verifyEnvelope({
      signed: flipped,
      verifier,
      expectedAudience: 'relay',
      now: T0,
    });

    expect(result.ok).toBe(false);
    expect(result.error.code).toBe('ENVELOPE_SIGNATURE_INVALID');
  });
});

describe('freshness — endpoint audience (±60 s, both directions)', () => {
  it('accepts an envelope exactly at issuedAt', async () => {
    const signed = await sign(coreAt({ audience: 'endpoint' }));
    const result = await relay.verifyEnvelope({
      signed,
      verifier,
      expectedAudience: 'endpoint',
      now: T0,
    });
    expect(result.ok).toBe(true);
  });

  it('accepts the inclusive +60 s boundary and rejects one millisecond past it', async () => {
    const signed = await sign(coreAt({ audience: 'endpoint', deadlineMs: T0 + 60000 }));

    const atBoundary = await relay.verifyEnvelope({
      signed,
      verifier,
      expectedAudience: 'endpoint',
      now: T0 + 60000,
    });
    const pastBoundary = await relay.verifyEnvelope({
      signed,
      verifier,
      expectedAudience: 'endpoint',
      now: T0 + 60001,
    });

    expect(atBoundary.ok).toBe(true);
    expect(pastBoundary.ok).toBe(false);
    expect(pastBoundary.error.code).toBe('FRESHNESS_EXPIRED');
  });

  it('rejects a future-dated envelope beyond the same window (the other direction)', async () => {
    const signed = await sign(coreAt({ audience: 'endpoint' }));

    const slightlyFuture = await relay.verifyEnvelope({
      signed,
      verifier,
      expectedAudience: 'endpoint',
      now: T0 - 59999,
    });
    const tooFuture = await relay.verifyEnvelope({
      signed,
      verifier,
      expectedAudience: 'endpoint',
      now: T0 - 60001,
    });

    expect(slightlyFuture.ok).toBe(true);
    expect(tooFuture.ok).toBe(false);
    expect(tooFuture.error.code).toBe('FRESHNESS_NOT_YET_VALID');
  });

  it('rejects an envelope whose deadline has passed even inside the freshness window', async () => {
    // issuedAt is fresh (T0+60000 - 60000 = 0 age) but the deadline is 30 s in the past.
    const signed = await sign(coreAt({ audience: 'endpoint', deadlineMs: T0 + 30000 }));

    const result = await relay.verifyEnvelope({
      signed,
      verifier,
      expectedAudience: 'endpoint',
      now: T0 + 60000,
    });

    expect(result.ok).toBe(false);
    expect(result.error.code).toBe('DEADLINE_EXCEEDED');
  });

  it('rejects a mint-side deadline horizon longer than the frozen 120 s cap', async () => {
    expect(() => relay.buildEnvelopeCore(coreAt({ deadlineMs: T0 + 120001 }))).toThrow(
      expect.objectContaining({ code: 'DEADLINE_OUT_OF_BOUND' }),
    );
  });
});

describe('freshness — relay audience (±120 s, both directions)', () => {
  it('accepts a 90 s old relay envelope that the endpoint window would refuse', async () => {
    const signed = await sign(coreAt({ audience: 'relay', deadlineMs: T0 + 120000 }));

    const asRelay = await relay.verifyEnvelope({
      signed,
      verifier,
      expectedAudience: 'relay',
      now: T0 + 90000,
    });
    const asEndpoint = await relay.verifyEnvelope({
      signed,
      verifier,
      expectedAudience: 'endpoint',
      now: T0 + 90000,
    });

    expect(asRelay.ok).toBe(true);
    expect(asEndpoint.ok).toBe(false);
    expect(asEndpoint.error.code).toBe('ENVELOPE_AUDIENCE_MISMATCH');
  });

  it('accepts the inclusive +120 s boundary and rejects one millisecond past it', async () => {
    const signed = await sign(coreAt({ audience: 'relay', deadlineMs: T0 + 120000 }));

    const atBoundary = await relay.verifyEnvelope({
      signed,
      verifier,
      expectedAudience: 'relay',
      now: T0 + 120000,
    });
    const pastBoundary = await relay.verifyEnvelope({
      signed,
      verifier,
      expectedAudience: 'relay',
      now: T0 + 120001,
    });

    expect(atBoundary.ok).toBe(true);
    expect(pastBoundary.ok).toBe(false);
    expect(pastBoundary.error.code).toBe('FRESHNESS_EXPIRED');
  });

  it('rejects a future-dated relay envelope beyond 120 s', async () => {
    const signed = await sign(coreAt({ audience: 'relay', deadlineMs: T0 + 120000 }));

    const result = await relay.verifyEnvelope({
      signed,
      verifier,
      expectedAudience: 'relay',
      now: T0 - 120001,
    });

    expect(result.ok).toBe(false);
    expect(result.error.code).toBe('FRESHNESS_NOT_YET_VALID');
  });

  it('exposes the frozen windows as data', () => {
    expect(relay.AUDIENCE_FRESHNESS_WINDOWS_MS).toEqual({ endpoint: 60000, relay: 120000 });
    expect(relay.freshnessWindowMsFor('endpoint')).toBe(60000);
    expect(relay.freshnessWindowMsFor('relay')).toBe(120000);
    expect(relay.freshnessWindowMsFor('device')).toBeNull();
  });

  it('fails closed on an unusable clock reading', () => {
    const verdict = relay.evaluateFreshness({
      audience: 'endpoint',
      issuedAt: T0,
      deadlineMs: T0 + 60000,
      now: Number.NaN,
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.error.code).toBe('CLOCK_UNUSABLE');
  });
});

describe('replay window (unseen nonce)', () => {
  it('accepts a nonce once and rejects the identical envelope on second admission', async () => {
    const signed = await sign(coreAt());
    const replayWindow = relay.createReplayWindow({ now: () => T0 });

    const first = await relay.verifyEnvelope({
      signed,
      verifier,
      expectedAudience: 'endpoint',
      now: T0,
      replayWindow,
    });
    const second = await relay.verifyEnvelope({
      signed,
      verifier,
      expectedAudience: 'endpoint',
      now: T0,
      replayWindow,
    });

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(false);
    expect(second.error.code).toBe('REPLAY_DETECTED');
    expect(replayWindow.size()).toBe(1);
  });

  it('rejects a re-signed replay: a fresh signature over the same nonce is still a replay', async () => {
    const signed = await sign(coreAt());
    const replayWindow = relay.createReplayWindow({ now: () => T0 });

    await relay.verifyEnvelope({
      signed,
      verifier,
      expectedAudience: 'endpoint',
      now: T0,
      replayWindow,
    });

    // Deterministic Ed25519: identical core yields an identical signature; mutate a harmless field
    // (requestId) and re-sign, keeping the nonce and grant.
    const resigned = await sign(coreAt({ requestId: '3f0c5b1e-8a2d-4c7b-9e61-2d4f8a0b7c94' }));
    const result = await relay.verifyEnvelope({
      signed: resigned,
      verifier,
      expectedAudience: 'endpoint',
      now: T0,
      replayWindow,
    });

    expect(result.ok).toBe(false);
    expect(result.error.code).toBe('REPLAY_DETECTED');
  });

  it('scopes the ring by grantId: the same nonce is fresh under a new grant', async () => {
    const replayWindow = relay.createReplayWindow({ now: () => T0 });
    const oldGrant = await sign(coreAt({ grantId: 'EBESExQVFhcYGRobHB0eHw' }));
    const newGrant = await sign(coreAt({ grantId: 'EBESExQVFhcYGRobHB0eIA' }));

    const first = await relay.verifyEnvelope({
      signed: oldGrant,
      verifier,
      expectedAudience: 'endpoint',
      now: T0,
      replayWindow,
    });
    const rotated = await relay.verifyEnvelope({
      signed: newGrant,
      verifier,
      expectedAudience: 'endpoint',
      now: T0,
      replayWindow,
    });

    expect(first.ok).toBe(true);
    expect(rotated.ok).toBe(true);
    expect(replayWindow.keyOf({ grantId: 'EBESExQVFhcYGRobHB0eHw', nonce: WORKED_EXAMPLE_CORE.nonce }))
      .toBe('EBESExQVFhcYGRobHB0eHw:AAECAwQFBgcICQoLDA0ODw');
  });

  it('does not burn the nonce for a frame that failed an earlier check', async () => {
    const replayWindow = relay.createReplayWindow({ now: () => T0 });
    const genuine = await sign(coreAt());
    const stale = await sign(coreAt({ issuedAt: T0 - 60000, deadlineMs: T0 }));

    const staleResult = await relay.verifyEnvelope({
      signed: stale,
      verifier,
      expectedAudience: 'endpoint',
      now: T0 + 1,
      replayWindow,
    });
    const genuineResult = await relay.verifyEnvelope({
      signed: genuine,
      verifier,
      expectedAudience: 'endpoint',
      now: T0,
      replayWindow,
    });

    expect(staleResult.ok).toBe(false);
    expect(staleResult.error.code).toBe('FRESHNESS_EXPIRED');
    // Same nonce, but the stale frame never reserved it.
    expect(genuineResult.ok).toBe(true);
  });

  it('does not reserve the nonce for a frame whose signature failed', async () => {
    const replayWindow = relay.createReplayWindow({ now: () => T0 });
    const genuine = await sign(coreAt());
    // Deterministic forgery: flip one bit of the decoded signature. (Replacing the trailing
    // characters could, 1 time in 256, reproduce the original signature and make this test pass
    // for the wrong reason.)
    const forgedBytes = Buffer.from(genuine.signatureB64u, 'base64url');
    forgedBytes[0] ^= 0x01;
    const forged = { ...genuine, signatureB64u: forgedBytes.toString('base64url') };
    expect(forged.signatureB64u).not.toBe(genuine.signatureB64u);

    const forgedResult = await relay.verifyEnvelope({
      signed: forged,
      verifier,
      expectedAudience: 'endpoint',
      now: T0,
      replayWindow,
    });
    const genuineResult = await relay.verifyEnvelope({
      signed: genuine,
      verifier,
      expectedAudience: 'endpoint',
      now: T0,
      replayWindow,
    });

    expect(forgedResult.ok).toBe(false);
    expect(genuineResult.ok).toBe(true);
  });

  /**
   * SAFETY PROPERTY (GM-48 m2) — deliberately NOT a boundary-behaviour assertion.
   *
   *   A nonce is never forgotten while an envelope bearing it could still be fresh.
   *
   * The old test asserted that a reservation is forgotten at exactly `seenAt + retentionMs`. That
   * encoded the defect: freshness accepts `ageMs == windowMs`, so at that instant an envelope is
   * still admissible while its nonce had already been pruned. This test asserts the property
   * instead, at the ENFORCED MINIMUM retention (where the old off-by-one was live) and through the
   * real admission chain rather than the ring alone.
   */
  it('never forgets a nonce while an envelope bearing it could still be fresh (minimum retention)', async () => {
    let now = T0;
    const replayWindow = relay.createReplayWindow({
      now: () => now,
      retentionMs: relay.MIN_REPLAY_RETENTION_MS,
    });
    expect(replayWindow.retentionMs).toBe(relay.MAX_FRESHNESS_WINDOW_MS);

    const signed = await sign(coreAt({ audience: 'relay', deadlineMs: T0 + 120000 }));
    const admit = (atMs) =>
      relay.verifyEnvelope({
        signed,
        verifier,
        expectedAudience: 'relay',
        now: atMs,
        replayWindow,
      });

    const first = await admit(T0);
    expect(first.ok).toBe(true);

    // One millisecond inside the freshness window: forgotten => replay accepted. Must not happen.
    now = T0 + relay.MAX_FRESHNESS_WINDOW_MS - 1;
    const inside = await admit(now);
    expect({ at: 'window-1', ok: inside.ok, code: inside.error?.code }).toEqual({
      at: 'window-1',
      ok: false,
      code: 'REPLAY_DETECTED',
    });

    // EXACTLY at the widest freshness window: freshness still accepts `ageMs == windowMs`, so the
    // envelope is still admissible and the nonce MUST still be remembered. This is the boundary the
    // old `<=` prune reopened.
    now = T0 + relay.MAX_FRESHNESS_WINDOW_MS;
    expect(relay.evaluateFreshness({ audience: 'relay', issuedAt: T0, deadlineMs: T0 + 120000, now }).ok)
      .toBe(true);
    const atBoundary = await admit(now);
    expect({ at: 'window', ok: atBoundary.ok, code: atBoundary.error?.code }).toEqual({
      at: 'window',
      ok: false,
      code: 'REPLAY_DETECTED',
    });

    // Only once the envelope can no longer be fresh is forgetting it safe.
    now = T0 + relay.MAX_FRESHNESS_WINDOW_MS + 1;
    expect(relay.evaluateFreshness({ audience: 'relay', issuedAt: T0, deadlineMs: T0 + 120000, now }).ok)
      .toBe(false);
    expect(replayWindow.has({ grantId: WORKED_EXAMPLE_CORE.grantId, nonce: WORKED_EXAMPLE_CORE.nonce }))
      .toBe(false);
  });

  it('honours a supplied freshness horizon even when it is longer than the retention', async () => {
    let now = T0;
    const replayWindow = relay.createReplayWindow({
      now: () => now,
      retentionMs: relay.MIN_REPLAY_RETENTION_MS,
    });
    const params = { grantId: WORKED_EXAMPLE_CORE.grantId, nonce: WORKED_EXAMPLE_CORE.nonce };

    // Admitted at T0-60000 (future-dated by 60 s): fresh until T0+60000, i.e. 180 s after seenAt.
    now = T0 - 60000;
    expect((await replayWindow.checkAndRemember({ ...params, freshUntilMs: T0 + 60000 })).ok).toBe(true);

    now = T0 + 60000;
    const stillFresh = await replayWindow.checkAndRemember(params);
    expect({ ok: stillFresh.ok, code: stillFresh.error?.code }).toEqual({
      ok: false,
      code: 'REPLAY_DETECTED',
    });
  });

  it('fails closed instead of evicting a nonce that could still be fresh', async () => {
    const replayWindow = relay.createReplayWindow({ now: () => T0, maxEntries: 1 });
    const first = { grantId: WORKED_EXAMPLE_CORE.grantId, nonce: WORKED_EXAMPLE_CORE.nonce };
    const second = { grantId: WORKED_EXAMPLE_CORE.grantId, nonce: 'AAECAwQFBgcICQoLDA0OEQ' };

    expect((await replayWindow.checkAndRemember(first)).ok).toBe(true);
    const blocked = await replayWindow.checkAndRemember(second);
    expect({ ok: blocked.ok, code: blocked.error?.code }).toEqual({
      ok: false,
      code: 'REPLAY_STORE_UNAVAILABLE',
    });
    // The original nonce is still remembered: no eviction reopened its replay window.
    expect(replayWindow.has(first)).toBe(true);
  });

  it('refuses a retention shorter than the widest freshness window at construction', () => {
    expect(() => relay.createReplayWindow({ retentionMs: 60000 })).toThrow(
      expect.objectContaining({ code: 'ENVELOPE_SHAPE_INVALID' }),
    );
    expect(() => relay.createReplayWindow({ retentionMs: relay.MAX_FRESHNESS_WINDOW_MS })).not.toThrow();
  });

  it('refuses non-canonical ring components instead of joining them', async () => {
    const replayWindow = relay.createReplayWindow({ now: () => T0 });
    await expect(
      replayWindow.checkAndRemember({ grantId: 'not base64url!', nonce: WORKED_EXAMPLE_CORE.nonce }),
    ).rejects.toMatchObject({ code: 'ENVELOPE_SHAPE_INVALID' });
    await expect(
      replayWindow.checkAndRemember({ grantId: WORKED_EXAMPLE_CORE.grantId, nonce: 'short' }),
    ).rejects.toMatchObject({ code: 'ENVELOPE_SHAPE_INVALID' });
  });

  it('accepts exactly one of two concurrent admissions of the same nonce', async () => {
    const replayWindow = relay.createReplayWindow({ now: () => T0 });
    const params = {
      grantId: WORKED_EXAMPLE_CORE.grantId,
      nonce: WORKED_EXAMPLE_CORE.nonce,
    };

    const results = await Promise.all([
      replayWindow.checkAndRemember(params),
      replayWindow.checkAndRemember(params),
    ]);

    expect(results.filter((entry) => entry.ok === true)).toHaveLength(1);
    expect(results.filter((entry) => entry.ok === false)).toHaveLength(1);
  });

  it('fails closed when the durable store seam fails', async () => {
    const replayWindow = relay.createReplayWindow({
      now: () => T0,
      store: {
        has: () => false,
        remember: async () => {
          throw new Error('store down');
        },
      },
    });

    const result = await replayWindow.checkAndRemember({
      grantId: WORKED_EXAMPLE_CORE.grantId,
      nonce: WORKED_EXAMPLE_CORE.nonce,
    });

    expect(result.ok).toBe(false);
    expect(result.error.code).toBe('REPLAY_STORE_UNAVAILABLE');
    // The failed reservation is rolled back, so a retry is not a false replay.
    expect(replayWindow.size()).toBe(0);
  });
});
