'use strict';

/**
 * W6 spec — THE RESULT SINK: device -> platform correlation under the OUTCOME LAW (GM-43).
 *
 * The law this spec exists to pin, in the order it can be broken:
 *   1. a result is a SUCCESS only when the DEVICE authenticated `success` for that `callId`;
 *   2. an unknown `callId` is REFUSED and nothing is stored;
 *   3. a duplicate/retry is refused and never completes a call twice;
 *   4. malformed, unauthenticated, replayed, stale, oversized or mis-bound results are `uncertain`
 *      — never success, and never a completion;
 *   5. correlation is by `callId`, never by arrival order or by the relay's `resultSeq`;
 *   6. a payload the RELAY could have authored (the forgery shape) is never a success.
 *
 * The device half is a throwaway Ed25519 keypair inside this process; the reply frames are minted
 * through the one audited signing primitive plus the named GM-56 `allowRelayAudience` opt-in, which
 * exists for exactly this caller. Nothing on the backend dispatch path can reach that opt-in.
 */

const {
  relay,
  nodeCrypto,
  AUTHORITY,
  makeTransport,
  makeCustodySeam,
  makeTestKeypair,
  makeDeviceResultMinter,
} = require('./_fixtures.cjs');

const { createDispatchLedger } = require('../dispatchLedger');
const { createResultSink } = require('../resultSink');

const T0 = 1761200000000;
const CLOCK = { now: () => T0 };

function pinnedVerifier(device) {
  return relay.createEnvelopeVerifier({
    publicKeySpkiB64u: device.keypair.publicKeySpkiB64u,
    expectedKeyId: device.keyId,
  });
}

/** A ledger holding one live call for the minted device identity. */
async function liveCall({ ledger, authority, callId, toolName = 'read_file' }) {
  const reservation = await ledger.reserve({
    callId,
    deviceId: authority.deviceId,
    deviceKeyId: authority.deviceKeyId,
    tenantId: authority.tenantId,
    grantId: authority.grantId,
    epoch: authority.epoch,
    requestId: `request-${callId}`,
    toolName,
    opKind: 'command',
  });
  if (reservation.ok !== true) {
    throw new Error(`fixture could not reserve ${callId}: ${reservation.error.code}`);
  }
  return reservation.entry;
}

function buildSink({ ledger, device, options = {} }) {
  return createResultSink({
    ledger,
    verifier: pinnedVerifier(device),
    clock: CLOCK,
    ...options,
  });
}

describe('A. correlation by callId, and the device-reported outcome', () => {
  it('completes the right call with the outcome the DEVICE reported', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device });
    await liveCall({ ledger, authority: device.deviceAuthority, callId: 'call-alpha' });
    await liveCall({ ledger, authority: device.deviceAuthority, callId: 'call-beta' });

    const alpha = await device.minter.mintResultFrame({ callId: 'call-alpha', outcome: 'success' });
    const beta = await device.minter.mintResultFrame({ callId: 'call-beta', outcome: 'failure' });

    const alphaVerdict = await sink.ingestResult({ callId: 'call-alpha', payload: alpha.payload, resultSeq: 1 });
    const betaVerdict = await sink.ingestResult({ callId: 'call-beta', payload: beta.payload, resultSeq: 2 });

    expect(alphaVerdict).toMatchObject({
      ok: true,
      status: 'completed',
      callId: 'call-alpha',
      success: true,
      outcome: 'success',
      stored: true,
    });
    expect(betaVerdict).toMatchObject({ status: 'completed', callId: 'call-beta', success: false, outcome: 'failure' });
    expect((await ledger.get('call-alpha')).outcome).toBe('success');
    expect((await ledger.get('call-beta')).outcome).toBe('failure');
    expect(await sink.size()).toBe(2);
  });

  it('round-trips a call from the real dispatch client to the sink', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device });
    const custody = makeTestKeypair();
    const { transport, calls } = makeTransport({ status: 200, body: { accepted: true } });
    const client = relay.createRelayDispatchClient({
      transport,
      signer: relay.createEnvelopeSigner(makeCustodySeam(custody)),
      ledger,
      clock: CLOCK,
      nonceFactory: () => 'AAECAwQFBgcICQoLDA0ODw',
      requestIdFactory: () => '3f0c5b1e-8a2d-4c7b-9e61-2d4f8a0b7c93',
      replayWindow: relay.createReplayWindow({ now: CLOCK.now }),
    });

    const dispatch = await client.dispatchCommand({
      authority: device.deviceAuthority,
      toolName: 'read_file',
      argsBytes: Buffer.from('{"path":"C:/notes/today.txt"}', 'utf8'),
      callId: 'call-round-trip',
    });

    // The call is on the wire, and the ledger knows exactly one call id.
    expect(dispatch.ok).toBe(true);
    expect(dispatch.delivered).toBe('accepted');
    expect(calls[0].frame.callId).toBe('call-round-trip');
    expect(await ledger.size()).toBe(1);
    expect((await ledger.get('call-round-trip')).state).toBe('dispatched');

    // The device answers, the relay forwards the opaque string, the sink correlates it.
    const result = await device.minter.mintResultFrame({ callId: 'call-round-trip', outcome: 'success' });
    const verdict = await sink.ingestResult({ callId: 'call-round-trip', payload: result.payload, resultSeq: 7 });

    expect(verdict).toMatchObject({ status: 'completed', success: true, outcome: 'success', callId: 'call-round-trip' });
    expect(verdict.resultSeq).toBe(7);
    expect((await ledger.get('call-round-trip'))).toMatchObject({ state: 'completed', outcome: 'success' });
  });

  it('correlates by callId when results arrive out of order and with reversed transport seq', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device });
    for (const callId of ['call-1', 'call-2', 'call-3']) {
      await liveCall({ ledger, authority: device.deviceAuthority, callId });
    }

    const frames = {};
    for (const callId of ['call-1', 'call-2', 'call-3']) {
      frames[callId] = (await device.minter.mintResultFrame({ callId, outcome: 'success' })).payload;
    }

    // Arrival order 3, 1, 2 with transport sequence numbers that disagree with everything.
    const verdicts = [
      await sink.ingestResult({ callId: 'call-3', payload: frames['call-3'], resultSeq: 99 }),
      await sink.ingestResult({ callId: 'call-1', payload: frames['call-1'], resultSeq: 1 }),
      await sink.ingestResult({ callId: 'call-2', payload: frames['call-2'], resultSeq: 42 }),
    ];

    expect(verdicts.map((v) => v.callId)).toEqual(['call-3', 'call-1', 'call-2']);
    expect(verdicts.every((v) => v.status === 'completed' && v.success === true)).toBe(true);
    for (const callId of ['call-1', 'call-2', 'call-3']) {
      expect((await ledger.get(callId)).state).toBe('completed');
      expect((await sink.resultFor(callId)).callId).toBe(callId);
    }
  });
});

describe('B. an unknown callId is REFUSED and nothing is stored', () => {
  it('refuses a result for a call that was never dispatched', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device });
    await liveCall({ ledger, authority: device.deviceAuthority, callId: 'call-known' });

    const unknown = await device.minter.mintResultFrame({ callId: 'call-never-dispatched', outcome: 'success' });
    const verdict = await sink.ingestResult({ callId: 'call-never-dispatched', payload: unknown.payload });

    expect(verdict).toMatchObject({
      ok: false,
      status: 'refused',
      code: 'RESULT_UNKNOWN_CALL_ID',
      callId: 'call-never-dispatched',
      success: false,
      outcome: null,
      stored: false,
    });
    // Nothing was stored, and the OTHER live call was not disturbed.
    expect(await sink.size()).toBe(0);
    expect(await sink.resultFor('call-never-dispatched')).toBeNull();
    expect((await ledger.get('call-known')).state).toBe('dispatched');
    expect(await ledger.size()).toBe(1);
  });

  it('refuses a result whose ledger entry was released (a call that never reached the wire)', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device });
    await liveCall({ ledger, authority: device.deviceAuthority, callId: 'call-not-sent' });
    const released = await ledger.release('call-not-sent', 'relay-refused');
    expect(released.released).toBe(true);

    const frame = await device.minter.mintResultFrame({ callId: 'call-not-sent', outcome: 'success' });
    const verdict = await sink.ingestResult({ callId: 'call-not-sent', payload: frame.payload });

    expect(verdict.code).toBe('RESULT_UNKNOWN_CALL_ID');
    expect(verdict.status).toBe('refused');
    expect(await sink.size()).toBe(0);
  });

  it('refuses an authentic result for a call that is unknown even though a callId appears in the frame', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device });

    const frame = await device.minter.mintResultFrame({ callId: 'call-ghost', outcome: 'success' });
    const verdict = await sink.ingestResult({ callId: 'call-ghost', payload: frame.payload, resultSeq: 1 });

    expect(verdict.status).toBe('refused');
    expect(verdict.code).toBe('RESULT_UNKNOWN_CALL_ID');
    expect(verdict.success).toBe(false);
    expect(await sink.size()).toBe(0);
  });
});

describe('C. a duplicate or retried result never completes a call twice', () => {
  it('refuses the second ingest of the same result and leaves the recorded outcome alone', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device });
    await liveCall({ ledger, authority: device.deviceAuthority, callId: 'call-retry' });

    const frame = await device.minter.mintResultFrame({ callId: 'call-retry', outcome: 'success' });
    const first = await sink.ingestResult({ callId: 'call-retry', payload: frame.payload, resultSeq: 1 });
    const completedAt = (await ledger.get('call-retry')).completedAt;
    const second = await sink.ingestResult({ callId: 'call-retry', payload: frame.payload, resultSeq: 1 });

    expect(first.status).toBe('completed');
    expect(second).toMatchObject({
      ok: false,
      status: 'refused',
      code: 'RESULT_CALL_ALREADY_COMPLETED',
      duplicate: true,
      success: false,
      stored: false,
    });
    // The recorded outcome is exposed as information, NOT as this frame's verdict.
    expect(second.recordedOutcome).toBe('success');
    expect(second.outcome).toBeNull();
    expect((await ledger.get('call-retry')).completedAt).toBe(completedAt);
    expect(await sink.size()).toBe(1);
  });

  it('a retry cannot downgrade or upgrade a recorded outcome', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device });
    await liveCall({ ledger, authority: device.deviceAuthority, callId: 'call-downgrade' });

    const success = await device.minter.mintResultFrame({ callId: 'call-downgrade', outcome: 'success' });
    const failure = await device.minter.mintResultFrame({ callId: 'call-downgrade', outcome: 'failure' });
    await sink.ingestResult({ callId: 'call-downgrade', payload: success.payload });
    const retry = await sink.ingestResult({ callId: 'call-downgrade', payload: failure.payload });

    expect(retry.status).toBe('refused');
    expect(retry.code).toBe('RESULT_CALL_ALREADY_COMPLETED');
    expect(retry.success).toBe(false);
    expect((await ledger.get('call-downgrade')).outcome).toBe('success');
    expect((await sink.resultFor('call-downgrade')).outcome).toBe('success');
  });

  it('two concurrent ingests of the same result complete the call exactly once', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device });
    await liveCall({ ledger, authority: device.deviceAuthority, callId: 'call-race' });

    const frame = await device.minter.mintResultFrame({ callId: 'call-race', outcome: 'success' });
    const [a, b] = await Promise.all([
      sink.ingestResult({ callId: 'call-race', payload: frame.payload, resultSeq: 1 }),
      sink.ingestResult({ callId: 'call-race', payload: frame.payload, resultSeq: 1 }),
    ]);

    const completed = [a, b].filter((verdict) => verdict.status === 'completed');
    const refusedVerdicts = [a, b].filter((verdict) => verdict.status === 'refused');
    expect(completed).toHaveLength(1);
    expect(refusedVerdicts).toHaveLength(1);
    expect(refusedVerdicts[0].code).toBe('RESULT_CALL_ALREADY_COMPLETED');
    expect(await sink.size()).toBe(1);
  });
});

describe('D. malformed, unauthenticated and mis-bound results are UNCERTAIN, never success', () => {
  async function fixture(callId = 'call-hostile') {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device });
    await liveCall({ ledger, authority: device.deviceAuthority, callId });
    return { device, ledger, sink, callId };
  }

  it('is uncertain for a payload that is not parseable at all', async () => {
    const { sink, ledger, callId } = await fixture();
    const verdict = await sink.ingestResult({ callId, payload: 'not-a-frame' });
    expect(verdict).toMatchObject({ status: 'uncertain', code: 'RESULT_MALFORMED', success: false, stored: false });
    expect((await ledger.get(callId)).state).toBe('dispatched');
    expect(await sink.size()).toBe(0);
  });

  it('is uncertain for a well-formed JSON payload that is not a frame', async () => {
    const { sink, callId } = await fixture();
    const verdict = await sink.ingestResult({
      callId,
      payload: JSON.stringify({ callId, outcome: 'success' }),
    });
    expect(verdict.status).toBe('uncertain');
    expect(verdict.code).toBe('ENVELOPE_SHAPE_INVALID');
    expect(verdict.success).toBe(false);
  });

  it('is uncertain for a frame signed by a key that is not the pinned device key', async () => {
    const { ledger, sink, callId } = await fixture();
    const entry = await ledger.get(callId);
    const attacker = makeDeviceResultMinter(relay, { now: CLOCK.now, keyId: 'attacker-key' });
    // The attacker authenticates `success` for THIS call, with a key that is valid but not the
    // pinned one; every binding field is copied from the real entry, so only the key differs.
    const forged = await attacker.minter.mintResultFrame({
      callId,
      outcome: 'success',
      core: {
        deviceId: entry.deviceId,
        deviceKeyId: entry.deviceKeyId,
        tenantId: entry.tenantId,
        grantId: entry.grantId,
      },
      frameCallId: callId,
    });

    const verdict = await sink.ingestResult({ callId, payload: forged.payload });
    expect(verdict).toMatchObject({ status: 'uncertain', code: 'ENVELOPE_SIGNATURE_INVALID', success: false, stored: false });
    expect((await ledger.get(callId)).state).toBe('dispatched');
    expect(await sink.size()).toBe(0);
  });

  it('is uncertain when the result bytes do not hash to the signed digest (the relay rewrote the outcome)', async () => {
    const { device, sink, ledger, callId } = await fixture();
    const genuine = await device.minter.mintResultFrame({ callId, outcome: 'failure' });
    const tampered = JSON.parse(genuine.payload);
    tampered.argsB64u = Buffer.from(
      JSON.stringify({ callId, outcome: 'success', toolName: 'read_file' }),
      'utf8',
    ).toString('base64url');

    const verdict = await sink.ingestResult({ callId, payload: JSON.stringify(tampered) });
    expect(verdict).toMatchObject({ status: 'uncertain', code: 'ARGS_DIGEST_MISMATCH', success: false });
    expect((await ledger.get(callId)).state).toBe('dispatched');
    expect(await sink.size()).toBe(0);
  });

  it('is uncertain when the outcome word is not a device-reported outcome', async () => {
    const { device, sink, callId } = await fixture();
    const frame = await device.minter.mintResultFrame({
      callId,
      outcome: 'success',
      bytes: Buffer.from(JSON.stringify({ callId, outcome: 'probably-fine' }), 'utf8'),
    });
    const verdict = await sink.ingestResult({ callId, payload: frame.payload });
    expect(verdict).toMatchObject({ status: 'uncertain', code: 'RESULT_MALFORMED', success: false });
  });

  it('is uncertain when the authenticated result document names a different call', async () => {
    const { device, sink, callId } = await fixture();
    const frame = await device.minter.mintResultFrame({
      callId,
      outcome: 'success',
      bytes: Buffer.from(JSON.stringify({ callId: 'call-somewhere-else', outcome: 'success' }), 'utf8'),
    });
    const verdict = await sink.ingestResult({ callId, payload: frame.payload });
    expect(verdict).toMatchObject({ status: 'uncertain', code: 'RESULT_CALL_MISMATCH', success: false });
  });

  it('is uncertain when the frame was forwarded under a different call id than it names', async () => {
    const { device, sink, callId } = await fixture();
    const frame = await device.minter.mintResultFrame({ callId, outcome: 'success', frameCallId: 'call-other' });
    const verdict = await sink.ingestResult({ callId, payload: frame.payload });
    expect(verdict).toMatchObject({ status: 'uncertain', code: 'RESULT_CALL_MISMATCH', success: false });
  });

  it('is uncertain when the authenticated frame binds a different device, tenant or grant', async () => {
    const { device, sink, ledger, callId } = await fixture();
    for (const overrides of [
      { deviceId: '65a1b2c3d4e5f6071829ffff' },
      { tenantId: 'tenant-elsewhere' },
      { grantId: 'EBESExQVFhcYGRobHB0eHg' },
      { deviceKeyId: 'eBsXUXqHfJpRmak8ReOpt11QAUyjFQjaetmtzNS-IPw' },
    ]) {
      const frame = await device.minter.mintResultFrame({ callId, outcome: 'success', core: overrides });
      const verdict = await sink.ingestResult({ callId, payload: frame.payload });
      expect({ overrides, status: verdict.status, code: verdict.code }).toEqual({
        overrides,
        status: 'uncertain',
        code: 'RESULT_BINDING_MISMATCH',
      });
      expect(verdict.success).toBe(false);
    }
    expect((await ledger.get(callId)).state).toBe('dispatched');
    expect(await sink.size()).toBe(0);
  });

  it('is uncertain for the wrong audience, a stale frame, an expired deadline and a structurally broken frame', async () => {
    const { device, sink, callId } = await fixture();
    const minted = [
      { overrides: { audience: 'endpoint' }, code: 'ENVELOPE_AUDIENCE_MISMATCH' },
      { overrides: { issuedAt: String(T0 - 121000), deadlineMs: String(T0 - 1000) }, code: 'FRESHNESS_EXPIRED' },
      { overrides: { issuedAt: String(T0 + 121000), deadlineMs: String(T0 + 122000) }, code: 'FRESHNESS_NOT_YET_VALID' },
      { overrides: { issuedAt: String(T0 - 60000), deadlineMs: String(T0 - 1000) }, code: 'DEADLINE_EXCEEDED' },
    ];
    for (const { overrides, code } of minted) {
      const frame = await device.minter.mintResultFrame({ callId, outcome: 'success', core: overrides });
      const verdict = await sink.ingestResult({ callId, payload: frame.payload });
      expect({ overrides, status: verdict.status, code: verdict.code }).toEqual({ overrides, status: 'uncertain', code });
      expect(verdict.success).toBe(false);
    }

    // Structure precedes the signature by contract, so a tampered core is rejected as a shape
    // failure (never as success) without needing a key at all.
    const genuine = await device.minter.mintResultFrame({ callId, outcome: 'success' });
    for (const tamper of [{ epoch: '0' }, { toolName: '' }, { argsDigestHex: 'nope' }]) {
      const broken = { ...JSON.parse(genuine.payload), ...tamper };
      const verdict = await sink.ingestResult({ callId, payload: JSON.stringify(broken) });
      expect({ tamper, status: verdict.status, code: verdict.code }).toEqual({
        tamper,
        status: 'uncertain',
        code: 'ENVELOPE_SHAPE_INVALID',
      });
      expect(verdict.success).toBe(false);
    }
  });

  it('is uncertain for a replayed nonce when a replay window is wired', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device, options: { replayWindow: relay.createReplayWindow({ now: CLOCK.now }) } });
    await liveCall({ ledger, authority: device.deviceAuthority, callId: 'call-replay-1' });
    await liveCall({ ledger, authority: device.deviceAuthority, callId: 'call-replay-2' });

    const nonce = 'AAECAwQFBgcICQoLDA0ODw';
    const first = await device.minter.mintResultFrame({ callId: 'call-replay-1', outcome: 'success', nonce });
    const replayed = await device.minter.mintResultFrame({ callId: 'call-replay-2', outcome: 'success', nonce });

    const firstVerdict = await sink.ingestResult({ callId: 'call-replay-1', payload: first.payload });
    const replayedVerdict = await sink.ingestResult({ callId: 'call-replay-2', payload: replayed.payload });

    expect(firstVerdict.status).toBe('completed');
    expect(replayedVerdict).toMatchObject({ status: 'uncertain', code: 'REPLAY_DETECTED', success: false });
    expect((await ledger.get('call-replay-2')).state).toBe('dispatched');
  });

  it('is uncertain for an oversized decoded result document (GM-58 plaintext bound)', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device, options: { maxResultBytes: 64 } });
    await liveCall({ ledger, authority: device.deviceAuthority, callId: 'call-big-result' });

    const frame = await device.minter.mintResultFrame({
      callId: 'call-big-result',
      outcome: 'success',
      bytes: Buffer.from(JSON.stringify({ callId: 'call-big-result', outcome: 'success', pad: 'y'.repeat(256) }), 'utf8'),
    });
    const verdict = await sink.ingestResult({ callId: 'call-big-result', payload: frame.payload });

    expect(verdict).toMatchObject({ status: 'uncertain', code: 'RESULT_TOO_LARGE', success: false, stored: false });
    expect((await ledger.get('call-big-result')).state).toBe('dispatched');
    expect(await sink.size()).toBe(0);
  });
});

describe('E. the relay cannot make the platform report success', () => {
  it('refuses a payload that is only a plausible success document (no device authentication at all)', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device });
    await liveCall({ ledger, authority: device.deviceAuthority, callId: 'call-forged' });

    // Exactly what a compromised relay can produce: bytes of its own choosing under a call id it
    // forwarded. It holds no key, so it cannot produce the device's authentication over them.
    const synthesised = JSON.stringify({ callId: 'call-forged', outcome: 'success', toolName: 'read_file' });
    const verdict = await sink.ingestResult({ callId: 'call-forged', payload: synthesised });

    expect(verdict.status).toBe('uncertain');
    expect(verdict.success).toBe(false);
    expect(verdict.outcome).toBeNull();
    expect((await ledger.get('call-forged')).state).toBe('dispatched');
    expect(await sink.size()).toBe(0);
  });

  it('refuses a relay-shaped envelope whose signature is not the device’s', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device });
    const entry = await liveCall({ ledger, authority: device.deviceAuthority, callId: 'call-forged-2' });

    const document = Buffer.from(JSON.stringify({ callId: 'call-forged-2', outcome: 'success' }), 'utf8');
    const forgedFrame = {
      tag: 'CBHR-RPC-V2',
      requestId: '3f0c5b1e-8a2d-4c7b-9e61-2d4f8a0b7c93',
      nonce: 'AAECAwQFBgcICQoLDA0ODw',
      issuedAt: String(T0),
      deadlineMs: String(T0 + 120000),
      epoch: String(entry.epoch),
      grantId: entry.grantId,
      ownerPrincipalId: AUTHORITY.ownerPrincipalId,
      tenantId: entry.tenantId,
      deviceId: entry.deviceId,
      deviceKeyId: entry.deviceKeyId,
      toolName: 'read_file',
      opKind: 'command',
      audience: 'relay',
      argsDigestHex: nodeCrypto.createHash('sha256').update(document).digest('hex'),
      signatureB64u: Buffer.alloc(64, 9).toString('base64url'),
      keyId: device.keyId,
      argsB64u: document.toString('base64url'),
      callId: 'call-forged-2',
    };

    const verdict = await sink.ingestResult({ callId: 'call-forged-2', payload: JSON.stringify(forgedFrame) });
    expect(verdict).toMatchObject({ status: 'uncertain', code: 'ENVELOPE_SIGNATURE_INVALID', success: false });
    expect((await ledger.get('call-forged-2')).state).toBe('dispatched');
  });

  it('does not let an uncertain result block the genuine one, and the genuine one is the only success', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device });
    await liveCall({ ledger, authority: device.deviceAuthority, callId: 'call-recover' });

    const forged = await sink.ingestResult({
      callId: 'call-recover',
      payload: JSON.stringify({ callId: 'call-recover', outcome: 'success' }),
    });
    const genuine = await device.minter.mintResultFrame({ callId: 'call-recover', outcome: 'failure' });
    const genuineVerdict = await sink.ingestResult({ callId: 'call-recover', payload: genuine.payload });

    expect(forged.status).toBe('uncertain');
    expect(forged.success).toBe(false);
    expect(genuineVerdict).toMatchObject({ status: 'completed', success: false, outcome: 'failure' });
    expect((await ledger.get('call-recover')).outcome).toBe('failure');
  });
});

describe('F. transport shape, sizing and the sink seam', () => {
  it('refuses an oversized forwarded payload without touching the ledger', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device, options: { maxForwardedChars: 512 } });
    await liveCall({ ledger, authority: device.deviceAuthority, callId: 'call-large-forward' });

    const verdict = await sink.ingestResult({ callId: 'call-large-forward', payload: 'z'.repeat(513) });
    expect(verdict).toMatchObject({ status: 'refused', code: 'RESULT_TOO_LARGE', success: false, stored: false });
    expect((await ledger.get('call-large-forward')).state).toBe('dispatched');
  });

  it('refuses a forwarded entry of the wrong shape', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device });
    await liveCall({ ledger, authority: device.deviceAuthority, callId: 'call-shape' });

    for (const forwarded of [
      null,
      'not-an-object',
      { payload: 'x' },
      { callId: 'call-shape' },
      { callId: 'call-shape', payload: '' },
      { callId: 'call-shape', payload: 42 },
      { callId: 'call-shape', payload: 'x', resultSeq: 0 },
      { callId: 'call-shape', payload: 'x', surprise: true },
      { callId: `bad\u001fid`, payload: 'x' },
      { callId: 'c'.repeat(201), payload: 'x' },
    ]) {
      const verdict = await sink.ingestResult(forwarded);
      expect({ forwarded, status: verdict.status, code: verdict.code }).toEqual({
        forwarded,
        status: 'refused',
        code: 'RESULT_MALFORMED',
      });
      expect(verdict.success).toBe(false);
    }
    expect((await ledger.get('call-shape')).state).toBe('dispatched');
    expect(await sink.size()).toBe(0);
  });

  it('cannot be constructed without the ledger and the pinned verifier', () => {
    const ledger = createDispatchLedger({ now: CLOCK.now });
    // A field-naming RelayError carries a GENERIC external message by design (invariant 3), so the
    // assertions below read the typed CODE and the server-side `field`, never the message text.
    const codeOf = (fn) => {
      try {
        fn();
        return null;
      } catch (err) {
        return { code: err.code, field: err.field };
      }
    };
    expect(codeOf(() => createResultSink({ verifier: { verifySignature: () => ({ ok: false }) }, clock: CLOCK }))).toEqual({
      code: 'SINK_SEAM_INVALID',
      field: 'ledger',
    });
    expect(codeOf(() => createResultSink({ ledger, clock: CLOCK }))).toEqual({ code: 'SINK_SEAM_INVALID', field: 'verifier' });
    expect(codeOf(() => createResultSink({ ledger, verifier: {}, clock: CLOCK }))).toEqual({
      code: 'SINK_SEAM_INVALID',
      field: 'verifier',
    });
    expect(codeOf(() => createResultSink({ ledger, verifier: { verifySignature: () => ({ ok: false }) }, clock: {} }))).toEqual({
      code: 'CLOCK_UNUSABLE',
      field: 'clock',
    });
    expect(codeOf(() =>
      createResultSink({ ledger, verifier: { verifySignature: () => ({ ok: false }) }, clock: CLOCK, maxResultBytes: 0 }),
    )).toEqual({ code: 'SINK_SEAM_INVALID', field: 'maxResultBytes' });
    expect(codeOf(() =>
      createResultSink({ ledger, verifier: { verifySignature: () => ({ ok: false }) }, clock: CLOCK, store: {} }),
    )).toEqual({ code: 'SINK_SEAM_INVALID', field: 'store' });
  });

  it('reports a device-reported non-success as a completed NON-success, never as a failure of the platform', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device });

    for (const outcome of ['failure', 'refused', 'cancelled', 'timeout']) {
      const callId = `call-${outcome}`;
      await liveCall({ ledger, authority: device.deviceAuthority, callId });
      const frame = await device.minter.mintResultFrame({ callId, outcome });
      const verdict = await sink.ingestResult({ callId, payload: frame.payload });
      expect({ outcome, status: verdict.status, success: verdict.success, reported: verdict.outcome }).toEqual({
        outcome,
        status: 'completed',
        success: false,
        reported: outcome,
      });
    }
    // Only the device-reported `success` is ever a success.
    expect(await sink.size()).toBe(4);
  });
});