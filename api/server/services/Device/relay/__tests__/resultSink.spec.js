'use strict';

/**
 * W6 spec — THE RESULT SINK: device -> platform correlation under the OUTCOME LAW (GM-43),
 * re-expressed against the `CBHR-RPC-RESULT-V2` frame (GM-80).
 *
 * WHY THIS SPEC CHANGED, AND WHY IT DID NOT SHRINK
 * GM-80 §2 rules that the endpoint agent's result document WINS: a result is not a command, so it
 * carries its own domain tag, a twelve-field core and an explicit signed `outcome`. The sink therefore
 * verifies a different frame, and every case below that used to mint a `CBHR-RPC-V2` reply with the
 * outcome inside `argsB64u` now mints a genuinely signed `CBHR-RPC-RESULT-V2` frame. Nothing was
 * weakened to meet the other half: the same twenty-seven cases run, three of them re-expressed for the
 * new frame type (the domain-separation case, the unrecognised-outcome case and the outcome-law case),
 * and the frame builder in `_fixtures.cjs` joins the twelve fields with a literal 0x1F array that
 * shares no code with `../resultFrame.js`.
 *
 * The law this spec exists to pin, in the order it can be broken:
 *   1. a result is a SUCCESS only when the DEVICE signed `succeeded` for that `callId` AND the
 *      platform's own call state agrees (the call is live and binds this device/key/grant/epoch);
 *   2. an unknown `callId` is REFUSED and nothing is stored;
 *   3. a duplicate/retry is refused and never completes a call twice;
 *   4. malformed, unauthenticated, replayed, stale, oversized, mis-bound or self-reported-uncertain
 *      results are `uncertain` — never success, and never a completion;
 *   5. correlation is by the SIGNED `callId`, never by arrival order or by the relay's `resultSeq`;
 *   6. a payload the RELAY could have authored (the forgery shape) is never a success;
 *   7. `refused` completes a call as a NON-success; `uncertain` leaves it open (GM-80 §4.7).
 *
 * The device half is a throwaway Ed25519 keypair inside this process; the result frames are signed by
 * the fixture's own independent join over the twelve fields, and the verifier the sink pins is built
 * from the same public key.
 */

const {
  relay,
  nodeCrypto,
  AUTHORITY,
  T0,
  makeTransport,
  makeCustodySeam,
  makeTestKeypair,
  makeDeviceResultMinter,
} = require('./_fixtures.cjs');

const { createDispatchLedger } = require('../dispatchLedger');
const {
  createResultSink,
  RESULT_BINDING_FIELDS,
  RESULT_BINDING_FIELDS_NOT_CARRIED,
} = require('../resultSink');
const { createResultFrameVerifier, RESULT_V2_TAG } = require('../resultFrame');

const CLOCK = { now: () => T0 };
const COMMAND_NONCE = 'AAECAwQFBgcICQoLDA0ODw';

/** The pinned DEVICE verifier: the only key that can produce a result (GM-80 §4.2). */
function pinnedVerifier(device) {
  return createResultFrameVerifier({
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

describe('A. correlation by callId, and the device-signed outcome', () => {
  it('completes the right call with the outcome the DEVICE signed', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device });
    await liveCall({ ledger, authority: device.deviceAuthority, callId: 'call-alpha' });
    await liveCall({ ledger, authority: device.deviceAuthority, callId: 'call-beta' });

    // GM-80 §4.7: `succeeded` is the ONLY word that maps to success; `refused` is a completed
    // non-success, because the endpoint can prove nothing ran.
    const alpha = device.minter.mintResultFrame({ callId: 'call-alpha', outcome: 'succeeded' });
    const beta = device.minter.mintResultFrame({ callId: 'call-beta', outcome: 'refused' });

    const alphaVerdict = await sink.ingestResult({
      callId: 'call-alpha',
      payload: alpha.payload,
      resultSeq: 1,
    });
    const betaVerdict = await sink.ingestResult({
      callId: 'call-beta',
      payload: beta.payload,
      resultSeq: 2,
    });

    expect(alphaVerdict).toMatchObject({
      ok: true,
      status: 'completed',
      callId: 'call-alpha',
      success: true,
      outcome: 'succeeded',
      stored: true,
    });
    expect(betaVerdict).toMatchObject({
      status: 'completed',
      callId: 'call-beta',
      success: false,
      outcome: 'refused',
    });
    expect((await ledger.get('call-alpha')).outcome).toBe('succeeded');
    expect((await ledger.get('call-beta')).outcome).toBe('refused');
    expect(await sink.size()).toBe(2);
  });

  it('round-trips a call from the real dispatch client to the sink, and a FRESH result nonce is accepted though the command nonce is spent', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    // ONE ring, shared by the dispatch client and the sink. That is the hard case GM-80 §4.5 names:
    // the command's nonce is spent by the dispatch, and the result's OWN fresh nonce must still be
    // accepted by the same window.
    const replayWindow = relay.createReplayWindow({ now: CLOCK.now });
    const sink = buildSink({ ledger, device, options: { replayWindow } });
    const custody = makeTestKeypair();
    const { transport, calls } = makeTransport({ status: 200, body: { accepted: true } });
    const client = relay.createRelayDispatchClient({
      transport,
      signer: relay.createEnvelopeSigner(makeCustodySeam(custody)),
      ledger,
      clock: CLOCK,
      nonceFactory: () => COMMAND_NONCE,
      requestIdFactory: () => '3f0c5b1e-8a2d-4c7b-9e61-2d4f8a0b7c93',
      replayWindow,
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

    // The COMMAND's nonce is spent in that ring...
    expect(
      replayWindow.has({ grantId: device.deviceAuthority.grantId, nonce: COMMAND_NONCE }),
    ).toBe(true);

    // ...and the result, signed over the twelve result fields with a nonce of its own, is accepted
    // anyway: the ring key is `(grantId, nonce)` and the result's nonce is fresh (GM-80 §4.5).
    const result = device.minter.mintResultFrame({
      callId: 'call-round-trip',
      outcome: 'succeeded',
    });
    expect(result.frame.nonce).not.toBe(COMMAND_NONCE);
    expect(result.frame.tag).toBe(RESULT_V2_TAG);
    const verdict = await sink.ingestResult({
      callId: 'call-round-trip',
      payload: result.payload,
      resultSeq: 7,
    });

    expect(verdict).toMatchObject({
      status: 'completed',
      success: true,
      outcome: 'succeeded',
      callId: 'call-round-trip',
    });
    expect(verdict.resultSeq).toBe(7);
    expect(await ledger.get('call-round-trip')).toMatchObject({
      state: 'completed',
      outcome: 'succeeded',
    });
    expect(
      replayWindow.has({ grantId: device.deviceAuthority.grantId, nonce: result.frame.nonce }),
    ).toBe(true);
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
      frames[callId] = device.minter.mintResultFrame({ callId, outcome: 'succeeded' }).payload;
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

    const unknown = device.minter.mintResultFrame({
      callId: 'call-never-dispatched',
      outcome: 'succeeded',
    });
    const verdict = await sink.ingestResult({
      callId: 'call-never-dispatched',
      payload: unknown.payload,
    });

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

    const frame = device.minter.mintResultFrame({ callId: 'call-not-sent', outcome: 'succeeded' });
    const verdict = await sink.ingestResult({ callId: 'call-not-sent', payload: frame.payload });

    expect(verdict.code).toBe('RESULT_UNKNOWN_CALL_ID');
    expect(verdict.status).toBe('refused');
    expect(await sink.size()).toBe(0);
  });

  it('refuses an authentic result for a call that is unknown even though a callId appears in the frame', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device });

    const frame = device.minter.mintResultFrame({ callId: 'call-ghost', outcome: 'succeeded' });
    const verdict = await sink.ingestResult({
      callId: 'call-ghost',
      payload: frame.payload,
      resultSeq: 1,
    });

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

    const frame = device.minter.mintResultFrame({ callId: 'call-retry', outcome: 'succeeded' });
    const first = await sink.ingestResult({
      callId: 'call-retry',
      payload: frame.payload,
      resultSeq: 1,
    });
    const completedAt = (await ledger.get('call-retry')).completedAt;
    const second = await sink.ingestResult({
      callId: 'call-retry',
      payload: frame.payload,
      resultSeq: 1,
    });

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
    expect(second.recordedOutcome).toBe('succeeded');
    expect(second.outcome).toBeNull();
    expect((await ledger.get('call-retry')).completedAt).toBe(completedAt);
    expect(await sink.size()).toBe(1);
  });

  it('a retry cannot downgrade or upgrade a recorded outcome', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device });
    await liveCall({ ledger, authority: device.deviceAuthority, callId: 'call-downgrade' });

    const succeeded = device.minter.mintResultFrame({
      callId: 'call-downgrade',
      outcome: 'succeeded',
    });
    const refused = device.minter.mintResultFrame({ callId: 'call-downgrade', outcome: 'refused' });
    await sink.ingestResult({ callId: 'call-downgrade', payload: succeeded.payload });
    const retry = await sink.ingestResult({ callId: 'call-downgrade', payload: refused.payload });

    expect(retry.status).toBe('refused');
    expect(retry.code).toBe('RESULT_CALL_ALREADY_COMPLETED');
    expect(retry.success).toBe(false);
    expect((await ledger.get('call-downgrade')).outcome).toBe('succeeded');
    expect((await sink.resultFor('call-downgrade')).outcome).toBe('succeeded');
  });

  it('two concurrent ingests of the same result complete the call exactly once', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device });
    await liveCall({ ledger, authority: device.deviceAuthority, callId: 'call-race' });

    const frame = device.minter.mintResultFrame({ callId: 'call-race', outcome: 'succeeded' });
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
    expect(verdict).toMatchObject({
      status: 'uncertain',
      code: 'RESULT_MALFORMED',
      success: false,
      stored: false,
    });
    expect((await ledger.get(callId)).state).toBe('dispatched');
    expect(await sink.size()).toBe(0);
  });

  it('is uncertain for a well-formed JSON payload that is not a CBHR-RPC-RESULT-V2 frame — including the retired command document', async () => {
    const { device, sink, ledger, callId } = await fixture();
    const genuine = device.minter.mintResultFrame({ callId, outcome: 'succeeded' });
    const commandDocument = Buffer.from('{"path":"C:/notes/today.txt"}', 'utf8').toString(
      'base64url',
    );
    const cases = [
      // A bare success document: what a keyless relay would most like to be believed.
      ['bare success document', JSON.stringify({ callId, outcome: 'succeeded' })],
      // The SAME bytes with the COMMAND domain tag: one document may not be presented as the other.
      ['command domain tag', JSON.stringify({ ...genuine.frame, tag: 'CBHR-RPC-V2' })],
      // The retired W6 frame: a 15-field `CBHR-RPC-V2` reply. It is no longer a result (GM-80 §1/§3).
      [
        'the retired 15-field command frame',
        JSON.stringify({
          tag: 'CBHR-RPC-V2',
          requestId: '3f0c5b1e-8a2d-4c7b-9e61-2d4f8a0b7c93',
          nonce: COMMAND_NONCE,
          issuedAt: String(T0),
          deadlineMs: String(T0 + 120000),
          epoch: String(device.deviceAuthority.epoch),
          grantId: device.deviceAuthority.grantId,
          ownerPrincipalId: AUTHORITY.ownerPrincipalId,
          tenantId: device.deviceAuthority.tenantId,
          deviceId: device.deviceAuthority.deviceId,
          deviceKeyId: device.deviceAuthority.deviceKeyId,
          toolName: 'read_file',
          opKind: 'command',
          audience: 'relay',
          argsDigestHex: nodeCrypto
            .createHash('sha256')
            .update(commandDocument, 'base64url')
            .digest('hex'),
          signatureB64u: Buffer.alloc(64, 9).toString('base64url'),
          keyId: device.keyId,
          argsB64u: commandDocument,
          callId,
        }),
      ],
    ];
    for (const [label, payload] of cases) {
      const verdict = await sink.ingestResult({ callId, payload });
      expect({
        label,
        status: verdict.status,
        code: verdict.code,
        success: verdict.success,
      }).toEqual({
        label,
        status: 'uncertain',
        code: 'RESULT_FRAME_SHAPE_INVALID',
        success: false,
      });
    }
    expect((await ledger.get(callId)).state).toBe('dispatched');
    expect(await sink.size()).toBe(0);
  });

  it('is uncertain for a frame signed by a key that is not the pinned device key', async () => {
    const { ledger, sink, callId } = await fixture();
    const entry = await ledger.get(callId);
    const attacker = makeDeviceResultMinter(relay, { now: CLOCK.now, keyId: 'attacker-key' });
    // The attacker signs `succeeded` for THIS call, with a key that is valid but not the pinned one;
    // every signed identity field is copied from the real entry, so only the key differs.
    const forged = attacker.minter.mintResultFrame({
      callId,
      outcome: 'succeeded',
      core: {
        deviceId: entry.deviceId,
        deviceKeyId: entry.deviceKeyId,
        grantId: entry.grantId,
        epoch: String(entry.epoch),
      },
    });

    const verdict = await sink.ingestResult({ callId, payload: forged.payload });
    expect(verdict).toMatchObject({
      status: 'uncertain',
      code: 'RESULT_SIGNATURE_INVALID',
      success: false,
      stored: false,
    });
    expect((await ledger.get(callId)).state).toBe('dispatched');
    expect(await sink.size()).toBe(0);
  });

  it('is uncertain when the result bytes do not hash to the signed digest (the relay rewrote them)', async () => {
    const { device, sink, ledger, callId } = await fixture();
    const genuine = device.minter.mintResultFrame({ callId, outcome: 'refused' });
    const tampered = {
      ...genuine.frame,
      // The signature is genuine; only the transported result bytes were swapped after signing.
      argsB64u: Buffer.from(JSON.stringify({ status: 'succeeded', callId }), 'utf8').toString(
        'base64url',
      ),
    };

    const verdict = await sink.ingestResult({ callId, payload: JSON.stringify(tampered) });
    expect(verdict).toMatchObject({
      status: 'uncertain',
      code: 'ARGS_DIGEST_MISMATCH',
      success: false,
    });
    expect((await ledger.get(callId)).state).toBe('dispatched');
    expect(await sink.size()).toBe(0);
  });

  it('is uncertain for the wrong audience, a stale frame, an expired deadline and a structurally broken frame', async () => {
    const { device, sink, callId } = await fixture();
    const genuine = device.minter.mintResultFrame({ callId, outcome: 'succeeded' });
    // `audience` is transport metadata (GM-31), so flipping it leaves the signature valid — which is
    // exactly why GM-80 §4.3 requires the check and why it is not authority.
    const wrongAudience = await sink.ingestResult({
      callId,
      payload: JSON.stringify({ ...genuine.frame, audience: 'endpoint' }),
    });
    expect({ status: wrongAudience.status, code: wrongAudience.code }).toEqual({
      status: 'uncertain',
      code: 'RESULT_AUDIENCE_MISMATCH',
    });

    const minted = [
      {
        overrides: { issuedAt: String(T0 - 121000), deadlineMs: String(T0 - 1000) },
        code: 'FRESHNESS_EXPIRED',
      },
      {
        overrides: { issuedAt: String(T0 + 121000), deadlineMs: String(T0 + 122000) },
        code: 'FRESHNESS_NOT_YET_VALID',
      },
      {
        overrides: { issuedAt: String(T0 - 60000), deadlineMs: String(T0 - 1000) },
        code: 'DEADLINE_EXCEEDED',
      },
    ];
    for (const { overrides, code } of minted) {
      const frame = device.minter.mintResultFrame({
        callId,
        outcome: 'succeeded',
        core: overrides,
      });
      const verdict = await sink.ingestResult({ callId, payload: frame.payload });
      expect({ overrides, status: verdict.status, code: verdict.code }).toEqual({
        overrides,
        status: 'uncertain',
        code,
      });
      expect(verdict.success).toBe(false);
    }

    // Structure precedes the signature by contract, so a tampered core is rejected as a shape
    // failure (never as success) without needing a key at all.
    for (const tamper of [
      { epoch: '0' },
      { deviceId: '' },
      { argsDigestHex: 'nope' },
      { tag: 'CBHR-RPC-V2' },
    ]) {
      const broken = { ...genuine.frame, ...tamper };
      const verdict = await sink.ingestResult({ callId, payload: JSON.stringify(broken) });
      expect({ tamper, status: verdict.status, code: verdict.code }).toEqual({
        tamper,
        status: 'uncertain',
        code: 'RESULT_FRAME_SHAPE_INVALID',
      });
      expect(verdict.success).toBe(false);
    }
  });

  it('is uncertain for a replayed RESULT nonce when a replay window is wired', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({
      ledger,
      device,
      options: { replayWindow: relay.createReplayWindow({ now: CLOCK.now }) },
    });
    await liveCall({ ledger, authority: device.deviceAuthority, callId: 'call-replay-1' });
    await liveCall({ ledger, authority: device.deviceAuthority, callId: 'call-replay-2' });

    const first = device.minter.mintResultFrame({
      callId: 'call-replay-1',
      outcome: 'succeeded',
      nonce: COMMAND_NONCE,
    });
    const replayed = device.minter.mintResultFrame({
      callId: 'call-replay-2',
      outcome: 'succeeded',
      nonce: COMMAND_NONCE,
    });

    const firstVerdict = await sink.ingestResult({
      callId: 'call-replay-1',
      payload: first.payload,
    });
    const replayedVerdict = await sink.ingestResult({
      callId: 'call-replay-2',
      payload: replayed.payload,
    });

    expect(firstVerdict.status).toBe('completed');
    expect(replayedVerdict).toMatchObject({
      status: 'uncertain',
      code: 'REPLAY_DETECTED',
      success: false,
    });
    expect((await ledger.get('call-replay-2')).state).toBe('dispatched');
  });

  it('is uncertain when the authenticated frame binds a different device, key, grant or epoch', async () => {
    const { device, sink, ledger, callId } = await fixture();

    // The result core is TWELVE fields and signs no tenant (GM-80 §2 / W7 README §4), so the binding
    // compares exactly the four identity fields the frame carries; `tenantId` stays the platform's own
    // ledger record of the call rather than an identity invented for the device.
    expect([...RESULT_BINDING_FIELDS]).toEqual(['deviceId', 'deviceKeyId', 'grantId', 'epoch']);
    expect([...RESULT_BINDING_FIELDS_NOT_CARRIED]).toEqual(['tenantId']);

    for (const overrides of [
      { deviceId: '65a1b2c3d4e5f6071829ffff' },
      { grantId: 'EBESExQVFhcYGRobHB0eHg' },
      { deviceKeyId: 'eBsXUXqHfJpRmak8ReOpt11QAUyjFQjaetmtzNS-IPw' },
      { epoch: '8' },
    ]) {
      const frame = device.minter.mintResultFrame({
        callId,
        outcome: 'succeeded',
        core: overrides,
      });
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

  it('is uncertain when the SIGNED callId names a different call than the envelope it was forwarded under', async () => {
    const { device, sink, callId } = await fixture();
    const frame = device.minter.mintResultFrame({
      callId,
      outcome: 'succeeded',
      core: { callId: 'call-somewhere-else' },
    });
    const verdict = await sink.ingestResult({ callId, payload: frame.payload });
    expect(verdict).toMatchObject({
      status: 'uncertain',
      code: 'RESULT_CALL_MISMATCH',
      success: false,
    });
  });

  it('is uncertain for result bytes beyond the platform bound (GM-58 plaintext bound)', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device, options: { maxResultBytes: 64 } });
    await liveCall({ ledger, authority: device.deviceAuthority, callId: 'call-big-result' });

    const frame = device.minter.mintResultFrame({
      callId: 'call-big-result',
      outcome: 'succeeded',
      bytes: Buffer.from(JSON.stringify({ status: 'succeeded', pad: 'y'.repeat(256) }), 'utf8'),
    });
    const verdict = await sink.ingestResult({ callId: 'call-big-result', payload: frame.payload });

    expect(verdict).toMatchObject({
      status: 'uncertain',
      code: 'RESULT_TOO_LARGE',
      success: false,
      stored: false,
    });
    expect((await ledger.get('call-big-result')).state).toBe('dispatched');
    expect(await sink.size()).toBe(0);
  });

  it('is uncertain — never success — when the SIGNED outcome word is not one this platform knows', async () => {
    const { device, sink, ledger, callId } = await fixture();
    // The word is inside the signature, so the frame is authentic; the platform simply cannot say
    // what it means, and an unknown word is never spelled "success" (GM-80 §4.7).
    const frame = device.minter.mintResultFrame({ callId, outcome: 'probably-fine' });
    const verdict = await sink.ingestResult({ callId, payload: frame.payload });
    expect(verdict).toMatchObject({
      status: 'uncertain',
      code: 'RESULT_OUTCOME_UNRECOGNISED',
      success: false,
      stored: false,
      reportedOutcome: 'probably-fine',
    });
    expect((await ledger.get(callId)).state).toBe('dispatched');
    expect(await sink.size()).toBe(0);
  });

  it('leaves the call OPEN when the device itself signs `uncertain`, and a later genuine report still lands', async () => {
    const { device, sink, ledger, callId } = await fixture();
    const deviceIsUnsure = device.minter.mintResultFrame({ callId, outcome: 'uncertain' });
    const verdict = await sink.ingestResult({
      callId,
      payload: deviceIsUnsure.payload,
      resultSeq: 3,
    });

    expect(verdict).toMatchObject({
      status: 'uncertain',
      code: 'RESULT_OUTCOME_UNCERTAIN',
      success: false,
      outcome: null,
      stored: false,
      reportedOutcome: 'uncertain',
    });
    expect((await ledger.get(callId)).state).toBe('dispatched');
    expect(await sink.size()).toBe(0);

    // The genuine report afterwards is the one that completes the call.
    const genuine = device.minter.mintResultFrame({ callId, outcome: 'succeeded' });
    const genuineVerdict = await sink.ingestResult({
      callId,
      payload: genuine.payload,
      resultSeq: 4,
    });
    expect(genuineVerdict).toMatchObject({
      status: 'completed',
      success: true,
      outcome: 'succeeded',
    });
    expect(await sink.size()).toBe(1);
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
    const synthesised = JSON.stringify({
      callId: 'call-forged',
      outcome: 'succeeded',
      toolName: 'read_file',
    });
    const verdict = await sink.ingestResult({ callId: 'call-forged', payload: synthesised });

    expect(verdict.status).toBe('uncertain');
    expect(verdict.success).toBe(false);
    expect(verdict.outcome).toBeNull();
    expect((await ledger.get('call-forged')).state).toBe('dispatched');
    expect(await sink.size()).toBe(0);
  });

  it('refuses a result-shaped frame whose 64-byte signature is not the device’s', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device });
    await liveCall({ ledger, authority: device.deviceAuthority, callId: 'call-forged-2' });

    // A frame the relay built itself: correct twelve fields, a well-formed 64-byte signature, and no
    // device key behind it. Signature verification is what stops it (GM-80 §4.2).
    const forged = device.minter.mintResultFrame({
      callId: 'call-forged-2',
      outcome: 'succeeded',
      signatureB64u: Buffer.alloc(64, 7).toString('base64url'),
    });

    const verdict = await sink.ingestResult({ callId: 'call-forged-2', payload: forged.payload });
    expect(verdict).toMatchObject({
      status: 'uncertain',
      code: 'RESULT_SIGNATURE_INVALID',
      success: false,
    });
    expect((await ledger.get('call-forged-2')).state).toBe('dispatched');
  });

  it('is uncertain for a GENUINE frame whose result bytes were rewritten, and the genuine report is the only completion', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device });
    await liveCall({ ledger, authority: device.deviceAuthority, callId: 'call-recover' });

    const genuine = device.minter.mintResultFrame({ callId: 'call-recover', outcome: 'refused' });
    const rewritten = {
      ...genuine.frame,
      argsB64u: Buffer.from(
        JSON.stringify({ callId: 'call-recover', outcome: 'succeeded' }),
        'utf8',
      ).toString('base64url'),
    };

    const forgedVerdict = await sink.ingestResult({
      callId: 'call-recover',
      payload: JSON.stringify(rewritten),
    });
    const genuineVerdict = await sink.ingestResult({
      callId: 'call-recover',
      payload: genuine.payload,
    });

    expect(forgedVerdict).toMatchObject({
      status: 'uncertain',
      code: 'ARGS_DIGEST_MISMATCH',
      success: false,
    });
    expect(forgedVerdict.success).toBe(false);
    // The device's own word is what completes the call — not the rewritten success.
    expect(genuineVerdict).toMatchObject({
      status: 'completed',
      success: false,
      outcome: 'refused',
    });
    expect((await ledger.get('call-recover')).outcome).toBe('refused');
    expect(await sink.size()).toBe(1);
  });
});

describe('F. transport shape, sizing and the sink seam', () => {
  it('refuses an oversized forwarded payload without touching the ledger', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device, options: { maxForwardedChars: 512 } });
    await liveCall({ ledger, authority: device.deviceAuthority, callId: 'call-large-forward' });

    const verdict = await sink.ingestResult({
      callId: 'call-large-forward',
      payload: 'z'.repeat(513),
    });
    expect(verdict).toMatchObject({
      status: 'refused',
      code: 'RESULT_TOO_LARGE',
      success: false,
      stored: false,
    });
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

  it('cannot be constructed without the ledger and the pinned device verifier', () => {
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
    const verifier = { verifyResultSignature: () => ({ ok: false }) };
    expect(codeOf(() => createResultSink({ verifier, clock: CLOCK }))).toEqual({
      code: 'SINK_SEAM_INVALID',
      field: 'ledger',
    });
    expect(codeOf(() => createResultSink({ ledger, clock: CLOCK }))).toEqual({
      code: 'SINK_SEAM_INVALID',
      field: 'verifier',
    });
    expect(codeOf(() => createResultSink({ ledger, verifier: {}, clock: CLOCK }))).toEqual({
      code: 'SINK_SEAM_INVALID',
      field: 'verifier',
    });
    expect(codeOf(() => createResultSink({ ledger, verifier, clock: {} }))).toEqual({
      code: 'CLOCK_UNUSABLE',
      field: 'clock',
    });
    expect(
      codeOf(() => createResultSink({ ledger, verifier, clock: CLOCK, maxResultBytes: 0 })),
    ).toEqual({
      code: 'SINK_SEAM_INVALID',
      field: 'maxResultBytes',
    });
    expect(codeOf(() => createResultSink({ ledger, verifier, clock: CLOCK, store: {} }))).toEqual({
      code: 'SINK_SEAM_INVALID',
      field: 'store',
    });
  });

  it('applies the outcome law: `succeeded` succeeds, `refused` completes a non-success, `uncertain` stays open', async () => {
    const device = makeDeviceResultMinter(relay, { now: CLOCK.now });
    const ledger = createDispatchLedger({ now: CLOCK.now });
    const sink = buildSink({ ledger, device });

    const expected = [
      { outcome: 'succeeded', status: 'completed', success: true, stored: true, code: null },
      { outcome: 'refused', status: 'completed', success: false, stored: true, code: null },
      {
        outcome: 'uncertain',
        status: 'uncertain',
        success: false,
        stored: false,
        code: 'RESULT_OUTCOME_UNCERTAIN',
      },
    ];
    for (const scenario of expected) {
      const callId = `call-${scenario.outcome}`;
      await liveCall({ ledger, authority: device.deviceAuthority, callId });
      const frame = device.minter.mintResultFrame({ callId, outcome: scenario.outcome });
      const verdict = await sink.ingestResult({ callId, payload: frame.payload });
      expect({
        outcome: scenario.outcome,
        status: verdict.status,
        success: verdict.success,
        stored: verdict.stored,
        code: verdict.code,
      }).toEqual({
        outcome: scenario.outcome,
        status: scenario.status,
        success: scenario.success,
        stored: scenario.stored,
        code: scenario.code,
      });
      expect((await ledger.get(callId)).state).toBe(
        scenario.status === 'completed' ? 'completed' : 'dispatched',
      );
    }
    // Only the two completed calls produced a stored result.
    expect(await sink.size()).toBe(2);
  });
});
