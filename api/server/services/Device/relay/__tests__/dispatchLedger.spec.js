'use strict';

/**
 * W6 spec — THE DISPATCH LEDGER: the correlation memory behind the result sink (GM-43).
 *
 * What is pinned here:
 *   A. a reservation is an EXACT-KEY projection of server truth — nothing request-shaped gets in;
 *   B. one `callId` identifies exactly one call (a second reservation is refused, by name);
 *   C. a call completes exactly once, with the DEVICE's outcome word, and never on speculation;
 *   D. a call that was not put on the wire can be released, and then cannot be correlated at all;
 *   E. the ledger is bounded and fails CLOSED: only a completed call is ever forgotten;
 *   F. the dispatch client's optional ledger seam reserves before the wire, releases on a refusal and
 *      KEEPS the reservation when the outcome is unknown.
 */

const { relay, AUTHORITY, makeTestKeypair, makeCustodySeam, makeTransport } = require('./_fixtures.cjs');
const { createDispatchLedger } = require('../dispatchLedger');

const T0 = 1761200000000;
const CLOCK = { now: () => T0 };

const CALL = Object.freeze({
  callId: 'call-ledger-1',
  deviceId: AUTHORITY.deviceId,
  deviceKeyId: AUTHORITY.deviceKeyId,
  tenantId: AUTHORITY.tenantId,
  grantId: AUTHORITY.grantId,
  epoch: AUTHORITY.epoch,
  requestId: '3f0c5b1e-8a2d-4c7b-9e61-2d4f8a0b7c93',
  toolName: 'read_file',
  opKind: 'command',
});

/**
 * A field-naming `RelayError` deliberately carries a GENERIC external message (relay invariant 3), so
 * a construction refusal is asserted by its typed CODE and its server-side `field`, never by text.
 */
function refusalOf(fn) {
  try {
    fn();
    return null;
  } catch (err) {
    return { code: err.code, field: err.field };
  }
}

function buildLedger(options = {}) {
  return createDispatchLedger({ now: CLOCK.now, ...options });
}

describe('A. a reservation is a projection of server truth', () => {
  it('records exactly the projected keys, in the dispatched state', async () => {
    const ledger = buildLedger();
    const reserved = await ledger.reserve(CALL);

    expect(reserved.ok).toBe(true);
    expect(Object.keys(reserved.entry)).toEqual([
      ...Object.keys(CALL),
      'state',
      'reservedAt',
      'completedAt',
      'outcome',
      'resultSeq',
    ]);
    expect(reserved.entry).toMatchObject({ ...CALL, state: 'dispatched', reservedAt: T0, outcome: null });
    expect(Object.isFrozen(reserved.entry)).toBe(true);
    expect(await ledger.has(CALL.callId)).toBe(true);
    expect(await ledger.size()).toBe(1);
  });

  it('refuses a request-shaped object by name, before anything is recorded', async () => {
    const ledger = buildLedger();
    for (const hostile of [
      { ...CALL, headers: { authorization: 'Bearer x' } },
      { ...CALL, body: { tool: 'read_file' } },
      { ...CALL, user: { id: 'someone' } },
      { ...CALL, query: {} },
    ]) {
      const refused = await ledger.reserve(hostile);
      expect(refused.ok).toBe(false);
      expect(refused.error.code).toBe('DISPATCH_LEDGER_ENTRY_INVALID');
      // The error names the refused KEY and never its value.
      expect(refused.error.field).toBe(Object.keys(hostile).filter((key) => !(key in CALL))[0]);
      expect(refused.error.message).not.toContain('Bearer');
    }
    expect(await ledger.size()).toBe(0);
  });

  it('refuses missing fields and unusable values without recording anything', async () => {
    const ledger = buildLedger();
    const cases = [
      (() => {
        const { toolName, ...rest } = CALL;
        return rest;
      })(),
      { ...CALL, callId: '' },
      { ...CALL, callId: 'x'.repeat(201) },
      { ...CALL, callId: `bad\u001fid` },
      { ...CALL, callId: 42 },
      { ...CALL, epoch: 0 },
      { ...CALL, epoch: '1' },
      { ...CALL, deviceId: '' },
    ];
    for (const input of cases) {
      const refused = await ledger.reserve(input);
      expect({ input, ok: refused.ok, code: refused.error.code }).toEqual({
        input,
        ok: false,
        code: 'DISPATCH_LEDGER_ENTRY_INVALID',
      });
    }
    expect(await ledger.size()).toBe(0);
  });

  it('refuses a ledger that was constructed without a usable store seam', () => {
    expect(refusalOf(() => createDispatchLedger({ now: CLOCK.now, store: {} }))).toEqual({
      code: 'DISPATCH_LEDGER_ENTRY_INVALID',
      field: 'store',
    });
    expect(refusalOf(() => createDispatchLedger({ now: CLOCK.now, maxEntries: 0 }))).toEqual({
      code: 'DISPATCH_LEDGER_ENTRY_INVALID',
      field: 'maxEntries',
    });
    expect(() => createDispatchLedger({ now: 42 })).toThrow(/now\(\) clock/);
  });
});

describe('B. one callId identifies exactly one call', () => {
  it('refuses a second reservation under a live call id', async () => {
    const ledger = buildLedger();
    await ledger.reserve(CALL);
    const second = await ledger.reserve({ ...CALL, requestId: 'a-different-request' });

    expect(second.ok).toBe(false);
    expect(second.error.code).toBe('DISPATCH_CALL_ID_REUSED');
    expect(second.error.field).toBe('callId');
    // The first reservation is untouched.
    expect((await ledger.entries())[0].requestId).toBe(CALL.requestId);
    expect(await ledger.size()).toBe(1);
  });

  it('refuses a second reservation even after the call completed', async () => {
    const ledger = buildLedger();
    await ledger.reserve(CALL);
    await ledger.complete(CALL.callId, { outcome: 'success', resultSeq: 1 });
    const second = await ledger.reserve(CALL);
    expect(second.error.code).toBe('DISPATCH_CALL_ID_REUSED');
  });

  it('lists tracked calls in reservation order', async () => {
    const ledger = buildLedger();
    for (const suffix of ['a', 'b', 'c']) {
      await ledger.reserve({ ...CALL, callId: `call-${suffix}` });
    }
    expect((await ledger.entries()).map((entry) => entry.callId)).toEqual(['call-a', 'call-b', 'call-c']);
  });
});

describe('C. a call completes exactly once', () => {
  it('records the outcome word it was given and refuses a second completion', async () => {
    const ledger = buildLedger();
    await ledger.reserve(CALL);
    const first = await ledger.complete(CALL.callId, { outcome: 'failure', resultSeq: 4 });

    expect(first.ok).toBe(true);
    expect(first.entry).toMatchObject({ state: 'completed', outcome: 'failure', resultSeq: 4, completedAt: T0 });

    const second = await ledger.complete(CALL.callId, { outcome: 'success', resultSeq: 5 });
    expect(second.ok).toBe(false);
    expect(second.error.code).toBe('DISPATCH_CALL_ALREADY_COMPLETED');
    // The recorded outcome did not move: a retry cannot upgrade a failure to a success.
    expect((await ledger.get(CALL.callId)).outcome).toBe('failure');
    expect((await ledger.get(CALL.callId)).resultSeq).toBe(4);
  });

  it('refuses to complete a call it never dispatched, and stores nothing', async () => {
    const ledger = buildLedger();
    const completion = await ledger.complete('call-never-dispatched', { outcome: 'success' });
    expect(completion.ok).toBe(false);
    expect(completion.error.code).toBe('DISPATCH_CALL_UNKNOWN');
    expect(await ledger.size()).toBe(0);
    expect(await ledger.get('call-never-dispatched')).toBeNull();
  });

  it('refuses a completion whose outcome is missing, empty or over-long', async () => {
    const ledger = buildLedger();
    await ledger.reserve(CALL);
    for (const completion of [{}, { outcome: '' }, { outcome: 7 }, { outcome: 'x'.repeat(65) }, { outcome: 'success', surprise: 1 }]) {
      const refused = await ledger.complete(CALL.callId, completion);
      expect({ completion, ok: refused.ok, code: refused.error.code }).toEqual({
        completion,
        ok: false,
        code: 'DISPATCH_LEDGER_ENTRY_INVALID',
      });
    }
    expect((await ledger.get(CALL.callId)).state).toBe('dispatched');
  });

  it('refuses a completion whose resultSeq is not a positive integer', async () => {
    const ledger = buildLedger();
    await ledger.reserve(CALL);
    const refused = await ledger.complete(CALL.callId, { outcome: 'success', resultSeq: 0 });
    expect(refused.error.code).toBe('DISPATCH_LEDGER_ENTRY_INVALID');
    expect((await ledger.get(CALL.callId)).state).toBe('dispatched');
  });
});

describe('D. a call that never reached the wire is released', () => {
  it('removes the reservation and is idempotent', async () => {
    const ledger = buildLedger();
    await ledger.reserve(CALL);
    const first = await ledger.release(CALL.callId, 'relay-refused');
    const second = await ledger.release(CALL.callId, 'relay-refused');

    expect(first).toMatchObject({ ok: true, released: true, reason: 'relay-refused' });
    expect(second).toMatchObject({ ok: true, released: false, reason: 'NOT_RESERVED' });
    expect(await ledger.size()).toBe(0);
    expect(await ledger.get(CALL.callId)).toBeNull();
  });

  it('refuses to release a completed call', async () => {
    const ledger = buildLedger();
    await ledger.reserve(CALL);
    await ledger.complete(CALL.callId, { outcome: 'success' });
    const refused = await ledger.release(CALL.callId);

    expect(refused.ok).toBe(false);
    expect(refused.error.code).toBe('DISPATCH_CALL_ALREADY_COMPLETED');
    expect((await ledger.get(CALL.callId)).state).toBe('completed');
  });

  it('refuses a release for an unusable call id', async () => {
    const ledger = buildLedger();
    const refused = await ledger.release('');
    expect(refused.ok).toBe(false);
    expect(refused.error.code).toBe('DISPATCH_LEDGER_ENTRY_INVALID');
  });
});

describe('E. the ledger is bounded and fails closed', () => {
  it('forgets a COMPLETED call to make room, and never a live one', async () => {
    const ledger = buildLedger({ maxEntries: 2 });
    await ledger.reserve({ ...CALL, callId: 'call-1' });
    await ledger.reserve({ ...CALL, callId: 'call-2' });
    await ledger.complete('call-1', { outcome: 'success' });

    const third = await ledger.reserve({ ...CALL, callId: 'call-3' });
    expect(third.ok).toBe(true);
    expect(await ledger.size()).toBe(2);
    expect(await ledger.get('call-1')).toBeNull();
    expect(await ledger.get('call-2')).not.toBeNull();
  });

  it('refuses a reservation when every tracked call is still live', async () => {
    const ledger = buildLedger({ maxEntries: 2 });
    await ledger.reserve({ ...CALL, callId: 'call-1' });
    await ledger.reserve({ ...CALL, callId: 'call-2' });

    const third = await ledger.reserve({ ...CALL, callId: 'call-3' });
    expect(third.ok).toBe(false);
    expect(third.error.code).toBe('DISPATCH_LEDGER_SATURATED');
    // Nothing was forgotten: both live calls are still correlatable.
    expect((await ledger.entries()).map((entry) => entry.callId)).toEqual(['call-1', 'call-2']);
    expect(await ledger.size()).toBe(2);
  });
});

describe('F. the dispatch client’s optional ledger seam', () => {
  function buildClient({ ledger, response }) {
    const keypair = makeTestKeypair();
    const { transport, calls } = makeTransport(response);
    const client = relay.createRelayDispatchClient({
      transport,
      signer: relay.createEnvelopeSigner(makeCustodySeam(keypair)),
      ledger,
      clock: CLOCK,
      nonceFactory: () => 'AAECAwQFBgcICQoLDA0ODw',
      requestIdFactory: () => '3f0c5b1e-8a2d-4c7b-9e61-2d4f8a0b7c93',
      replayWindow: relay.createReplayWindow({ now: CLOCK.now }),
    });
    return { client, calls };
  }

  it('reserves the call before the frame leaves, and the entry carries the authority projection', async () => {
    const ledger = buildLedger();
    const { client, calls } = buildClient({ ledger, response: { status: 200, body: { accepted: true } } });

    const outcome = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: Buffer.from('{"path":"C:/notes/today.txt"}', 'utf8'),
      callId: 'call-wired',
    });

    expect(outcome.ok).toBe(true);
    expect(calls).toHaveLength(1);
    expect(await ledger.get('call-wired')).toMatchObject({
      deviceId: AUTHORITY.deviceId,
      deviceKeyId: AUTHORITY.deviceKeyId,
      tenantId: AUTHORITY.tenantId,
      grantId: AUTHORITY.grantId,
      epoch: AUTHORITY.epoch,
      requestId: outcome.requestId,
      toolName: 'read_file',
      opKind: 'command',
      state: 'dispatched',
    });
  });

  it('releases the reservation when the relay refused the frame', async () => {
    const ledger = buildLedger();
    const { client } = buildClient({ ledger, response: { status: 400, body: { accepted: false } } });

    const outcome = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: Buffer.from('{}', 'utf8'),
      callId: 'call-refused',
    });

    expect(outcome.ok).toBe(false);
    expect(outcome.delivered).toBe('refused');
    expect(await ledger.size()).toBe(0);
  });

  it('KEEPS the reservation when the outcome is unknown, because the frame may have been delivered', async () => {
    const ledger = buildLedger();
    const { client } = buildClient({ ledger, response: { status: 503 } });

    const outcome = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: Buffer.from('{}', 'utf8'),
      callId: 'call-uncertain',
    });

    expect(outcome.ok).toBe(false);
    expect(outcome.delivered).toBe('unknown');
    expect((await ledger.get('call-uncertain')).state).toBe('dispatched');
  });

  it('refuses a dispatch whose call id is already live, without sending anything', async () => {
    const ledger = buildLedger();
    await ledger.reserve({ ...CALL, callId: 'call-duplicate' });
    const { client, calls } = buildClient({ ledger, response: { status: 200, body: { accepted: true } } });

    const outcome = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: Buffer.from('{}', 'utf8'),
      callId: 'call-duplicate',
    });

    expect(outcome.ok).toBe(false);
    expect(outcome.delivered).toBe('no');
    expect(outcome.code).toBe('DISPATCH_CALL_ID_REUSED');
    expect(calls).toHaveLength(0);
  });

  it('behaves exactly as before when no ledger is supplied', async () => {
    const keypair = makeTestKeypair();
    const { transport, calls } = makeTransport({ status: 200, body: { accepted: true } });
    const client = relay.createRelayDispatchClient({
      transport,
      signer: relay.createEnvelopeSigner(makeCustodySeam(keypair)),
      clock: CLOCK,
      nonceFactory: () => 'AAECAwQFBgcICQoLDA0ODw',
      requestIdFactory: () => '3f0c5b1e-8a2d-4c7b-9e61-2d4f8a0b7c93',
      replayWindow: relay.createReplayWindow({ now: CLOCK.now }),
    });

    const outcome = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: 'read_file',
      argsBytes: Buffer.from('{}', 'utf8'),
      callId: 'call-unledgered',
    });

    expect(outcome.ok).toBe(true);
    expect(calls).toHaveLength(1);
  });

  it('refuses a malformed ledger seam at construction', () => {
    const keypair = makeTestKeypair();
    const { transport } = makeTransport({ status: 200 });
    expect(
      refusalOf(() =>
        relay.createRelayDispatchClient({
          transport,
          signer: relay.createEnvelopeSigner(makeCustodySeam(keypair)),
          ledger: {},
          clock: CLOCK,
          replayWindow: relay.createReplayWindow({ now: CLOCK.now }),
        }),
      ),
    ).toEqual({ code: 'DISPATCH_LEDGER_ENTRY_INVALID', field: 'ledger' });
  });
});