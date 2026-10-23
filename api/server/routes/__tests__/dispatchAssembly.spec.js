'use strict';

/**
 * GM-83 WIRING PROOF. This spec lives OUTSIDE `api/server/services/Device/relay/` on purpose.
 *
 * The dispatch gate arrives through an INJECTED port, because the frozen `noKeyMaterial.spec.js` guard
 * forbids `process.env` and non-allow-listed requires anywhere in the relay directory. The cost of that
 * decision is a seam, and this file is the thing that makes the seam safe: it proves that the ONE
 * production assembly point builds an ARMED client, and that the assembled path refuses a tool outside
 * the ceiling before anything is signed, reserved or sent.
 *
 * If someone ever deletes the assembly's policy wiring, or adds a second dispatch construction path
 * that forgets it, THIS is the test that breaks — not a customer.
 */

const path = require('node:path');

const REPO = path.resolve(__dirname, '..', '..', '..', '..');
const FIXTURES = path.join(REPO, 'api/server/services/Device/relay/__tests__/_fixtures.cjs');

const assembly = require(path.join(REPO, 'api/server/services/Device/dispatchAssembly.js'));
const registry = require(path.join(REPO, 'api/server/services/Device/deviceToolRegistry.js'));
const { relay, AUTHORITY, makeTestKeypair, makeCustodySeam, makeTransport } = require(FIXTURES);

const ARGS_BYTES = Buffer.from('{"path":"C:/notes/today.txt"}', 'utf8');
const silentLogger = { warn: () => {}, error: () => {}, info: () => {}, log: () => {} };

/**
 * Build through the REAL assembly, with a recording transport (the wire), a custody seam that COUNTS
 * sign calls, and a ledger spy. Signing and reserving are the last steps before the wire, so a
 * non-zero count on a refused tool proves the gate did not run early enough.
 */
function build({ env = {}, resolvePolicy = null, hasOwnerApproval = null, keypair = makeTestKeypair() } = {}) {
  const custody = makeCustodySeam(keypair);
  const signCalls = { count: 0 };
  const counted = {
    keyId: custody.keyId,
    sign: async (canonicalBytes) => {
      signCalls.count += 1;
      return custody.sign(canonicalBytes);
    },
  };
  const { transport, calls } = makeTransport();
  const reserves = { count: 0 };
  const ledger = {
    reserve: () => {
      reserves.count += 1;
      return { ok: true };
    },
    release: () => ({ ok: true }),
    complete: () => ({ ok: true }),
  };

  const built = assembly.createDeviceDispatchAssembly({
    sign: counted.sign,
    keyId: counted.keyId,
    transport,
    replayWindow: relay.createReplayWindow(),
    ledger,
    resolvePolicy,
    hasOwnerApproval,
    env,
    logger: silentLogger,
  });

  return { ...built, calls, signCalls, reserves };
}

let callCounter = 0;
function dispatchArgs(overrides = {}) {
  callCounter += 1;
  return {
    authority: AUTHORITY,
    toolName: 'read_file',
    argsBytes: ARGS_BYTES,
    callId: `cbhr-assembly-${String(callCounter).padStart(4, '0')}`,
    opKind: 'command',
    ...overrides,
  };
}

describe('GM-83 — the production assembly arms the dispatch policy gate', () => {
  describe('the assembly is the single wiring point, and it is armed', () => {
    it('reports an armed port and the narrowest stage when the environment says nothing', () => {
      const { wiring } = build();
      expect(wiring.policyArmed).toBe(true);
      expect(wiring.stage).toBe('A');
      expect(wiring.stageSource).toBe('default');
      expect(wiring.assembledBy).toMatch(/dispatchAssembly\.js$/);
    });

    it('honours a recognised stage from the environment', () => {
      const { wiring } = build({ env: { [assembly.CAPABILITY_STAGE_ENV]: 'C' } });
      expect(wiring.stage).toBe('C');
      expect(wiring.stageSource).toBe('env');
    });

    it('keeps the NARROWEST stage and warns loudly on an unrecognised value', () => {
      const warnings = [];
      const built = assembly.createDeviceDispatchAssembly({
        sign: async () => Buffer.alloc(64, 7).toString('base64url'),
        keyId: 'test-custody-key-1',
        transport: makeTransport().transport,
        replayWindow: relay.createReplayWindow(),
        env: { [assembly.CAPABILITY_STAGE_ENV]: 'FULL-ADMIN-PLEASE' },
        logger: { warn: (m) => warnings.push(m) },
      });
      expect(built.wiring.stage).toBe('A');
      expect(built.wiring.stageSource).toBe('unrecognised');
      // A widening attempt must never be quiet.
      expect(warnings.length).toBeGreaterThan(0);
      expect(warnings[0]).toMatch(/NARROWEST/);
    });

    it('never warns when the stage is simply unset — the default is not a fault', () => {
      const warnings = [];
      assembly.createDeviceDispatchAssembly({
        sign: async () => Buffer.alloc(64, 7).toString('base64url'),
        keyId: 'test-custody-key-1',
        transport: makeTransport().transport,
        replayWindow: relay.createReplayWindow(),
        env: {},
        logger: { warn: (m) => warnings.push(m) },
      });
      expect(warnings).toEqual([]);
    });
  });

  describe('a tool outside the ceiling is refused BEFORE the wire', () => {
    it('touches nothing: not the transport, not the signer, not the ledger', async () => {
      const { client, calls, signCalls, reserves } = build({ env: {} }); // stage A = read-only
      const outcome = await client.dispatchCommand(dispatchArgs({ toolName: 'write_file' }));

      expect(outcome.ok).toBe(false);
      expect(outcome.delivered).toBe('no');
      expect(outcome.policy.evaluated).toBe(true);

      // The wire is the thing that matters: nothing left the process.
      expect(calls).toHaveLength(0);
      expect(signCalls.count).toBe(0);
      expect(reserves.count).toBe(0);
    });

    it('admits a tool INSIDE the ceiling, so the test above is not vacuous', async () => {
      const { client, calls } = build({ env: {} }); // read_file is stage A
      const outcome = await client.dispatchCommand(dispatchArgs({ toolName: 'read_file' }));
      expect(outcome.delivered).not.toBe('no');
      expect(calls.length).toBeGreaterThan(0);
    });
  });

  describe('the resolver seam narrows, and never widens', () => {
    it('honours a resolver that narrows inside the ceiling', async () => {
      const { client, calls } = build({
        env: { [assembly.CAPABILITY_STAGE_ENV]: 'C' },
        resolvePolicy: () => ['read_file'],
      });
      const admitted = await client.dispatchCommand(dispatchArgs({ toolName: 'read_file' }));
      expect(admitted.delivered).not.toBe('no');

      const before = calls.length;
      const narrowed = await client.dispatchCommand(dispatchArgs({ toolName: 'write_file' }));
      expect(narrowed.delivered).toBe('no');
      expect(calls.length).toBe(before); // still nothing on the wire
    });

    it('is refused when the resolver THROWS — the load-bearing fail-closed case', async () => {
      const { client, calls, signCalls } = build({
        env: { [assembly.CAPABILITY_STAGE_ENV]: 'full' },
        resolvePolicy: () => {
          throw new Error('policy store unreachable');
        },
      });
      const outcome = await client.dispatchCommand(dispatchArgs({ toolName: 'read_file' }));

      // A policy source that errors must never become an allow.
      expect(outcome.ok).toBe(false);
      expect(outcome.delivered).toBe('no');
      expect(calls).toHaveLength(0);
      expect(signCalls.count).toBe(0);
    });

    it('is refused when the resolver returns something that is not a tool list at all', async () => {
      // NOTE: `{ tools: [...] }` is a DOCUMENTED VALID form, not garbage — an earlier version of this
      // test wrongly treated it as garbage and failed, correctly. The genuinely unusable answers are
      // scalars and objects with no tool list, which yield an EMPTY narrowing and are refused.
      const unusable = [42, 'read_file', true, { enabled: ['read_file'] }, { tools: 'read_file' }];
      for (const answer of unusable) {
        const { client, calls } = build({
          env: { [assembly.CAPABILITY_STAGE_ENV]: 'full' },
          resolvePolicy: () => answer,
        });
        const outcome = await client.dispatchCommand(dispatchArgs({ toolName: 'read_file' }));
        expect({ answer, ok: outcome.ok }).toEqual({ answer, ok: false });
        expect(calls).toHaveLength(0);
      }
    });

    it('honours the documented `{ tools }` answer shape as a NARROWING, not garbage', async () => {
      // The positive control for the test above: the object form is supported, so a resolver that
      // returns it must narrow rather than refuse.
      const { client, calls } = build({
        env: { [assembly.CAPABILITY_STAGE_ENV]: 'full' },
        resolvePolicy: () => ({ tools: ['read_file'] }),
      });
      const inside = await client.dispatchCommand(dispatchArgs({ toolName: 'read_file' }));
      expect(inside.delivered).not.toBe('no');

      const before = calls.length;
      const outsideTheNarrowing = await client.dispatchCommand(dispatchArgs({ toolName: 'write_file' }));
      expect(outsideTheNarrowing.delivered).toBe('no');
      expect(calls.length).toBe(before);
    });

    it('cannot be widened by a wildcard from the resolver', async () => {
      const { client, calls } = build({
        env: { [assembly.CAPABILITY_STAGE_ENV]: 'A' },
        resolvePolicy: () => ['*'],
      });
      const outcome = await client.dispatchCommand(dispatchArgs({ toolName: 'write_file' }));
      expect(outcome.ok).toBe(false);
      expect(calls).toHaveLength(0);
    });
  });

  describe('the law-denied tools are refused at every stage, including the widest', () => {
    it.each(['track_ui_event', 'give_feedback_to_desktop_commander'])(
      'refuses %s even at stage full',
      async (tool) => {
        const { client, calls } = build({ env: { [assembly.CAPABILITY_STAGE_ENV]: 'full' } });
        const outcome = await client.dispatchCommand(dispatchArgs({ toolName: tool }));
        expect(outcome.ok).toBe(false);
        expect(outcome.delivered).toBe('no');
        expect(calls).toHaveLength(0);
      },
    );
  });

  describe('an unarmed client is LOUD rather than silent', () => {
    it('declares policy.evaluated false when no port was supplied at all', async () => {
      // Constructing directly is the bypass this assembly exists to prevent. It must be visible.
      const keypair = makeTestKeypair();
      const custody = makeCustodySeam(keypair);
      const { transport, calls } = makeTransport();
      const bare = relay.createRelayDispatchClient({
        transport,
        signer: relay.createEnvelopeSigner(custody),
        replayWindow: relay.createReplayWindow(),
      });
      const outcome = await bare.dispatchCommand(dispatchArgs({ toolName: 'read_file' }));

      expect(outcome.policy.evaluated).toBe(false);
      expect(outcome.policy.reason).toBe('policy-port-absent');
      expect(outcome.policy.decision).toBe('not-evaluated');
      // And it did dispatch, which is exactly why the bypass must be visible.
      expect(calls.length).toBeGreaterThan(0);
    });
  });
});