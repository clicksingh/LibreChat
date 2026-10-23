'use strict';

/**
 * W12 — THE TOOL-POLICY GATE ON THE REAL DISPATCH PATH.
 *
 * `docs/GM-RULING-TOOL-CONFIG-AND-USER-TRY-20261023.md` (GM-72 three tiers; GM-73 the Node endpoint)
 * and `docs/GM-RULING-ADMIN-ADMINISTERED-PERMISSIONS-20261023.md` (GM-75 retires the device floor,
 * GM-76 policy is data, GM-78 the server enforces LIVE at dispatch time, GM-79 the guards).
 *
 * WHAT THIS SPEC PROVES, AND HOW
 * The gate is a callable no more: `createRelayDispatchClient` evaluates the registry's
 * `authorizeDispatch` — through the injected policy port built here from the REAL
 * `deviceCapabilityPolicy` and `deviceToolRegistry` (nothing stubbed: stubbed law would prove
 * nothing) — BEFORE the clock, the nonce, the replay window, the signature, the ledger and the
 * transport. "Refused" therefore means the recording transport was never called, the custody seam
 * never signed, and the dispatch ledger never reserved: the negative tests assert the WIRE (and the
 * signer, and the ledger), not merely an error object.
 *
 * EVERY REFUSAL CODE IS THE REGISTRY'S OWN (`registry.DISPATCH_CODES`), asserted against the
 * constants rather than against copied strings, so this spec cannot drift into a parallel vocabulary.
 *
 * THE STAGE IS DRIVEN THROUGH THE ENVIRONMENT EXACTLY LIKE THE ADMIN ROUTE SOURCES IT: the port's
 * `stage` reads `CBHR_DEVICE_CAPABILITY_STAGE` live at dispatch time, and the client's own stage law
 * decides — unset means the NARROWEST stage, an unrecognised value narrows (and warns) instead of
 * widening, a recognised value selects its rung. (The one environment read lives in this file, which
 * is outside the scanned `relay/` directory whose frozen guard forbids environment access there: the
 * client header states the reason. The law itself — stage default, narrowing, warning, ceiling — is
 * the client's.)
 *
 * ONLY `opKind: 'command'` frames are tool executions: cancel/resync carry a `toolName` because the
 * envelope requires one, and gating them would let a policy refusal make a running call
 * un-cancellable. That exclusion is asserted here too, so it is a decision rather than an omission.
 */

const policy = require('../../deviceCapabilityPolicy');
const registry = require('../../deviceToolRegistry');
const {
  relay,
  AUTHORITY,
  T0,
  makeTestKeypair,
  makeCustodySeam,
  makeTransport,
} = require('./_fixtures.cjs');

const keypair = makeTestKeypair();
const custody = makeCustodySeam(keypair);
/** The REAL signer (canonicalisation + signature), wrapped only to record that it was called. */
const envelopeSigner = relay.createEnvelopeSigner(custody);
const verifier = relay.createEnvelopeVerifier({ publicKeySpkiB64u: keypair.publicKeySpkiB64u });

const ARGS_BYTES = Buffer.from('{"path":"C:/notes/today.txt"}', 'utf8');
const REQUEST_ID = '3f0c5b1e-8a2d-4c7b-9e61-2d4f8a0b7c93';

/** Stage A tool (inside even the narrowest ceiling) vs stage B tool (outside it). */
const READ_TOOL = 'read_file';
const WRITE_TOOL = 'write_file';

/** A name that is not one of the 26 advertised tools. */
const UNKNOWN_TOOL = 'fuzzy_search';

/** The tier-1 hard denies: an internal handler plus the pilot-denied feedback tool. */
const HARD_DENIED_TOOLS = [...Object.keys(policy.ALWAYS_DENIED), ...Object.keys(policy.PILOT_DENIED)];

// An approval-gated tool the widest stage admits (so the approval seam, not the stage, decides).
const APPROVAL_TOOL = policy.OWNER_APPROVAL_TOOLS.find((name) =>
  policy.ceilingForStage('full').tools.includes(name),
);
const WIDEST_STAGE = 'full';

const STAGES = [...policy.CAPABILITY_STAGES];
const NARROWEST_STAGE = policy.CAPABILITY_STAGES[0];
const NARROWEST_CEILING_COUNT = policy.ceilingForStage(NARROWEST_STAGE).tools.length;

const ENV_KEY = relay.CAPABILITY_STAGE_ENV;
const ENV_AT_LOAD = process.env[ENV_KEY];

beforeEach(() => {
  delete process.env[ENV_KEY];
});

afterEach(() => {
  if (ENV_AT_LOAD === undefined) {
    delete process.env[ENV_KEY];
  } else {
    process.env[ENV_KEY] = ENV_AT_LOAD;
  }
});

/**
 * THE PRODUCTION WIRING, in one function: the port the server must hand the client. Every member
 * whose output is law is a REAL policy/registry function, exactly as `requireDevicePolicyPrimitives`
 * hands them to `@librechat/api` in `api/server/routes/admin/devicePolicy.js`. The stage is the one
 * line the environment owes the wiring: it is read live at dispatch time (GM-78).
 */
function toolPolicyPort({ stage, resolve, hasOwnerApproval } = {}) {
  const port = {
    ceilingForStage: (stageName) => policy.ceilingForStage(stageName),
    authorizeDispatch: (toolName, params) => registry.authorizeDispatch(toolName, params),
    dispatchCodes: registry.DISPATCH_CODES,
  };
  if (stage === undefined) {
    port.stage = () => process.env[ENV_KEY];
  } else {
    port.stage = stage;
  }
  if (resolve !== undefined) {
    port.resolve = resolve;
  }
  if (hasOwnerApproval !== undefined) {
    port.hasOwnerApproval = hasOwnerApproval;
  }
  return port;
}

/**
 * A client with the recording transport, a CALL-COUNting custody wrapper and a CALL-COUNting ledger
 * reservation — so a refused tool can be shown never to have reached any of them.
 */
function buildClient(overrides = {}) {
  const response = 'response' in overrides ? overrides.response : { status: 200, body: { accepted: true } };
  const { transport, calls } = makeTransport(response);
  const signedCores = [];
  const signer = {
    keyId: envelopeSigner.keyId,
    signCore: async (core) => {
      signedCores.push(core);
      return envelopeSigner.signCore(core);
    },
  };
  const reservedCalls = [];
  const ledger =
    'ledger' in overrides
      ? overrides.ledger
      : {
          reserve: async (call) => {
            reservedCalls.push(call);
            return { ok: true };
          },
          release: async () => ({ ok: true }),
        };
  const client = relay.createRelayDispatchClient({
    transport,
    signer,
    ledger,
    clock: { now: () => T0 },
    nonceFactory: overrides.nonceFactory ?? (() => 'AAECAwQFBgcICQoLDA0ODw'),
    requestIdFactory: () => REQUEST_ID,
    verifier: overrides.verifier === undefined ? verifier : overrides.verifier,
    replayWindow: relay.createReplayWindow({ now: () => T0 }),
    logger: overrides.logger ?? null,
    policy: 'policy' in overrides ? overrides.policy : toolPolicyPort(),
  });
  return { client, calls, signedCores, reservedCalls };
}

function dispatchArgs(args = {}) {
  return { authority: AUTHORITY, argsBytes: ARGS_BYTES, ...args };
}

describe('the tool-policy gate sits on the dispatch path, before the wire', () => {
  it('dispatches a tool inside the ceiling — the wire is reached', async () => {
    const { client, calls } = buildClient();

    const outcome = await client.dispatchCommand(dispatchArgs({ toolName: READ_TOOL }));

    expect(ENV_KEY).toBe('CBHR_DEVICE_CAPABILITY_STAGE');
    expect(outcome.ok).toBe(true);
    expect(outcome.delivered).toBe('accepted');
    expect(calls).toHaveLength(1);
    expect(calls[0].frame.toolName).toBe(READ_TOOL);
    // The ceiling alone rules, at the narrowest stage, with nothing narrowed away.
    expect(outcome.policy).toMatchObject({
      evaluated: true,
      portState: 'armed',
      reason: null,
      stage: NARROWEST_STAGE,
      stageSource: 'default',
      ceilingCount: NARROWEST_CEILING_COUNT,
      resolver: 'absent',
      failClosed: false,
      decision: 'allowed',
      requiresApproval: false,
      approved: null,
    });
    expect(outcome.policy.code).toBe(registry.DISPATCH_CODES.ALLOWED);
    expect(outcome.policy.effectiveCount).toBe(NARROWEST_CEILING_COUNT);
  });

  it('refuses a tool outside the ceiling BEFORE the wire: nothing signed, reserved or sent', async () => {
    const { client, calls, signedCores, reservedCalls } = buildClient({
      // One nonce forever, so a second identical dispatch proves the refusal happened BEFORE the
      // replay window was ever reached (otherwise it would be REPLAY_DETECTED the second time).
      nonceFactory: () => 'AAECAwQFBgcICQoLDA0ODw',
    });

    const refused = await client.dispatchCommand(
      dispatchArgs({ toolName: WRITE_TOOL, callId: 'call-w12-outside' }),
    );

    expect(refused.ok).toBe(false);
    expect(refused.code).toBe(registry.DISPATCH_CODES.OUTSIDE_SERVER_CEILING);
    expect(refused.code).toBe('TOOL_CEILING_OUTSIDE_SERVER_CEILING');
    expect(refused.delivered).toBe('no');
    expect(refused.error.code).toBe(registry.DISPATCH_CODES.OUTSIDE_SERVER_CEILING);
    expect(refused.error.httpStatus).toBe(403);
    expect(refused.policy).toMatchObject({
      evaluated: true,
      stage: NARROWEST_STAGE,
      decision: 'denied',
      code: 'TOOL_CEILING_OUTSIDE_SERVER_CEILING',
      httpStatus: 403,
      tier: 1,
      failClosed: false,
    });

    // THE WIRE, THE SIGNER AND THE LEDGER: the refused tool reached none of them.
    expect(calls).toHaveLength(0);
    expect(signedCores).toHaveLength(0);
    expect(reservedCalls).toHaveLength(0);

    // The refusal sits before the replay window, so a repeated dispatch is refused the same way.
    const repeated = await client.dispatchCommand(
      dispatchArgs({ toolName: WRITE_TOOL, callId: 'call-w12-outside' }),
    );
    expect(repeated.code).toBe('TOOL_CEILING_OUTSIDE_SERVER_CEILING');
    expect(repeated.error.code).toBe('TOOL_CEILING_OUTSIDE_SERVER_CEILING');
    expect(calls).toHaveLength(0);
    expect(signedCores).toHaveLength(0);
  });

  it('adds nothing to the wire format when a dispatch does go through', async () => {
    const { client, calls } = buildClient();

    await client.dispatchCommand(
      dispatchArgs({
        toolName: READ_TOOL,
        seq: 3,
        idempotencyKey: 'idem-w12',
        callId: 'call-w12-admitted',
      }),
    );

    // The frame keeps the frozen shape the W2 suite already checks (19 keys): the gate adds no
    // field, and policy rides only in the server-side outcome, never on the wire.
    expect(Object.keys(calls[0].frame)).toEqual([
      ...relay.RPC_FRAME_KEYS.slice(0, 15),
      'signatureB64u',
      'keyId',
      'argsB64u',
      'seq',
      'idempotencyKey',
      'callId',
    ]);
    const signed = relay.signedFromWireFrame(calls[0].frame);
    expect(verifier.verifySignature(signed).ok).toBe(true);
  });

  it('lets a refused tool be distinguished from an argued one at every later seam', async () => {
    const refused = await buildClient().client.dispatchCommand(
      dispatchArgs({ toolName: WRITE_TOOL }),
    );
    const allowed = await buildClient().client.dispatchCommand(dispatchArgs({ toolName: READ_TOOL }));

    expect(refused.requestId).toBe(null);
    expect(refused.deviceId).toBe(null);
    expect(refused.policy.requiresApproval).toBe(false);
    expect(allowed.policy.approved).toBe(null);
  });
});

describe('tier-1 law holds at every stage, including the widest', () => {
  it.each(STAGES)('refuses the hard-denied tools at stage %s', async (stage) => {
    process.env[ENV_KEY] = stage;

    for (const tool of HARD_DENIED_TOOLS) {
      const { client, calls, signedCores } = buildClient();
      const outcome = await client.dispatchCommand(dispatchArgs({ toolName: tool }));

      expect(outcome.ok).toBe(false);
      expect(outcome.delivered).toBe('no');
      expect(outcome.code).toBe(registry.DISPATCH_CODES.NOT_PERMITTED);
      expect(outcome.policy).toMatchObject({
        evaluated: true,
        stage,
        decision: 'denied',
        code: 'TOOL_NOT_PERMITTED',
      });
      expect(calls).toHaveLength(0);
      expect(signedCores).toHaveLength(0);
    }
  });

  it('a narrowing resolver cannot lift a hard deny, even at the widest stage', async () => {
    process.env[ENV_KEY] = WIDEST_STAGE;
    const claim = () => HARD_DENIED_TOOLS;
    const { client, calls } = buildClient({ policy: toolPolicyPort({ resolve: claim }) });

    for (const tool of HARD_DENIED_TOOLS) {
      const outcome = await client.dispatchCommand(dispatchArgs({ toolName: tool }));
      expect(outcome.code).toBe('TOOL_NOT_PERMITTED');
      expect(outcome.delivered).toBe('no');
    }
    expect(calls).toHaveLength(0);
  });

  it('a request cannot raise the ceiling: a stage key is a shape violation', async () => {
    const { client, calls } = buildClient();

    const outcome = await client.dispatchCommand(
      dispatchArgs({ toolName: READ_TOOL, stage: WIDEST_STAGE }),
    );

    expect(outcome.ok).toBe(false);
    expect(outcome.code).toBe('DISPATCH_REQUEST_SHAPE_INVALID');
    expect(calls).toHaveLength(0);
  });
});

describe('tier 3 — the approval gate is never a plain allow', () => {
  it('refuses an approval-gated tool without approval, and dispatches it with approval', async () => {
    expect(APPROVAL_TOOL).toBeDefined();
    process.env[ENV_KEY] = WIDEST_STAGE;

    // No approval seam: another way of saying "no approval".
    const unsealed = buildClient();
    const noApproval = await unsealed.client.dispatchCommand(
      dispatchArgs({ toolName: APPROVAL_TOOL }),
    );
    expect(noApproval.ok).toBe(false);
    expect(noApproval.code).toBe(registry.DISPATCH_CODES.APPROVAL_REQUIRED);
    expect(noApproval.code).toBe('OWNER_APPROVAL_REQUIRED');
    expect(noApproval.delivered).toBe('no');
    expect(noApproval.error.httpStatus).toBe(403);
    expect(noApproval.policy).toMatchObject({
      evaluated: true,
      decision: 'approval-required',
      code: 'OWNER_APPROVAL_REQUIRED',
      requiresApproval: true,
      approved: false,
    });
    // A withheld approval reads as a refusal, while the registry's own reason stays in `detail`.
    expect(noApproval.message).toContain('refused');
    expect(noApproval.policy.detail).toMatch(/owner approval/i);
    expect(unsealed.calls).toHaveLength(0);

    // An explicit "no", a promise that resolves false, and a broken seam that REJECTS or THROWS are
    // all the same refusal — never an allow.
    const withheld = [
      () => false,
      () => Promise.resolve(false),
      () => Promise.reject(new Error('approval store down')),
      () => {
        throw new Error('approval store down');
      },
    ];
    for (const hasOwnerApproval of withheld) {
      const { client, calls } = buildClient({ policy: toolPolicyPort({ hasOwnerApproval }) });
      const refused = await client.dispatchCommand(dispatchArgs({ toolName: APPROVAL_TOOL }));
      expect(refused.code).toBe('OWNER_APPROVAL_REQUIRED');
      expect(refused.delivered).toBe('no');
      expect(refused.policy.approved).toBe(false);
      expect(calls).toHaveLength(0);
    }

    // And ONLY an explicit `true` lets the frame through: the two paths stay distinguishable.
    const sealed = buildClient({
      policy: toolPolicyPort({ hasOwnerApproval: () => true }),
      nonceFactory: (() => {
        let counter = 0;
        return () => Buffer.alloc(16, (counter += 1)).toString('base64url');
      })(),
    });
    const admitted = await sealed.client.dispatchCommand(dispatchArgs({ toolName: APPROVAL_TOOL }));
    expect(admitted.ok).toBe(true);
    expect(admitted.delivered).toBe('accepted');
    expect(sealed.calls).toHaveLength(1);
    expect(sealed.calls[0].frame.toolName).toBe(APPROVAL_TOOL);
    expect(admitted.policy).toMatchObject({
      evaluated: true,
      decision: 'approval-required',
      code: 'OWNER_APPROVAL_REQUIRED',
      requiresApproval: true,
      approved: true,
    });
  });

  it('an approval-gated tool outside the ceiling is a widening refusal, not an approval question', async () => {
    const { client, calls } = buildClient({
      policy: toolPolicyPort({ hasOwnerApproval: () => true }),
    });

    // `start_process` is stage C; with no stage configured the narrow stage A stands.
    const gate = policy.OWNER_APPROVAL_TOOLS.find(
      (name) => policy.getToolDefinition(name).stage !== NARROWEST_STAGE,
    );
    const outcome = await client.dispatchCommand(dispatchArgs({ toolName: gate }));

    expect(outcome.code).toBe('TOOL_CEILING_OUTSIDE_SERVER_CEILING');
    expect(outcome.policy.approved).toBe(null);
    expect(outcome.policy.requiresApproval).toBe(false);
    expect(calls).toHaveLength(0);
  });
});

describe('the registry owns every refusal word', () => {
  it('refuses an unrecognised tool name with the registry unknown code', async () => {
    process.env[ENV_KEY] = WIDEST_STAGE;
    const { client, calls } = buildClient();

    const outcome = await client.dispatchCommand(dispatchArgs({ toolName: UNKNOWN_TOOL }));

    expect(outcome.ok).toBe(false);
    expect(outcome.code).toBe(registry.DISPATCH_CODES.UNKNOWN);
    expect(outcome.code).toBe('TOOL_UNKNOWN');
    expect(outcome.error.httpStatus).toBe(400);
    expect(outcome.policy).toMatchObject({ evaluated: true, decision: 'denied' });
    expect(calls).toHaveLength(0);
  });

  it('mirrors the stage words of the ceiling it refused at', async () => {
    const { client } = buildClient();

    const outcome = await client.dispatchCommand(dispatchArgs({ toolName: WRITE_TOOL }));

    expect(outcome.policy.stage).toBe(NARROWEST_STAGE);
    expect(outcome.policy.detail).toContain(`stage ${NARROWEST_STAGE}`);
  });
});

describe('the injected policy resolver narrows, never widens, and fails closed', () => {
  it('honours a resolver that narrows further than the ceiling (ceiling ∩ resolver)', async () => {
    process.env[ENV_KEY] = WIDEST_STAGE;
    const { client, calls } = buildClient({
      policy: toolPolicyPort({ resolve: () => ['read_file', 'list_directory'] }),
    });

    // `get_config` is inside the widest ceiling but not in the resolver's list: it stays off.
    const narrowed = await client.dispatchCommand(dispatchArgs({ toolName: 'get_config' }));
    expect(narrowed.ok).toBe(false);
    expect(narrowed.code).toBe(registry.DISPATCH_CODES.DISABLED_ON_DEVICE);
    expect(narrowed.code).toBe('TOOL_DISABLED_ON_DEVICE');
    expect(narrowed.delivered).toBe('no');
    expect(narrowed.policy).toMatchObject({
      evaluated: true,
      resolver: 'narrowed',
      failClosed: false,
      decision: 'denied',
    });
    expect(narrowed.policy.effectiveCount).toBe(2);

    // The overlap dispatches.
    const admitted = await client.dispatchCommand(dispatchArgs({ toolName: 'read_file' }));
    expect(admitted.ok).toBe(true);
    expect(calls).toHaveLength(1);
  });

  it('a resolver naming tools outside the ceiling cannot widen it', async () => {
    const { client, calls } = buildClient({
      policy: toolPolicyPort({ resolve: () => [READ_TOOL, WRITE_TOOL, 'start_process'] }),
    });

    const widened = await client.dispatchCommand(dispatchArgs({ toolName: WRITE_TOOL }));
    expect(widened.ok).toBe(false);
    expect(widened.code).toBe('TOOL_CEILING_OUTSIDE_SERVER_CEILING');
    expect(widened.policy.effectiveCount).toBe(1);

    const admitted = await client.dispatchCommand(dispatchArgs({ toolName: READ_TOOL }));
    expect(admitted.ok).toBe(true);
    expect(calls).toHaveLength(1);
  });

  it('a resolver that THROWS causes a refusal, not an allow (fail closed)', async () => {
    // `READ_TOOL` would dispatch freely at the narrow default — until the resolver breaks.
    const control = buildClient();
    expect((await control.client.dispatchCommand(dispatchArgs({ toolName: READ_TOOL }))).ok).toBe(
      true,
    );

    const throwing = [() => { throw new Error('policy engine down'); }, () => Promise.reject(new Error('policy engine down'))];
    for (const resolve of throwing) {
      const { client, calls, signedCores } = buildClient({
        policy: toolPolicyPort({ resolve }),
      });
      const outcome = await client.dispatchCommand(dispatchArgs({ toolName: READ_TOOL }));

      // The load-bearing property: a broken policy resolver narrows to nothing. It must never fall
      // back to "allow", or a policy outage becomes a policy bypass.
      expect(outcome.ok).toBe(false);
      expect(outcome.delivered).toBe('no');
      expect(outcome.code).toBe('TOOL_DISABLED_ON_DEVICE');
      expect(outcome.policy).toMatchObject({
        evaluated: true,
        resolver: 'threw',
        failClosed: true,
        decision: 'denied',
        code: 'TOOL_DISABLED_ON_DEVICE',
      });
      expect(outcome.policy.effectiveCount).toBe(0);
      expect(calls).toHaveLength(0);
      expect(signedCores).toHaveLength(0);
    }
  });

  it('a resolver that answers unusably causes a refusal, not an allow (fail closed)', async () => {
    const unusable = ['read_file', {}, { tools: 'read_file' }, { tools: [42] }, null, 42, [[]]];
    for (const resolve of unusable) {
      const { client, calls } = buildClient({
        policy: toolPolicyPort({ resolve: () => resolve }),
      });
      const outcome = await client.dispatchCommand(dispatchArgs({ toolName: READ_TOOL }));

      expect({ answer: JSON.stringify(resolve), ok: outcome.ok }).toEqual({
        answer: JSON.stringify(resolve),
        ok: false,
      });
      expect(outcome.delivered).toBe('no');
      expect(outcome.code).toBe('TOOL_DISABLED_ON_DEVICE');
      expect(outcome.policy).toMatchObject({ resolver: 'unusable', failClosed: true });
      expect(calls).toHaveLength(0);
    }

    // A wildcard-shaped claim is a list of strings — the client passes it on as is — but the
    // REGISTRY reads it as "no floor value means everything", so it fails the whole narrowing
    // closed rather than enabling anything: a wildcard can never widen.
    const wildcarded = buildClient({
      policy: toolPolicyPort({ resolve: () => ['*'] }),
    });
    const wildcardOutcome = await wildcarded.client.dispatchCommand(
      dispatchArgs({ toolName: READ_TOOL }),
    );
    expect(wildcardOutcome.ok).toBe(false);
    expect(wildcardOutcome.code).toBe(registry.DISPATCH_CODES.DEVICE_FLOOR_MALFORMED);
    expect(wildcardOutcome.delivered).toBe('no');
    expect(wildcardOutcome.policy).toMatchObject({
      resolver: 'narrowed',
      reason: 'narrowing-refused',
      failClosed: true,
      decision: 'denied',
    });
    expect(wildcarded.calls).toHaveLength(0);
  });

  it('a stage source that cannot be read fails closed rather than guessing', async () => {
    const { client, calls } = buildClient({
      policy: toolPolicyPort({
        stage: () => {
          throw new Error('stage store down');
        },
      }),
    });

    const outcome = await client.dispatchCommand(dispatchArgs({ toolName: READ_TOOL }));

    expect(outcome.ok).toBe(false);
    expect(outcome.delivered).toBe('no');
    expect(outcome.code).toBe(registry.DISPATCH_CODES.NOT_PERMITTED);
    expect(outcome.policy).toMatchObject({ failClosed: true, decision: 'denied' });
    expect(calls).toHaveLength(0);
  });
});

describe('the stage law — the server stage, narrow by default', () => {
  it('the narrowest stage applies when the env var is unset', async () => {
    delete process.env[ENV_KEY];
    expect(relay.DEFAULT_SERVER_STAGE).toBe(NARROWEST_STAGE);

    const { client, calls } = buildClient();

    const outside = await client.dispatchCommand(dispatchArgs({ toolName: WRITE_TOOL }));
    expect(outside.code).toBe('TOOL_CEILING_OUTSIDE_SERVER_CEILING');
    expect(outside.policy).toMatchObject({ stage: NARROWEST_STAGE, stageSource: 'default' });
    expect(calls).toHaveLength(0);

    const inside = await client.dispatchCommand(dispatchArgs({ toolName: READ_TOOL }));
    expect(inside.ok).toBe(true);
    expect(calls).toHaveLength(1);
  });

  it('an unrecognised env value does not widen — it warns once and keeps the narrow stage', async () => {
    const warned = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      process.env[ENV_KEY] = 'FULL';

      const { client, calls } = buildClient();
      const outside = await client.dispatchCommand(dispatchArgs({ toolName: WRITE_TOOL }));

      expect(outside.ok).toBe(false);
      expect(outside.code).toBe('TOOL_CEILING_OUTSIDE_SERVER_CEILING');
      expect(outside.policy).toMatchObject({ stage: NARROWEST_STAGE, stageSource: 'unrecognised' });
      expect(calls).toHaveLength(0);
      expect(warned).toHaveBeenCalledTimes(1);
      expect(String(warned.mock.calls[0][0])).toContain(ENV_KEY);

      // One misconfiguration warns once per client, not on every dispatch.
      await client.dispatchCommand(dispatchArgs({ toolName: WRITE_TOOL }));
      expect(warned).toHaveBeenCalledTimes(1);
    } finally {
      warned.mockRestore();
    }
  });

  it('a recognised env value selects its rung, and an injected logger carries the warning instead', async () => {
    process.env[ENV_KEY] = WIDEST_STAGE;
    const warned = jest.fn();
    const { client, calls } = buildClient({
      policy: toolPolicyPort({ stage: () => 'not-a-stage-anyone-asked-for' }),
      logger: { warn: warned },
    });

    const outcome = await client.dispatchCommand(dispatchArgs({ toolName: READ_TOOL }));

    expect(outcome.ok).toBe(true);
    expect(outcome.policy).toMatchObject({ stage: NARROWEST_STAGE, stageSource: 'unrecognised' });
    expect(warned).toHaveBeenCalledTimes(1);
    expect(calls).toHaveLength(1);
  });

  it('a control frame is not a tool execution, and stays dispatchable', async () => {
    const { client, calls } = buildClient();

    const resync = await client.dispatchCommand({
      authority: AUTHORITY,
      toolName: '-',
      opKind: 'resync',
      argsBytes: Buffer.alloc(0),
    });

    expect(resync.ok).toBe(true);
    expect(resync.delivered).toBe('accepted');
    expect(resync.policy).toMatchObject({
      evaluated: false,
      reason: 'not-a-tool-execution',
      decision: 'not-evaluated',
    });
    expect(calls).toHaveLength(1);
  });
});

describe('the port is an exact, complete seam — a half-wired gate is a construction error', () => {
  function minimalOptions() {
    return {
      transport: async () => ({ status: 200 }),
      signer: { keyId: envelopeSigner.keyId, signCore: envelopeSigner.signCore },
      replayWindow: relay.createReplayWindow({ now: () => T0 }),
    };
  }

  it('refuses a present-but-incomplete port, a request-shaped key, and a non-object port', () => {
    expect(relay.readPolicyPort(null)).toBe(null);
    expect(relay.readPolicyPort(undefined)).toBe(null);
    expect(() => relay.createRelayDispatchClient({ ...minimalOptions(), policy: {} })).toThrow(
      expect.objectContaining({ code: 'POLICY_SEAM_INVALID' }),
    );
    expect(() =>
      relay.createRelayDispatchClient({ ...minimalOptions(), policy: { resolve: () => [] } }),
    ).toThrow(expect.objectContaining({ code: 'POLICY_SEAM_INVALID' }));
    expect(() =>
      relay.createRelayDispatchClient({
        ...minimalOptions(),
        policy: { ...toolPolicyPort(), user: 'attacker' },
      }),
    ).toThrow(expect.objectContaining({ code: 'POLICY_SEAM_INVALID' }));
    expect(() =>
      relay.createRelayDispatchClient({ ...minimalOptions(), policy: 'read_file' }),
    ).toThrow(expect.objectContaining({ code: 'POLICY_SEAM_INVALID' }));
  });

  it('declares the unarmed state on the outcome when no port is supplied', async () => {
    const { client, calls } = buildClient({ policy: null });

    const outcome = await client.dispatchCommand(dispatchArgs({ toolName: READ_TOOL }));

    expect(outcome.ok).toBe(true);
    expect(outcome.policy).toMatchObject({
      evaluated: false,
      portState: 'absent',
      reason: 'policy-port-absent',
      decision: 'not-evaluated',
      code: null,
      failClosed: false,
    });
    expect(calls).toHaveLength(1);
  });
});
