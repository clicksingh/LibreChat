'use strict';

/**
 * W14 — THE AI-FACING DEVICE TOOL: outcome honesty, session identity, custody fail-closed.
 *
 * WHAT THIS SPEC IS FOR
 * The dispatch side is already covered by its own suites; this file does NOT re-prove the gate, the
 * envelope, the replay window or the ledger. It proves the thing W14 adds and the thing most likely
 * to be got wrong: what the MODEL is told. Every assertion below is about the payload that leaves
 * `device_command`, because the platform's own uncertainty is exactly what a well-meaning tool turns
 * into "done".
 *
 * The dispatch client is exercised through the REAL assembly (`createDeviceDispatchAssembly`, with
 * its armed policy port), a REAL replay window and a REAL Ed25519 signing seam from the shared relay
 * fixtures; only the relay HOP (the transport that has no frozen route yet) and the device database
 * are stand-ins. The transport is a recording spy, so "refused" always means the wire was never
 * touched, and the custody seam counts signatures, so "nothing was signed" is witnessed rather than
 * asserted from prose.
 */

const nodeCrypto = require('node:crypto');
const {
  relay,
  makeTestKeypair,
  makeCustodySeam,
  makeTransport,
} = require('~/server/services/Device/relay/__tests__/_fixtures.cjs');
const { CAPABILITY_STAGE_ENV } = require('~/server/services/Device/dispatchAssembly');
const { DISPATCH_CODES } = require('~/server/services/Device/deviceToolRegistry');
const {
  TOOL_CATALOG,
  OWNER_APPROVAL_TOOLS,
} = require('~/server/services/Device/deviceCapabilityPolicy');
const {
  DEVICE_COMMAND_TOOL_NAME,
  DEVICE_COMMAND_INPUT_SCHEMA,
  DEVICE_COMMAND_OUTCOMES,
  SUPPORTED_TOOL_NAMES,
  deviceCommandSchema,
  createDeviceCommandTool,
} = require('../deviceCommand');
// Required at module scope: the registration path pulls the server's tool graph in, and loading it
// while jest collects the file keeps that cost out of a single test's timeout budget.
const { loadTools } = require('../util/handleTools');

const TENANT = 'tenant-w14';
/**
 * Identity values are shaped the way the frozen CBHR-RPC-V2 core requires them: `grantId` is
 * canonical unpadded base64url of 16 bytes and `deviceKeyId` of 32, exactly as a real
 * `DeviceAuthority` row carries them. A hand-written placeholder would be refused by the envelope
 * layer for the wrong reason and would prove nothing about this tool.
 */
const GRANT_ID = 'EBESExQVFhcYGRobHB0eHw';
const DEVICE_KEY_ID = 'eBsXUXqHfJpRmak8ReOpt11QAUyjFQjaetmtzNS-IPw';
const PRINCIPAL = '64f0a1b2c3d4e5f60718293a';
const FOREIGN_PRINCIPAL = '64f0a1b2c3d4e5f60718293b';
const SESSION_DEVICE = '65a1b2c3d4e5f60718293b4c';
const FOREIGN_DEVICE = '65a1b2c3d4e5f60718293b4d';
const FOREIGN_TENANT = 'tenant-w14-foreign';
const EPOCH = 3;

const silentLogger = {
  warn: () => {},
  error: () => {},
  info: () => {},
  debug: () => {},
  log: () => {},
};

/** The session-owned device row, shaped as `DeviceAuthority` stores it. */
function rowFor(deviceId, ownerId, tenantId) {
  return {
    _id: { toString: () => deviceId },
    tenantId,
    ownerId,
    deviceKeyId: DEVICE_KEY_ID,
    grantId: GRANT_ID,
    epoch: EPOCH,
    leaseState: 'active',
    identityState: 'active',
  };
}

/** A mongoose-query stand-in: every chain the two read paths use ends at `.lean()`. */
function chainable(value, record, filter) {
  const chain = {
    readConcern: () => chain,
    select: () => chain,
    lean: async () => {
      record.push(filter);
      return value;
    },
  };
  return chain;
}

/**
 * The database and tenant-context seams. The resolver's query (`tenantId`/`ownerId`/state, no `_id`)
 * and this tool's re-read (`_id`/`tenantId`) are answered separately, so a lookup that named a
 * FOREIGN device id would visibly return the foreign row instead of failing quietly.
 */
function makeRealm({ device = 'session' } = {}) {
  const reads = [];
  const rows = {
    [SESSION_DEVICE]: rowFor(SESSION_DEVICE, PRINCIPAL, TENANT),
    [FOREIGN_DEVICE]: rowFor(FOREIGN_DEVICE, FOREIGN_PRINCIPAL, FOREIGN_TENANT),
  };
  const realm = {
    db: {
      DeviceAuthority: {
        findOne: (filter) => {
          const byId = Object.prototype.hasOwnProperty.call(filter, '_id');
          if (byId) {
            return chainable(rows[filter._id] ?? null, reads, filter);
          }
          return chainable(device === 'none' ? null : rows[SESSION_DEVICE], reads, filter);
        },
      },
    },
    tenantContext: { getActiveTenantId: () => TENANT, alsAbsencePermitted: false },
  };
  return { realm, reads };
}

/**
 * The authenticated request. Every request-supplied identity channel is populated with a FOREIGN
 * value, so a tool that read any of them would resolve the foreign device and be caught.
 */
function makeReq() {
  return {
    user: { id: PRINCIPAL, tenantId: TENANT },
    body: {
      deviceId: FOREIGN_DEVICE,
      ownerId: FOREIGN_PRINCIPAL,
      tenantId: FOREIGN_TENANT,
      deviceFloor: { enabled: ['write_file', 'start_process'] },
    },
    query: { deviceId: FOREIGN_DEVICE },
    params: { deviceId: FOREIGN_DEVICE },
    headers: { 'x-device-id': FOREIGN_DEVICE, 'x-owner-id': FOREIGN_PRINCIPAL },
  };
}

/** A custody seam that COUNTS signatures, so "nothing was signed" is a witnessed fact. */
function countedCustody() {
  const seam = makeCustodySeam(makeTestKeypair());
  const calls = { count: 0 };
  return {
    calls,
    surface: {
      keyId: seam.keyId,
      sign: async (canonicalBytes) => {
        calls.count += 1;
        return seam.sign(canonicalBytes);
      },
    },
  };
}

/**
 * Builds the tool over the real assembly, with a recording transport.
 * @param {object} [overrides]
 */
function build(overrides = {}) {
  const custody = overrides.custody === undefined ? countedCustody() : overrides.custody;
  const scripted =
    overrides.response === undefined
      ? { status: 200, body: { accepted: true } }
      : overrides.response;
  const hop = makeTransport(scripted);
  const { realm, reads } = makeRealm({ device: overrides.device ?? 'session' });

  const deviceTool = createDeviceCommandTool({
    req: overrides.req === undefined ? makeReq() : overrides.req,
    custody: custody === null ? null : (custody.surface ?? custody),
    transport: overrides.transport === undefined ? hop.transport : overrides.transport,
    replayWindow:
      overrides.replayWindow === undefined ? relay.createReplayWindow() : overrides.replayWindow,
    assembly: overrides.assembly ?? null,
    realm,
    resolveAuthority: overrides.resolveAuthority ?? null,
    env: overrides.env ?? {},
    logger: silentLogger,
    ...(overrides.extra ?? {}),
  });

  return {
    deviceTool,
    hop,
    calls: hop.calls,
    reads,
    custody,
    signCount: () => (custody !== null && custody.calls ? custody.calls.count : 0),
  };
}

/** Invokes the tool the way the model does (a tool-call shaped input) and parses the payload. */
async function invoke(deviceTool, input) {
  const raw = await deviceTool.invoke({
    name: DEVICE_COMMAND_TOOL_NAME,
    args: input,
    type: 'tool_call',
  });
  return { raw, payload: JSON.parse(raw) };
}

const READ_FILE_ARGS = { path: 'C:/notes/today.txt' };

describe('W14 — device_command: the AI-facing tool that reaches the employee’s PC', () => {
  describe('a real dispatch returns the DEVICE’s own outcome', () => {
    it('reports accepted, and only accepted, as success', async () => {
      const { deviceTool, calls, signCount } = build();
      const { payload } = await invoke(deviceTool, {
        tool: 'read_file',
        arguments: READ_FILE_ARGS,
      });

      expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.ACCEPTED);
      expect(payload.ok).toBe(true);
      expect(payload.status).toBe('success');
      // A stable payload shape the model can be told to read.
      expect(payload.schema).toBe(DEVICE_COMMAND_INPUT_SCHEMA);
      // The platform's own word for what happened, echoed rather than reinterpreted.
      expect(payload.delivered).toBe('accepted');
      expect(payload.tool).toBe('read_file');
      expect(payload.deviceId).toBe(SESSION_DEVICE);
      expect(typeof payload.requestId).toBe('string');
      // Acceptance is the dispatch path's verdict, never a claim that the PC finished the work.
      expect(payload.summary).toMatch(/accepted/i);
      expect(payload.summary).toMatch(/not a report that the tool finished/i);
      expect(payload.policy).toMatchObject({ evaluated: true, decision: 'allowed', stage: 'A' });
      // Exactly one frame left, and it was signed.
      expect(calls).toHaveLength(1);
      expect(signCount()).toBe(1);
    });

    it('carries the requested tool name and the exact argument bytes the PC re-hashes', async () => {
      const { deviceTool, calls } = build();
      await invoke(deviceTool, { tool: 'read_file', arguments: READ_FILE_ARGS });

      const { frame } = calls[0];
      expect(calls[0].deviceId).toBe(SESSION_DEVICE);
      expect(frame.toolName).toBe('read_file');
      const bytes = relay.decodeArgsB64u(frame.argsB64u);
      expect(bytes.toString('utf8')).toBe(JSON.stringify(READ_FILE_ARGS));
      expect(nodeCrypto.createHash('sha256').update(bytes).digest('hex')).toBe(frame.argsDigestHex);
      expect(frame.audience).toBe('endpoint');
    });

    it('sends an empty argument object when the model omits arguments', async () => {
      const { deviceTool, calls } = build();
      const { payload } = await invoke(deviceTool, { tool: 'list_directory' });
      expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.ACCEPTED);
      expect(relay.decodeArgsB64u(calls[0].frame.argsB64u).toString('utf8')).toBe('{}');
    });
  });

  describe('delivered:unknown is surfaced as UNKNOWN — never as success', () => {
    it('classifies a 5xx relay answer as unknown, and says the outcome is unknown', async () => {
      const { deviceTool, calls } = build({ response: { status: 503 } });
      const { payload } = await invoke(deviceTool, {
        tool: 'read_file',
        arguments: READ_FILE_ARGS,
      });

      expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.UNKNOWN);
      expect(payload.ok).toBe(false);
      expect(payload.status).toBe('warning');
      expect(payload.delivered).toBe('unknown');
      expect(payload.code).toBe('RELAY_DISPATCH_UNCERTAIN');
      expect(payload.summary).toMatch(/UNKNOWN/);
      expect(payload.summary).not.toMatch(/\baccepted\b/i);
      // The warning not to retry the same envelope blindly, with the fresh-nonce instruction.
      expect(payload.next_action).toMatch(/do NOT retry/i);
      expect(payload.next_action).toMatch(/NEW call/);
      expect(payload.next_action).toMatch(/nonce/);
      expect(payload.next_action).toMatch(/never report an unknown outcome as success/i);
      // The frame DID leave: unknown means "may have been delivered", not "not sent".
      expect(calls).toHaveLength(1);
    });

    it('classifies a transport throw as unknown too', async () => {
      const { deviceTool } = build({
        transport: async () => {
          throw new Error('relay hop unreachable');
        },
      });
      const { payload } = await invoke(deviceTool, { tool: 'read_file' });
      expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.UNKNOWN);
      expect(payload.ok).toBe(false);
      expect(payload.delivered).toBe('unknown');
    });

    it('classifies a malformed relay answer as unknown (the same law, another shape)', async () => {
      // A relay hop that answers with nothing usable: the client must classify, not assume.
      const { deviceTool } = build({ response: () => undefined });
      const { payload } = await invoke(deviceTool, { tool: 'read_file' });
      expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.UNKNOWN);
      expect(payload.ok).toBe(false);
    });

    it('is not vacuous: the SAME build reports success when the platform accepted', async () => {
      const { deviceTool } = build();
      const { payload } = await invoke(deviceTool, { tool: 'read_file' });
      expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.ACCEPTED);
      expect(payload.ok).toBe(true);
    });
  });

  describe('a refusal is surfaced with its code, and is never a success', () => {
    it.each([
      ['a 4xx relay answer', { status: 403 }, 'refused', 'RELAY_REJECTED'],
      [
        'a 2xx answer that explicitly refuses',
        { status: 200, body: { accepted: false } },
        'refused',
        'RELAY_REJECTED',
      ],
    ])('surfaces %s', async (_label, response, delivered, code) => {
      const { deviceTool } = build({ response });
      const { payload } = await invoke(deviceTool, { tool: 'read_file' });

      expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.REFUSED);
      expect(payload.ok).toBe(false);
      expect(payload.status).toBe('error');
      expect(payload.delivered).toBe(delivered);
      expect(payload.code).toBe(code);
      expect(payload.summary).toContain(code);
    });
  });

  describe('OWNER_APPROVAL_REQUIRED is a DISTINCT outcome', () => {
    const stageC = { [CAPABILITY_STAGE_ENV]: 'C' };

    it('reports approval-required — not a failure, not a success — and dispatches nothing', async () => {
      const { deviceTool, calls, signCount } = build({ env: stageC });
      const { payload } = await invoke(deviceTool, {
        tool: 'start_process',
        arguments: { command: 'notepad.exe' },
      });

      expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.APPROVAL_REQUIRED);
      expect(payload.outcome).not.toBe(DEVICE_COMMAND_OUTCOMES.REFUSED);
      expect(payload.outcome).not.toBe(DEVICE_COMMAND_OUTCOMES.ACCEPTED);
      expect(payload.ok).toBe(false);
      expect(payload.status).toBe('warning');
      expect(payload.code).toBe(DISPATCH_CODES.APPROVAL_REQUIRED);
      expect(payload.policy).toMatchObject({ requiresApproval: true, approved: false, tier: 3 });
      // An approval gate that did not open must not have touched the wire or the signer.
      expect(calls).toHaveLength(0);
      expect(signCount()).toBe(0);
    });

    it('treats an approval seam that answers false as approval-required, never as allowed', async () => {
      const { deviceTool, calls } = build({
        env: stageC,
        ...{ extra: { hasOwnerApproval: () => false } },
      });
      const { payload } = await invoke(deviceTool, { tool: 'start_process' });
      expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.APPROVAL_REQUIRED);
      expect(calls).toHaveLength(0);
    });

    it('executes only when the approval seam really approves (the non-vacuous control)', async () => {
      const { deviceTool, calls } = build({
        env: stageC,
        extra: { hasOwnerApproval: () => true },
      });
      const { payload } = await invoke(deviceTool, { tool: 'start_process' });
      expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.ACCEPTED);
      expect(payload.ok).toBe(true);
      expect(calls).toHaveLength(1);
    });

    it('names the four approval tools as data, never as a literal in this spec', () => {
      expect(OWNER_APPROVAL_TOOLS).toContain('start_process');
      expect(DISPATCH_CODES.APPROVAL_REQUIRED).toBe('OWNER_APPROVAL_REQUIRED');
    });
  });

  describe('an out-of-ceiling tool is refused by the EXISTING gate, and surfaced', () => {
    it('refuses write_file at stage A with the registry’s widening code', async () => {
      const { deviceTool, calls, signCount } = build({ env: {} });
      const { raw, payload } = await invoke(deviceTool, {
        tool: 'write_file',
        arguments: { path: 'C:/x' },
      });

      expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.REFUSED);
      expect(payload.ok).toBe(false);
      expect(payload.code).toBe(DISPATCH_CODES.OUTSIDE_SERVER_CEILING);
      expect(payload.delivered).toBe('no');
      expect(payload.policy).toMatchObject({ evaluated: true, decision: 'denied', stage: 'A' });
      // Surfaced, not swallowed: the code reaches the model in the text it reads.
      expect(raw).toContain(DISPATCH_CODES.OUTSIDE_SERVER_CEILING);
      // The gate runs before the clock, the nonce, the signer and the wire.
      expect(calls).toHaveLength(0);
      expect(signCount()).toBe(0);
    });

    it('refuses a law-denied name at the widest stage, and refuses an unknown name', async () => {
      const widest = build({ env: { [CAPABILITY_STAGE_ENV]: 'full' } });
      const lawDenied = await invoke(widest.deviceTool, { tool: 'track_ui_event' });
      expect(lawDenied.payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.REFUSED);
      expect(lawDenied.payload.code).toBe(DISPATCH_CODES.NOT_PERMITTED);
      expect(widest.calls).toHaveLength(0);

      const unknown = build({ env: { [CAPABILITY_STAGE_ENV]: 'full' } });
      const notATool = await invoke(unknown.deviceTool, { tool: 'rm_rf_everything' });
      expect(notATool.payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.REFUSED);
      expect(notATool.payload.code).toBe(DISPATCH_CODES.UNKNOWN);
      expect(unknown.calls).toHaveLength(0);
    });

    it('is not vacuous: read_file at the same stage IS admitted', async () => {
      const { deviceTool, calls } = build({ env: {} });
      const { payload } = await invoke(deviceTool, { tool: 'read_file' });
      expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.ACCEPTED);
      expect(calls).toHaveLength(1);
    });
  });

  describe('no custody configured: fail CLOSED, with no dispatch and no unsigned frame', () => {
    it('returns not-configured and never touches the transport, the signer or a client', async () => {
      const dispatchSpy = jest.fn();
      const { deviceTool, calls } = build({
        custody: null,
        assembly: { client: { dispatchCommand: dispatchSpy }, wiring: { policyArmed: true } },
      });
      const { raw, payload } = await invoke(deviceTool, {
        tool: 'read_file',
        arguments: READ_FILE_ARGS,
      });

      expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.NOT_CONFIGURED);
      expect(payload.ok).toBe(false);
      expect(payload.status).toBe('error');
      expect(payload.summary).toMatch(/custody/i);
      expect(payload.summary).toMatch(/[Nn]othing was signed/);
      expect(payload.next_action).toMatch(/do not dispatch/i);
      expect(calls).toHaveLength(0);
      expect(dispatchSpy).not.toHaveBeenCalled();
      expect(raw).not.toMatch(/"ok":\s*true/);
    });

    it('treats a custody provider that answers null, or throws, as unconfigured', async () => {
      for (const provider of [
        () => null,
        () => undefined,
        () => {
          throw new Error('custody store unreachable');
        },
      ]) {
        const { deviceTool, calls } = build({ custody: provider });
        const { payload } = await invoke(deviceTool, { tool: 'read_file' });
        expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.NOT_CONFIGURED);
        expect(calls).toHaveLength(0);
      }
    });

    it('never echoes key material or a custody error into the model’s payload', async () => {
      const secret = 'PRIVATE-KEY-MATERIAL-MUST-NOT-APPEAR';
      const { deviceTool, calls } = build({
        custody: {
          keyId: 'custody-key-w14',
          privateKey: secret,
          sign: async () => {
            throw new Error(`custody failure containing ${secret}`);
          },
        },
      });
      const { raw, payload } = await invoke(deviceTool, { tool: 'read_file' });

      // The signature failed before the wire: the platform refuses the call, and neither the key
      // material nor the custody error text is echoed to the model.
      expect(calls).toHaveLength(0);
      expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.REFUSED);
      expect(payload.ok).toBe(false);
      expect(payload.delivered).toBe('no');
      expect(payload.code).toBe('SIGNER_SEAM_INVALID');
      expect(raw).not.toContain(secret);
      expect(raw).not.toContain('custody failure');
      expect(JSON.stringify(payload)).not.toContain(secret);
    });

    it('fails closed when the relay hop itself is unconfigured', async () => {
      const { deviceTool, calls } = build({ transport: null });
      const { payload } = await invoke(deviceTool, { tool: 'read_file' });
      expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.NOT_CONFIGURED);
      expect(payload.summary).toMatch(/relay hop/i);
      expect(calls).toHaveLength(0);
    });
  });

  describe('identity comes from the SESSION: nothing supplied to the call can redirect it', () => {
    it('resolves the session’s own device and ignores request-supplied device/owner/tenant', async () => {
      const { deviceTool, calls, reads } = build();
      const { payload } = await invoke(deviceTool, {
        tool: 'read_file',
        arguments: READ_FILE_ARGS,
      });

      // 1. The trusted tuple the resolver is allowed to query: session principal + ALS tenant.
      const resolverQuery = reads[0];
      expect(resolverQuery).toMatchObject({
        tenantId: TENANT,
        ownerId: PRINCIPAL,
        leaseState: 'active',
        identityState: { $in: ['active', 'paired'] },
      });
      expect(JSON.stringify(resolverQuery)).not.toContain(FOREIGN_DEVICE);
      expect(JSON.stringify(resolverQuery)).not.toContain(FOREIGN_PRINCIPAL);
      expect(JSON.stringify(resolverQuery)).not.toContain(FOREIGN_TENANT);

      // 2. The re-read names the SERVER-RESOLVED device id, never a supplied one.
      expect(reads[1]).toMatchObject({ _id: SESSION_DEVICE, tenantId: TENANT });
      expect(reads.every((filter) => String(filter._id ?? '') !== FOREIGN_DEVICE)).toBe(true);

      // 3. What actually crossed the wire is the session identity.
      expect(payload.deviceId).toBe(SESSION_DEVICE);
      expect(calls[0].deviceId).toBe(SESSION_DEVICE);
      expect(calls[0].frame.deviceId).toBe(SESSION_DEVICE);
      expect(calls[0].frame.tenantId).toBe(TENANT);
      expect(calls[0].frame.ownerPrincipalId).toBe(PRINCIPAL);
      expect(JSON.stringify(calls[0].frame)).not.toContain(FOREIGN_DEVICE);
      expect(JSON.stringify(calls[0].frame)).not.toContain(FOREIGN_PRINCIPAL);
    });

    it('refuses to dispatch when the session holds no current active device', async () => {
      const { deviceTool, calls } = build({ device: 'none' });
      const { payload } = await invoke(deviceTool, { tool: 'read_file' });
      expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.NO_DEVICE);
      expect(payload.ok).toBe(false);
      expect(payload.deviceId).toBeNull();
      expect(payload.next_action).toMatch(/pair/i);
      expect(calls).toHaveLength(0);
    });

    it('does not fall back to a caller-supplied identity when the resolver declines', async () => {
      const seen = [];
      const { deviceTool, calls } = build({
        resolveAuthority: async ({ req }) => {
          seen.push(req);
          return null; // the platform's own answer: no usable session authority
        },
      });
      const { payload } = await invoke(deviceTool, {
        tool: 'read_file',
        arguments: { deviceId: FOREIGN_DEVICE, ownerId: FOREIGN_PRINCIPAL },
      });
      expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.NO_DEVICE);
      expect(calls).toHaveLength(0);
      expect(seen).toHaveLength(1);
    });
  });

  describe('the schema the model sees cannot choose a device or raise policy', () => {
    it('exposes exactly a tool name and an argument object', () => {
      expect(Object.keys(deviceCommandSchema.shape).sort()).toEqual(['arguments', 'tool']);
      // No identity, no policy, no stage, no ceiling, no approval.
      for (const forbidden of [
        'deviceId',
        'device_id',
        'ownerId',
        'tenantId',
        'principalId',
        'stage',
        'ceiling',
        'policy',
        'toolFloor',
        'deviceFloor',
        'approval',
        'hasOwnerApproval',
      ]) {
        expect(deviceCommandSchema.shape[forbidden]).toBeUndefined();
      }
    });

    it('REFUSES a call that names a device, a stage, a ceiling or an approval', () => {
      expect(deviceCommandSchema.safeParse({ tool: 'read_file' }).success).toBe(true);
      expect(
        deviceCommandSchema.safeParse({ tool: 'read_file', arguments: READ_FILE_ARGS }).success,
      ).toBe(true);
      for (const forged of [
        { tool: 'read_file', deviceId: FOREIGN_DEVICE },
        { tool: 'read_file', ownerId: FOREIGN_PRINCIPAL },
        { tool: 'read_file', tenantId: FOREIGN_TENANT },
        { tool: 'read_file', stage: 'full' },
        { tool: 'read_file', ceiling: { tools: ['write_file'] } },
        { tool: 'read_file', hasOwnerApproval: true },
        { tool: 'read_file', policy: { decision: 'allowed' } },
      ]) {
        const result = deviceCommandSchema.safeParse(forged);
        expect({ forged, success: result.success }).toEqual({ forged, success: false });
      }
    });

    it('rejects a forged identity at the tool boundary, without dispatching', async () => {
      const { deviceTool, calls } = build();
      await expect(
        deviceTool.invoke({ args: { tool: 'read_file', deviceId: FOREIGN_DEVICE } }),
      ).rejects.toThrow(/did not match expected schema/);
      expect(calls).toHaveLength(0);
    });

    it('is the schema the model actually receives, with an honest description', () => {
      const { deviceTool } = build();
      expect(deviceTool.name).toBe(DEVICE_COMMAND_TOOL_NAME);
      expect(deviceTool.schema).toBe(deviceCommandSchema);
      expect(typeof deviceTool.description).toBe('string');
      // Every supported name is discoverable, from the catalog DATA rather than a second list.
      for (const name of SUPPORTED_TOOL_NAMES) {
        expect(deviceTool.description).toContain(name);
      }
      expect(SUPPORTED_TOOL_NAMES).toEqual(TOOL_CATALOG.map((entry) => entry.name));
      // The description states the honesty contract the payload enforces.
      expect(deviceTool.description).toMatch(/unknown/i);
      expect(deviceTool.description).toMatch(/approval-required/i);
      expect(deviceTool.description).toMatch(/session/i);
    });
  });

  describe('registration: the model can actually be given this tool', () => {
    it('loadTools resolves the device_command key to a real tool for the session', async () => {
      // The registration edit is one import and one entry in `handleTools.js`; this asserts the
      // EFFECT of that entry — the loader hands back a constructible device tool — rather than the
      // shape of a diff, so removing the entry breaks a test instead of a customer.
      const toolMap = await loadTools({
        user: PRINCIPAL,
        tools: [DEVICE_COMMAND_TOOL_NAME],
        returnMap: true,
        options: { req: makeReq() },
      });

      expect(Object.keys(toolMap)).toEqual([DEVICE_COMMAND_TOOL_NAME]);
      const loaded = await toolMap[DEVICE_COMMAND_TOOL_NAME]();
      expect(loaded.name).toBe(DEVICE_COMMAND_TOOL_NAME);
      expect(loaded.schema).toBe(deviceCommandSchema);
      // Registered but UNCONFIGURED: the registration must not silently dispatch. With no custody
      // configured, invoking it fails closed rather than sending an unsigned frame.
      const { payload } = await invoke(loaded, { tool: 'read_file' });
      expect(payload.outcome).toBe(DEVICE_COMMAND_OUTCOMES.NOT_CONFIGURED);
    });
  });
});
