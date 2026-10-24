'use strict';

/**
 * `device_command` — THE AI-FACING TOOL THAT REACHES THE EMPLOYEE'S OWN COMPUTER (W14).
 *
 * LOCAL LAB ONLY. Production G0 remains BLOCKED; nothing here changes that.
 *
 * WHY THIS FILE EXISTS
 * The dispatch side was already built and proven: `dispatchAssembly` arms the policy gate,
 * `relayDispatchClient.dispatchCommand` mints, signs and classifies one frame, and the relay/ledger
 * code correlates results. Nothing under `api/app/clients/tools/` mentioned any of it, so a user
 * could not ask the AI to do anything on their PC — the loop was reachable only from a test. This
 * module is that missing consumer, and it is the ONLY thing it is: it invokes the assembly and
 * `dispatchCommand`; it never re-implements, re-checks or anticipates what they decide.
 *
 * THE ONE ASSEMBLY POINT IS USED, AND POLICY IS NOT RE-CHECKED HERE (GM-83, W14 requirement 5)
 * The client comes from `createDeviceDispatchAssembly` — the single production assembly — which
 * supplies the armed policy port. The gate runs inside `dispatchCommand`, before anything is signed.
 * A second check in this file would be a second vocabulary that drifts from the registry's, so there
 * is none: an out-of-ceiling tool, a law-denied tool, a tool switched off by the issued policy and a
 * non-existent tool name all arrive here as the registry's own refusal, and are surfaced verbatim.
 *
 * IDENTITY COMES FROM THE SESSION AND NOWHERE ELSE
 * `defaultResolveAuthority` uses the existing device services exactly as the accepted `GET
 * /api/devices/current` handler does: `createCurrentOwnerDeviceResolver` (the trusted tuple
 * `{tenantId, ownerId:<authenticated principal>, identityState ∈ {active,paired}, leaseState:'active'}`)
 * re-read from the server-observed `DeviceAuthority` row, projected by
 * `trustedAuthorityFromDeviceRow`. The model's tool input carries a tool name and arguments and
 * NOTHING ELSE — the schema is strict, so a device id, an owner id, a tenant or a stage in the call
 * is refused rather than silently ignored — and no request field is ever read: there is no code path
 * in this file that reads `req.body`, `req.query`, `req.params` or the tool input for identity.
 *
 * KEY CUSTODY IS AN OWNER DECISION THAT IS UNMADE, SO THIS TOOL FAILS CLOSED WITHOUT IT
 * `sign`/`keyId` arrive only through an INJECTED custody seam, handed to the assembly exactly as
 * `createEnvelopeSigner` requires `{ sign, keyId }`. This file never generates, reads, stores, logs
 * or echoes key material, and a caught custody/assembly error is never re-emitted (an error object
 * from a custody implementation could carry key material). With no custody configured the tool
 * returns `not-configured` WITHOUT building a client, signing anything or touching the transport:
 * the unconfigured state is the current state, and it must never become an unsigned frame.
 *
 * OUTCOME HONESTY (F-V24C-9; W14 requirement 6 — the whole point of this file)
 * The model is told what the platform decided, in the platform's own words:
 *   accepted          `delivered: 'accepted'` — the platform's dispatch path took the call. This is
 *                     the ONLY outcome reported as success (`ok: true`). It is acceptance by the
 *                     relay hop, not a report that the tool finished on the PC.
 *   unknown           `delivered: 'unknown'` — the frame may have been delivered and may have
 *                     executed. NEVER a success, never "done": the summary says so, and the
 *                     next_action forbids a blind retry of the same call (a retry is a NEW call with
 *                     a fresh nonce, and the user must be told the outcome is unknown first).
 *   refused           the relay refused the frame (`delivered: 'refused'`), or the platform refused
 *                     it before the wire (`delivered: 'no'`) — reported with the platform's code.
 *   approval-required `OWNER_APPROVAL_REQUIRED`: a DISTINCT outcome, never a failure and never a
 *                     success. The tool was admissible and enabled, and did not execute because the
 *                     owner has not approved that call (tier 3).
 *   no-device         the authenticated principal holds no current active device.
 *   not-configured    no custody (or no usable transport) is configured server-side.
 * An uncertainty is never paraphrased into a success anywhere in this file: `classifyDispatch`
 * reads `delivered` first, and only an exact `accepted` can reach the success class.
 *
 * WHAT IS NOT WIRED YET, DISCLOSED RATHER THAN FAKED
 * The relay HTTP hop (a `transport`) and the durable replay window are integration choices that the
 * relay's own route has not frozen; this tool therefore takes them as injected seams and fails
 * closed with `not-configured` when they are absent, exactly as it does for custody. Nothing here
 * invents a relay URL, a payload canonicalisation or a retry policy.
 *
 * The registration entry in `handleTools.js` forwards `options.deviceCommand` (spread FIRST, so the
 * session `req` cannot be overridden from it) and nothing else. A deployment — or a spec — therefore
 * wires this tool by passing `{ custody, transport, replayWindow, ledger, resolvePolicy,
 * hasOwnerApproval }` in that bag; with the bag absent the tool is visible to the model and answers
 * honestly that it is not configured. That is the current state, because key custody is unmade.
 */

const nodeCrypto = require('node:crypto');
const { z } = require('zod');
const { tool } = require('@librechat/agents/langchain/tools');
const { getTenantId } = require('@librechat/data-schemas');
const db = require('~/db/models');
const relay = require('~/server/services/Device/relay');
const { createDeviceDispatchAssembly } = require('~/server/services/Device/dispatchAssembly');
const {
  TOOL_CATALOG,
  OWNER_APPROVAL_TOOLS,
} = require('~/server/services/Device/deviceCapabilityPolicy');
const { DISPATCH_CODES } = require('~/server/services/Device/deviceToolRegistry');
const {
  createCurrentOwnerDeviceResolver,
} = require('~/server/services/Device/currentOwnerDeviceResolver');

/** The tool name the model calls. One name; the device tool is an argument. */
const DEVICE_COMMAND_TOOL_NAME = 'device_command';

/** The argument schema id the model's call is judged against. */
const DEVICE_COMMAND_INPUT_SCHEMA = 'cbhr.rdc.device-command-input/1';

/**
 * The outcome classes the model can receive. A small, closed vocabulary: every dispatch outcome
 * maps onto exactly one of these, so the model never has to infer from prose whether something
 * happened. `accepted` is the only class that can carry `ok: true`.
 */
const DEVICE_COMMAND_OUTCOMES = Object.freeze({
  /** `delivered: 'accepted'` — the platform's dispatch path took the call. */
  ACCEPTED: 'accepted',
  /** `delivered: 'refused'` or `'no'` — refused, with the platform's own code. */
  REFUSED: 'refused',
  /** Tier-3 admission whose owner approval was not established: admissible, not executed. */
  APPROVAL_REQUIRED: 'approval-required',
  /** `delivered: 'unknown'` — delivery could not be established. Never a success. */
  UNKNOWN: 'unknown',
  /** The authenticated principal holds no current active device. */
  NO_DEVICE: 'no-device',
  /** No custody (or no usable transport) is configured server-side: nothing was signed or sent. */
  NOT_CONFIGURED: 'not-configured',
  /** The dispatch call itself threw outside the client's typed outcomes: nothing is claimed. */
  FAILED: 'failed',
});

/** The supported tool names, as DATA (GM-76: the catalog is data, never a literal here). */
const SUPPORTED_TOOL_NAMES = Object.freeze(TOOL_CATALOG.map((entry) => entry.name));

/** The registry's own code for the tier-3 outcome, read from the registry and never restated. */
const APPROVAL_REQUIRED_CODE = DISPATCH_CODES.APPROVAL_REQUIRED;

/** Fixed, payload-free text — no identity, no arguments, no key material. */
const FIXED_MESSAGES = Object.freeze({
  /** Custody absent. The unconfigured state must not become an unsigned frame. */
  CUSTODY_ABSENT:
    'Not dispatched: this server has no device signing-key custody configured, so no command frame ' +
    'can be signed. Nothing was signed, reserved or sent to the PC.',
  CUSTODY_ABSENT_NEXT:
    'Tell the user that reaching their computer is unavailable until the deployment configures device ' +
    'signing custody. Do not dispatch, and do not retry as if the call had failed.',
  /** Transport/replay absent: the same class of unconfigured seam, on the hop side. */
  HOP_ABSENT:
    'Not dispatched: the relay hop (transport and replay window) is not configured on this server, so ' +
    'no frame can leave the process. Nothing was signed or sent.',
  HOP_ABSENT_NEXT:
    'Tell the user that reaching their computer is unavailable until the relay hop is configured. Do ' +
    'not retry.',
  /** No device: the session has no active leased device. */
  NO_DEVICE:
    'Not dispatched: the authenticated user holds no current active device, so there is no PC to run ' +
    'this on. Nothing was sent.',
  NO_DEVICE_NEXT:
    'Ask the user to pair their PC (an expired 48-hour lease needs a fresh pairing code) and try again ' +
    'afterwards. Do not retry until they confirm the PC is connected.',
  /** Unknown outcome: the load-bearing honesty case. */
  UNKNOWN:
    'OUTCOME UNKNOWN: the frame may have reached the PC and the tool may have executed. The platform ' +
    'could not establish delivery, so this is NOT a success and NOT a failure.',
  UNKNOWN_NEXT:
    'Tell the user the outcome is unknown before doing anything else. Do NOT retry this call blindly ' +
    'and do not report it as done: a retry would be a NEW call (a fresh envelope and nonce), and the ' +
    'user has to accept the risk of running it twice.',
  UNKNOWN_SUMMARY_SUFFIX: 'Never report an unknown outcome as success.',
  /** Approval withheld: distinct from both failure and success. */
  APPROVAL_REQUIRED:
    'NOT EXECUTED — OWNER APPROVAL REQUIRED: the tool is inside the server ceiling and enabled, but ' +
    'this tool always needs the owner\u2019s explicit approval for each call, and that approval was not ' +
    'established. Nothing was signed or sent.',
  APPROVAL_REQUIRED_NEXT:
    'Tell the user this action needs their explicit approval on this call and ask them to approve it, ' +
    'then call again. Do not report it as failed, and do not report it as done.',
});

/** A stylised no-op logger, so an absent logger never turns into a console write of its own. */
const NO_LOGGER = Object.freeze({
  warn: () => {},
  error: () => {},
  info: () => {},
  debug: () => {},
});

function isNonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

/**
 * The tool's argument schema AS THE MODEL SEES IT.
 *
 * It carries a tool name and an argument object, and that is all: there is deliberately no device,
 * tenant, owner, stage, ceiling or policy parameter, because identity is resolved from the session
 * and the ceiling is server data (GM-76, GM-79). `.strict()` makes that a REFUSAL rather than a
 * silent drop: a call that names a device or tries to set a policy fails validation instead of
 * appearing to have been honoured.
 */
const deviceCommandSchema = z
  .object({
    tool: z
      .string()
      .min(1)
      .describe(
        `The exact name of the device tool to run on the user's PC (one of: ${SUPPORTED_TOOL_NAMES.join(
          ', ',
        )}). Names outside the supported set are refused by the server policy gate.`,
      ),
    arguments: z
      .record(z.any())
      .optional()
      .describe(
        'The argument object that device tool expects, for example {"path":"C:\\\\notes\\\\today.txt"}. ' +
          'It is transported as the exact argument bytes the PC verifies against the signed digest; ' +
          'omit it for a tool that takes no arguments.',
      ),
  })
  .strict();

/**
 * Projects the injected custody seam to EXACTLY `{ sign, keyId }`, or `null` when custody is not
 * configured.
 *
 * `custody` may be the surface itself or a provider function (so a deployment can decide custody
 * lazily). A provider that throws, or a surface that is not `{ sign, keyId }`, is NOT CONFIGURED:
 * fail closed. Nothing here reads, copies, stores or logs key material, and the caught error is
 * deliberately discarded rather than re-emitted.
 *
 * @param {object|Function|null} custody
 * @returns {{sign: Function, keyId: string}|null}
 */
function resolveCustodySeam(custody) {
  let surface = custody;
  if (typeof custody === 'function') {
    try {
      surface = custody();
    } catch {
      return null;
    }
  }
  if (surface === null || typeof surface !== 'object') {
    return null;
  }
  if (typeof surface.sign !== 'function' || !isNonEmptyString(surface.keyId)) {
    return null;
  }
  // Only the two seam keys travel on; an extra key on the custody surface never reaches anything.
  return { sign: surface.sign, keyId: surface.keyId };
}

/** A ciphertext-free, identity-free compression of the platform's policy block. */
function policySummary(policy) {
  if (policy === null || typeof policy !== 'object') {
    return null;
  }
  return {
    evaluated: policy.evaluated === true,
    decision: policy.decision ?? null,
    stage: policy.stage ?? null,
    code: policy.code ?? null,
    tier: policy.tier ?? null,
    requiresApproval: policy.requiresApproval === true,
    approved: policy.approved ?? null,
    reasonCode: policy.reasonCode ?? null,
  };
}

/**
 * Maps a `dispatchCommand` outcome onto the closed outcome vocabulary, honestly.
 *
 * Order is deliberate: `delivered: 'unknown'` is classified BEFORE anything that could read as
 * success, and the approval case is classified before the generic refusal so a tier-3 admission is
 * never reported as a failure or as a success.
 *
 * @param {object} outcome the dispatch client's outcome
 * @param {string} toolName the requested device tool
 * @returns {object} the model-facing payload
 */
function classifyDispatch(outcome, toolName) {
  const policy = policySummary(outcome.policy);
  const base = {
    schema: DEVICE_COMMAND_INPUT_SCHEMA,
    tool: toolName,
    deviceId: outcome.deviceId ?? null,
    requestId: outcome.requestId ?? null,
    delivered: outcome.delivered ?? null,
    code: outcome.code ?? null,
    retryable: outcome.retryable === true,
    policy,
  };

  if (outcome.delivered === DEVICE_COMMAND_OUTCOMES.UNKNOWN) {
    return {
      ...base,
      outcome: DEVICE_COMMAND_OUTCOMES.UNKNOWN,
      status: 'warning',
      ok: false,
      summary: FIXED_MESSAGES.UNKNOWN,
      next_action: `${FIXED_MESSAGES.UNKNOWN_NEXT} ${FIXED_MESSAGES.UNKNOWN_SUMMARY_SUFFIX}`,
    };
  }

  const approvalWithheld =
    (policy !== null && policy.requiresApproval && policy.approved !== true) ||
    outcome.code === APPROVAL_REQUIRED_CODE;
  if (approvalWithheld && outcome.ok !== true) {
    return {
      ...base,
      outcome: DEVICE_COMMAND_OUTCOMES.APPROVAL_REQUIRED,
      status: 'warning',
      ok: false,
      summary: FIXED_MESSAGES.APPROVAL_REQUIRED,
      next_action: FIXED_MESSAGES.APPROVAL_REQUIRED_NEXT,
    };
  }

  if (outcome.ok === true && outcome.delivered === DEVICE_COMMAND_OUTCOMES.ACCEPTED) {
    return {
      ...base,
      outcome: DEVICE_COMMAND_OUTCOMES.ACCEPTED,
      status: 'success',
      ok: true,
      summary:
        `The platform accepted this call for the user's PC (delivered: accepted${
          Number.isInteger(outcome.status) ? `, relay status ${outcome.status}` : ''
        }). Acceptance is the platform's own verdict on the dispatch; it is not a report that the ` +
        'tool finished on the PC.',
      next_action:
        'Report the acceptance as acceptance. Do not claim the tool finished on the PC unless the ' +
        'platform reports a result for this call.',
    };
  }

  return {
    ...base,
    outcome: DEVICE_COMMAND_OUTCOMES.REFUSED,
    status: 'error',
    ok: false,
    summary: `Refused by the platform${
      outcome.delivered === DEVICE_COMMAND_OUTCOMES.REFUSED
        ? ' (the relay refused the frame)'
        : ' before anything was signed or sent'
    }${base.code === null ? '' : `: ${base.code}`}.`,
    next_action:
      'Report the refusal and its code to the user, and do not retry the same call: the platform ' +
      'decided against it.',
  };
}

/** The custody-absent payload. Nothing was signed; nothing may be dispatched from here. */
function custodyAbsentPayload(toolName) {
  return {
    schema: DEVICE_COMMAND_INPUT_SCHEMA,
    outcome: DEVICE_COMMAND_OUTCOMES.NOT_CONFIGURED,
    status: 'error',
    ok: false,
    tool: toolName,
    deviceId: null,
    requestId: null,
    delivered: null,
    code: null,
    retryable: false,
    policy: null,
    summary: FIXED_MESSAGES.CUSTODY_ABSENT,
    next_action: FIXED_MESSAGES.CUSTODY_ABSENT_NEXT,
  };
}

/** The unconfigured-hop payload (transport and/or replay window absent). */
function hopAbsentPayload(toolName) {
  return {
    schema: DEVICE_COMMAND_INPUT_SCHEMA,
    outcome: DEVICE_COMMAND_OUTCOMES.NOT_CONFIGURED,
    status: 'error',
    ok: false,
    tool: toolName,
    deviceId: null,
    requestId: null,
    delivered: null,
    code: null,
    retryable: false,
    policy: null,
    summary: FIXED_MESSAGES.HOP_ABSENT,
    next_action: FIXED_MESSAGES.HOP_ABSENT_NEXT,
  };
}

/** The no-device payload: the session resolved to no current active device. */
function noDevicePayload(toolName) {
  return {
    schema: DEVICE_COMMAND_INPUT_SCHEMA,
    outcome: DEVICE_COMMAND_OUTCOMES.NO_DEVICE,
    status: 'error',
    ok: false,
    tool: toolName,
    deviceId: null,
    requestId: null,
    delivered: null,
    code: null,
    retryable: false,
    policy: null,
    summary: FIXED_MESSAGES.NO_DEVICE,
    next_action: FIXED_MESSAGES.NO_DEVICE_NEXT,
  };
}

/**
 * The production realm: the models and the trusted ALS tenant context, wired exactly as
 * `routes/devices.js` wires them. Injected by tests and by any caller that composes its own realm.
 */
function defaultRealm() {
  return {
    db,
    tenantContext: Object.freeze({ getActiveTenantId: getTenantId, alsAbsencePermitted: false }),
  };
}

/**
 * Resolves the caller's OWN current device from the SESSION, through the existing device services.
 *
 * Inputs are server truth only: the authenticated `req.user` and the trusted ALS tenant. A request
 * body, query, param or the model's tool input cannot reach this function — there is no parameter
 * for them. Isolation is enforced twice: the resolver's tenant-agreement check, then the row-level
 * `tenantId`/`ownerId`/`_id` equality, then the relay's own `trustedAuthorityFromDeviceRow` guard.
 *
 * @returns {Promise<Readonly<object>|null>} the authority projection, or null when there is none
 */
async function resolveAuthorityFromSession({ req, realm, logger }) {
  const resolver = createCurrentOwnerDeviceResolver({
    db: realm.db,
    tenantContext: realm.tenantContext,
  });
  const resolved = await resolver.resolveCurrentOwnerDevice({
    authenticatedUser: req?.user,
    logger: logger ?? undefined,
  });
  if (resolved === null) {
    return null;
  }

  let row;
  try {
    row = await realm.db.DeviceAuthority.findOne({
      _id: resolved.deviceId,
      tenantId: resolved.tenantId,
    })
      .readConcern('majority')
      .lean();
  } catch {
    return null;
  }
  const deviceId = row?._id?.toString?.();
  if (
    row === null ||
    row === undefined ||
    row.tenantId !== resolved.tenantId ||
    row.ownerId !== resolved.principalId ||
    deviceId !== resolved.deviceId
  ) {
    return null;
  }
  return relay.trustedAuthorityFromDeviceRow({
    row,
    tenantId: resolved.tenantId,
    ownerPrincipalId: resolved.principalId,
  });
}

/**
 * Builds the AI-facing device tool.
 *
 * Every seam is injected: `custody` and the relay `transport` are the two the owner/deployment has
 * not chosen (custody is an OWNER decision; the hop's route is an integration choice), and both fail
 * closed when absent. `assembly` allows a caller to REUSE an already-assembled
 * `{ client, wiring }` from `createDeviceDispatchAssembly`; otherwise this instance builds through
 * that same assembly once, lazily, on the first admissible call.
 *
 * @param {object} [options]
 * @param {object} [options.req] the authenticated server request — the ONLY identity source
 * @param {object|Function|null} [options.custody] the injected `{ sign, keyId }` custody seam
 * @param {Function|null} [options.transport] the injected relay hop: `({deviceId, frame}) => {status, body}`
 * @param {object|null} [options.replayWindow] the injected replay window (`createReplayWindow()`)
 * @param {object|null} [options.ledger] optional dispatch-ledger seam, passed through unchanged
 * @param {object|Function|null} [options.resolvePolicy] optional narrowing resolver (the W10 seam)
 * @param {Function|null} [options.hasOwnerApproval] optional tier-3 approval seam
 * @param {{client: object, wiring: object}|null} [options.assembly] an already-assembled dispatch
 * @param {{db: object, tenantContext: object}|null} [options.realm] models + trusted tenant context
 * @param {Function|null} [options.resolveAuthority] identity seam; defaults to the session resolver
 * @param {object} [options.env] environment read for the server capability stage
 * @param {object} [options.logger] fixed-message-only warn sink for the assembly
 * @returns {import('@librechat/agents/langchain/tools').Tool}
 */
function createDeviceCommandTool(options = {}) {
  const {
    req = null,
    custody = null,
    transport = null,
    replayWindow = null,
    ledger = null,
    resolvePolicy = null,
    hasOwnerApproval = null,
    assembly = null,
    realm = null,
    resolveAuthority = null,
    env = process.env,
    logger = null,
  } = options;

  const resultDb = realm ?? defaultRealm();

  /** Built once, lazily, and reused; an injected assembly is preferred over building one. */
  let built = assembly ?? null;

  function clientFor(custodySeam) {
    if (built !== null) {
      return built;
    }
    built = createDeviceDispatchAssembly({
      sign: custodySeam.sign,
      keyId: custodySeam.keyId,
      transport,
      replayWindow,
      ...(ledger ? { ledger } : {}),
      ...(typeof resolvePolicy === 'function' ? { resolvePolicy } : {}),
      ...(typeof hasOwnerApproval === 'function' ? { hasOwnerApproval } : {}),
      env,
      logger: logger ?? NO_LOGGER,
    });
    return built;
  }

  async function identityFor() {
    if (typeof resolveAuthority === 'function') {
      try {
        return await resolveAuthority({ req, realm: resultDb });
      } catch {
        return null;
      }
    }
    try {
      return await resolveAuthorityFromSession({ req, realm: resultDb, logger });
    } catch {
      return null;
    }
  }

  return tool(
    async (input) => {
      const toolName = input.tool;
      const argsBytes = Buffer.from(JSON.stringify(input.arguments ?? {}), 'utf8');

      // 1. CUSTODY. An unconfigured custody seam is the current state of this deployment, so it is
      //    checked FIRST and it ends the call here: no client, no signature, no frame.
      const custodySeam = resolveCustodySeam(custody);
      if (custodySeam === null) {
        return JSON.stringify(custodyAbsentPayload(toolName), null, 2);
      }

      // 2. THE HOP. The same fail-closed rule for the seams the relay's own route has not frozen.
      if (typeof transport !== 'function' || replayWindow === null || replayWindow === undefined) {
        return JSON.stringify(hopAbsentPayload(toolName), null, 2);
      }

      // 3. IDENTITY, from the authenticated session and the trusted tenant only.
      const authority = await identityFor();
      if (authority === null || authority === undefined) {
        return JSON.stringify(noDevicePayload(toolName), null, 2);
      }

      // 4. THE ONE DISPATCH PATH, through the assembled client. Policy is decided inside
      //    `dispatchCommand`; this file does not restate, pre-empt or second-guess it.
      let outcome;
      try {
        const { client } = clientFor(custodySeam);
        outcome = await client.dispatchCommand({
          authority,
          toolName,
          opKind: 'command',
          argsBytes,
          callId: `cbhr-tool-${nodeCrypto.randomUUID()}`,
        });
      } catch (err) {
        // The client returns typed outcomes for every expected failure, so reaching here is a
        // defect. Nothing is claimed: no success, no delivery, and the thrown text is not echoed.
        return JSON.stringify(
          {
            schema: DEVICE_COMMAND_INPUT_SCHEMA,
            outcome: DEVICE_COMMAND_OUTCOMES.FAILED,
            status: 'error',
            ok: false,
            tool: toolName,
            deviceId: null,
            requestId: null,
            delivered: null,
            code: isNonEmptyString(err?.code) ? err.code : null,
            retryable: false,
            policy: null,
            summary:
              'The dispatch call could not be completed, so nothing is known about what happened on ' +
              'the PC. Nothing was reported as done.',
            next_action:
              'Report that the call could not be completed. Do not report success, and do not retry ' +
              'before checking with the user.',
          },
          null,
          2,
        );
      }

      return JSON.stringify(classifyDispatch(outcome, toolName), null, 2);
    },
    {
      name: DEVICE_COMMAND_TOOL_NAME,
      description:
        "Runs one Desktop Commander tool on the user's OWN paired computer and reports the " +
        'platform\u2019s own verdict for that call. The device is the one leased to the authenticated ' +
        'session, so this call cannot name a device, a tenant, an owner or a policy: the tool name is ' +
        `an argument and nothing else. Supported tool names: ${SUPPORTED_TOOL_NAMES.join(', ')}; any ` +
        'other name is refused by the server policy gate. Whether a tool is currently allowed is ' +
        'decided server-side at dispatch time, so a refusal here is the platform\u2019s decision, not a ' +
        `guess. Owner-approval tools (${OWNER_APPROVAL_TOOLS.join(
          ', ',
        )}) never execute silently: they are reported as "approval-required" until the owner approves ` +
        'that call. Report what this tool returns exactly as it returns it: "accepted" means the ' +
        'platform\u2019s dispatch path accepted the call, "refused" carries the platform\u2019s refusal ' +
        'code, and "unknown" means delivery could not be established \u2014 an unknown outcome is never a ' +
        'success and must not be reported as one.',
      schema: deviceCommandSchema,
    },
  );
}

module.exports = {
  DEVICE_COMMAND_TOOL_NAME,
  DEVICE_COMMAND_INPUT_SCHEMA,
  DEVICE_COMMAND_OUTCOMES,
  SUPPORTED_TOOL_NAMES,
  deviceCommandSchema,
  classifyDispatch,
  resolveCustodySeam,
  resolveAuthorityFromSession,
  createDeviceCommandTool,
};
