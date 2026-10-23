'use strict';

/**
 * CBHR ENDPOINT AGENT — the agent core (workstream W7).
 *
 * One function does the whole job: `handleFrame(frame)` takes a flat `CBHR-RPC-V2` frame exactly as it
 * came off the socket and returns a device-signed result frame. Everything between those two points is
 * the argument this workstream exists to complete:
 *
 *   verify (own implementation, own codes)  ->  dispatch (ceiling ∩ floor)  ->  execute  ->  sign
 *
 * TWO INVARIANTS THE SHAPE OF THIS FILE ENFORCES
 *
 * 1. NOTHING EXECUTES BEFORE VERIFICATION COMPLETES. `execute` is reachable only from the single
 *    `ok: true` branch below, after the durable nonce reservation. There is no "best effort" path,
 *    no execute-then-check, and no branch that runs a tool on an unverified frame.
 *
 * 2. A RESULT IS NEVER REPORTED AS SUCCESS UNLESS IT WAS ONE. Three shapes exist:
 *      - refused   : a verification or policy refusal, nothing ran            -> outcome 'refused'
 *      - succeeded : the tool returned                                -> outcome 'succeeded'
 *      - uncertain : the tool threw, or the result could not be persisted     -> outcome 'uncertain'
 *    The `uncertain` branch is what stops "the agent crashed mid-execution" from reaching the platform
 *    as a success, and the outcome string is INSIDE the signature, so the relay cannot re-label it.
 *
 * DEVICE IDENTITY. `deviceId` must be the server-issued id for this endpoint (GM-33: it is not the
 * trust anchor — `deviceKeyId` is — but a command addressed to another device is refused here anyway,
 * per F-V24C-5's endpoint checks). It is stored in `device.json` in the agent root, written when the
 * agent is initialised, and it is a PUBLIC identifier: it is safe to log.
 */

const fs = require('node:fs');
const path = require('node:path');

const { refusal, isEndpointRefusal, describeRefusal } = require('./errors');
const { coreFromFrame, FIELD_ORDER } = require('./layout');
const { verifyCommandFrame, describeVerificationOrder } = require('./verify');
const { loadCeilingSnapshot, defaultSnapshotPath } = require('./ceiling');
const { loadDeviceToolConfig } = require('./deviceConfig');
const { createDispatcher } = require('./dispatch');
const { loadPinnedBackendKeys } = require('./pinnedKeys');
const { loadDeviceKeystore, resolveRootDir } = require('./keystore');
const { createDurableReplayWindow } = require('./replayWindow');
const { writeOwnerOnlyFile } = require('./permissions');
const { buildResultFrame, OUTCOMES } = require('./resultFrame');
const { resolveWorkspaceRoot, describeTools } = require('./tools');

/** The device identity file. PUBLIC data only: the server-issued id and the local epoch label. */
function defaultDeviceFile(rootDir) {
  return path.join(rootDir ?? resolveRootDir(), 'device.json');
}

/**
 * Reads (or initialises) this endpoint's device identity.
 * @param {object} [options]
 * @param {string} [options.rootDir]
 * @param {string} [options.deviceId] the server-issued id to record
 * @returns {{deviceId: string, file: string, created: boolean}}
 */
function loadDeviceIdentity(options = {}) {
  const file = options.deviceFile ?? defaultDeviceFile(options.rootDir);
  if (!fs.existsSync(file)) {
    const deviceId = typeof options.deviceId === 'string' && options.deviceId.length > 0 ? options.deviceId : null;
    if (deviceId === null) {
      throw refusal(
        'ENDPOINT_DEVICE_MISMATCH',
        'this endpoint has no recorded device id yet; initialise it with the server-issued id before frames can be accepted',
        { field: 'deviceId' },
      );
    }
    writeOwnerOnlyFile(file, `${JSON.stringify({ version: 1, deviceId, createdAt: new Date().toISOString() }, null, 2)}\n`);
    return { deviceId, file, created: true };
  }
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    throw refusal('ENDPOINT_DEVICE_MISMATCH', 'the recorded device identity is not valid JSON', {
      field: 'deviceId',
      cause: err,
    });
  }
  if (parsed === null || typeof parsed !== 'object' || typeof parsed.deviceId !== 'string' || parsed.deviceId.length === 0) {
    throw refusal('ENDPOINT_DEVICE_MISMATCH', 'the recorded device identity has no usable device id', {
      field: 'deviceId',
    });
  }
  return { deviceId: parsed.deviceId, file, created: false };
}

/**
 * Creates the agent. All policy inputs are materialized here, once: a running agent cannot have its
 * ceiling, its floor or its pin set changed by anything arriving on the wire.
 *
 * @param {object} [options]
 * @param {string} [options.rootDir] the agent root; defaults to `~/.cbhr/endpoint-agent`
 * @param {string} [options.deviceId] required on first use; recorded to `device.json`
 * @param {string} [options.snapshotPath] the server ceiling snapshot
 * @param {() => number} [options.now] injected clock
 * @param {boolean} [options.persistReplay] false keeps the replay window in memory (reference only)
 * @param {string} [options.workspaceRoot] the tool containment root
 * @returns {Readonly<object>}
 */
function createEndpointAgent(options = {}) {
  const rootDir = resolveRootDir(options.rootDir);
  const now = typeof options.now === 'function' ? options.now : () => Date.now();
  // The tool containment root defaults to a `workspace` directory INSIDE the agent root, so a
  // deployment that relocates the agent root (a test, a second profile, a lab machine) relocates the
  // workspace with it. An explicit `workspaceRoot` still wins.
  const workspaceRoot =
    typeof options.workspaceRoot === 'string' && options.workspaceRoot.length > 0
      ? options.workspaceRoot
      : path.join(rootDir, 'workspace');
  const ceiling = loadCeilingSnapshot(options.snapshotPath ?? defaultSnapshotPath());
  const deviceConfig = loadDeviceToolConfig({
    ceiling,
    rootDir,
    toolsConfigFile: options.toolsConfigFile,
    createIfMissing: options.createDeviceConfig !== false,
  });
  const dispatcher = createDispatcher({
    ceiling,
    deviceConfig,
    workspaceRoot,
  });
  const keystore = loadDeviceKeystore({ rootDir, createIfMissing: options.createDeviceKey !== false });
  const identity = loadDeviceIdentity({
    rootDir,
    deviceFile: options.deviceFile,
    deviceId: options.deviceId,
  });
  const pins = options.pins ?? loadPinnedBackendKeys({ rootDir, pinFile: options.pinFile });
  const replayWindow = createDurableReplayWindow({
    rootDir,
    replayFile: options.replayFile,
    now,
    persist: options.persistReplay !== false,
    retentionMs: options.replayRetentionMs,
  });

  /**
   * Handles one inbound frame end to end.
   *
   * @param {object} frame the flat wire frame, exactly as received
   * @returns {Promise<{outcome: string, resultFrame: object, refusalCode: string|null,
   *   executed: boolean}>}
   */
  async function handleFrame(frame) {
    // Correlation values for a result frame. When verification fails these are CLAIMS from an
    // unauthenticated document, which is why the result records `correlation: 'unverified-claim'`.
    let claim = { requestId: null, callId: null, grantId: null, epoch: null };
    try {
      const claimedCore = coreFromFrame(frame);
      claim = {
        requestId: claimedCore.requestId,
        callId: typeof frame.callId === 'string' ? frame.callId : null,
        grantId: claimedCore.grantId,
        epoch: claimedCore.epoch,
      };
    } catch {
      // An unreadable frame yields an unreadable claim; the result says so rather than guessing.
      claim = {
        requestId: null,
        callId: frame !== null && typeof frame === 'object' && typeof frame.callId === 'string' ? frame.callId : null,
        grantId: null,
        epoch: null,
      };
    }

    const verified = await verifyCommandFrame({
      frame,
      pins,
      deviceId: identity.deviceId,
      deviceKeyId: keystore.keyId(),
      now,
      replayWindow,
    });

    if (verified.ok !== true) {
      // REFUSED. Nothing ran. The refusal code is the ONLY thing about the failure that travels.
      const resultFrame = buildResultFrame({
        keystore,
        deviceId: identity.deviceId,
        outcome: OUTCOMES.REFUSED,
        errorCode: verified.error.code,
        payloadBytes: Buffer.from(
          JSON.stringify({
            status: 'refused',
            code: verified.error.code,
            // The fixed external message. `detail` is deliberately NOT included: endpoint-verifier
            // invariant 3 forbids an error reply that reveals which field mismatched.
            message: verified.error.message,
          }),
          'utf8',
        ),
        correlation: { ...claim, correlation: 'unverified-claim' },
        now,
      });
      return { outcome: OUTCOMES.REFUSED, resultFrame, refusalCode: verified.error.code, executed: false };
    }

    const { core, argsBytes } = verified;

    // Policy: server ceiling (tier 1), then the device floor (tier 2), then local implementation.
    try {
      const executed = dispatcher.execute({ toolName: core.toolName, argsBytes });
      const payload = Buffer.from(
        JSON.stringify({
          status: 'succeeded',
          toolName: executed.toolName,
          executedAtMs: executed.executedAtMs,
          result: executed.result,
        }),
        'utf8',
      );
      const resultFrame = buildResultFrame({
        keystore,
        deviceId: identity.deviceId,
        outcome: OUTCOMES.SUCCEEDED,
        payloadBytes: payload,
        correlation: { ...claim, correlation: 'verified' },
        now,
      });
      return { outcome: OUTCOMES.SUCCEEDED, resultFrame, refusalCode: null, executed: true };
    } catch (err) {
      const refusalCode = isEndpointRefusal(err) ? err.code : 'ENDPOINT_EXECUTION_UNCERTAIN';
      // The OUTCOME LAW. `refused` means the endpoint can PROVE nothing ran: a verification failure
      // or a policy decision before execution. `uncertain` means anything else — a genuine execution
      // failure whose effect the endpoint cannot prove. Nothing in this branch is ever 'succeeded'.
      //
      // Policy refusals are a NARROWER set than "every EndpointRefusal raised by a tool call". When a
      // tool itself raises a field-named refusal for a per-call problem it could not settle locally
      // (for example an `args` shape the policy stage confused with a missing file), mapping it to
      // 'refused' would claim certainty the endpoint does not have. So only the FOUR gate decisions —
      // ceiling, floor, implementation, argument shape — are 'refused'; every other tool-raised refusal
      // is 'uncertain', the same as a non-refusal throw. See resultFrame's three-way `outcome` enum.
      const isPolicyRefusal =
        refusalCode === 'ENDPOINT_TOOL_OUTSIDE_CEILING' ||
        refusalCode === 'ENDPOINT_TOOL_NOT_ENABLED_ON_DEVICE' ||
        refusalCode === 'ENDPOINT_TOOL_NOT_IMPLEMENTED' ||
        refusalCode === 'ENDPOINT_TOOL_ARGS_INVALID';
      const outcome = isPolicyRefusal ? OUTCOMES.REFUSED : OUTCOMES.UNCERTAIN;
      const payload = Buffer.from(
        JSON.stringify({
          status: outcome,
          code: refusalCode,
          message: isEndpointRefusal(err) ? err.message : 'the tool call could not be completed',
        }),
        'utf8',
      );
      const resultFrame = buildResultFrame({
        keystore,
        deviceId: identity.deviceId,
        outcome,
        errorCode: refusalCode,
        payloadBytes: payload,
        correlation: { ...core, correlation: 'verified' },
        now,
      });
      return { outcome, resultFrame, refusalCode, executed: false };
    }
  }

  return Object.freeze({
    handleFrame,
    deviceId: () => identity.deviceId,
    deviceKeyId: () => keystore.keyId(),
    /** The public half of the device identity: needed by the platform to verify result frames. */
    devicePublicKeySpkiB64u: () => keystore.publicKeySpkiB64u(),
    effectiveTools: () => dispatcher.effectiveTools(),
    decideTool: (toolName) => dispatcher.decide(toolName),
    /** Serializable, secret-free description of the whole agent. Safe to print. */
    describe: () => ({
      deviceId: identity.deviceId,
      deviceKeyId: keystore.keyId(),
      // The PUBLIC half is published on purpose: the platform needs it to verify result frames.
      devicePublicKeySpkiB64u: keystore.publicKeySpkiB64u(),
      deviceKeyFile: keystore.keyFile(),
      deviceKeyPermission: keystore.permission(),
      deviceIdentityFile: identity.file,
      pinnedBackendKeyIds: pins.keyIds(),
      ceiling: ceiling.describe(),
      dispatch: dispatcher.describe(),
      verificationOrder: describeVerificationOrder(),
      replay: replayWindow.describe(),
      tools: describeTools(workspaceRoot),
      workspaceRoot: describeTools(workspaceRoot).workspaceRoot,
      frameFields: [...FIELD_ORDER],
    }),
    _internal: Object.freeze({
      ceiling,
      deviceConfig,
      dispatcher,
      keystore,
      pins,
      replayWindow,
      now,
      rootDir,
    }),
  });
}

module.exports = {
  createEndpointAgent,
  loadDeviceIdentity,
  defaultDeviceFile,
  describeRefusal,
};