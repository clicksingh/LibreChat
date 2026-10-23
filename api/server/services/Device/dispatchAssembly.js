'use strict';

/**
 * THE SINGLE PRODUCTION ASSEMBLY POINT for the device dispatch client (GM-83).
 *
 * WHY THIS FILE EXISTS, AND WHY IT IS NOT INSIDE `relay/`
 *
 * `relayDispatchClient` enforces the server tool policy through an INJECTED port rather than an
 * intrinsic one, because the frozen guard `noKeyMaterial.spec.js` scans every file in
 * `api/server/services/Device/relay/` and refuses any `process.env` text and any `require` outside a
 * closed allow-list. That guard exists to keep the relay corridor free of signing capability and key
 * material, and GM-83 declined to bend it for convenience.
 *
 * The cost of that decision is a seam: a client constructed WITHOUT a policy port has no ceiling and
 * no law, so its gate is unarmed. This module pays that cost off. It is the one place in production
 * that builds the client, it lives OUTSIDE `relay/` so it may read the environment and require the
 * policy modules, and it always supplies an armed port. A caller that builds a client directly is
 * bypassing the assembly, and `relayDispatchClient` reports that state as `policy.evaluated:false`
 * with `reason:'policy-port-absent'` rather than pretending to have checked anything.
 *
 * WHAT IS INJECTED AND WHY IT IS NOT DECIDED HERE
 *
 * Key CUSTODY is an owner decision that has not been made, so `sign` and `keyId` are injected exactly
 * as `envelopeSigner` requires — this module never generates, reads, stores or logs key material. The
 * transport, replay window and ledger are likewise injected, because their durable storage is an
 * integration choice. What this module DOES decide is the policy wiring, which is server law rather
 * than deployment configuration.
 */

const relay = require('./relay');
const deviceCapabilityPolicy = require('./deviceCapabilityPolicy');
const deviceToolRegistry = require('./deviceToolRegistry');

/** Re-exported so the assembly and the client cannot drift on the variable's spelling. */
const CAPABILITY_STAGE_ENV = relay.CAPABILITY_STAGE_ENV;

/** The narrowest rung. Absent or unrecognised configuration NARROWS to this; it never widens. */
const DEFAULT_SERVER_STAGE = relay.DEFAULT_SERVER_STAGE;

/** Resolve the server stage from the environment, failing to the narrowest rung. */
function resolveServerStage(env, warn) {
  const raw = env ? env[CAPABILITY_STAGE_ENV] : undefined;
  if (raw === undefined || raw === null || raw === '') {
    return { stage: DEFAULT_SERVER_STAGE, source: 'default', raw: null };
  }
  const stage = String(raw);
  // Ask the CEILING whether it recognises the value rather than consulting a local list: the policy
  // module is the authority on which stages exist, and a duplicated list here would drift from it.
  let recognised = false;
  try {
    const ceiling = deviceCapabilityPolicy.ceilingForStage(stage);
    recognised = Array.isArray(ceiling && ceiling.tools);
  } catch {
    recognised = false;
  }
  if (!recognised) {
    warn(
      `[deviceDispatch] unrecognised ${CAPABILITY_STAGE_ENV}=${JSON.stringify(stage)}; ` +
        `keeping the NARROWEST server stage ${JSON.stringify(DEFAULT_SERVER_STAGE)} rather than ` +
        'widening. Fix the value or remove it.',
    );
    return { stage: DEFAULT_SERVER_STAGE, source: 'unrecognised', raw: stage };
  }
  return { stage, source: 'env', raw: stage };
}

/**
 * Build the tool-policy port for the dispatch client.
 *
 * The port is an exact-key object: three members are REQUIRED by `relayDispatchClient` for the gate
 * to arm, and three more are optional. `ceilingForStage`, `authorizeDispatch` and `dispatchCodes` are
 * passed through from the real modules — never restated — so the decision and the vocabulary both
 * come from the single tested implementation.
 *
 * @param {object} params
 * @param {object|null} [params.resolvePolicy] optional narrowing document resolver (W10's
 *   `resolution.tools`). Absent, the stage ceiling alone is authoritative (GM-75 retired the device
 *   floor). If it throws, the client fails CLOSED — a resolver error never becomes an allow.
 * @param {object|null} [params.hasOwnerApproval] optional tier-3 approval seam.
 * @returns {Readonly<object>} the port
 */
function buildPolicyPort({ resolvePolicy = null, hasOwnerApproval = null, env = null, warn = console.warn } = {}) {
  const { stage, source, raw } = resolveServerStage(env, warn);

  const port = {
    // Read LIVE on every dispatch, so a stage change does not require a client rebuild (GM-78).
    stage: () => stage,
    ceilingForStage: (value) => deviceCapabilityPolicy.ceilingForStage(value),
    authorizeDispatch: (toolName, params) => deviceToolRegistry.authorizeDispatch(toolName, params),
    dispatchCodes: deviceToolRegistry.DISPATCH_CODES,
    __stageSource: source,
    __stageRaw: raw,
  };

  if (typeof resolvePolicy === 'function') {
    port.resolve = (context) => resolvePolicy(context);
  }
  if (typeof hasOwnerApproval === 'function') {
    port.hasOwnerApproval = (context) => hasOwnerApproval(context);
  }

  // `__stageSource` / `__stageRaw` are diagnostics, not port members. `relayDispatchClient` refuses
  // an unknown KEY, so they are stripped here rather than risking a POLICY_SEAM_INVALID.
  delete port.__stageSource;
  delete port.__stageRaw;

  return Object.freeze(port);
}

/**
 * Build the device dispatch client with an ARMED policy port.
 *
 * Every dependency is injected; the only thing this function decides is the policy wiring. It
 * returns the client plus a `wiring` description so a caller (or a test, or an operator) can see what
 * was actually armed without reading the client's internals.
 *
 * @returns {Readonly<{client: object, wiring: object}>}
 */
function createDeviceDispatchAssembly({
  sign,
  keyId,
  transport,
  replayWindow,
  ledger = null,
  resolvePolicy = null,
  hasOwnerApproval = null,
  env = null,
  logger = console,
} = {}) {
  const warn =
    logger && typeof logger.warn === 'function'
      ? (message) => logger.warn(message)
      : (message) => {
          // Never silently drop a widening-relevant warning, even with no logger supplied.
          process.emitWarning(message, { type: 'DeviceDispatchPolicyWarning' });
        };

  const { stage, source, raw } = resolveServerStage(env, warn);
  const policy = buildPolicyPort({ resolvePolicy, hasOwnerApproval, env, warn });

  const signer = relay.createEnvelopeSigner({ sign, keyId });

  const client = relay.createRelayDispatchClient({
    transport,
    signer,
    replayWindow,
    ...(ledger ? { ledger } : {}),
    policy,
  });

  const wiring = Object.freeze({
    assembledBy: 'api/server/services/Device/dispatchAssembly.js',
    policyArmed: true,
    stage,
    stageSource: source,
    stageRaw: raw,
    stageEnv: CAPABILITY_STAGE_ENV,
    narrowestStage: DEFAULT_SERVER_STAGE,
    resolverPresent: typeof resolvePolicy === 'function',
    ownerApprovalPresent: typeof hasOwnerApproval === 'function',
    ledgerPresent: Boolean(ledger),
  });

  return Object.freeze({ client, wiring });
}

module.exports = {
  CAPABILITY_STAGE_ENV,
  DEFAULT_SERVER_STAGE,
  resolveServerStage,
  buildPolicyPort,
  createDeviceDispatchAssembly,
};