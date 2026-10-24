'use strict';

/**
 * BACKEND -> RELAY DISPATCH CLIENT — workstream W2 acceptance item 3.
 *
 * WHAT THIS OWNS
 * - It mints, signs and hands one CBHR-RPC-V2 frame to the relay hop, and it classifies the relay's
 *   answer so the caller can tell "refused" from "may have been delivered".
 * - It is the ONLY place in the backend that decides what goes into a command envelope, and every
 *   identity value in that envelope comes from an explicitly trusted authority projection.
 *
 * WHAT THIS REFUSES (the security property, mechanically enforced)
 * - It NEVER reads a request. It accepts no `req`, no `headers`, no `body`, no `query`, no `params`
 *   and no user object: the dispatch request and the authority projection are both EXACT-KEY
 *   whitelists, so a request-shaped object is rejected by name (`DISPATCH_REQUEST_SHAPE_INVALID` /
 *   `AUTHORITY_SHAPE_INVALID`) before anything is signed or sent.
 * - Identity comes ONLY from `trustedAuthorityFromDeviceRow()`, which takes a SERVER-OBSERVED device
 *   row plus the tenant/principal already resolved from the trusted session/ALS context, and refuses
 *   a row whose `tenantId`/`ownerId` disagree. There is no default, no fallback and no inference: a
 *   missing grant, epoch, device key or owner is a refusal, never a guess.
 * - It refuses to mint `audience: 'relay'`. Relay-audience frames are ENDPOINT-signed replies and
 *   cancel-acks; a backend-signed relay-audience frame would forge the endpoint's half of the
 *   protocol. The refusal is ALSO enforced inside the signing primitive (`./envelopeSigner`), so it
 *   does not depend on this path being used (GM-48 m3).
 * - It refuses a dispatch with no args PREIMAGE. GM-47 requires the frame to carry `argsB64u`, the
 *   exact bytes whose sha256 is the signed field 15; a digest with no bytes cannot be re-hashed by
 *   the endpoint, so it is refused (`ENVELOPE_ARGS_INVALID`) rather than signed. A declared digest
 *   that disagrees with the supplied bytes is `ARGS_DIGEST_MISMATCH`.
 * - It refuses to exist without a replay window (GM-49): `replayWindow: null` is permitted for
 *   non-dispatch use of the verification primitives, never for a real dispatch.
 *
 * OUTCOME LAW (F-V24C-9: unknown-outcome is never success)
 * - `delivered: 'accepted'` only for a 2xx relay answer that does not explicitly refuse.
 * - `delivered: 'refused'` for a 4xx answer or `{accepted:false}`: the relay did not forward it.
 * - `delivered: 'unknown'` for a transport throw/timeout/malformed answer or a 5xx: the relay may
 *   have written-ahead and emitted the frame before failing. The caller MUST treat that as an
 *   unknown outcome, never as a success and never as a blind retry of the same envelope.
 * - `delivered: 'no'` when nothing was signed or sent (shape, authority, replay, self-check).
 *
 * THE TOOL-POLICY GATE (W12 / GM-72, GM-75, GM-78) — EVALUATED BEFORE ANYTHING IS SIGNED
 * A dispatched tool name is checked against server policy HERE, at the top of `dispatchCommand`:
 * after the request has been parsed and BEFORE the clock is read, a nonce is minted, the replay
 * window is consulted, the core is built, anything is signed, the ledger is touched or a frame
 * reaches the transport. A refused tool therefore never consumes a nonce, never enters the replay
 * ring, is never signed, is never reserved and never reaches the wire — the refusal is a policy
 * decision, not a transport outcome (`delivered: 'no'`).
 *
 * THE CEILING IS SERVER DATA, AT A SERVER STAGE
 * The ceiling is `deviceCapabilityPolicy.ceilingForStage(stage)` — tier 1, never device-settable —
 * and the stage is operator configuration, never request data and never device data. The stage
 * arrives through the injected policy port (below), sourced from the environment variable named by
 * `CAPABILITY_STAGE_ENV`, and an ABSENT stage means the NARROWEST stage (`DEFAULT_SERVER_STAGE`,
 * 'A'). A value the ceiling refuses is a configuration fault, not licence to widen: the narrowest
 * stage stands, and a warning is emitted (once per client per value).
 *
 * WHY THE POLICY LAW IS INJECTED (and not imported here)
 * `__tests__/noKeyMaterial.spec.js` scans every module in this directory and asserts that none of
 * them performs environment access or reaches anything outside a frozen import allow-list. So the
 * law arrives the same way the admin surface hands it to `@librechat/api`: through a port built by
 * the server wiring — `{ ceilingForStage, authorizeDispatch, dispatchCodes }` taken from
 * `deviceCapabilityPolicy` and `deviceToolRegistry`, plus the optional `stage`, `resolve` and
 * `hasOwnerApproval` seams. No tool name, no stage ladder and no refusal code is restated here: the
 * codes this path emits are the registry's own, read from the port.
 *
 *   ceilingForStage    the server ceiling document for a stage
 *   authorizeDispatch  the registry's dispatch gate (the intersection law's single implementation)
 *   dispatchCodes      the registry's `DISPATCH_CODES`, the ONLY refusal vocabulary this path emits
 *   stage              OPTIONAL: the configured server stage — a string, or a function read live on
 *                      each dispatch (GM-78: the server enforces at dispatch time). Absent = 'A'
 *   resolve            OPTIONAL injected policy resolver (the W10 seam): a tool-name list, or
 *                      `{ tools }`. PRESENT -> the ceiling is intersected with it. ABSENT -> the
 *                      stage ceiling ALONE is authoritative (GM-75 retired the device floor, so
 *                      nothing narrows by default). It can never widen: the registry checks the
 *                      ceiling before it looks at the narrowing at all.
 *   hasOwnerApproval   OPTIONAL tier-3 seam: an approval-gated tool dispatches ONLY when this returns
 *                      `true`; otherwise it is refused with the registry's `OWNER_APPROVAL_REQUIRED`.
 *
 * FAIL CLOSED, NEVER "ALLOW ON ERROR"
 * A resolver that throws, or that answers with something which is not a list of tool names, yields
 * an EMPTY narrowing: the registry then refuses with its own tier code. An approval seam that throws
 * or does not return `true` is not an approval. A stage source or ceiling that cannot be resolved,
 * and a registry that refuses to answer, are refusals too — never a dispatch.
 *
 * The port's absence is NOT silent: the gate reports `evaluated: false` with the fixed reason
 * `policy-port-absent` on every outcome, so an unarmed dispatch path is visible in the result rather
 * than assumed gated.
 *
 * ONLY COMMAND FRAMES ARE TOOL EXECUTIONS
 * Cancel and resync frames carry a `toolName` because the envelope requires one, but they execute no
 * tool. They are deliberately not gated (the block says so: `reason: 'not-a-tool-execution'`),
 * because gating them would let a policy refusal make a running call un-cancellable.
 *
 * WHAT IS *NOT* A REFUSAL: `approval-required` is ADMISSIBLE — it dispatches once the approval seam
 * says yes, and until then it is refused with `OWNER_APPROVAL_REQUIRED`. The two paths are
 * distinguishable in `outcome.policy` (`decision`, `requiresApproval`, `approved`), and every
 * outcome produced after the request has parsed carries that block, so a caller can see which tier
 * decided what, and why.
 *
 * THE HOP ITSELF
 * The HTTP transport is INJECTED (`transport({ deviceId, frame })`). This module deliberately does
 * not freeze a relay URL path: the relay (workstream W1) has not defined its route yet, and inventing
 * one here would be a format invention, not a contract. L (integration) wires the transport; the
 * frame shape below is what crosses that seam.
 *
 * THE DISPATCH LEDGER SEAM (W6 / GM-43) — OPTIONAL, AND OFF BY DEFAULT
 * A result can only be correlated to a call the platform knows it dispatched. When a
 * `createDispatchLedger()` is supplied, this client RESERVES the call (`callId`) immediately before
 * the frame leaves, so the ledger contains exactly the calls that reached the wire:
 *   - the relay REFUSED the frame (4xx / `{accepted:false}`)  -> the reservation is RELEASED, because
 *     no result can legitimately arrive for it;
 *   - the outcome is UNKNOWN (5xx, throw, malformed answer)   -> the reservation is KEPT, because the
 *     frame may have been delivered and its result must still be correlatable;
 *   - nothing was signed or sent                              -> nothing was reserved.
 * With no ledger the client behaves exactly as before (this seam is additive); with one, a call id
 * that is already live is refused before anything is sent, so one call id never denotes two calls.
 */

const nodeCrypto = require('node:crypto');
const deviceCrypto = require('../crypto');
const {
  RPC_ENVELOPE_AUDIENCES,
  RPC_OP_KINDS,
  buildEnvelopeCore,
  toWireFrame,
  isPlainRecord,
  decodeArgsB64u,
} = require('./envelopeCore');
const { resolveArgsDigestHex, argsBytesToB64u, sha256Hex } = require('./argsDigest');
const { freshnessWindowMsFor } = require('./freshness');
const { isRelayError, relayFailure } = require('./errors');

/** The ONLY identity fields a trusted dispatch authority may carry. */
const TRUSTED_AUTHORITY_FIELDS = Object.freeze([
  'tenantId',
  'ownerPrincipalId',
  'deviceId',
  'deviceKeyId',
  'grantId',
  'epoch',
]);

/**
 * The ONLY request keys `dispatchCommand` accepts. Nothing else is read, ever.
 *
 * `argsBytes` / `argsB64u` are the PREIMAGE sources: GM-47 requires the exact args bytes to travel
 * with the frame (`argsB64u`), so a dispatch that supplies only a digest is refused — a signature
 * over a digest whose preimage never travels is not authority over the payload. `argsDigestHex` /
 * `argsDigestB64u` remain accepted as CROSS-CHECKS alongside a preimage and are refused alone.
 */
const DISPATCH_REQUEST_KEYS = Object.freeze([
  'authority',
  'toolName',
  'opKind',
  'argsBytes',
  'argsB64u',
  'argsDigestB64u',
  'argsDigestHex',
  'audience',
  'seq',
  'idempotencyKey',
  'callId',
]);

/**
 * The ONLY keys the injected tool-policy port may carry. An exact-key whitelist for the same reason
 * the dispatch request has one: a request-shaped value (a body, a session, a user record) smuggled in
 * as the policy port is refused BY NAME rather than half-read as authority over a tool.
 */
const POLICY_PORT_KEYS = Object.freeze([
  'stage',
  'ceilingForStage',
  'authorizeDispatch',
  'dispatchCodes',
  'resolve',
  'hasOwnerApproval',
]);

/** The port members the gate needs in order to ARM. Without them there is no ceiling and no law. */
const POLICY_PORT_REQUIRED_KEYS = Object.freeze([
  'ceilingForStage',
  'authorizeDispatch',
  'dispatchCodes',
]);

/**
 * The environment variable that carries the server's capability stage. Exported so the wiring, the
 * panel and CI read one name rather than three copies of it: the port's `stage` is sourced from it.
 */
const CAPABILITY_STAGE_ENV = 'CBHR_DEVICE_CAPABILITY_STAGE';

/**
 * The NARROWEST capability stage, and the default when no stage is configured. A wrong default must
 * never be the wide one, so this is 'A' — the read-only rung — and never 'full'.
 */
const DEFAULT_SERVER_STAGE = 'A';

/** Where the stage that governed a decision came from. */
const STAGE_SOURCES = Object.freeze({
  /** The configured stage was accepted by the server ceiling. */
  CONFIGURED: 'configured',
  /** Nothing was configured, so the narrowest stage was used. */
  DEFAULT: 'default',
  /** Something was configured and the ceiling refused it: warned, and narrowed. */
  UNRECOGNISED: 'unrecognised',
});

/** Whether the tool-policy gate was armed for a dispatch. Only `armed` evaluates policy. */
const POLICY_PORT_STATES = Object.freeze({ ARMED: 'armed', ABSENT: 'absent' });

/**
 * How the narrowing channel resolved. `absent` and `narrowed` are the only outcomes that can leave a
 * tool enabled; `threw` and `unusable` are the fail-closed ones.
 */
const POLICY_RESOLVER_OUTCOMES = Object.freeze({
  /** No resolver was injected: the stage ceiling alone is authoritative. */
  ABSENT: 'absent',
  /** The resolver answered with a list of tool names. */
  NARROWED: 'narrowed',
  /** The resolver threw (or rejected): an empty narrowing, never "allow". */
  THREW: 'threw',
  /** The resolver answered with something that is not a list of tool names: fail closed. */
  UNUSABLE: 'unusable',
});

/** The decisions the gate can reach: the registry's three, plus "the gate did not decide". */
const POLICY_DECISIONS = Object.freeze({
  ALLOWED: 'allowed',
  APPROVAL_REQUIRED: 'approval-required',
  DENIED: 'denied',
  NOT_EVALUATED: 'not-evaluated',
});

/** Fixed machine reasons a policy block can carry. No payload, no device-supplied text. */
const POLICY_REASONS = Object.freeze({
  /** The port was absent, so no policy was consulted (declared, never silent). */
  POLICY_PORT_ABSENT: 'policy-port-absent',
  /** A cancel/resync frame: not a tool execution, so no tool policy applies. */
  NOT_A_TOOL_EXECUTION: 'not-a-tool-execution',
  /** The configured stage, and therefore the ceiling, could not be resolved: fail closed. */
  STAGE_UNUSABLE: 'stage-unusable',
  /** The registry refused to answer for this dispatch: fail closed. */
  POLICY_UNAVAILABLE: 'policy-unavailable',
  /** The resolver threw or answered unusably: empty narrowing, so the registry refuses. */
  RESOLVER_UNUSABLE: 'resolver-unusable',
  /** The registry refused the narrowing document itself (its own fail-closed floor codes). */
  NARROWING_REFUSED: 'narrowing-refused',
});

/** The schema id of the `policy` block every outcome carries. */
const DISPATCH_TOOL_POLICY_SCHEMA = 'cbhr.rdc.dispatch-tool-policy/1';

function defaultNonceFactory() {
  return nodeCrypto.randomBytes(16).toString('base64url');
}

function defaultRequestIdFactory() {
  return nodeCrypto.randomUUID();
}

function shapeFailure(message, field) {
  return relayFailure('AUTHORITY_SHAPE_INVALID', message, { field });
}

function authorityMismatch(message, field) {
  return relayFailure('AUTHORITY_MISMATCH', message, { field });
}

/**
 * Validates and freezes a trusted dispatch authority projection.
 *
 * The exact-key whitelist is the anti-synthesis guard: a request-shaped object (a `req`, a body, a
 * session, a user record, anything carrying `headers`/`user`/`query`/`params`) is refused by name.
 * `epoch` is the only non-string field (a server-observed integer, converted to its canonical decimal
 * form at the core boundary — never coerced from a string).
 *
 * @param {unknown} authority
 * @returns {Readonly<{tenantId: string, ownerPrincipalId: string, deviceId: string,
 *   deviceKeyId: string, grantId: string, epoch: number}>}
 */
function assertTrustedDispatchAuthority(authority) {
  if (!isPlainRecord(authority)) {
    throw shapeFailure(
      'a trusted dispatch authority must be a plain object projected from server truth',
      'authority',
    );
  }
  for (const key of Object.keys(authority)) {
    if (!TRUSTED_AUTHORITY_FIELDS.includes(key)) {
      throw shapeFailure(
        `trusted dispatch authority refuses the key "${key}"; identity is never taken from a request`,
        key,
      );
    }
  }
  const projection = {};
  for (const field of TRUSTED_AUTHORITY_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(authority, field)) {
      throw shapeFailure(`trusted dispatch authority is missing "${field}"`, field);
    }
    projection[field] = authority[field];
  }
  for (const field of ['tenantId', 'ownerPrincipalId', 'deviceId', 'deviceKeyId', 'grantId']) {
    if (typeof projection[field] !== 'string' || projection[field].length === 0) {
      throw shapeFailure(`trusted dispatch authority "${field}" must be a non-empty string`, field);
    }
  }
  if (!Number.isInteger(projection.epoch) || projection.epoch < 1) {
    throw shapeFailure('trusted dispatch authority "epoch" must be an integer >= 1', 'epoch');
  }
  return Object.freeze(projection);
}

/**
 * Projects a trusted dispatch authority from a SERVER-OBSERVED device row.
 *
 * Inputs are server truth only: `row` is a `DeviceAuthority` document read by the backend, and
 * `tenantId`/`ownerPrincipalId` are the values already resolved from the trusted ALS tenant context
 * and the authenticated session. The joint equality checks mirror the I-0 conjuncts that decide
 * ownership; a disagreement is `AUTHORITY_MISMATCH`, never a repair.
 *
 * NOTE: this projection does NOT re-implement I-0. Lease state/expiry admission stays the authority
 * service's decision; callers must have run it, and may pass `assertAuthorityCurrent` to the client
 * to re-check inside the dispatch window.
 *
 * @param {object} params
 * @param {object} params.row server-observed device row
 * @param {string} params.tenantId trusted active tenant
 * @param {string} params.ownerPrincipalId trusted authenticated principal
 * @returns {Readonly<object>} frozen authority projection
 */
function trustedAuthorityFromDeviceRow({ row, tenantId, ownerPrincipalId } = {}) {
  if (!isPlainRecord(row)) {
    throw shapeFailure('a trusted dispatch authority requires a server-observed device row', 'row');
  }
  if (typeof tenantId !== 'string' || tenantId.length === 0) {
    throw shapeFailure('a trusted dispatch authority requires the trusted tenant id', 'tenantId');
  }
  if (typeof ownerPrincipalId !== 'string' || ownerPrincipalId.length === 0) {
    throw shapeFailure(
      'a trusted dispatch authority requires the authenticated principal id',
      'ownerPrincipalId',
    );
  }
  if (row.tenantId !== tenantId) {
    throw authorityMismatch(
      'the server-observed device row belongs to a different tenant',
      'tenantId',
    );
  }
  if (row.ownerId !== ownerPrincipalId) {
    throw authorityMismatch(
      'the authenticated principal does not own the server-observed device row',
      'ownerPrincipalId',
    );
  }
  const deviceId = row._id?.toString?.();
  if (typeof deviceId !== 'string' || deviceId.length === 0) {
    throw shapeFailure('the server-observed device row carries no usable device id', 'deviceId');
  }
  if (typeof row.deviceKeyId !== 'string' || row.deviceKeyId.length === 0) {
    throw shapeFailure('the server-observed device row carries no device key id', 'deviceKeyId');
  }
  if (typeof row.grantId !== 'string' || row.grantId.length === 0) {
    throw shapeFailure(
      'the server-observed device row carries no live grant id, so no envelope can be authorized',
      'grantId',
    );
  }
  return assertTrustedDispatchAuthority({
    tenantId,
    ownerPrincipalId,
    deviceId,
    deviceKeyId: row.deviceKeyId,
    grantId: row.grantId,
    epoch: row.epoch,
  });
}

/**
 * Resolves the args preimage and the signed `sha256(args)` field from a dispatch request (GM-47).
 *
 * The frame must transport the exact bytes, so a PREIMAGE source is required:
 *   - `argsBytes` (raw Buffer/TypedArray/DataView), or
 *   - `argsB64u` (the same bytes already in canonical unpadded base64url).
 * Exactly one of those two may be present. `argsDigestHex` / `argsDigestB64u` are optional
 * CROSS-CHECKS: when supplied they must agree with the recomputed digest (`ARGS_DIGEST_MISMATCH`),
 * and on their own they are refused, because a digest with no preimage cannot be verified by the
 * endpoint and therefore cannot be dispatched at all.
 * @param {object} request the validated-key dispatch request
 * @returns {{argsDigestHex: string, argsB64u: string}}
 */
function resolveDispatchArgs(request) {
  const hasBytes = request.argsBytes !== undefined && request.argsBytes !== null;
  const hasB64u = request.argsB64u !== undefined && request.argsB64u !== null;
  if (hasBytes === hasB64u) {
    throw relayFailure(
      'ENVELOPE_ARGS_INVALID',
      'dispatch requires exactly one args PREIMAGE source (argsBytes | argsB64u); a digest alone cannot travel, because the endpoint must re-hash the bytes it actually received (GM-47)',
      { field: 'argsB64u' },
    );
  }
  let argsB64u;
  let argsDigestHex;
  if (hasBytes) {
    argsDigestHex = resolveArgsDigestHex({ bytes: request.argsBytes });
    argsB64u = argsBytesToB64u(request.argsBytes);
  } else {
    const decoded = decodeArgsB64u(request.argsB64u);
    if (decoded === null) {
      throw relayFailure(
        'ENVELOPE_ARGS_INVALID',
        'dispatch argsB64u must be canonical unpadded base64url of the exact args bytes',
        { field: 'argsB64u' },
      );
    }
    argsB64u = request.argsB64u;
    argsDigestHex = sha256Hex(decoded);
  }
  const declaredHex =
    request.argsDigestHex !== undefined && request.argsDigestHex !== null
      ? request.argsDigestHex
      : undefined;
  const declaredB64u =
    request.argsDigestB64u !== undefined && request.argsDigestB64u !== null
      ? resolveArgsDigestHex({ digestB64u: request.argsDigestB64u })
      : undefined;
  for (const declared of [declaredHex, declaredB64u]) {
    if (declared !== undefined && declared !== argsDigestHex) {
      throw relayFailure(
        'ARGS_DIGEST_MISMATCH',
        'the declared sha256(args) does not match the supplied args bytes; refusing to sign a digest whose preimage disagrees',
        { field: 'argsDigestHex' },
      );
    }
  }
  return { argsDigestHex, argsB64u };
}

/**
 * Parses and validates a dispatch request. Exact-key whitelist; every failure is typed.
 * @param {unknown} request
 * @returns {object} normalized request
 */
function parseDispatchRequest(request) {
  if (!isPlainRecord(request)) {
    throw relayFailure(
      'DISPATCH_REQUEST_SHAPE_INVALID',
      'a dispatch request must be a plain object of protocol values',
    );
  }
  for (const key of Object.keys(request)) {
    if (!DISPATCH_REQUEST_KEYS.includes(key)) {
      throw relayFailure(
        'DISPATCH_REQUEST_SHAPE_INVALID',
        `dispatch refuses the request key "${key}"; identity is never taken from a request`,
        { field: key },
      );
    }
  }
  const authority = assertTrustedDispatchAuthority(request.authority);

  if (typeof request.toolName !== 'string' || request.toolName.length === 0) {
    throw relayFailure('DISPATCH_REQUEST_SHAPE_INVALID', 'dispatch requires a non-empty toolName', {
      field: 'toolName',
    });
  }
  const opKind = request.opKind ?? RPC_OP_KINDS.COMMAND;
  if (!Object.values(RPC_OP_KINDS).includes(opKind)) {
    throw relayFailure(
      'DISPATCH_REQUEST_SHAPE_INVALID',
      'dispatch opKind must be one of command | cancel | resync',
      { field: 'opKind' },
    );
  }
  const audience = request.audience ?? RPC_ENVELOPE_AUDIENCES.ENDPOINT;
  if (audience !== RPC_ENVELOPE_AUDIENCES.ENDPOINT) {
    throw relayFailure(
      'ENVELOPE_AUDIENCE_NOT_DISPATCHABLE',
      'the backend mints audience "endpoint" only: relay-audience frames are endpoint-signed replies and cancel-acks, so a backend-signed one would forge the endpoint half of the protocol',
      { field: 'audience' },
    );
  }

  const { argsDigestHex, argsB64u } = resolveDispatchArgs(request);

  const seq = request.seq ?? null;
  if (seq !== null && (!Number.isInteger(seq) || seq < 1)) {
    throw relayFailure('DISPATCH_REQUEST_SHAPE_INVALID', 'dispatch seq must be an integer >= 1', {
      field: 'seq',
    });
  }
  for (const field of ['idempotencyKey', 'callId']) {
    const value = request[field];
    if (value === undefined || value === null) {
      continue;
    }
    if (typeof value !== 'string' || value.length === 0 || value.length > 200) {
      throw relayFailure(
        'DISPATCH_REQUEST_SHAPE_INVALID',
        `dispatch ${field} must be a non-empty string of at most 200 characters`,
        { field },
      );
    }
  }

  return {
    authority,
    toolName: request.toolName,
    opKind,
    audience,
    argsDigestHex,
    argsB64u,
    seq,
    idempotencyKey: request.idempotencyKey ?? null,
    callId: request.callId ?? null,
  };
}

/**
 * Classifies a relay answer. Never throws; never upgrades an uncertain outcome to success.
 * @param {unknown} response `{ status, body }` as resolved by the transport
 * @returns {{accepted: boolean, delivered: string, code: (string|null), retryable: boolean,
 *   status: (number|null)}}
 */
function interpretRelayResponse(response) {
  if (!isPlainRecord(response) || !Number.isInteger(response.status)) {
    return {
      accepted: false,
      delivered: 'unknown',
      code: 'RELAY_DISPATCH_UNCERTAIN',
      retryable: true,
      status: null,
    };
  }
  const { status } = response;
  if (status >= 200 && status < 300) {
    /**
     * A 2xx IS NOT AN ACCEPTANCE BY ITSELF — the relay states its verdict in its own body, and a
     * refusal must never be read as a success.
     *
     * The relay's Durable Object answers HTTP 200 for BOTH outcomes: `{ok:true, admitted:true, seq}`
     * when it forwards the frame, and `{ok:false, admitted:false, reason}` when it refuses it
     * (`NO_GRANT_FAIL_CLOSED`, `GRANT_EXPIRED`, `CALL_ID_IN_USE`, `PAYLOAD_MUST_BE_OPAQUE_STRING`, …).
     * This test previously looked only for `body.accepted === false` — a field the relay never sends —
     * so a refusal fell straight through to `accepted: true` and the platform recorded a dispatch the
     * relay had actually refused. That is a false success, the one outcome the outcome law forbids.
     *
     * Any explicit negative is now a refusal. The frozen contract that a 2xx WITHOUT an explicit
     * refusal is accepted is deliberately preserved — a bodiless 200 is accepted exactly as the
     * outcome-law suite pins — so this recognises the relay's real negative signals rather than
     * tightening the rule around them.
     */
    const body = response.body;
    const relayRefused =
      isPlainRecord(body) &&
      (body.accepted === false || body.admitted === false || body.ok === false);
    if (relayRefused) {
      return {
        accepted: false,
        delivered: 'refused',
        code: 'RELAY_REJECTED',
        retryable: false,
        status,
      };
    }
    return { accepted: true, delivered: 'accepted', code: null, retryable: false, status };
  }
  if (status >= 400 && status < 500) {
    return {
      accepted: false,
      delivered: 'refused',
      code: 'RELAY_REJECTED',
      retryable: status === 429,
      status,
    };
  }
  // 5xx (and anything non-2xx/4xx): the relay may have written-ahead and emitted the frame.
  return {
    accepted: false,
    delivered: 'unknown',
    code: 'RELAY_DISPATCH_UNCERTAIN',
    retryable: true,
    status,
  };
}

/**
 * Builds the `policy` block every parsed dispatch outcome carries. Every key is always present, so a
 * consumer (an audit trail, the panel, a spec) reads one shape and never has to guess whether a
 * missing key means "not applicable" or "the field was forgotten".
 *
 * `decision` is one of `POLICY_DECISIONS`; `code` is ALWAYS a registry code when the block can block
 * a dispatch; `approved` is `null` when the approval gate was never reached, `true`/`false` when it
 * was consulted.
 * @param {object} [fields]
 * @returns {Readonly<object>}
 */
function buildPolicyBlock(fields = {}) {
  return Object.freeze({
    schema: DISPATCH_TOOL_POLICY_SCHEMA,
    portState: POLICY_PORT_STATES.ARMED,
    evaluated: false,
    reason: null,
    stage: null,
    stageSource: null,
    ceilingCount: null,
    resolver: POLICY_RESOLVER_OUTCOMES.ABSENT,
    effectiveCount: 0,
    failClosed: false,
    decision: POLICY_DECISIONS.NOT_EVALUATED,
    code: null,
    httpStatus: null,
    requiresApproval: false,
    approved: null,
    deniedBy: null,
    tier: null,
    reasonCode: null,
    detail: null,
    ...fields,
  });
}

/**
 * Validates and freezes the injected tool-policy port, or returns `null` when none was supplied.
 *
 * The exact-key whitelist is the anti-synthesis guard, exactly as it is for the dispatch request and
 * the authority projection: a request-shaped value passed as the port is refused by name. A port that
 * is present but incomplete is refused at CONSTRUCTION rather than silently unarming the gate at
 * dispatch time — a half-wired gate is a defect, not a configuration.
 *
 * @param {unknown} policy
 * @returns {Readonly<object>|null}
 * @throws {RelayError} POLICY_SEAM_INVALID
 */
function readPolicyPort(policy) {
  if (policy === undefined || policy === null) {
    return null;
  }
  if (!isPlainRecord(policy)) {
    throw relayFailure(
      'POLICY_SEAM_INVALID',
      'the tool-policy port must be a plain object built by the server wiring, not a request-shaped value',
      { field: 'policy' },
    );
  }
  for (const key of Object.keys(policy)) {
    if (!POLICY_PORT_KEYS.includes(key)) {
      throw relayFailure(
        'POLICY_SEAM_INVALID',
        `the tool-policy port refuses the key "${key}"; policy is server data and never request data`,
        { field: key },
      );
    }
  }
  for (const key of POLICY_PORT_REQUIRED_KEYS) {
    if (policy[key] === undefined || policy[key] === null) {
      throw relayFailure(
        'POLICY_SEAM_INVALID',
        `the tool-policy port is incomplete: "${key}" is required for the dispatch gate to arm`,
        { field: key },
      );
    }
  }
  for (const key of ['ceilingForStage', 'authorizeDispatch']) {
    if (typeof policy[key] !== 'function') {
      throw relayFailure('POLICY_SEAM_INVALID', `the tool-policy port "${key}" must be a function`, {
        field: key,
      });
    }
  }
  if (!isPlainRecord(policy.dispatchCodes)) {
    throw relayFailure(
      'POLICY_SEAM_INVALID',
      'the tool-policy port "dispatchCodes" must be the registry\'s own DISPATCH_CODES record',
      { field: 'dispatchCodes' },
    );
  }
  if (typeof policy.dispatchCodes.NOT_PERMITTED !== 'string') {
    throw relayFailure(
      'POLICY_SEAM_INVALID',
      'the tool-policy port "dispatchCodes" must carry the registry\'s NOT_PERMITTED code; this path never invents a refusal code of its own',
      { field: 'dispatchCodes' },
    );
  }
  for (const key of ['resolve', 'hasOwnerApproval']) {
    if (policy[key] !== undefined && policy[key] !== null && typeof policy[key] !== 'function') {
      throw relayFailure(
        'POLICY_SEAM_INVALID',
        `the tool-policy port "${key}" must be a function when supplied`,
        { field: key },
      );
    }
  }
  if (
    policy.stage !== undefined &&
    policy.stage !== null &&
    typeof policy.stage !== 'string' &&
    typeof policy.stage !== 'function'
  ) {
    throw relayFailure(
      'POLICY_SEAM_INVALID',
      'the tool-policy port "stage" must be a stage name or a function returning one',
      { field: 'stage' },
    );
  }
  return Object.freeze({ ...policy });
}

/**
 * Resolves the SERVER stage and the ceiling it selects — the whole of the stage law, and the only
 * place a stage becomes a ceiling.
 *
 * The policy module is the authority on which stages exist: `ceilingForStage` refuses an unknown
 * stage, and that refusal NARROWS (the narrowest stage stands, with `unrecognised` reported and a
 * warning emitted by the caller) instead of widening. A stage source that cannot be read at all, or
 * a ceiling the narrow default cannot build, is `usable: false`: the caller then fails closed rather
 * than dispatching under a policy nobody could resolve.
 *
 * @param {Readonly<object>} port a validated tool-policy port
 * @returns {Readonly<{usable: boolean, stage: string, source: string, configured: (string|null),
 *   ceiling: (object|null), problem: (string|null)}>}
 */
function resolveDispatchStage(port) {
  let configured;
  if (port.stage !== undefined && port.stage !== null) {
    try {
      configured = typeof port.stage === 'function' ? port.stage() : port.stage;
    } catch {
      return Object.freeze({
        usable: false,
        stage: DEFAULT_SERVER_STAGE,
        source: STAGE_SOURCES.DEFAULT,
        configured: null,
        ceiling: null,
        problem: POLICY_REASONS.STAGE_UNUSABLE,
      });
    }
  }

  const unset = configured === undefined || configured === null || configured === '';
  if (!unset) {
    try {
      return Object.freeze({
        usable: true,
        stage: configured,
        source: STAGE_SOURCES.CONFIGURED,
        configured,
        ceiling: port.ceilingForStage(configured),
        problem: null,
      });
    } catch {
      /* Not a stage the server ceiling recognises: fall through to the narrow default. */
    }
  }

  try {
    return Object.freeze({
      usable: true,
      stage: DEFAULT_SERVER_STAGE,
      source: unset ? STAGE_SOURCES.DEFAULT : STAGE_SOURCES.UNRECOGNISED,
      configured: unset ? null : configured,
      ceiling: port.ceilingForStage(DEFAULT_SERVER_STAGE),
      problem: null,
    });
  } catch {
    return Object.freeze({
      usable: false,
      stage: DEFAULT_SERVER_STAGE,
      source: unset ? STAGE_SOURCES.DEFAULT : STAGE_SOURCES.UNRECOGNISED,
      configured: unset ? null : configured,
      ceiling: null,
      problem: POLICY_REASONS.STAGE_UNUSABLE,
    });
  }
}

/**
 * Reads the injected policy resolver's narrowing answer. Never throws, never repairs.
 *
 * The answer is a tool-name list, or a record carrying one (`{ tools: [...] }`) — the shape the W10
 * resolver already produces. Anything else is `unusable`, and a throw is `threw`; both yield an
 * EMPTY narrowing, so the registry refuses. That is the load-bearing security property of this seam:
 * a broken policy resolver can only ever narrow to nothing, never fall back to "allow".
 *
 * A list that IS a list of strings is passed on UNCHANGED (barring names the ceiling does not admit):
 * whether a list is a valid narrowing document — duplicates, wildcard sentinels, size — is the
 * registry's law to apply, and it is not restated here.
 *
 * @param {unknown} resolver
 * @param {Readonly<object>} context the frozen dispatch context (trusted identity + stage + ceiling)
 * @returns {Promise<Readonly<{outcome: string, tools: (string[]|null), problem: (string|null)}>>}
 */
async function readPolicyNarrowing(resolver, context) {
  if (typeof resolver !== 'function') {
    return Object.freeze({
      outcome: POLICY_RESOLVER_OUTCOMES.ABSENT,
      tools: null,
      problem: null,
    });
  }

  let answer;
  try {
    answer = await resolver(context);
  } catch {
    return Object.freeze({
      outcome: POLICY_RESOLVER_OUTCOMES.THREW,
      tools: Object.freeze([]),
      problem: 'the injected policy resolver threw, so nothing is narrowed in and nothing is enabled',
    });
  }

  const list = Array.isArray(answer)
    ? answer
    : isPlainRecord(answer) && Array.isArray(answer.tools)
      ? answer.tools
      : null;
  if (list === null || list.some((entry) => typeof entry !== 'string')) {
    return Object.freeze({
      outcome: POLICY_RESOLVER_OUTCOMES.UNUSABLE,
      tools: Object.freeze([]),
      problem:
        'the injected policy resolver did not answer with a list of tool names, so nothing is enabled',
    });
  }
  return Object.freeze({
    outcome: POLICY_RESOLVER_OUTCOMES.NARROWED,
    tools: Object.freeze([...list]),
    problem: null,
  });
}

/**
 * Consults the tier-3 approval seam. Only a literal `true` is an approval: a missing seam, a `false`,
 * a throw or any other value is a refusal, because an approval that cannot be established is not one.
 * @param {unknown} hasOwnerApproval
 * @param {Readonly<object>} context
 * @returns {Promise<boolean>}
 */
async function consultOwnerApproval(hasOwnerApproval, context) {
  if (typeof hasOwnerApproval !== 'function') {
    return false;
  }
  try {
    return (await hasOwnerApproval(context)) === true;
  } catch {
    return false;
  }
}

/** The registry's own code for a failure it named, else its own "not permitted" code. */
function registryFailureCode(err, dispatchCodes) {
  if (
    err !== null &&
    typeof err === 'object' &&
    typeof err.code === 'string' &&
    err.code.length > 0
  ) {
    return err.code;
  }
  return dispatchCodes.NOT_PERMITTED;
}

/** Fixed, payload-free failure notice; a throwing logger must never mask a dispatch outcome. */
function warnFixed(logger, message) {
  if (logger === null || logger === undefined || typeof logger.warn !== 'function') {
    return;
  }
  try {
    logger.warn(message);
  } catch {
    /* the dispatch outcome is unaffected */
  }
}

function failureResult(error, { delivered, requestId, deviceId }) {
  return Object.freeze({
    ok: false,
    code: error.code,
    message: error.message,
    retryable: error.retryable === true,
    delivered,
    requestId: requestId ?? null,
    deviceId: deviceId ?? null,
    error,
  });
}

/**
 * Builds the backend -> relay dispatch client.
 *
 * @param {object} options
 * @param {(request: {deviceId: string, frame: object}) => Promise<{status: number, body?: object}>}
 *   options.transport injected relay hop; owns URL, TLS and retry policy
 * @param {{keyId: string, signCore: Function}} options.signer the injected custody seam
 * @param {{now: () => number}} [options.clock] server clock (epoch-ms)
 * @param {object} options.replayWindow REQUIRED `createReplayWindow()` guard for unseen nonces; a
 *   null window is refused at construction, because a real dispatch without replay enforcement is a
 *   defect (replayWindow: null is permitted only for non-dispatch use of the primitives)
 * @param {{verifySignature: Function}} [options.verifier] optional pre-dispatch self-check
 * @param {(authority: object) => (boolean|Promise<boolean>)} [options.assertAuthorityCurrent]
 *   optional I-0 re-check inside the dispatch window
 * @param {object} [options.ledger] optional `createDispatchLedger()` surface `{ reserve(call), release(callId) }`:
 *   the correlation memory for the W6 uplink. Off by default; see the module header.
 * @param {object} [options.policy] THE TOOL-POLICY PORT (W12): `{ ceilingForStage, authorizeDispatch,
 *   dispatchCodes, stage?, resolve?, hasOwnerApproval? }`, built by the server wiring from
 *   `deviceCapabilityPolicy` and `deviceToolRegistry` (see the module header). Supplied => the gate
 *   is ARMED and every `opKind: 'command'` dispatch is checked against the server ceiling before
 *   anything is signed. Absent => no policy is consulted, and every outcome says so
 *   (`policy.evaluated: false, reason: 'policy-port-absent'`). Present but incomplete is refused
 *   here, at construction.
 * @param {object} [options.logger] fixed-message-only warn sink
 * @param {() => string} [options.nonceFactory] 128-bit CSPRNG nonce minter (injectable for tests)
 * @param {() => string} [options.requestIdFactory] UUIDv4 minter (injectable for tests)
 * @param {object} [options.crypto] accepted crypto module (canonicalisation stays in `../crypto`)
 * @returns {Readonly<{keyId: string, dispatchCommand: Function}>}
 */
function createRelayDispatchClient(options = {}) {
  const { transport, signer, replayWindow = null, verifier = null, assertAuthorityCurrent = null } =
    options;
  const ledger = options.ledger ?? null;
  const clock = options.clock ?? { now: () => Date.now() };
  const logger = options.logger ?? null;
  const cryptoModule = options.crypto ?? deviceCrypto;
  const nonceFactory = options.nonceFactory ?? defaultNonceFactory;
  const requestIdFactory = options.requestIdFactory ?? defaultRequestIdFactory;

  if (typeof transport !== 'function') {
    throw relayFailure(
      'SIGNER_SEAM_INVALID',
      'the relay dispatch client requires an injected transport function',
      { field: 'transport' },
    );
  }
  if (
    signer === null ||
    typeof signer !== 'object' ||
    typeof signer.signCore !== 'function' ||
    typeof signer.keyId !== 'string' ||
    signer.keyId.length === 0
  ) {
    throw relayFailure(
      'SIGNER_SEAM_INVALID',
      'the relay dispatch client requires the injected envelope signer seam { keyId, signCore }',
      { field: 'signer' },
    );
  }
  if (clock === null || typeof clock.now !== 'function') {
    throw relayFailure('CLOCK_UNUSABLE', 'the relay dispatch client requires a now() clock');
  }
  if (verifier !== null && typeof verifier.verifySignature !== 'function') {
    throw relayFailure(
      'SIGNER_SEAM_INVALID',
      'the dispatch self-check verifier must expose verifySignature()',
      { field: 'verifier' },
    );
  }
  // GM-49: replay enforcement may be opt-in for NON-dispatch use, but a real dispatch without a
  // replay window is a defect — it would let the same nonce be admitted twice. Refused at
  // construction, so no dispatch can ever run unprotected.
  if (replayWindow === null || replayWindow === undefined) {
    throw relayFailure(
      'SIGNER_SEAM_INVALID',
      'the relay dispatch client requires a replay window: a null replayWindow would accept a replayed nonce on a real dispatch (it is permitted only for non-dispatch use of the verification primitives)',
      { field: 'replayWindow' },
    );
  }
  if (typeof replayWindow.checkAndRemember !== 'function') {
    throw relayFailure(
      'SIGNER_SEAM_INVALID',
      'the replay window must expose checkAndRemember()',
      { field: 'replayWindow' },
    );
  }
  if (assertAuthorityCurrent !== null && typeof assertAuthorityCurrent !== 'function') {
    throw relayFailure(
      'SIGNER_SEAM_INVALID',
      'assertAuthorityCurrent must be a function when supplied',
      { field: 'assertAuthorityCurrent' },
    );
  }
  if (
    ledger !== null &&
    (typeof ledger !== 'object' ||
      typeof ledger.reserve !== 'function' ||
      typeof ledger.release !== 'function')
  ) {
    throw relayFailure(
      'DISPATCH_LEDGER_ENTRY_INVALID',
      'the dispatch ledger seam must expose { reserve(call), release(callId) } when supplied',
      { field: 'ledger' },
    );
  }
  if (typeof nonceFactory !== 'function' || typeof requestIdFactory !== 'function') {
    throw relayFailure(
      'SIGNER_SEAM_INVALID',
      'the nonce and request-id minters must be functions when supplied',
    );
  }
  // W12: the tool-policy port. Read (and refused) at CONSTRUCTION, so a half-wired gate can never
  // look armed at dispatch time. Absent on purpose for non-enforcing callers; the outcome then
  // declares `policy.evaluated: false` rather than pretending a policy was consulted.
  const policyPort = readPolicyPort(options.policy);

  /** Configured stage values already warned about, so one misconfiguration warns once per client. */
  const warnedStages = new Set();

  /**
   * Emits the ONE console-capable notice in this module: an unrecognised stage value is a
   * configuration fault that must not be silent, and the fix (a narrow default) is already applied.
   * It carries operator configuration only — never a payload, an identity or key material — and an
   * injected logger is always preferred over the console. A throwing sink never changes the stage.
   * @param {unknown} configured
   */
  function warnUnrecognisedStage(configured) {
    const shown = configured === null || configured === undefined ? 'null' : String(configured);
    if (warnedStages.has(shown)) {
      return;
    }
    warnedStages.add(shown);
    const message =
      `[relayDispatchClient] ignoring unrecognised ${CAPABILITY_STAGE_ENV}="${shown}"; ` +
      `using the narrowest stage "${DEFAULT_SERVER_STAGE}"`;
    if (logger !== null && typeof logger.warn === 'function') {
      warnFixed(logger, message);
      return;
    }
    try {
      console.warn(message);
    } catch {
      /* the narrow default stands whether or not the warning could be emitted */
    }
  }

  /**
   * THE TOOL-POLICY GATE. Evaluates the tier-1 ceiling, the optional narrowing resolver, the
   * registry's decision for this tool name and the tier-3 approval — in that order, before anything
   * is signed or sent. NEVER THROWS and never returns a block that would let an unresolved policy
   * through: every failure to resolve is expressed as a DENIED block carrying a registry code.
   *
   * @param {object} parsed the validated dispatch request
   * @returns {Promise<Readonly<object>>} the frozen policy block
   */
  async function evaluateDispatchPolicy(parsed) {
    if (policyPort === null) {
      return buildPolicyBlock({
        portState: POLICY_PORT_STATES.ABSENT,
        reason: POLICY_REASONS.POLICY_PORT_ABSENT,
      });
    }
    if (parsed.opKind !== RPC_OP_KINDS.COMMAND) {
      return buildPolicyBlock({
        portState: POLICY_PORT_STATES.ARMED,
        reason: POLICY_REASONS.NOT_A_TOOL_EXECUTION,
      });
    }

    const stageDecision = resolveDispatchStage(policyPort);
    if (stageDecision.source === STAGE_SOURCES.UNRECOGNISED) {
      warnUnrecognisedStage(stageDecision.configured);
    }
    if (stageDecision.usable !== true) {
      return buildPolicyBlock({
        portState: POLICY_PORT_STATES.ARMED,
        evaluated: true,
        reason: POLICY_REASONS.STAGE_UNUSABLE,
        failClosed: true,
        decision: POLICY_DECISIONS.DENIED,
        code: policyPort.dispatchCodes.NOT_PERMITTED,
        httpStatus: 403,
        detail:
          'The server capability stage could not be resolved, so no tool policy is available and nothing is permitted (fail closed).',
      });
    }

    // The resolver and the approval seam see trusted identity only: the authority projection is the
    // server-observed one the caller supplied, never a request field, and the ceiling is server data.
    const context = Object.freeze({
      schema: DISPATCH_TOOL_POLICY_SCHEMA,
      authority: parsed.authority,
      toolName: parsed.toolName,
      opKind: parsed.opKind,
      callId: parsed.callId,
      stage: stageDecision.stage,
      stageSource: stageDecision.source,
      ceiling: stageDecision.ceiling,
    });

    const narrowing = await readPolicyNarrowing(policyPort.resolve, context);
    const ceilingTools = Array.isArray(stageDecision.ceiling.tools)
      ? stageDecision.ceiling.tools
      : null;
    const admitted = ceilingTools === null ? null : new Set(ceilingTools);

    let floorTools;
    if (narrowing.outcome === POLICY_RESOLVER_OUTCOMES.NARROWED) {
      // The claim is passed on UNCHANGED, barring nothing: whether a narrowing document is valid —
      // duplicates, wildcard sentinels, size — is the registry's law to apply, and applying it here
      // as well would let the panel's report and a dispatch refusal disagree about ONE document. A
      // name the ceiling does not admit still cannot widen anything: the registry checks the ceiling
      // before it ever looks at the narrowing.
      floorTools = [...narrowing.tools];
    } else if (narrowing.outcome === POLICY_RESOLVER_OUTCOMES.ABSENT) {
      // No resolver: the stage ceiling ALONE is authoritative (GM-75 retired the device floor, so
      // nothing narrows by default). The narrowing document therefore claims exactly the ceiling.
      if (ceilingTools === null) {
        return buildPolicyBlock({
          portState: POLICY_PORT_STATES.ARMED,
          evaluated: true,
          reason: POLICY_REASONS.POLICY_UNAVAILABLE,
          stage: stageDecision.stage,
          stageSource: stageDecision.source,
          resolver: narrowing.outcome,
          failClosed: true,
          decision: POLICY_DECISIONS.DENIED,
          code: policyPort.dispatchCodes.NOT_PERMITTED,
          httpStatus: 403,
          detail:
            'The server ceiling did not carry a tool list, so the effective set could not be established and nothing is permitted (fail closed).',
        });
      }
      floorTools = [...ceilingTools];
    } else {
      // The resolver threw or answered unusably: an EMPTY narrowing, so the registry refuses with
      // its own tier code. Fail closed — never "allow because the policy engine was unavailable".
      floorTools = [];
    }

    const resolverFailed =
      narrowing.outcome === POLICY_RESOLVER_OUTCOMES.THREW ||
      narrowing.outcome === POLICY_RESOLVER_OUTCOMES.UNUSABLE;
    // Diagnostic only, never a decision: how many of the claimed names the ceiling actually admits.
    // With no resolver the claim is the ceiling itself; with a broken one it is nothing.
    const effectiveCount =
      ceilingTools === null
        ? null
        : narrowing.tools === null
          ? ceilingTools.length
          : narrowing.tools.filter((name) => typeof name === 'string' && admitted.has(name.trim()))
              .length;
    const common = {
      portState: POLICY_PORT_STATES.ARMED,
      evaluated: true,
      reason: resolverFailed ? POLICY_REASONS.RESOLVER_UNUSABLE : null,
      stage: stageDecision.stage,
      stageSource: stageDecision.source,
      ceilingCount: ceilingTools === null ? null : ceilingTools.length,
      resolver: narrowing.outcome,
      effectiveCount,
      failClosed: resolverFailed,
    };

    /** A policy the registry would not answer for is a refusal, with the registry's own code. */
    const policyUnavailable = (fields = {}) =>
      buildPolicyBlock({
        ...common,
        failClosed: true,
        decision: POLICY_DECISIONS.DENIED,
        code: policyPort.dispatchCodes.NOT_PERMITTED,
        httpStatus: 403,
        detail:
          'The server tool policy could not be resolved for this dispatch, so nothing is permitted (fail closed).',
        ...fields,
      });

    let decision;
    try {
      decision = policyPort.authorizeDispatch(parsed.toolName, {
        ceiling: stageDecision.ceiling,
        deviceFloor: { enabled: floorTools },
      });
    } catch (err) {
      return policyUnavailable({ code: registryFailureCode(err, policyPort.dispatchCodes) });
    }
    if (decision === null || typeof decision !== 'object') {
      return policyUnavailable();
    }

    if (decision.allowed !== true) {
      if (typeof decision.code !== 'string' || decision.code.length === 0) {
        // A refusal with no registry code would be an unlabelled refusal: a wiring fault, not policy.
        return policyUnavailable();
      }
      // The registry refused the narrowing DOCUMENT itself (`TOOL_DEVICE_FLOOR_MALFORMED` /
      // `_ABSENT`, its own fail-closed pair): a wildcard sentinel, a duplicate or an over-long list
      // is a narrowing that enabled nothing, not a narrowing that was honoured.
      const narrowingRefused =
        decision.code === policyPort.dispatchCodes.DEVICE_FLOOR_MALFORMED ||
        decision.code === policyPort.dispatchCodes.DEVICE_FLOOR_ABSENT;
      return buildPolicyBlock({
        ...common,
        reason: resolverFailed
          ? POLICY_REASONS.RESOLVER_UNUSABLE
          : narrowingRefused
            ? POLICY_REASONS.NARROWING_REFUSED
            : null,
        failClosed: resolverFailed || narrowingRefused,
        decision: POLICY_DECISIONS.DENIED,
        code: decision.code,
        httpStatus: Number.isInteger(decision.httpStatus) ? decision.httpStatus : 403,
        deniedBy: decision.deniedBy ?? null,
        tier: decision.tier ?? null,
        reasonCode: decision.reasonCode ?? null,
        detail: decision.reason ?? null,
      });
    }

    const approvalRequired = decision.requiresApproval === true;
    const admittedBlock = {
      ...common,
      decision: approvalRequired ? POLICY_DECISIONS.APPROVAL_REQUIRED : POLICY_DECISIONS.ALLOWED,
      code: typeof decision.code === 'string' ? decision.code : null,
      // A tier-3 admission is carried as `requiresApproval`, so the caller (and this client) can
      // never read an approval-gated decision as a plain allow.
      requiresApproval: approvalRequired,
      tier: decision.tier ?? null,
      reasonCode: decision.reasonCode ?? null,
      detail: decision.reason ?? null,
    };
    if (!approvalRequired) {
      return buildPolicyBlock(admittedBlock);
    }
    // Tier 3 is never a plain allow: the tool dispatches only when the approval seam says yes. The
    // refusal keeps this same block, with `approved: false`, so the two paths stay distinguishable.
    const approved = await consultOwnerApproval(policyPort.hasOwnerApproval, context);
    return buildPolicyBlock({
      ...admittedBlock,
      approved,
      httpStatus: approved ? null : 403,
    });
  }

  /**
   * The refusal outcome for a dispatch the policy gate did not admit. The code is ALWAYS the
   * registry's (`policy.code`), the status is the policy status when the registry named one, and
   * `delivered: 'no'` means nothing was signed and nothing was sent.
   * @param {Readonly<object>} policy a DENIED, or approval-withheld, policy block
   * @returns {Readonly<object>}
   */
  function policyRefusal(policy) {
    if (typeof policy.code !== 'string' || policy.code.length === 0) {
      return Object.freeze({
        ...failureResult(
          relayFailure(
            'POLICY_SEAM_INVALID',
            'the tool-policy gate blocked a dispatch without a registry code',
            { field: 'policy' },
          ),
          { delivered: 'no' },
        ),
        policy,
      });
    }
    const error = relayFailure(
      policy.code,
      policy.requiresApproval === true && policy.approved !== true
        ? `the dispatch was refused: owner approval was not established (${policy.code})`
        : policy.detail ?? `dispatch refused by tool policy: ${policy.code}`,
      { httpStatus: Number.isInteger(policy.httpStatus) ? policy.httpStatus : 403 },
    );
    return Object.freeze({ ...failureResult(error, { delivered: 'no' }), policy });
  }

  /**
   * Signs and dispatches one command frame to the relay.
   * @param {object} request see `DISPATCH_REQUEST_KEYS`
   * @returns {Promise<object>} typed outcome; never throws for an expected failure
   */
  async function dispatchCommand(request = {}) {
    let parsed;
    try {
      parsed = parseDispatchRequest(request);
    } catch (err) {
      if (!isRelayError(err)) {
        throw err;
      }
      return failureResult(err, { delivered: 'no' });
    }

    // ── W12: THE TOOL-POLICY GATE ───────────────────────────────────────────────────────────────
    // The gate runs HERE, before the clock, the nonce, the replay window, the envelope, the
    // signature, the ledger and the wire. A tool the policy does not admit (or an approval-gated
    // tool whose approval was not established) never becomes a frame — see the module header.
    const policy = await evaluateDispatchPolicy(parsed);
    if (
      policy.decision === POLICY_DECISIONS.DENIED ||
      (policy.requiresApproval === true && policy.approved !== true)
    ) {
      return policyRefusal(policy);
    }

    const outcome = await signAndSend(parsed);
    // Every dispatched outcome carries the block, so a caller can see which tier decided what.
    return Object.freeze({ ...outcome, policy });
  }

  /**
   * Signs and hands one ALREADY-PARSED, ALREADY-POLICY-ADMITTED dispatch to the relay hop. This is
   * the W2 path unchanged: policy never touches identity, the envelope, the ledger or the wire.
   * @param {object} parsed the validated dispatch request
   * @returns {Promise<object>} typed outcome (no `policy` block; `dispatchCommand` attaches it)
   */
  async function signAndSend(parsed) {
    const { authority, toolName, opKind, audience, argsDigestHex, argsB64u, seq, idempotencyKey, callId } =
      parsed;

    const now = clock.now();
    if (!Number.isSafeInteger(now) || now < 0) {
      return failureResult(
        relayFailure('CLOCK_UNUSABLE', 'the dispatch clock did not return epoch milliseconds'),
        { delivered: 'no' },
      );
    }
    const windowMs = freshnessWindowMsFor(audience);
    const issuedAt = String(now);
    const deadlineMs = String(now + windowMs);
    const nonce = nonceFactory();
    const requestId = requestIdFactory();

    // Unconditional: the construction guard refuses a client without a replay window (GM-49).
    if (typeof replayWindow.checkAndRemember !== 'function') {
      return failureResult(
        relayFailure('SIGNER_SEAM_INVALID', 'the replay window must expose checkAndRemember()'),
        { delivered: 'no' },
      );
    }
    const reservation = await replayWindow.checkAndRemember({
      grantId: authority.grantId,
      nonce,
      freshUntilMs: now + windowMs,
    });
    if (reservation.ok !== true) {
      return failureResult(reservation.error, { delivered: 'no', requestId });
    }

    let core;
    try {
      core = buildEnvelopeCore(
        {
          requestId,
          nonce,
          issuedAt,
          deadlineMs,
          epoch: String(authority.epoch),
          grantId: authority.grantId,
          ownerPrincipalId: authority.ownerPrincipalId,
          tenantId: authority.tenantId,
          deviceId: authority.deviceId,
          deviceKeyId: authority.deviceKeyId,
          toolName,
          opKind,
          audience,
          argsDigestHex,
        },
        { crypto: cryptoModule },
      );
    } catch (err) {
      if (!isRelayError(err)) {
        throw err;
      }
      return failureResult(err, { delivered: 'no', requestId });
    }

    let signed;
    try {
      signed = await signer.signCore(core);
    } catch (err) {
      if (!isRelayError(err)) {
        throw err;
      }
      return failureResult(err, { delivered: 'no', requestId });
    }

    if (verifier !== null) {
      const selfCheck = verifier.verifySignature(signed);
      if (selfCheck.ok !== true) {
        return failureResult(selfCheck.error, { delivered: 'no', requestId });
      }
    }

    if (assertAuthorityCurrent !== null) {
      let current;
      try {
        current = await assertAuthorityCurrent(Object.freeze({ ...authority }));
      } catch {
        current = false;
      }
      if (current !== true) {
        return failureResult(
          authorityMismatch(
            'the dispatch authority is no longer current; nothing was sent',
            'authority',
          ),
          { delivered: 'no', requestId },
        );
      }
    }

    let frame;
    try {
      frame = toWireFrame({ signed, argsB64u, seq, idempotencyKey, callId });
    } catch (err) {
      if (!isRelayError(err)) {
        throw err;
      }
      return failureResult(err, { delivered: 'no', requestId });
    }

    // W6/GM-43: reserve the call BEFORE it can reach the wire, so the ledger holds
    // exactly the calls a result may legitimately be correlated to.
    let reserved = false;
    if (ledger !== null && callId !== null) {
      try {
        const reservation = await ledger.reserve({
          callId,
          deviceId: authority.deviceId,
          deviceKeyId: authority.deviceKeyId,
          tenantId: authority.tenantId,
          grantId: authority.grantId,
          epoch: authority.epoch,
          requestId,
          toolName,
          opKind,
        });
        if (reservation.ok !== true) {
          return failureResult(reservation.error, { delivered: 'no', requestId, deviceId: authority.deviceId });
        }
        reserved = true;
      } catch (err) {
        warnFixed(logger, 'dispatch ledger reservation failed');
        return failureResult(
          relayFailure(
            'DISPATCH_LEDGER_ENTRY_INVALID',
            'the dispatch ledger could not record this call, so no result could ever be correlated to it; nothing was sent',
            { cause: err },
          ),
          { delivered: 'no', requestId, deviceId: authority.deviceId },
        );
      }
    }

    let response;
    try {
      response = await transport({ deviceId: authority.deviceId, frame });
    } catch (err) {
      warnFixed(logger, 'relay dispatch transport failure');
      return failureResult(
        relayFailure(
          'RELAY_DISPATCH_UNCERTAIN',
          'the relay hop failed after signing; the frame may have been delivered, so the outcome is unknown',
          { cause: err, retryable: true },
        ),
        { delivered: 'unknown', requestId, deviceId: authority.deviceId },
      );
    }

    const verdict = interpretRelayResponse(response);
    if (verdict.accepted !== true) {
      if (reserved === true && verdict.delivered === 'refused' && ledger !== null) {
        // The relay did not forward it, so no result can legitimately arrive: withdraw the call so a
        // stray result for that call id is refused as unknown instead of completing a call never sent.
        try {
          await ledger.release(callId, 'relay-refused');
        } catch {
          warnFixed(logger, 'dispatch ledger release failed');
        }
      }
      if (verdict.delivered === 'unknown') {
        warnFixed(logger, 'relay dispatch outcome uncertain');
      }
      return failureResult(
        relayFailure(
          verdict.code,
          verdict.code === 'RELAY_REJECTED'
            ? 'the relay refused the frame'
            : 'the relay hop outcome is unknown; treat it as unknown-outcome, never as success',
          { retryable: verdict.retryable },
        ),
        { delivered: verdict.delivered, requestId, deviceId: authority.deviceId },
      );
    }

    return Object.freeze({
      ok: true,
      requestId,
      deviceId: authority.deviceId,
      grantId: authority.grantId,
      epoch: authority.epoch,
      audience,
      seq: frame.seq ?? null,
      status: verdict.status,
      delivered: verdict.delivered,
    });
  }

  return Object.freeze({ keyId: signer.keyId, dispatchCommand });
}

module.exports = {
  TRUSTED_AUTHORITY_FIELDS,
  DISPATCH_REQUEST_KEYS,
  // W12 — the tool-policy gate: the port's keys, the stage law and the vocabulary a caller (or CI)
  // asserts against without reading prose.
  POLICY_PORT_KEYS,
  POLICY_PORT_REQUIRED_KEYS,
  CAPABILITY_STAGE_ENV,
  DEFAULT_SERVER_STAGE,
  STAGE_SOURCES,
  POLICY_PORT_STATES,
  POLICY_RESOLVER_OUTCOMES,
  POLICY_DECISIONS,
  POLICY_REASONS,
  DISPATCH_TOOL_POLICY_SCHEMA,
  assertTrustedDispatchAuthority,
  trustedAuthorityFromDeviceRow,
  resolveDispatchArgs,
  parseDispatchRequest,
  interpretRelayResponse,
  readPolicyPort,
  resolveDispatchStage,
  readPolicyNarrowing,
  consultOwnerApproval,
  buildPolicyBlock,
  createRelayDispatchClient,
};