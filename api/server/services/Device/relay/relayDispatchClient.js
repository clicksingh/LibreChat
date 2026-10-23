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
 *   protocol. The backend mints `audience: 'endpoint'` only (`ENVELOPE_AUDIENCE_NOT_DISPATCHABLE`).
 *
 * OUTCOME LAW (F-V24C-9: unknown-outcome is never success)
 * - `delivered: 'accepted'` only for a 2xx relay answer that does not explicitly refuse.
 * - `delivered: 'refused'` for a 4xx answer or `{accepted:false}`: the relay did not forward it.
 * - `delivered: 'unknown'` for a transport throw/timeout/malformed answer or a 5xx: the relay may
 *   have written-ahead and emitted the frame before failing. The caller MUST treat that as an
 *   unknown outcome, never as a success and never as a blind retry of the same envelope.
 * - `delivered: 'no'` when nothing was signed or sent (shape, authority, replay, self-check).
 *
 * THE HOP ITSELF
 * The HTTP transport is INJECTED (`transport({ deviceId, frame })`). This module deliberately does
 * not freeze a relay URL path: the relay (workstream W1) has not defined its route yet, and inventing
 * one here would be a format invention, not a contract. L (integration) wires the transport; the
 * frame shape below is what crosses that seam.
 */

const nodeCrypto = require('node:crypto');
const deviceCrypto = require('../crypto');
const {
  RPC_ENVELOPE_AUDIENCES,
  RPC_OP_KINDS,
  buildEnvelopeCore,
  toWireFrame,
  isPlainRecord,
} = require('./envelopeCore');
const { resolveArgsDigestHex } = require('./argsDigest');
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

/** The ONLY request keys `dispatchCommand` accepts. Nothing else is read, ever. */
const DISPATCH_REQUEST_KEYS = Object.freeze([
  'authority',
  'toolName',
  'opKind',
  'argsBytes',
  'argsDigestB64u',
  'argsDigestHex',
  'audience',
  'seq',
  'idempotencyKey',
  'callId',
]);

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

  const argsSources = [
    request.argsBytes !== undefined && request.argsBytes !== null,
    request.argsDigestB64u !== undefined && request.argsDigestB64u !== null,
    request.argsDigestHex !== undefined && request.argsDigestHex !== null,
  ].filter(Boolean).length;
  if (argsSources !== 1) {
    throw relayFailure(
      'ENVELOPE_ARGS_INVALID',
      'dispatch requires exactly one of argsBytes | argsDigestB64u | argsDigestHex for sha256(args)',
      { field: 'argsDigestHex' },
    );
  }
  let argsDigestHex;
  if (request.argsDigestHex !== undefined && request.argsDigestHex !== null) {
    argsDigestHex = request.argsDigestHex;
  } else if (request.argsDigestB64u !== undefined && request.argsDigestB64u !== null) {
    argsDigestHex = resolveArgsDigestHex({ digestB64u: request.argsDigestB64u });
  } else {
    argsDigestHex = resolveArgsDigestHex({ bytes: request.argsBytes });
  }

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
    if (isPlainRecord(response.body) && response.body.accepted === false) {
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
 * @param {object} [options.replayWindow] `createReplayWindow()` guard for unseen nonces
 * @param {{verifySignature: Function}} [options.verifier] optional pre-dispatch self-check
 * @param {(authority: object) => (boolean|Promise<boolean>)} [options.assertAuthorityCurrent]
 *   optional I-0 re-check inside the dispatch window
 * @param {object} [options.logger] fixed-message-only warn sink
 * @param {() => string} [options.nonceFactory] 128-bit CSPRNG nonce minter (injectable for tests)
 * @param {() => string} [options.requestIdFactory] UUIDv4 minter (injectable for tests)
 * @param {object} [options.crypto] accepted crypto module (canonicalisation stays in `../crypto`)
 * @returns {Readonly<{keyId: string, dispatchCommand: Function}>}
 */
function createRelayDispatchClient(options = {}) {
  const { transport, signer, replayWindow = null, verifier = null, assertAuthorityCurrent = null } =
    options;
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
  if (assertAuthorityCurrent !== null && typeof assertAuthorityCurrent !== 'function') {
    throw relayFailure(
      'SIGNER_SEAM_INVALID',
      'assertAuthorityCurrent must be a function when supplied',
      { field: 'assertAuthorityCurrent' },
    );
  }
  if (typeof nonceFactory !== 'function' || typeof requestIdFactory !== 'function') {
    throw relayFailure(
      'SIGNER_SEAM_INVALID',
      'the nonce and request-id minters must be functions when supplied',
    );
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
    const { authority, toolName, opKind, audience, argsDigestHex, seq, idempotencyKey, callId } =
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

    if (replayWindow !== null) {
      if (typeof replayWindow.checkAndRemember !== 'function') {
        return failureResult(
          relayFailure('SIGNER_SEAM_INVALID', 'the replay window must expose checkAndRemember()'),
          { delivered: 'no' },
        );
      }
      const reservation = await replayWindow.checkAndRemember({
        grantId: authority.grantId,
        nonce,
      });
      if (reservation.ok !== true) {
        return failureResult(reservation.error, { delivered: 'no', requestId });
      }
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
      frame = toWireFrame({ signed, seq, idempotencyKey, callId });
    } catch (err) {
      if (!isRelayError(err)) {
        throw err;
      }
      return failureResult(err, { delivered: 'no', requestId });
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
  assertTrustedDispatchAuthority,
  trustedAuthorityFromDeviceRow,
  parseDispatchRequest,
  interpretRelayResponse,
  createRelayDispatchClient,
};