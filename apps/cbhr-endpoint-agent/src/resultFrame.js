'use strict';

/**
 * CBHR ENDPOINT AGENT — device-signed result frames (workstream W7 / W6 uplink seam).
 *
 * DIRECTION BINDING. Commands arrive with `audience:'endpoint'`, signed by the BACKEND key. Results
 * leave with `audience:'relay'`, signed by the DEVICE key. Neither signature can be replayed as the
 * other: the audience is inside the canonical string (field 14), the signing key is different, and
 * the domain tag differs. That is the "both directions" rule (C06 finding 3) and it is what makes a
 * result unforgeable by the relay as well as by the platform.
 *
 * WHY THE RESULT CORE HAS ITS OWN DOMAIN TAG
 * The frozen command string is `CBHR-RPC-V2 ‖ requestId ‖ nonce ‖ ... ‖ audience ‖ sha256(args)`.
 * A result frame is not a command: its `audience` is `relay`, it carries no `toolName`/`opKind`
 * semantics the server resolves, and its field 15 binds the RESULT bytes rather than the argument
 * bytes. Reusing the command tag for a differently-shaped document would be the "two documents, one
 * domain" ambiguity the tag exists to prevent, so results use `CBHR-RPC-RESULT-V2` — a DISTINCT
 * prefix, so a result signature can never be presented as a command signature or vice versa.
 *
 * HONEST STATUS REPORTING (the outcome law)
 * `outcome` is one of three values and is bound INSIDE the signature, so a result cannot be
 * re-labelled in flight:
 *
 *   'succeeded'  the tool ran and the platform is being told what it produced
 *   'refused'    the endpoint (or a tool policy) declined, and nothing executed
 *   'uncertain'  the endpoint cannot prove what happened — a tool threw, the workspace failed, the
 *                result could not be persisted. NEVER reported as success.
 *
 * A refusal that happens before the core is authentic (bad signature, bad shape) still carries the
 * frame's CLAIMED `requestId`/`callId`, because the platform has to correlate the refusal with the
 * call it dispatched; the signature makes the refusal authentic, while the claim stays explicitly a
 * claim (`correlation: 'unverified-claim'`).
 */

const nodeCrypto = require('node:crypto');

const { refusal } = require('./errors');
const {
  RESULT_TAG,
  UNIT_SEPARATOR,
  decodeArgsBytes,
  assertTransportText,
} = require('./layout');
const { canonicalEncode, verifyEd25519 } = require('./vendoredCrypto');
const { sha256Hex } = require('./freshness');

/** The three outcomes. `uncertain` exists so "I do not know" is never spelled "success". */
const OUTCOMES = Object.freeze({
  SUCCEEDED: 'succeeded',
  REFUSED: 'refused',
  UNCERTAIN: 'uncertain',
});

/** Field order of the result core. Same 0x1F law, twelve fields, own tag. */
const RESULT_FIELD_ORDER = Object.freeze([
  'tag',
  'requestId',
  'callId',
  'nonce',
  'issuedAt',
  'deadlineMs',
  'grantId',
  'epoch',
  'deviceId',
  'deviceKeyId',
  'outcome',
  'argsDigestHex',
]);

/** The relay's reply freshness window (GM-32: replies get 120 s, commands get 60 s). */
const RESULT_WINDOW_MS = 120000;

/** A fresh 128-bit nonce per result. The command's nonce is never reused (it is already spent). */
function freshNonce() {
  return nodeCrypto.randomBytes(16).toString('base64url');
}

function assertResultText(property, value, fallback) {
  const candidate = typeof value === 'string' && value.length > 0 && !value.includes(UNIT_SEPARATOR)
    ? value
    : fallback;
  return candidate;
}

/**
 * Builds the canonical bytes of a result core. Exported so a reviewer (and the test suite) can check
 * the exact signed bytes without re-implementing the join.
 * @param {object} core
 * @returns {Buffer}
 */
function resultCanonicalBytes(core) {
  const fields = RESULT_FIELD_ORDER.slice(1).map((property) => {
    const value = core[property];
    if (typeof value !== 'string') {
      throw refusal('ENDPOINT_RESULT_ASSEMBLY_FAILED', 'a result core field is not a string', {
        field: property,
      });
    }
    return value;
  });
  try {
    return canonicalEncode({ domainTag: core.tag, fields });
  } catch (err) {
    throw refusal('ENDPOINT_RESULT_ASSEMBLY_FAILED', 'the result core is not canonical under the 0x1F law', {
      field: 'resultCore',
      cause: err,
    });
  }
}

/**
 * Produces a signed `audience:'relay'` result frame correlating by `callId`.
 *
 * @param {object} params
 * @param {object} params.keystore the device keystore (`keystore.loadDeviceKeystore`)
 * @param {string} params.deviceId
 * @param {'succeeded'|'refused'|'uncertain'} params.outcome
 * @param {Buffer|string} params.payloadBytes the result payload; its sha256 becomes field 15
 * @param {string} [params.errorCode] the refusal/uncertainty code, when there is one
 * @param {object} [params.correlation] `{ requestId, callId, grantId, epoch, correlation }`
 * @param {() => number} [params.now]
 * @returns {Readonly<object>} the flat result frame
 */
function buildResultFrame(params = {}) {
  const { keystore, deviceId, outcome, payloadBytes } = params;
  if (keystore === null || typeof keystore !== 'object' || typeof keystore.sign !== 'function') {
    throw refusal('ENDPOINT_RESULT_ASSEMBLY_FAILED', 'a result frame needs the device keystore to sign it');
  }
  if (!Object.values(OUTCOMES).includes(outcome)) {
    throw refusal('ENDPOINT_RESULT_ASSEMBLY_FAILED', 'the result outcome must be succeeded, refused or uncertain');
  }
  if (typeof deviceId !== 'string' || deviceId.length === 0) {
    throw refusal('ENDPOINT_RESULT_ASSEMBLY_FAILED', 'a result frame needs this endpoint device id');
  }
  const bytes = Buffer.isBuffer(payloadBytes)
    ? payloadBytes
    : payloadBytes === undefined || payloadBytes === null
      ? Buffer.alloc(0)
      : decodeArgsBytes(String(payloadBytes));
  if (bytes === null) {
    throw refusal('ENDPOINT_RESULT_ASSEMBLY_FAILED', 'the result payload must be canonical unpadded base64url');
  }

  const clock = typeof params.now === 'function' ? params.now : () => Date.now();
  const issuedAtMs = clock();
  if (!Number.isSafeInteger(issuedAtMs) || issuedAtMs < 0) {
    throw refusal('ENDPOINT_CLOCK_UNUSABLE', 'the result clock did not return epoch milliseconds');
  }
  const correlation = params.correlation ?? {};
  const deviceKeyId = keystore.keyId();

  const core = Object.freeze({
    tag: RESULT_TAG,
    // Correlation values travel with the frame because the platform keys its sink by `callId`. When
    // the incoming frame failed verification these are CLAIMS: the signature authenticates the
    // refusal, not the claim, and `correlation` records which of the two this is.
    requestId: assertResultText('requestId', correlation.requestId, 'unknown'),
    callId: assertResultText('callId', correlation.callId, 'unknown'),
    nonce: freshNonce(),
    issuedAt: String(issuedAtMs),
    deadlineMs: String(issuedAtMs + RESULT_WINDOW_MS),
    grantId: assertResultText('grantId', correlation.grantId, 'unknown'),
    epoch: assertResultText('epoch', correlation.epoch, '1'),
    deviceId,
    deviceKeyId,
    outcome,
    argsDigestHex: sha256Hex(bytes),
  });

  const canonical = resultCanonicalBytes(core);
  const signatureB64u = keystore.sign(canonical);

  const frame = Object.freeze({
    tag: core.tag,
    requestId: core.requestId,
    callId: core.callId,
    nonce: core.nonce,
    issuedAt: core.issuedAt,
    deadlineMs: core.deadlineMs,
    grantId: core.grantId,
    epoch: core.epoch,
    deviceId: core.deviceId,
    deviceKeyId: core.deviceKeyId,
    outcome: core.outcome,
    argsDigestHex: core.argsDigestHex,
    // Unsigned transport metadata, exactly as on the command leg (GM-31 / GM-47 / GM-35).
    signatureB64u,
    keyId: deviceKeyId,
    argsB64u: bytes.toString('base64url'),
    audience: 'relay',
    direction: 'endpoint-to-relay',
    ...(typeof params.errorCode === 'string' && params.errorCode.length > 0
      ? { errorCode: assertTransportText('errorCode', params.errorCode) }
      : {}),
    correlation: typeof correlation.correlation === 'string' && correlation.correlation.length > 0
      ? correlation.correlation
      : 'verified',
    ...(params.seq === undefined || params.seq === null ? {} : { seq: params.seq }),
  });
  return frame;
}

/**
 * Verifies a result frame against a DEVICE public key — the mirror of `verifyCommandFrame`, used by
 * the W6 sink tests (and by this repo's own tests) to prove a result cannot be forged by the relay.
 * It is deliberately a small, separate reader rather than a mode switch on the command verifier: the
 * two documents have different tags and different fields.
 *
 * @param {object} params
 * @param {object} params.frame
 * @param {string} params.devicePublicKeySpkiB64u
 * @returns {{ok: true, core: object, payloadBytes: Buffer} | {ok: false, error: import('./errors').EndpointRefusal}}
 */
function verifyResultFrame(params = {}) {
  const { frame, devicePublicKeySpkiB64u } = params;
  try {
    if (frame === null || typeof frame !== 'object' || Array.isArray(frame)) {
      throw refusal('ENDPOINT_RESULT_ASSEMBLY_FAILED', 'a result frame must be a flat object');
    }
    if (frame.audience !== 'relay') {
      throw refusal('ENDPOINT_AUDIENCE_MISMATCH', 'a result frame must carry audience "relay"', {
        field: 'audience',
      });
    }
    if (frame.tag !== RESULT_TAG) {
      throw refusal('ENDPOINT_ENVELOPE_SHAPE_INVALID', 'a result frame must carry the result domain tag', {
        field: 'tag',
      });
    }
    const core = {};
    for (const property of RESULT_FIELD_ORDER) {
      core[property] = frame[property];
    }
    const canonical = resultCanonicalBytes(core);
    const verified = verifyEd25519({
      publicKeySpkiB64u: devicePublicKeySpkiB64u,
      message: canonical,
      signatureB64u: frame.signatureB64u,
    });
    if (verified !== true) {
      throw refusal('ENDPOINT_SIGNATURE_INVALID', 'the result signature does not verify against the device key', {
        field: 'signatureB64u',
      });
    }
    const payloadBytes = decodeArgsBytes(frame.argsB64u);
    if (payloadBytes === null || sha256Hex(payloadBytes) !== core.argsDigestHex) {
      throw refusal('ENDPOINT_ARGS_DIGEST_MISMATCH', 'the result payload bytes do not hash to the signed digest', {
        field: 'argsB64u',
      });
    }
    return { ok: true, core: Object.freeze(core), payloadBytes };
  } catch (err) {
    if (err && err.name === 'EndpointRefusal') {
      return { ok: false, error: err };
    }
    return {
      ok: false,
      error: refusal('ENDPOINT_RESULT_ASSEMBLY_FAILED', 'the result frame could not be read', { cause: err }),
    };
  }
}

module.exports = {
  OUTCOMES,
  RESULT_FIELD_ORDER,
  RESULT_WINDOW_MS,
  resultCanonicalBytes,
  buildResultFrame,
  verifyResultFrame,
};