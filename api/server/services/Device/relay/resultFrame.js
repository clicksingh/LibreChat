'use strict';

/**
 * `CBHR-RPC-RESULT-V2` — the device -> platform RESULT frame, read by the AUTHORITY side.
 *
 * CONTRACT OF RECORD: GM-80 (`docs/GM-RULING-RESULT-FRAME-V2-20261023.md`) §2 and §4, which rule
 * that the endpoint agent's (W7) result frame definition WINS, and that this side adapts.

 * WHY A SEPARATE DOCUMENT, AND A SEPARATE MODULE
 * A result is not a command: different audience, different subject, and field 12 binds the RESULT
 * bytes rather than the argument bytes. W6 originally reused the `CBHR-RPC-V2` command tag and
 * smuggled the outcome through `argsB64u`; GM-80 §1/§2 rejects that as the "two documents, one
 * domain" ambiguity a versioned tag exists to prevent, and rules the outcome an EXPLICIT SIGNED
 * FIELD. So this module fixes the result core (twelve fields, own tag), its per-field encodings and
 * its verification order, and nothing else in `relay/**` has to know the shape.
 *
 * THE SIGNED STRING, in this exact fixed order (no reordering, no missing field, no extra field):
 *
 *   CBHR-RPC-RESULT-V2 ‖ requestId ‖ callId ‖ nonce ‖ issuedAt ‖ deadlineMs ‖ grantId ‖ epoch ‖
 *   deviceId ‖ deviceKeyId ‖ outcome ‖ sha256(result bytes)
 *
 * `‖` is exactly one 0x1F byte, and the join is NOT reimplemented here: `../crypto.canonicalEncode`
 * is the one accepted implementation of the 0x1F law (GM-29/GM-54), exactly as
 * `./envelopeCore` delegates it for the command domain. This module supplies the field ORDER and the
 * value domains.
 *
 * VERIFICATION ORDER (fixed; each step short-circuits, and the order is the accepted platform order)
 *   1. structural parse + per-field encoding + the deadline horizon
 *        -> RESULT_FRAME_SHAPE_INVALID / RESULT_FRAME_FIELD_NOT_CANONICAL / RESULT_FRAME_EXTRA_FIELD
 *   2. signature against the PINNED DEVICE key  -> RESULT_SIGNATURE_INVALID
 *   3. pinned `keyId` label (GM-31)             -> RESULT_KEY_MISMATCH
 *   4. `audience === 'relay'` (transport field) -> RESULT_AUDIENCE_MISMATCH
 *   5. freshness + deadline on the frame's OWN signed fields -> FRESHNESS_* / DEADLINE_*
 *   6. sha256(result bytes) re-hashed AS RECEIVED against the signed digest -> ARGS_DIGEST_MISMATCH
 *   7. unseen `(grantId, nonce)` in the replay ring -> REPLAY_DETECTED
 *
 * Step 1 precedes the signature only because the signed bytes must be constructible before they can
 * be verified; it is a parse, never an authority decision. Step 2 precedes every semantic check
 * (contract invariant 3), so a forged frame cannot burn a nonce or probe a key pin. Step 6 precedes
 * step 7 for the same reason `./envelopeVerifier` does it: a payload that cannot be bound to the
 * signed digest must not consume the nonce a genuine frame could still need.
 *
 * THE DEVICE KEY IS THE ONLY KEY THAT CAN PRODUCE A RESULT
 * `createResultFrameVerifier({ publicKeySpkiB64u })` pins the DEVICE public key. A keyless relay
 * cannot produce a signature over these bytes, so it can neither invent an outcome nor re-label one
 * (GM-80 §4.2). This module never signs, never generates a key, never reads a key from disk or the
 * environment, and holds no key material: the only key-shaped input is a PUBLIC SPKI, and the only
 * crypto call is `verifyEd25519`.
 *
 * THE OUTCOME WORD IS NOT MAPPED HERE
 * `outcome` is validated only as a bounded transport-safe WORD. Mapping it onto the platform's
 * outcome law — `succeeded` -> success only when the platform's own call state agrees, `refused` ->
 * a completed non-success, anything unrecognised -> uncertain, never success — belongs to
 * `./resultSink`, which is the module that owns that law (GM-80 §4.7). Keeping the mapping out of
 * the reader is what makes the law greppable in exactly one place.
 *
 * WHAT THIS MODULE DOES NOT DO
 * - It never re-implements a check another accepted module already owns: freshness and the deadline
 *   are `./freshness.evaluateFreshness` (the relay audience's frozen +/-120 s window), the digest
 *   equality is `./argsDigest.verifyArgsBytes` (GM-47/GM-29), the ring is `./replayWindow`, and the
 *   field encodings are borrowed from `./envelopeCore` wherever the two domains agree.
 * - It never reads `audience` as authority: `audience`/`direction`/`correlation`/`errorCode` are
 *   UNSIGNED transport metadata (GM-31). `audience` is checked, as GM-80 §4.3 requires, but it is
 *   never the reason a frame is believed.
 */

const deviceCrypto = require('../crypto');
const {
  MAX_DEADLINE_HORIZON_MS,
  RPC_ENVELOPE_AUDIENCES,
  isPlainRecord,
  decodeBase64UrlBytes,
  decodeArgsB64u,
  parseEpochMs,
} = require('./envelopeCore');
const { evaluateFreshness } = require('./freshness');
const { verifyArgsBytes } = require('./argsDigest');
const { isRelayError, relayFailure } = require('./errors');

/** Versioned domain separator of the RESULT document. One byte wrong refuses. */
const RESULT_V2_TAG = 'CBHR-RPC-RESULT-V2';

/** The audience a result frame must carry (the contract's reply direction). */
const RESULT_AUDIENCE = RPC_ENVELOPE_AUDIENCES.RELAY;

/** The three outcome words the endpoint may sign. The mapping onto the platform law is in the sink. */
const RESULT_OUTCOMES = Object.freeze({
  SUCCEEDED: 'succeeded',
  REFUSED: 'refused',
  UNCERTAIN: 'uncertain',
});

/** The one word that means success. Named once, so the law is greppable. */
const SUCCESS_OUTCOME = RESULT_OUTCOMES.SUCCEEDED;

/**
 * Twelve core properties, in the exact fixed canonical order. Written from GM-80 §4.1 and W7's
 * frozen core (README §4), NOT imported from the endpoint: if the endpoint reordered a field, this
 * side must refuse its frames rather than follow it.
 */
const RESULT_FRAME_FIELD_ORDER = Object.freeze([
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

/**
 * The unsigned transport fields the endpoint's result frame carries (GM-31/GM-35/GM-47 shape).
 *
 * `signatureB64u`/`keyId`/`argsB64u` are the same three the command leg carries. `audience` and
 * `direction` are the reply direction labels, `correlation` records whether the endpoint could
 * verify the correlation it reports (`verified` | `unverified-claim`), and `errorCode` is the
 * endpoint's own refusal code when there is one. None of them is inside the signature, so none of
 * them is authority: the sink reads `correlation` as INFORMATION and never as a decision input.
 */
const RESULT_FRAME_TRANSPORT_FIELDS = Object.freeze([
  'signatureB64u',
  'keyId',
  'argsB64u',
  'audience',
  'direction',
  'errorCode',
  'correlation',
  'seq',
]);

/** Every key a result wire frame may carry: exactly the twelve core fields plus the transport set. */
const RESULT_FRAME_KEYS = Object.freeze([
  ...RESULT_FRAME_FIELD_ORDER,
  ...RESULT_FRAME_TRANSPORT_FIELDS,
]);

const ED25519_SIGNATURE_BYTES = 64;
const NONCE_BYTES = 16;
const GRANT_ID_BYTES = 16;
const DEVICE_KEY_ID_BYTES = 32;

const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
/** Positive decimal for `epoch` (contract: integer >= 1). */
const POSITIVE_DECIMAL_PATTERN = /^[1-9][0-9]*$/;
const ARGS_DIGEST_HEX_PATTERN = /^[0-9a-f]{64}$/;

const TRANSPORT_TEXT_MAX_CHARS = 200;
const OUTCOME_TEXT_MAX_CHARS = 64;

function shapeFailure(property, reason) {
  return relayFailure('RESULT_FRAME_SHAPE_INVALID', `result field "${property}" ${reason}`, {
    field: property,
  });
}

function base64UrlFieldFailure(property, bytes) {
  return shapeFailure(property, `must be canonical unpadded base64url of exactly ${bytes} bytes`);
}

function asRelayError(err, code, message) {
  return isRelayError(err) ? err : relayFailure(code, message, { cause: err });
}

/** Own-property test. Local, like `./dispatchLedger` and `./resultSink`, so nothing is monkey-patched. */
function hasOwn(record, key) {
  return Object.prototype.hasOwnProperty.call(record, key);
}

/** Short non-empty transport text without the 0x1F separator. Never an authority input. */
function isTransportText(value) {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= TRANSPORT_TEXT_MAX_CHARS &&
    !value.includes('\u001f')
  );
}

/**
 * Per-field value-domain check, read from GM-80 §4 and W7's frozen core. Returns `null` when the
 * value satisfies the encoding, else a `RelayError` naming the field (never the value).
 *
 * `callId` is a SIGNED field of the result core (field 3). That is the one structural difference
 * that matters to the sink: the correlation claim is authenticated here, and the envelope the relay
 * delivered is compared against it rather than the other way round.
 *
 * `outcome` is checked as a WORD only (`succeeded | refused | uncertain` are mapped by the sink; an
 * unrecognised word must reach the sink as `uncertain`, never as a shape error that could be
 * confused with a refusal).
 * @param {string} property
 * @param {unknown} value
 * @returns {import('./errors').RelayError|null}
 */
function validateResultFieldValue(property, value) {
  if (typeof value !== 'string') {
    return shapeFailure(property, 'must be a string');
  }
  switch (property) {
    case 'tag':
      return value === RESULT_V2_TAG
        ? null
        : shapeFailure(property, `must be the literal "${RESULT_V2_TAG}"`);
    case 'requestId':
      return UUID_V4_PATTERN.test(value)
        ? null
        : shapeFailure(property, 'must be a canonical lowercase hyphenated UUIDv4');
    case 'callId':
      return isTransportText(value)
        ? null
        : shapeFailure(
            property,
            `must be a non-empty string of at most ${TRANSPORT_TEXT_MAX_CHARS} characters without the 0x1F separator`,
          );
    case 'nonce': {
      const bytes = decodeBase64UrlBytes(value);
      return bytes !== null && bytes.length === NONCE_BYTES
        ? null
        : base64UrlFieldFailure(property, NONCE_BYTES);
    }
    case 'issuedAt':
      return parseEpochMs(value) !== null
        ? null
        : shapeFailure(property, 'must be a canonical decimal epoch-millisecond string');
    case 'deadlineMs':
      return parseEpochMs(value) !== null
        ? null
        : shapeFailure(property, 'must be a canonical decimal epoch-millisecond string');
    case 'grantId': {
      const bytes = decodeBase64UrlBytes(value);
      return bytes !== null && bytes.length === GRANT_ID_BYTES
        ? null
        : base64UrlFieldFailure(property, GRANT_ID_BYTES);
    }
    case 'epoch':
      return POSITIVE_DECIMAL_PATTERN.test(value)
        ? null
        : shapeFailure(property, 'must be a canonical decimal integer >= 1');
    case 'deviceId':
      return value.length > 0 ? null : shapeFailure(property, 'must be a non-empty string');
    case 'deviceKeyId': {
      const bytes = decodeBase64UrlBytes(value);
      return bytes !== null && bytes.length === DEVICE_KEY_ID_BYTES
        ? null
        : base64UrlFieldFailure(property, DEVICE_KEY_ID_BYTES);
    }
    case 'outcome':
      return value.length > 0 && value.length <= OUTCOME_TEXT_MAX_CHARS && !value.includes('\u001f')
        ? null
        : shapeFailure(
            property,
            `must be a non-empty outcome word of at most ${OUTCOME_TEXT_MAX_CHARS} characters`,
          );
    case 'argsDigestHex':
      return ARGS_DIGEST_HEX_PATTERN.test(value)
        ? null
        : shapeFailure(property, 'must be 64 lowercase hex characters over sha256(result bytes)');
    default:
      return shapeFailure(property, 'is not a field of the CBHR-RPC-RESULT-V2 core');
  }
}

/** Maps a `canonicalEncode` rejection back to the contract field name. */
function canonicalFieldLabel(err) {
  const message = err instanceof Error ? err.message : '';
  if (message.includes('domainTag')) {
    return 'tag';
  }
  const match = /fields\[(\d+)\]/.exec(message);
  if (match === null) {
    return 'fields';
  }
  const entry = RESULT_FRAME_FIELD_ORDER[Number(match[1]) + 1];
  return entry === undefined ? `fields[${match[1]}]` : entry;
}

/**
 * Joins a validated result core through the accepted canonical encoder.
 * @param {object} core validated core (tag + 11 fields)
 * @returns {Buffer} exact signed bytes
 */
function joinResultCoreFields(core) {
  const fields = RESULT_FRAME_FIELD_ORDER.slice(1).map((property) => core[property]);
  try {
    return deviceCrypto.canonicalEncode({ domainTag: core.tag, fields });
  } catch (err) {
    const field = canonicalFieldLabel(err);
    throw relayFailure(
      'RESULT_FRAME_FIELD_NOT_CANONICAL',
      `result field "${field}" is not canonical under the 0x1F serialization law`,
      { field, cause: err },
    );
  }
}

/**
 * Validates the core's exact key set, every per-field encoding, the deadline horizon and the
 * 0x1F/well-formed-UTF-16 canonical law.
 * @param {object} core
 * @returns {object} the same core
 */
function assertResultCore(core) {
  if (!isPlainRecord(core)) {
    throw shapeFailure('core', 'must be a plain object carrying exactly the 12 result core fields');
  }
  for (const key of Object.keys(core)) {
    if (!RESULT_FRAME_FIELD_ORDER.includes(key)) {
      throw relayFailure(
        'RESULT_FRAME_EXTRA_FIELD',
        `result field "${key}" is not part of the CBHR-RPC-RESULT-V2 core (transport metadata never belongs inside the signature)`,
        { field: key },
      );
    }
  }
  for (const property of RESULT_FRAME_FIELD_ORDER) {
    if (!hasOwn(core, property)) {
      throw shapeFailure(property, 'is missing from the core');
    }
    const failure = validateResultFieldValue(property, core[property]);
    if (failure !== null) {
      throw failure;
    }
  }
  const issuedAt = parseEpochMs(core.issuedAt);
  const deadlineMs = parseEpochMs(core.deadlineMs);
  const horizon = deadlineMs - issuedAt;
  if (horizon < 0) {
    throw shapeFailure('deadlineMs', 'must not precede issuedAt');
  }
  if (horizon > MAX_DEADLINE_HORIZON_MS) {
    throw relayFailure(
      'DEADLINE_OUT_OF_BOUND',
      `result field "deadlineMs" exceeds the frozen ${MAX_DEADLINE_HORIZON_MS} ms horizon`,
      { field: 'deadlineMs' },
    );
  }
  joinResultCoreFields(core);
  return core;
}

/**
 * The exact bytes the device signs for a given result core.
 * @param {object} core
 * @returns {Buffer}
 */
function resultCanonicalBytes(core) {
  return joinResultCoreFields(assertResultCore(core));
}

/**
 * Validates the transport fields of a result wire frame. Shape only: whether a value is ACCEPTABLE
 * is decided by the chain (`audience` by step 4), never here.
 * @param {object} frame
 * @returns {object} the frame's transport projection
 */
function resultTransportFields(frame) {
  const signatureB64u = frame.signatureB64u;
  const signatureBytes = decodeBase64UrlBytes(signatureB64u);
  if (signatureBytes === null || signatureBytes.length !== ED25519_SIGNATURE_BYTES) {
    throw relayFailure(
      'RESULT_SIGNATURE_INVALID',
      `result field "signatureB64u" must be canonical unpadded base64url of exactly ${ED25519_SIGNATURE_BYTES} bytes`,
      { field: 'signatureB64u' },
    );
  }
  if (!isTransportText(frame.keyId)) {
    throw shapeFailure('keyId', 'must be a non-empty transport string of at most 200 characters');
  }
  const argsB64u = frame.argsB64u;
  if (decodeArgsB64u(argsB64u) === null) {
    throw shapeFailure(
      'argsB64u',
      'must be canonical unpadded base64url of the exact result bytes the device hashed (the empty string for empty bytes)',
    );
  }
  if (typeof frame.audience !== 'string') {
    throw shapeFailure('audience', 'must be a string');
  }
  for (const property of ['direction', 'errorCode', 'correlation']) {
    if (hasOwn(frame, property) && !isTransportText(frame[property])) {
      throw shapeFailure(
        property,
        'must be a non-empty transport string of at most 200 characters',
      );
    }
  }
  if (hasOwn(frame, 'seq') && (!Number.isInteger(frame.seq) || frame.seq < 1)) {
    throw shapeFailure('seq', 'must be an integer >= 1');
  }
  return { signatureB64u, keyId: frame.keyId, argsB64u, audience: frame.audience };
}

/**
 * Extracts the signed core from a flat result wire frame, rejecting missing, extra and non-core
 * keys, so a frame cannot smuggle a field past the signature.
 * @param {object} frame
 * @returns {{core: object, signatureB64u: string, keyId: string, argsB64u: string, audience: string}}
 */
function resultCoreFromWireFrame(frame) {
  if (!isPlainRecord(frame)) {
    throw shapeFailure('frame', 'must be a plain object');
  }
  for (const key of Object.keys(frame)) {
    if (!RESULT_FRAME_KEYS.includes(key)) {
      throw shapeFailure(key, 'is not a permitted result wire-frame key');
    }
  }
  const core = {};
  for (const property of RESULT_FRAME_FIELD_ORDER) {
    if (!hasOwn(frame, property)) {
      throw shapeFailure(property, 'is missing from the wire frame');
    }
    core[property] = frame[property];
  }
  const transport = resultTransportFields(frame);
  return Object.freeze({ core: Object.freeze(assertResultCore(core)), ...transport });
}

/**
 * Verifies a result signature against a PINNED DEVICE key. Signature verification precedes every
 * semantic check (contract invariant 3); the optional `keyId` pin is applied after the signature, so
 * a wrong key cannot be probed before the cryptographic check.
 *
 * Malformed input never throws: it resolves to `{ ok: false, error }`.
 *
 * @param {object} options
 * @param {string} options.publicKeySpkiB64u unpadded base64url SPKI DER Ed25519 DEVICE public key
 * @param {string} [options.expectedKeyId] pinned device signing-key label
 * @param {object} [options.crypto] injected crypto module (defaults to the accepted `../crypto`)
 * @returns {Readonly<{publicKeyThumbprint: string, verifyResultSignature: Function}>}
 */
function createResultFrameVerifier(options = {}) {
  const { publicKeySpkiB64u, expectedKeyId = null } = options;
  const cryptoModule = options.crypto ?? deviceCrypto;
  if (typeof publicKeySpkiB64u !== 'string' || publicKeySpkiB64u.length === 0) {
    throw relayFailure(
      'SINK_SEAM_INVALID',
      'the result frame verifier requires an unpadded base64url SPKI device public key',
      { field: 'publicKeySpkiB64u' },
    );
  }
  let publicKeyThumbprint;
  try {
    publicKeyThumbprint = cryptoModule.thumbprintB64u(publicKeySpkiB64u);
  } catch (err) {
    throw relayFailure(
      'SINK_SEAM_INVALID',
      'the result frame verifier requires a canonical unpadded base64url SPKI device key',
      { field: 'publicKeySpkiB64u', cause: err },
    );
  }
  if (expectedKeyId !== null && (typeof expectedKeyId !== 'string' || expectedKeyId.length === 0)) {
    throw relayFailure(
      'SINK_SEAM_INVALID',
      'the result frame verifier expectedKeyId pin must be a non-empty string or null',
      {
        field: 'expectedKeyId',
      },
    );
  }

  /**
   * @param {{core: object, signatureB64u: string, keyId: string}} signed
   * @returns {{ok: true, core: object, keyId: string}|{ok: false, error: import('./errors').RelayError}}
   */
  function verifyResultSignature(signed) {
    if (signed === null || typeof signed !== 'object') {
      return {
        ok: false,
        error: relayFailure(
          'RESULT_FRAME_SHAPE_INVALID',
          'verifyResultSignature requires a { core, signatureB64u, keyId } object',
        ),
      };
    }
    let core;
    let message;
    try {
      core = assertResultCore(signed.core);
      message = joinResultCoreFields(signed.core);
    } catch (err) {
      return {
        ok: false,
        error: asRelayError(err, 'RESULT_FRAME_SHAPE_INVALID', 'the result core is unusable'),
      };
    }
    let verified = false;
    try {
      verified =
        cryptoModule.verifyEd25519({
          publicKeySpkiB64u,
          message,
          signatureB64u: signed.signatureB64u,
        }) === true;
    } catch {
      verified = false;
    }
    if (!verified) {
      return {
        ok: false,
        error: relayFailure(
          'RESULT_SIGNATURE_INVALID',
          'the result signature does not verify against the pinned device key',
          { field: 'signatureB64u' },
        ),
      };
    }
    if (expectedKeyId !== null && signed.keyId !== expectedKeyId) {
      return {
        ok: false,
        error: relayFailure(
          'RESULT_KEY_MISMATCH',
          'the result keyId does not match the pinned device signing key',
          { field: 'keyId' },
        ),
      };
    }
    return { ok: true, core, keyId: signed.keyId };
  }

  return Object.freeze({ publicKeyThumbprint, verifyResultSignature });
}

/**
 * Verifies one `CBHR-RPC-RESULT-V2` frame end to end, in the frozen order documented at the top.
 *
 * @param {object} params
 * @param {object} params.frame the flat wire frame, exactly as the relay forwarded it
 * @param {{verifyResultSignature: Function}} params.verifier from `createResultFrameVerifier`
 * @param {string} [params.expectedAudience] the audience this receiver accepts (default: `relay`)
 * @param {number} params.now epoch-ms clock reading
 * @param {{checkAndRemember: Function}} [params.replayWindow] required to enforce replay rejection
 * @returns {Promise<{ok: true, core: object, keyId: string, windowMs: number, resultBytes: Buffer,
 *   audience: string, argsB64u: string}
 *   | {ok: false, error: import('./errors').RelayError}>}
 */
async function verifyResultFrame(params = {}) {
  const { frame, verifier, expectedAudience = RESULT_AUDIENCE, now, replayWindow = null } = params;

  if (
    verifier === null ||
    typeof verifier !== 'object' ||
    typeof verifier.verifyResultSignature !== 'function'
  ) {
    return {
      ok: false,
      error: relayFailure(
        'SINK_SEAM_INVALID',
        'verifyResultFrame requires a verifier with verifyResultSignature() from createResultFrameVerifier()',
      ),
    };
  }

  // 1. structural parse + per-field encodings + the deadline horizon
  let parsed;
  try {
    parsed = resultCoreFromWireFrame(frame);
  } catch (err) {
    return {
      ok: false,
      error: asRelayError(
        err,
        'RESULT_FRAME_SHAPE_INVALID',
        'the result frame is not a well-formed wire frame',
      ),
    };
  }

  // 2 + 3. signature against the PINNED DEVICE key, then the pinned keyId label
  const signatureResult = verifier.verifyResultSignature({
    core: parsed.core,
    signatureB64u: parsed.signatureB64u,
    keyId: parsed.keyId,
  });
  if (signatureResult.ok !== true) {
    return { ok: false, error: signatureResult.error };
  }
  const { core, keyId } = signatureResult;

  // 4. audience binding. `audience` is unsigned transport metadata (GM-31): the check is required by
  // GM-80 §4.3, but the signature above is what makes the frame authentic.
  if (parsed.audience !== expectedAudience) {
    return {
      ok: false,
      error: relayFailure(
        'RESULT_AUDIENCE_MISMATCH',
        'the result frame audience does not match the audience this receiver accepts',
        { field: 'audience' },
      ),
    };
  }

  // 5. freshness + deadline on the frame's OWN signed fields. The window is the RECEIVER's frozen
  // window for this audience (120 s for replies), never a value the sender supplied.
  const freshness = evaluateFreshness({
    audience: expectedAudience,
    issuedAt: core.issuedAt,
    deadlineMs: core.deadlineMs,
    now,
  });
  if (freshness.ok !== true) {
    return { ok: false, error: freshness.error };
  }

  // 6. sha256(result bytes) re-hashed AS RECEIVED (GM-47/GM-29), before the nonce is spent.
  const args = verifyArgsBytes({ argsB64u: parsed.argsB64u, argsDigestHex: core.argsDigestHex });
  if (args.ok !== true) {
    return { ok: false, error: args.error };
  }

  // 7. replay: the result's OWN fresh nonce, keyed `(grantId, nonce)`. It is a different key from the
  // command's, so a spent command nonce never blocks a result (GM-80 §4.5) — and a REPLAYED result
  // nonce is still refused.
  if (replayWindow !== null && replayWindow !== undefined) {
    if (typeof replayWindow.checkAndRemember !== 'function') {
      return {
        ok: false,
        error: relayFailure(
          'SINK_SEAM_INVALID',
          'the replay window must expose checkAndRemember()',
        ),
      };
    }
    let reservation;
    try {
      reservation = await replayWindow.checkAndRemember({
        grantId: core.grantId,
        nonce: core.nonce,
        freshUntilMs: freshness.issuedMs + freshness.windowMs,
      });
    } catch (err) {
      // A ring that cannot key this frame fails CLOSED rather than admitting it unreserved.
      return {
        ok: false,
        error: asRelayError(
          err,
          'RESULT_FRAME_SHAPE_INVALID',
          'the replay ring cannot key this result frame',
        ),
      };
    }
    if (reservation.ok !== true) {
      return { ok: false, error: reservation.error };
    }
  }

  return {
    ok: true,
    core,
    keyId,
    windowMs: freshness.windowMs,
    resultBytes: args.argsBytes,
    audience: parsed.audience,
    argsB64u: parsed.argsB64u,
  };
}

module.exports = {
  RESULT_V2_TAG,
  RESULT_AUDIENCE,
  RESULT_OUTCOMES,
  SUCCESS_OUTCOME,
  RESULT_FRAME_FIELD_ORDER,
  RESULT_FRAME_TRANSPORT_FIELDS,
  RESULT_FRAME_KEYS,
  ED25519_SIGNATURE_BYTES,
  TRANSPORT_TEXT_MAX_CHARS,
  OUTCOME_TEXT_MAX_CHARS,
  validateResultFieldValue,
  assertResultCore,
  joinResultCoreFields,
  resultCanonicalBytes,
  resultCoreFromWireFrame,
  createResultFrameVerifier,
  verifyResultFrame,
};
