'use strict';

/**
 * RESULT SINK — the device -> platform result path's authority half (workstream W6, GM-43; adapted to
 * the `CBHR-RPC-RESULT-V2` frame by GM-80).
 *
 * WHAT ARRIVES. The relay forwards, verbatim and unopened, the bytes a device sent for one call:
 *
 *   { callId, payload, resultSeq, at, replay }         // the relay's transport envelope
 *
 * `payload` is the device's own `CBHR-RPC-RESULT-V2` wire frame with `audience: 'relay'` — the
 * ENDPOINT-signed reply GM-80 §2 rules is a document of its OWN (twelve fields, its own domain tag,
 * an explicit signed `outcome` field) — serialized as a string. The relay never parses it; the
 * platform does, and that asymmetry is the whole security argument: the relay is a keyless
 * forwarder, so nothing it says about an outcome can be believed, and this module believes nothing
 * but the device's own authentication.
 *
 * WHY THE FRAME TYPE CHANGED (GM-80). W6 verified the command document (`CBHR-RPC-V2`, 15 fields)
 * with the outcome smuggled inside `argsB64u`. The endpoint agent (W7) signs a DISTINCT document: a
 * result is not a command (different audience, different subject, field 12 binds the RESULT bytes),
 * so results carry their own tag and an explicit signed `outcome`. GM-80 rules W7's definition wins
 * and this side adapts. The verification chain lives in `./resultFrame`; this module owns the
 * CORRELATION and the OUTCOME LAW, and nothing about the frame layout.
 *
 * OUTCOME LAW (GM-80 §4.7, non-negotiable — F-V24C-9 / GM-43):
 *   - `succeeded` — `success: true`, and ONLY when the platform's own call state agrees: the call
 *     exists, is still `dispatched`, binds this device/key/grant/epoch, and the ledger's atomic
 *     conditional completion wins the call. If any of that disagrees, nothing is completed as a
 *     success.
 *   - `refused` — a completed call with `success: false`. The endpoint can PROVE nothing ran.
 *   - `uncertain` — the call STAYS OPEN and nothing is stored. `uncertain` exists so that "I do not
 *     know" is never spelled "success".
 *   - absent or unrecognised `outcome` — `uncertain`, never success.
 *   - Anything malformed, unauthenticated, replayed, stale, oversized, mis-bound or mis-correlated is
 *     `uncertain`: a 5xx-shaped, thrown, unparsable or contradictory result is NEVER a success and
 *     NEVER a failure — it is unknown. Nothing is stored, and the call stays open so a genuine report
 *     can still land.
 *   - `status: 'refused'` is reserved for a result that cannot be attributed at all: an unknown
 *     `callId`, a call that is already completed (a duplicate or a retry), or a forwarded entry of
 *     the wrong shape or size. Nothing is stored. A duplicate never re-reports success: it reports
 *     `success: false` and exposes the already-recorded outcome as `recordedOutcome`, clearly not as
 *     this frame's verdict.
 *
 * THE RESULT'S NONCE IS ITS OWN (GM-80 §4.5). The endpoint generates a FRESH nonce per result, so the
 * replay ring key `(grantId, nonce)` is a different key from the command's and a spent command nonce
 * can never block a result. A REPLAYED result nonce is still refused (`REPLAY_DETECTED`).
 *
 * WHAT THIS MODULE DOES NOT DO
 * - It never signs and never holds, reads, derives or logs key material: verification is the injected
 *   `verifier` from the accepted `createResultFrameVerifier` (pinned DEVICE key) and the message is
 *   joined by the accepted `../crypto` canonicalisation. There is exactly one signing implementation
 *   in this repository and this file is not it.
 * - It never re-implements a check the result-frame chain already owns: structure, signature, keyId
 *   pin, audience, freshness, the result-bytes digest and replay are `verifyResultFrame`'s order.
 * - It never reads unsigned transport metadata as authority. `correlation` (`verified` |
 *   `unverified-claim`) is carried by the endpoint as INFORMATION about its own correlation claim —
 *   it is outside the signature, so this module neither requires it nor acts on it. The signed
 *   `callId`, the signed identity fields and the platform's own ledger are what correlation rests on.
 * - It never repairs a correlation. If the authenticated frame names a different call, device, grant
 *   or epoch than the one that was dispatched, the result is UNCERTAIN — the sink does not re-file it
 *   under another call id, because that would be inventing the attribution it exists to check.
 *
 * STORAGE. Accepted results are held in an in-process store by default (NOT durable). The dispatch
 * ledger — not this store — is the authority on "has this call been completed"; the durable choice for
 * both is the same injected seam described in `./dispatchLedger`.
 */

const { relayFailure } = require('./errors');
const { isPlainRecord } = require('./envelopeCore');
const {
  RESULT_AUDIENCE,
  RESULT_OUTCOMES,
  SUCCESS_OUTCOME,
  verifyResultFrame,
} = require('./resultFrame');

/** The sink's kind label, so a wiring mistake is visible in a log. */
const RESULT_SINK_KIND = 'relay-result-sink';

/** The exact keys a forwarded result entry may carry (the relay's transport envelope). */
const FORWARDED_RESULT_KEYS = Object.freeze([
  'callId',
  'payload',
  'resultSeq',
  'at',
  'replay',
  't',
]);

/** The verdict vocabulary of this module. Only `completed` can ever carry `success: true`. */
const RESULT_STATUS = Object.freeze({
  COMPLETED: 'completed',
  UNCERTAIN: 'uncertain',
  REFUSED: 'refused',
});

/**
 * The outcome words a device may sign (GM-80 §2.3). `succeeded` is the only one that maps to success;
 * `refused` is a real, provable non-success; `uncertain` stays open. Any other word is unrecognised
 * and therefore ALSO uncertain — never success.
 */
const RESULT_OUTCOME_VOCABULARY = Object.freeze([
  RESULT_OUTCOMES.SUCCEEDED,
  RESULT_OUTCOMES.REFUSED,
  RESULT_OUTCOMES.UNCERTAIN,
]);

/**
 * The ledger identity fields the RESULT CORE actually carries and this module compares.
 *
 * `tenantId` is deliberately absent: the frozen `CBHR-RPC-RESULT-V2` core (GM-80 §2, W7 README §4) is
 * twelve fields and does NOT sign a tenant. Inventing one, or inferring it from the frame, would be
 * manufacturing an identity the device never authenticated. The tenant is not lost: the ledger entry
 * is the platform's own record of which tenant dispatched the call, and `deviceId`/`deviceKeyId` bind
 * the result to the device that was issued inside that tenant.
 */
const RESULT_BINDING_FIELDS = Object.freeze(['deviceId', 'deviceKeyId', 'grantId', 'epoch']);
const RESULT_BINDING_FIELDS_NOT_CARRIED = Object.freeze(['tenantId']);

const TRANSPORT_TEXT_MAX_CHARS = 200;
const RESERVED_SEPARATOR = '\u001f';
const DEFAULT_MAX_FORWARDED_CHARS = 65536;
const DEFAULT_MAX_RESULT_BYTES = 65536;

function sinkFailure(code, message, options) {
  return relayFailure(code, message, options);
}

function hasOwn(record, key) {
  return Object.prototype.hasOwnProperty.call(record, key);
}

function isTransportText(value) {
  if (typeof value !== 'string') return false;
  if (value.length === 0 || value.length > TRANSPORT_TEXT_MAX_CHARS) return false;
  return !value.includes(RESERVED_SEPARATOR);
}

/** A frozen verdict, so a caller cannot mutate a classification after the fact. */
function verdict({
  status,
  code,
  callId = null,
  detail = null,
  success = false,
  outcome = null,
  extra = {},
}) {
  return Object.freeze({
    ok: status === RESULT_STATUS.COMPLETED,
    status,
    code,
    callId,
    detail,
    success,
    outcome,
    stored: status === RESULT_STATUS.COMPLETED,
    ...extra,
  });
}

/** Refused: the result cannot be attributed to a dispatched call. Nothing is stored. */
function refused(code, callId, extra = {}) {
  return verdict({ status: RESULT_STATUS.REFUSED, code, callId, extra });
}

/**
 * Uncertain: the frame reached us, but it establishes nothing. Nothing is stored, and the call stays
 * open — this is the ONLY classification the outcome law permits for malformed, unauthenticated,
 * replayed, stale, mis-correlated, mis-bound or self-reported-uncertain results.
 */
function uncertain(code, callId, detail = null, extra = {}) {
  return verdict({ status: RESULT_STATUS.UNCERTAIN, code, callId, detail, extra });
}

/**
 * Transport shape of one forwarded entry. Sizing and shape only: this is the platform's own boundary
 * check, mirroring the bound the relay enforces independently (GM-58).
 * @param {unknown} forwarded
 * @param {number} maxForwardedChars
 * @returns {{ok: true, callId: string, payload: string, resultSeq: (number|null)}
 *   | {ok: false, code: string, detail: string, callId: (string|null)}}
 */
function forwardedShape(forwarded, maxForwardedChars) {
  if (!isPlainRecord(forwarded)) {
    return {
      ok: false,
      code: 'RESULT_MALFORMED',
      detail: 'a forwarded result must be a plain object',
      callId: null,
    };
  }
  for (const key of Object.keys(forwarded)) {
    if (!FORWARDED_RESULT_KEYS.includes(key)) {
      return {
        ok: false,
        code: 'RESULT_MALFORMED',
        detail: `the forwarded result carries an unexpected key "${key}"`,
        callId: null,
      };
    }
  }
  if (!hasOwn(forwarded, 'callId') || !isTransportText(forwarded.callId)) {
    return {
      ok: false,
      code: 'RESULT_MALFORMED',
      detail: 'a forwarded result must carry a usable callId',
      callId: null,
    };
  }
  if (typeof forwarded.payload !== 'string' || forwarded.payload.length === 0) {
    return {
      ok: false,
      code: 'RESULT_MALFORMED',
      detail: 'a forwarded result must carry the device bytes as a non-empty string',
      callId: forwarded.callId,
    };
  }
  if (forwarded.payload.length > maxForwardedChars) {
    return {
      ok: false,
      code: 'RESULT_TOO_LARGE',
      detail: `the forwarded payload exceeds ${maxForwardedChars} characters`,
      callId: forwarded.callId,
    };
  }
  const resultSeq = forwarded.resultSeq ?? null;
  if (resultSeq !== null && (!Number.isInteger(resultSeq) || resultSeq < 1)) {
    return {
      ok: false,
      code: 'RESULT_MALFORMED',
      detail: 'resultSeq is transport bookkeeping and must be an integer >= 1 when present',
      callId: forwarded.callId,
    };
  }
  return { ok: true, callId: forwarded.callId, payload: forwarded.payload, resultSeq };
}

/**
 * The binding check: the AUTHENTICATED core must name the same device, key, grant and epoch the call
 * was dispatched to. Without this, a genuine result from device B could complete a call dispatched to
 * device A — a valid signature over the wrong call.
 *
 * `tenantId` cannot be compared and is reported as such rather than assumed: the result core does not
 * carry it (see `RESULT_BINDING_FIELDS_NOT_CARRIED`). The ledger's own `tenantId` remains the platform
 * record of the call, and the device identity is bound to exactly one tenant.
 * @param {object} core the verified core
 * @param {object} entry the dispatch ledger entry
 * @returns {{ok: true, compared: ReadonlyArray<string>, notCarried: ReadonlyArray<string>}
 *   | {ok: false, field: string}}
 */
function checkBinding(core, entry) {
  for (const field of RESULT_BINDING_FIELDS) {
    if (field === 'epoch') {
      if (String(core.epoch) !== String(entry.epoch)) {
        return { ok: false, field };
      }
      continue;
    }
    if (core[field] !== entry[field]) {
      return { ok: false, field };
    }
  }
  return {
    ok: true,
    compared: RESULT_BINDING_FIELDS,
    notCarried: RESULT_BINDING_FIELDS_NOT_CARRIED,
  };
}

/**
 * The default result store: in-process, NOT durable (see the module header). The seam is async so a
 * durable implementation never has to change this module.
 * @returns {Readonly<object>}
 */
function createMapResultStore() {
  const entries = new Map();
  return Object.freeze({
    kind: 'in-memory-result-store',
    async get(key) {
      return entries.has(key) ? entries.get(key) : null;
    },
    async set(key, value) {
      entries.set(key, value);
    },
    async size() {
      return entries.size;
    },
  });
}

/**
 * Builds the result sink.
 *
 * @param {object} options
 * @param {object} options.ledger REQUIRED dispatch ledger (`createDispatchLedger()`): the correlation
 *   authority. Without it a result cannot be attributed to anything, so it is refused at construction.
 * @param {{verifyResultSignature: Function}} options.verifier REQUIRED verifier from
 *   `createResultFrameVerifier({ publicKeySpkiB64u: <pinned DEVICE key>, expectedKeyId })`. The sink
 *   never chooses which key is pinned; that is the wiring's decision, taken once.
 * @param {{now: () => number}} [options.clock] server clock (epoch-ms)
 * @param {object} [options.replayWindow] `createReplayWindow()` guard; when supplied, a replayed result
 *   nonce is `uncertain` (`REPLAY_DETECTED`) instead of merely being caught by the ledger
 * @param {number} [options.maxResultBytes] bound on the DECODED result bytes (GM-58.4)
 * @param {number} [options.maxForwardedChars] bound on the forwarded payload string
 * @param {object} [options.store] result store seam `{ get(key), set(key, value) }`
 * @returns {Readonly<object>} `{ sinkKind, ingestResult, resultFor, size, ledger }`
 */
function createResultSink(options = {}) {
  const { verifier, replayWindow = null, store = createMapResultStore() } = options;
  const ledger = options.ledger;
  const clock = options.clock ?? { now: () => Date.now() };
  const maxResultBytes = options.maxResultBytes ?? DEFAULT_MAX_RESULT_BYTES;
  const maxForwardedChars = options.maxForwardedChars ?? DEFAULT_MAX_FORWARDED_CHARS;

  if (
    ledger === null ||
    ledger === undefined ||
    typeof ledger.get !== 'function' ||
    typeof ledger.complete !== 'function'
  ) {
    throw sinkFailure(
      'SINK_SEAM_INVALID',
      'the result sink requires the dispatch ledger ({ get, complete }) it correlates results against',
      { field: 'ledger' },
    );
  }
  if (
    verifier === null ||
    verifier === undefined ||
    typeof verifier !== 'object' ||
    typeof verifier.verifyResultSignature !== 'function'
  ) {
    throw sinkFailure(
      'SINK_SEAM_INVALID',
      'the result sink requires the injected verifier from createResultFrameVerifier(); it never pins a key itself and never signs',
      { field: 'verifier' },
    );
  }
  if (clock === null || typeof clock.now !== 'function') {
    throw sinkFailure('CLOCK_UNUSABLE', 'the result sink requires a now() clock', {
      field: 'clock',
    });
  }
  if (!Number.isSafeInteger(maxResultBytes) || maxResultBytes < 1) {
    throw sinkFailure('SINK_SEAM_INVALID', 'maxResultBytes must be an integer >= 1', {
      field: 'maxResultBytes',
    });
  }
  if (!Number.isSafeInteger(maxForwardedChars) || maxForwardedChars < 1) {
    throw sinkFailure('SINK_SEAM_INVALID', 'maxForwardedChars must be an integer >= 1', {
      field: 'maxForwardedChars',
    });
  }
  if (
    store === null ||
    typeof store !== 'object' ||
    typeof store.get !== 'function' ||
    typeof store.set !== 'function'
  ) {
    throw sinkFailure(
      'SINK_SEAM_INVALID',
      'the result store seam requires { get(key), set(key, value) }',
      {
        field: 'store',
      },
    );
  }

  function nowMs() {
    const value = clock.now();
    if (!Number.isSafeInteger(value) || value < 0) {
      throw sinkFailure(
        'CLOCK_UNUSABLE',
        'the result sink clock did not return epoch milliseconds',
      );
    }
    return value;
  }

  /**
   * Ingests ONE forwarded result and classifies it under the outcome law.
   *
   * Never throws for a malformed, forged, stale, replayed, mis-correlated or self-reported-uncertain
   * input: every one of those is a typed verdict, so a caller cannot accidentally turn a parsing
   * failure into a success.
   *
   * @param {object} forwarded the relay's transport envelope for one result
   * @returns {Promise<object>} a frozen verdict
   */
  async function ingestResult(forwarded) {
    // 1. TRANSPORT SHAPE — the platform's own bound, independent of the relay's.
    const shape = forwardedShape(forwarded, maxForwardedChars);
    if (!shape.ok) {
      return refused(shape.code, shape.callId);
    }
    const { callId, payload, resultSeq } = shape;

    // 2. CORRELATION — the call must exist and must not already be completed. This is the platform's
    // OWN call state, and it is the first thing `succeeded` is compared against below.
    const entry = await ledger.get(callId);
    if (entry === null || entry === undefined) {
      return refused('RESULT_UNKNOWN_CALL_ID', callId);
    }
    if (entry.state !== 'dispatched') {
      return refused('RESULT_CALL_ALREADY_COMPLETED', callId, {
        duplicate: true,
        recordedOutcome: entry.outcome ?? null,
      });
    }

    // 3. THE DEVICE'S OWN BYTES — parse only; an unparsable payload establishes nothing.
    let frame;
    try {
      frame = JSON.parse(payload);
    } catch {
      return uncertain(
        'RESULT_MALFORMED',
        callId,
        'the forwarded payload is not a parseable frame',
      );
    }
    if (!isPlainRecord(frame)) {
      return uncertain('RESULT_MALFORMED', callId, 'the forwarded payload is not a frame object');
    }
    // The frame's signed `callId` must agree with the envelope the relay delivered it under:
    // otherwise the correlation itself is in doubt, which is exactly what "uncertain" means. This is
    // a refusal-only comparison: it can never make a frame more believed than the chain below.
    if (frame.callId !== callId) {
      return uncertain(
        'RESULT_CALL_MISMATCH',
        callId,
        'the frame names a different call than the one it was forwarded under',
      );
    }

    // 4. THE RESULT-FRAME CHAIN (GM-80 §4.1-4.6) — structure, signature against the PINNED DEVICE
    // key, keyId pin, audience, freshness/deadline, sha256(result bytes) and the replay ring.
    const verified = await verifyResultFrame({
      frame,
      verifier,
      expectedAudience: RESULT_AUDIENCE,
      now: nowMs(),
      replayWindow,
    });
    if (verified.ok !== true) {
      return uncertain(verified.error.code, callId, verified.error.message);
    }
    const { core } = verified;

    // 5. BINDING — an authentic frame for a DIFFERENT call is not this call's result.
    const binding = checkBinding(core, entry);
    if (binding.ok !== true) {
      return uncertain(
        'RESULT_BINDING_MISMATCH',
        callId,
        `the authenticated frame does not bind "${binding.field}" to the dispatched call`,
      );
    }

    // 6. THE RESULT BYTES — re-hashed as received inside the chain (GM-47/GM-29), never re-serialized
    // and never parsed: their meaning is the endpoint's, and the platform's bound is on their size.
    if (verified.resultBytes.length > maxResultBytes) {
      return uncertain(
        'RESULT_TOO_LARGE',
        callId,
        `the result bytes exceed ${maxResultBytes} bytes`,
      );
    }

    // 7. THE OUTCOME MAPPING (GM-80 §4.7) — explicit, and the only place success can be produced.
    const reportedOutcome = core.outcome;
    if (reportedOutcome === RESULT_OUTCOMES.UNCERTAIN) {
      // The endpoint says it cannot prove what happened. The call STAYS OPEN and nothing is stored.
      return uncertain(
        'RESULT_OUTCOME_UNCERTAIN',
        callId,
        'the device reported an uncertain outcome; the call stays open and nothing is stored',
        { reportedOutcome },
      );
    }
    if (!RESULT_OUTCOME_VOCABULARY.includes(reportedOutcome)) {
      // An unrecognised word is NOT success and NOT failure: the platform cannot say what it meant.
      return uncertain(
        'RESULT_OUTCOME_UNRECOGNISED',
        callId,
        'the authenticated frame reports an outcome this platform does not recognise',
        { reportedOutcome },
      );
    }

    // 8. COMPLETE THE CALL — exactly once, against the ledger, and only here. `succeeded` becomes
    // `success: true` only because the platform's own state agreed at steps 2 and 5 and because this
    // atomic conditional completion wins the call; a concurrent or already-recorded result loses here.
    const completion = await ledger.complete(callId, { outcome: reportedOutcome, resultSeq });
    if (completion.ok !== true) {
      const code =
        completion.error.code === 'DISPATCH_CALL_ALREADY_COMPLETED'
          ? 'RESULT_CALL_ALREADY_COMPLETED'
          : 'RESULT_UNKNOWN_CALL_ID';
      const recorded = await ledger.get(callId);
      return refused(code, callId, {
        duplicate: code === 'RESULT_CALL_ALREADY_COMPLETED',
        recordedOutcome: recorded?.outcome ?? null,
      });
    }

    // 9. STORE THE ACCEPTED OUTCOME. `success` is true only for a device-signed `succeeded`.
    const record = Object.freeze({
      callId,
      outcome: reportedOutcome,
      success: reportedOutcome === SUCCESS_OUTCOME,
      // The device-signed identity of the frame...
      deviceId: core.deviceId,
      grantId: core.grantId,
      epoch: core.epoch,
      requestId: core.requestId,
      // ...and the PLATFORM's own record of the call. `tenantId` and `toolName` are not fields of the
      // result core, so they come from the ledger entry, never from the frame.
      tenantId: entry.tenantId,
      toolName: entry.toolName,
      keyId: verified.keyId,
      windowMs: verified.windowMs,
      resultSeq,
      recordedAt: nowMs(),
    });
    await store.set(callId, record);
    return verdict({
      status: RESULT_STATUS.COMPLETED,
      code: null,
      callId,
      success: record.success,
      outcome: reportedOutcome,
      extra: {
        duplicate: false,
        recordedOutcome: reportedOutcome,
        deviceId: record.deviceId,
        toolName: record.toolName,
        requestId: record.requestId,
        resultSeq,
        recordedAt: record.recordedAt,
      },
    });
  }

  /**
   * @param {string} callId
   * @returns {Promise<object|null>} the accepted result for that call, or null
   */
  async function resultFor(callId) {
    if (!isTransportText(callId)) {
      return null;
    }
    return (await store.get(callId)) ?? null;
  }

  /**
   * @returns {Promise<number>} how many results have been accepted
   */
  async function size() {
    if (typeof store.size === 'function') {
      return store.size();
    }
    return null;
  }

  return Object.freeze({
    sinkKind: RESULT_SINK_KIND,
    storeKind: store.kind ?? 'injected',
    resultAudience: RESULT_AUDIENCE,
    ingestResult,
    resultFor,
    size,
    ledger,
  });
}

module.exports = {
  RESULT_SINK_KIND,
  FORWARDED_RESULT_KEYS,
  RESULT_STATUS,
  RESULT_OUTCOME_VOCABULARY,
  RESULT_BINDING_FIELDS,
  RESULT_BINDING_FIELDS_NOT_CARRIED,
  SUCCESS_OUTCOME,
  RESULT_AUDIENCE,
  DEFAULT_MAX_FORWARDED_CHARS,
  DEFAULT_MAX_RESULT_BYTES,
  createMapResultStore,
  createResultSink,
  forwardedShape,
  checkBinding,
};
