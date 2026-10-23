'use strict';

/**
 * RESULT SINK — the device -> platform result path's authority half (workstream W6, GM-43).
 *
 * WHAT ARRIVES. The relay forwards, verbatim and unopened, the bytes a device sent for one call:
 *
 *   { callId, payload, resultSeq, at, replay }         // the relay's transport envelope
 *
 * `payload` is the device's own `CBHR-RPC-V2` wire frame with `audience: 'relay'` — the
 * ENDPOINT-signed reply the contract reserves for exactly this direction — serialized as a string.
 * The relay never parses it; the platform does, and that asymmetry is the whole security argument:
 * the relay is a keyless forwarder, so nothing it says about an outcome can be believed, and this
 * module believes nothing but the device's own authentication.
 *
 * WHERE THE OUTCOME LIVES, AND WHY. The frozen 15-field core has no `outcome` field, and it must not
 * grow one inside a signed core that the relay's own view checks read. The device therefore binds its
 * result document the way the contract already binds a payload: the exact bytes travel in `argsB64u`
 * and their SHA-256 is signed field 15 (`sha256(args)`). Field 15 is authenticated by the device's
 * signature, and `verifyArgsBytes` re-hashes the bytes AS RECEIVED (GM-47/GM-29), so the outcome the
 * platform reads is the outcome the device authenticated — byte for byte. A transport field would
 * have been forgeable by the relay; this is not.
 *
 * OUTCOME LAW (non-negotiable, F-V24C-9 / GM-43):
 *   - `status: 'completed'` — and ONLY then a possible `success: true` — requires a well-formed,
 *     correlated, authentic frame whose result document names a device-reported outcome.
 *   - `success` is true IF AND ONLY IF `status === 'completed'` AND the device reported `success`.
 *   - `status: 'uncertain'` for anything malformed, unauthenticated, replayed, stale, or bound to a
 *     different call/device/tenant/grant: a 5xx-shaped, thrown, unparsable or contradictory result is
 *     NEVER a success and NEVER a failure — it is unknown. Nothing is stored, and the call stays open
 *     so a genuine report can still land.
 *   - `status: 'refused'` for a result that cannot be attributed at all: an unknown `callId`, a call
 *     that is already completed (a duplicate or a retry), or a forwarded entry of the wrong shape or
 *     size. Nothing is stored. A duplicate never re-reports success: it reports `success: false` and
 *     exposes the already-recorded outcome as `recordedOutcome`, clearly not as this frame's verdict.
 *
 * WHAT THIS MODULE DOES NOT DO
 * - It never signs and never holds, reads, derives or logs key material: verification is the injected
 *   `verifier` from the accepted `createEnvelopeVerifier`, and the message is joined by the accepted
 *   `envelopeCore`/`../crypto` canonicalisation. There is exactly one signing implementation in this
 *   repository and this file is not it.
 * - It never re-implements a check the envelope chain already owns: structure, signature, keyId pin,
 *   audience, freshness, the args digest and replay are the accepted `verifyEnvelope` order.
 * - It never repairs a correlation. If the authenticated frame names a different call, device, tenant
 *   or grant than the one that was dispatched, the result is UNCERTAIN — the sink does not re-file it
 *   under another call id, because that would be inventing the attribution it exists to check.
 *
 * STORAGE. Accepted results are held in an in-process store by default (NOT durable). The dispatch
 * ledger — not this store — is the authority on "has this call been completed"; the durable choice for
 * both is the same injected seam described in `./dispatchLedger`.
 */

const { relayFailure } = require('./errors');
const { RPC_ENVELOPE_AUDIENCES, isPlainRecord } = require('./envelopeCore');
const { verifyEnvelope } = require('./envelopeVerifier');
const { verifyArgsBytes } = require('./argsDigest');

/** The sink's kind label, so a wiring mistake is visible in a log. */
const RESULT_SINK_KIND = 'relay-result-sink';

/** The exact keys a forwarded result entry may carry (the relay's transport envelope). */
const FORWARDED_RESULT_KEYS = Object.freeze(['callId', 'payload', 'resultSeq', 'at', 'replay', 't']);

/** The verdict vocabulary of this module. Only `completed` can ever carry `success: true`. */
const RESULT_STATUS = Object.freeze({
  COMPLETED: 'completed',
  UNCERTAIN: 'uncertain',
  REFUSED: 'refused',
});

/**
 * The outcome words a device may report. `success` is the only one that maps to success; every other
 * word is a perfectly valid device-reported NON-success (a real outcome, not an uncertainty).
 */
const DEVICE_RESULT_OUTCOMES = Object.freeze([
  'success',
  'failure',
  'refused',
  'cancelled',
  'timeout',
]);

/** The one word that means success. Named once, so the law is greppable. */
const SUCCESS_OUTCOME = 'success';

/** The audience a result frame must carry. Not an option: it is the contract's reply direction. */
const RESULT_AUDIENCE = RPC_ENVELOPE_AUDIENCES.RELAY;

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
function verdict({ status, code, callId = null, detail = null, success = false, outcome = null, extra = {} }) {
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
 * duplicated-by-content, replayed or contradictory results.
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
    return { ok: false, code: 'RESULT_MALFORMED', detail: 'a forwarded result must be a plain object', callId: null };
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
    return { ok: false, code: 'RESULT_MALFORMED', detail: 'a forwarded result must carry a usable callId', callId: null };
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
 * The binding check: the AUTHENTICATED core must name the same device, key, tenant and grant the
 * call was dispatched to. Without this, a genuine result from device B could complete a call
 * dispatched to device A — a valid signature over the wrong call.
 * @param {object} core the verified core
 * @param {object} entry the dispatch ledger entry
 * @returns {{ok: true}|{ok: false, field: string}}
 */
function checkBinding(core, entry) {
  for (const field of ['deviceId', 'deviceKeyId', 'tenantId', 'grantId']) {
    if (core[field] !== entry[field]) {
      return { ok: false, field };
    }
  }
  if (String(core.epoch) !== String(entry.epoch)) {
    return { ok: false, field: 'epoch' };
  }
  return { ok: true };
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
 * @param {{verifySignature: Function}} options.verifier REQUIRED verifier from
 *   `createEnvelopeVerifier({ publicKeySpkiB64u: <pinned DEVICE key>, expectedKeyId })`. The sink never
 *   chooses which key is pinned; that is the wiring's decision, taken once.
 * @param {{now: () => number}} [options.clock] server clock (epoch-ms)
 * @param {object} [options.replayWindow] `createReplayWindow()` guard; when supplied, a replayed nonce
 *   is `uncertain` (`REPLAY_DETECTED`) instead of merely being caught by the ledger
 * @param {number} [options.maxResultBytes] bound on the DECODED result document (GM-58.4)
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
    typeof verifier.verifySignature !== 'function'
  ) {
    throw sinkFailure(
      'SINK_SEAM_INVALID',
      'the result sink requires the injected verifier from createEnvelopeVerifier(); it never pins a key itself and never signs',
      { field: 'verifier' },
    );
  }
  if (clock === null || typeof clock.now !== 'function') {
    throw sinkFailure('CLOCK_UNUSABLE', 'the result sink requires a now() clock', { field: 'clock' });
  }
  if (!Number.isSafeInteger(maxResultBytes) || maxResultBytes < 1) {
    throw sinkFailure('SINK_SEAM_INVALID', 'maxResultBytes must be an integer >= 1', { field: 'maxResultBytes' });
  }
  if (!Number.isSafeInteger(maxForwardedChars) || maxForwardedChars < 1) {
    throw sinkFailure('SINK_SEAM_INVALID', 'maxForwardedChars must be an integer >= 1', { field: 'maxForwardedChars' });
  }
  if (
    store === null ||
    typeof store !== 'object' ||
    typeof store.get !== 'function' ||
    typeof store.set !== 'function'
  ) {
    throw sinkFailure('SINK_SEAM_INVALID', 'the result store seam requires { get(key), set(key, value) }', {
      field: 'store',
    });
  }

  function nowMs() {
    const value = clock.now();
    if (!Number.isSafeInteger(value) || value < 0) {
      throw sinkFailure('CLOCK_UNUSABLE', 'the result sink clock did not return epoch milliseconds');
    }
    return value;
  }

  /**
   * Ingests ONE forwarded result and classifies it under the outcome law.
   *
   * Never throws for a malformed, forged, stale, replayed or contradictory input: every one of those is
   * a typed verdict, so a caller cannot accidentally turn a parsing failure into a success.
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

    // 2. CORRELATION — the call must exist and must not already be completed.
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
      return uncertain('RESULT_MALFORMED', callId, 'the forwarded payload is not a parseable frame');
    }
    if (!isPlainRecord(frame)) {
      return uncertain('RESULT_MALFORMED', callId, 'the forwarded payload is not a frame object');
    }
    // The frame's own transport callId must agree with the envelope the relay delivered it under:
    // otherwise the correlation itself is in doubt, which is exactly what "uncertain" means.
    if (frame.callId !== callId) {
      return uncertain('RESULT_CALL_MISMATCH', callId, 'the frame names a different call than the one it was forwarded under');
    }

    // 4. THE ACCEPTED ADMISSION CHAIN — structure, signature, pin, audience, freshness, args digest, replay.
    const verified = await verifyEnvelope({
      signed: frame,
      verifier,
      expectedAudience: RESULT_AUDIENCE,
      now: nowMs(),
      replayWindow,
      requireArgsBytes: true,
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

    // 6. THE RESULT BYTES — re-hashed as received (GM-47/GM-29); never re-serialized.
    const args = verifyArgsBytes({ argsB64u: frame.argsB64u, argsDigestHex: core.argsDigestHex });
    if (args.ok !== true) {
      // verifyEnvelope already ran this check inside the chain; keeping it here makes the byte source
      // for step 7 impossible to reach without the equality having held.
      return uncertain(args.error.code, callId, args.error.message);
    }
    if (args.argsBytes.length > maxResultBytes) {
      return uncertain('RESULT_TOO_LARGE', callId, `the result document exceeds ${maxResultBytes} bytes`);
    }
    let document;
    try {
      document = JSON.parse(args.argsBytes.toString('utf8'));
    } catch (err) {
      return uncertain('RESULT_MALFORMED', callId, 'the authenticated result bytes are not a parseable document');
    }
    if (!isPlainRecord(document)) {
      return uncertain('RESULT_MALFORMED', callId, 'the authenticated result bytes are not a document object');
    }
    if (document.callId !== undefined && document.callId !== null && document.callId !== callId) {
      return uncertain('RESULT_CALL_MISMATCH', callId, 'the authenticated result document names a different call');
    }
    const outcome = document.outcome;
    if (typeof outcome !== 'string' || !DEVICE_RESULT_OUTCOMES.includes(outcome)) {
      // An unknown word is NOT success and NOT failure: the platform cannot say what the device meant.
      return uncertain('RESULT_MALFORMED', callId, 'the authenticated result document does not report a known outcome');
    }

    // 7. COMPLETE THE CALL — exactly once, against the ledger.
    const completion = await ledger.complete(callId, { outcome, resultSeq });
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

    // 8. STORE THE ACCEPTED OUTCOME. `success` is true only for a device-reported `success`.
    const record = Object.freeze({
      callId,
      outcome,
      success: outcome === SUCCESS_OUTCOME,
      deviceId: core.deviceId,
      tenantId: core.tenantId,
      grantId: core.grantId,
      epoch: core.epoch,
      toolName: core.toolName,
      requestId: core.requestId,
      keyId: verified.keyId,
      resultSeq,
      recordedAt: nowMs(),
    });
    await store.set(callId, record);
    return verdict({
      status: RESULT_STATUS.COMPLETED,
      code: null,
      callId,
      success: record.success,
      outcome,
      extra: {
        duplicate: false,
        recordedOutcome: outcome,
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
  DEVICE_RESULT_OUTCOMES,
  SUCCESS_OUTCOME,
  RESULT_AUDIENCE,
  DEFAULT_MAX_FORWARDED_CHARS,
  DEFAULT_MAX_RESULT_BYTES,
  createMapResultStore,
  createResultSink,
  forwardedShape,
  checkBinding,
};