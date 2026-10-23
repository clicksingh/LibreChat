'use strict';

/**
 * CBHR RDC relay/dispatch error taxonomy (workstream W2).
 *
 * LOCAL LAB ONLY. Production G0 remains BLOCKED. Nothing here is mounted on a production host.
 *
 * Every failure in the backend signing and dispatch path is a typed `RelayError`. The codes are the
 * contract between this layer and the (not yet built) route wiring, so the HTTP status is carried
 * here rather than guessed at the edge.
 *
 * LEAK RULES (mirrors `../errors.js`)
 * - An error that names a failing envelope field (the `field` option) carries a GENERIC external
 *   `message` — `"envelope field is invalid"` — and keeps the specific, field-naming text ONLY as
 *   the non-enumerable `detail` property. `field` is non-enumerable too. Therefore
 *   `JSON.stringify(err)`, `err.toJSON()` and `util.inspect(err)` expose neither the failing field
 *   nor which check failed: a route can serialize the error and only
 *   `{name, code, httpStatus, message, retryable}` escapes, which is exactly endpoint-verifier
 *   invariant 3 ("never an error reply that leaks which field mismatched"). Server-side code reads
 *   `err.field` / `err.detail` explicitly. GM-48 m4.
 * - No message built here ever interpolates a field VALUE. Messages name fields, never values, so a
 *   caller that logs `err.detail` cannot log key material, a signature, a nonce or an owner id.
 * - A caller-supplied `cause` is REPLACED by a leak-free stand-in that carries only the error code,
 *   exactly as `../errors.js` does for duplicate-key errors. Node prints an `Error#cause` chain in
 *   `util.inspect` and `console.error`, so forwarding a raw custody/transport error would print
 *   whatever its message contains — including key material. GM-48 m5.
 */

/** The only external text a field-named failure may carry (endpoint-verifier invariant 3). */
const GENERIC_FIELD_MESSAGE = 'envelope field is invalid';

const RELAY_ERROR_HTTP_STATUS = Object.freeze({
  ENVELOPE_SHAPE_INVALID: 400,
  ENVELOPE_FIELD_NOT_CANONICAL: 400,
  ENVELOPE_ARGS_INVALID: 400,
  ARGS_DIGEST_MISMATCH: 400,
  ENVELOPE_AUDIENCE_NOT_DISPATCHABLE: 400,
  DISPATCH_REQUEST_SHAPE_INVALID: 400,
  AUTHORITY_SHAPE_INVALID: 400,
  ENVELOPE_SIGNATURE_INVALID: 401,
  ENVELOPE_KEY_MISMATCH: 401,
  ENVELOPE_AUDIENCE_MISMATCH: 403,
  RESULT_AUDIENCE_MISMATCH: 403,
  AUTHORITY_MISMATCH: 403,
  FRESHNESS_EXPIRED: 409,
  FRESHNESS_NOT_YET_VALID: 409,
  DEADLINE_EXCEEDED: 409,
  DEADLINE_OUT_OF_BOUND: 400,
  REPLAY_DETECTED: 409,
  SIGNER_SEAM_INVALID: 500,
  CLOCK_UNUSABLE: 500,
  REPLAY_STORE_UNAVAILABLE: 500,
  RELAY_REJECTED: 502,
  RELAY_DISPATCH_UNCERTAIN: 502,
  // W6 / GM-43: the dispatch ledger and the result sink use the same map, so a route can still
  // carry the failure over the same typed wire as every other relay error.
  DISPATCH_LEDGER_ENTRY_INVALID: 400,
  RESULT_MALFORMED: 400,
  RESULT_TOO_LARGE: 413,
  // GM-80: the CBHR-RPC-RESULT-V2 frame's own taxonomy, additive like everything here.
  RESULT_FRAME_SHAPE_INVALID: 400,
  RESULT_FRAME_FIELD_NOT_CANONICAL: 400,
  RESULT_FRAME_EXTRA_FIELD: 400,
  RESULT_SIGNATURE_INVALID: 401,
  RESULT_KEY_MISMATCH: 401,
  RESULT_OUTCOME_UNRECOGNISED: 400,
  RESULT_OUTCOME_UNCERTAIN: 409,
  DISPATCH_CALL_ID_REUSED: 409,
  RESULT_CALL_MISMATCH: 409,
  RESULT_BINDING_MISMATCH: 409,
  DISPATCH_CALL_ALREADY_COMPLETED: 409,
  RESULT_CALL_ALREADY_COMPLETED: 409,
  DISPATCH_CALL_UNKNOWN: 404,
  RESULT_UNKNOWN_CALL_ID: 404,
  DISPATCH_LEDGER_SATURATED: 503,
  SINK_SEAM_INVALID: 500,
});

/**
 * Builds a leak-free stand-in for a caller-supplied `cause`.
 *
 * The stand-in preserves ONLY the error code, because that is all the relay layer classifies on.
 * The original message, stack, `keyPattern`, response body or custody detail never survives, so
 * `console.error(err)` and `util.inspect(err)` cannot print key material carried by a custody
 * implementation's error. Mirrors `sanitizedDuplicateCause` in `../errors.js`.
 * @param {unknown} err
 * @returns {Error|undefined} leak-free stand-in, or undefined when there is nothing to carry
 */
function sanitizedRelayCause(err) {
  if (err === null || typeof err !== 'object') {
    // A primitive cause (a string, say) could itself be the leaked text: drop it entirely.
    return undefined;
  }
  const sanitized = new Error('relay cause');
  sanitized.name = 'RelayCause';
  if (typeof err.code === 'string' || typeof err.code === 'number') {
    sanitized.code = err.code;
  }
  return sanitized;
}

/**
 * @typedef {object} RelayErrorJson
 * @property {string} name
 * @property {string} code
 * @property {number} httpStatus
 * @property {string} message
 * @property {boolean} retryable
 */

class RelayError extends Error {
  /**
   * @param {string} code one of `RELAY_ERROR_HTTP_STATUS`
   * @param {string} [message] server-side message; when `field` is supplied the EXTERNAL message is
   *   the fixed generic text and this string is retained as the non-enumerable `detail`
   * @param {object} [options]
   * @param {number} [options.httpStatus] override; defaults to the frozen status for `code`, else 500
   * @param {boolean} [options.retryable]
   * @param {Error} [options.cause] sanitized to a code-only stand-in before it is attached
   * @param {string} [options.field] server-side-only failing field; never serialized
   */
  constructor(code, message, options) {
    const settings = options ?? {};
    const field = settings.field;
    const hasField = field !== undefined && field !== null;
    const specific = message === undefined || message === null ? null : String(message);
    super(hasField ? GENERIC_FIELD_MESSAGE : specific ?? code, {
      cause: sanitizedRelayCause(settings.cause),
    });
    this.name = 'RelayError';
    this.code = code;
    this.httpStatus = settings.httpStatus ?? RELAY_ERROR_HTTP_STATUS[code] ?? 500;
    this.retryable = settings.retryable === true;
    if (hasField) {
      Object.defineProperty(this, 'field', {
        value: String(field),
        enumerable: false,
        writable: false,
      });
      if (specific !== null && specific.length > 0) {
        Object.defineProperty(this, 'detail', {
          value: specific,
          enumerable: false,
          writable: false,
        });
      }
    }
  }

  /**
   * Safe serialization: `field`, `detail` and `cause` are never included.
   * @returns {RelayErrorJson}
   */
  toJSON() {
    return {
      name: this.name,
      code: this.code,
      httpStatus: this.httpStatus,
      message: this.message,
      retryable: this.retryable,
    };
  }
}

/**
 * @param {unknown} value
 * @returns {boolean} true when `value` is a `RelayError`
 */
function isRelayError(value) {
  return value instanceof RelayError;
}

/**
 * Builds a `RelayError`.
 * @param {string} code
 * @param {string} message
 * @param {object} [options] see the constructor
 * @returns {RelayError}
 */
function relayFailure(code, message, options) {
  return new RelayError(code, message, options);
}

module.exports = {
  GENERIC_FIELD_MESSAGE,
  RELAY_ERROR_HTTP_STATUS,
  RelayError,
  isRelayError,
  relayFailure,
  sanitizedRelayCause,
};
