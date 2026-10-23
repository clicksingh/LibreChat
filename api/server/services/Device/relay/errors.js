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
 * - `field` is server-side diagnostic detail (which envelope field failed a shape check). It is
 *   defined NON-ENUMERABLE, so `JSON.stringify(err)`, `err.toJSON()` and `util.inspect(err)` never
 *   carry it. The endpoint-verifier invariant "never an error reply that leaks which field
 *   mismatched" is therefore satisfied by construction: a route can serialize the error and only
 *   `{name, code, httpStatus, message, retryable}` escapes.
 * - No message built here ever interpolates a field VALUE. Messages name fields, never values, so a
 *   caller that logs `err.message` cannot log key material, a signature, a nonce or an owner id.
 */

const RELAY_ERROR_HTTP_STATUS = Object.freeze({
  ENVELOPE_SHAPE_INVALID: 400,
  ENVELOPE_FIELD_NOT_CANONICAL: 400,
  ENVELOPE_ARGS_INVALID: 400,
  ENVELOPE_AUDIENCE_NOT_DISPATCHABLE: 400,
  DISPATCH_REQUEST_SHAPE_INVALID: 400,
  AUTHORITY_SHAPE_INVALID: 400,
  ENVELOPE_SIGNATURE_INVALID: 401,
  ENVELOPE_KEY_MISMATCH: 401,
  ENVELOPE_AUDIENCE_MISMATCH: 403,
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
});

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
   * @param {string} [message] caller-safe message; defaults to `code`
   * @param {object} [options]
   * @param {number} [options.httpStatus] override; defaults to the frozen status for `code`, else 500
   * @param {boolean} [options.retryable]
   * @param {Error} [options.cause]
   * @param {string} [options.field] server-side-only failing field; never serialized
   */
  constructor(code, message, options) {
    const settings = options ?? {};
    super(message ?? code, { cause: settings.cause });
    this.name = 'RelayError';
    this.code = code;
    this.httpStatus = settings.httpStatus ?? RELAY_ERROR_HTTP_STATUS[code] ?? 500;
    this.retryable = settings.retryable === true;
    if (settings.field !== undefined && settings.field !== null) {
      Object.defineProperty(this, 'field', {
        value: String(settings.field),
        enumerable: false,
        writable: false,
      });
    }
  }

  /**
   * Safe serialization: `field` and `cause` are never included.
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
  RELAY_ERROR_HTTP_STATUS,
  RelayError,
  isRelayError,
  relayFailure,
};
