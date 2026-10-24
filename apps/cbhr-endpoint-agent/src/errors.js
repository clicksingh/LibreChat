'use strict';

/**
 * CBHR ENDPOINT AGENT — refusal taxonomy (workstream W7).
 *
 * LAB ARTIFACT (GM-73). The owner's own machine, not the employee deliverable. `D008`'s "no Node CLI
 * for end users" still stands for the pilot: this module is the *logic* the Tauri shell will later
 * host, not a product surface.
 *
 * WHY A SEPARATE TAXONOMY FROM `relay/errors.js`
 * The endpoint is the party the relay cannot impersonate, so its verifier must be INDEPENDENT of the
 * backend's implementation (GM-54: an endpoint that trusts the sender's own code proves nothing).
 * Sharing a constructor would be harmless, but sharing one CODE SPACE would let a backend-side rename
 * silently change what the endpoint refuses. Every code below is prefixed `ENDPOINT_*` (plus four
 * invariant codes that mirror the frozen contract's own names) so the two taxonomies cannot collide
 * by accident, and each verification step in `verify.js` fails closed with its OWN distinct code.
 *
 * LEAK RULES (the same standard `DeviceError` / `RelayError` already meet)
 * - A refusal that names a failing field carries a GENERIC external `message`; the specific,
 *   field-naming text survives only as the NON-ENUMERABLE `detail`. So `JSON.stringify(err)`,
 *   `err.toJSON()` and `util.inspect(err)` expose neither the failing field, nor the offending value,
 *   nor which check failed (endpoint-verifier invariant 3: "never an error reply that leaks which
 *   field mismatched").
 * - No message built here interpolates a field VALUE. Messages name fields, never values.
 * - A caller-supplied `cause` is REPLACED by a leak-free stand-in carrying only an error code. Node
 *   prints an `Error#cause` chain in `util.inspect` and `console.error`, so forwarding a raw custody
 *   or filesystem error could print a private key that a custody implementation put in its message.
 * - Key material is never an argument to any function in this file. There is no code path by which a
 *   private key could reach a refusal.
 */

/** The only external text a field-named refusal may carry. */
const GENERIC_FIELD_MESSAGE = 'endpoint refused the frame';

/**
 * Refusal codes, grouped by the verification step that raises them. Every code listed here is
 * reachable from exactly one step of the frozen order in `verify.js` (or from result assembly), which
 * is what makes the refusal diagnosable without leaking anything to the sender.
 */
const ENDPOINT_REFUSAL_HTTP_STATUS = Object.freeze({
  // 1. canonical string rebuild / per-field encodings
  ENDPOINT_ENVELOPE_SHAPE_INVALID: 400,
  ENDPOINT_ENVELOPE_FIELD_NOT_CANONICAL: 400,
  ENDPOINT_FRAME_EXTRA_FIELD: 400,
  // 2. signature against the PINNED backend key
  ENDPOINT_SIGNATURE_INVALID: 401,
  // 3. pinned keyId label (GM-31: unsigned transport metadata, never authority)
  ENDPOINT_KEY_UNPINNED: 401,
  // 4. audience binding
  ENDPOINT_AUDIENCE_MISMATCH: 403,
  // 5. freshness +/- 60 s (dual bound)
  ENDPOINT_FRESHNESS_EXPIRED: 409,
  ENDPOINT_FRESHNESS_NOT_YET_VALID: 409,
  // 6. deadlineMs
  ENDPOINT_DEADLINE_EXCEEDED: 409,
  // 7. durable replay window on (grantId, nonce)
  ENDPOINT_REPLAY_DETECTED: 409,
  // 7b. inside the signature: the endpoint is the addressee (contract F-V24C-5 endpoint checks)
  ENDPOINT_DEVICE_MISMATCH: 403,
  ENDPOINT_DEVICE_KEY_MISMATCH: 403,
  // 8. GM-47: argsB64u decoded and re-hashed, equality with the SIGNED argsDigestHex
  ENDPOINT_ARGS_DIGEST_MISMATCH: 400,
  // 9. opKind admission
  ENDPOINT_OPKIND_REFUSED: 403,
  // 10. GM-72: server ceiling, then the device floor
  ENDPOINT_TOOL_OUTSIDE_CEILING: 403,
  ENDPOINT_TOOL_NOT_ENABLED_ON_DEVICE: 403,
  ENDPOINT_TOOL_NOT_IMPLEMENTED: 501,
  ENDPOINT_TOOL_ARGS_INVALID: 400,
  // 11. execution
  ENDPOINT_EXECUTION_UNCERTAIN: 502,
  // result-frame assembly (endpoint -> relay leg)
  ENDPOINT_RESULT_ASSEMBLY_FAILED: 500,
  // local (non-frame) conditions: never sent as a sender-facing diagnosis
  ENDPOINT_DEVICE_KEY_UNAVAILABLE: 500,
  ENDPOINT_REPLAY_STORE_UNAVAILABLE: 500,
  ENDPOINT_DEVICE_CONFIG_INVALID: 500,
  ENDPOINT_CEILING_SNAPSHOT_INVALID: 500,
  ENDPOINT_CLOCK_UNUSABLE: 500,
  // runtime (W13): the LONG-LIVED participant. Both are LOCAL conditions of the agent process —
  // they are never a frame's verdict and are never sent over the socket. They exist so that "this
  // machine cannot host the runtime at all" and "the operator's runtime configuration is unusable"
  // are distinguishable in a log, instead of both arriving as an untyped throw.
  ENDPOINT_RUNTIME_UNAVAILABLE: 503,
  ENDPOINT_RUNTIME_CONFIG_INVALID: 500,
});

/**
 * Builds the leak-free stand-in attached as `cause`.
 *
 * Only the error CODE survives, because a code is the only thing the endpoint classifies on. The
 * original message, stack, `keyPattern`, custody detail or filesystem path never survives, so
 * `console.error(err)` and `util.inspect(err)` cannot print key material that a custody
 * implementation carried in its error.
 * @param {unknown} err
 * @returns {Error|undefined} leak-free stand-in, or undefined when there is nothing to carry
 */
function sanitizedEndpointCause(err) {
  if (err === null || typeof err !== 'object') {
    // A primitive cause (a string, say) could itself be the leaked text: drop it entirely.
    return undefined;
  }
  const sanitized = new Error('endpoint cause');
  sanitized.name = 'EndpointCause';
  if (typeof err.code === 'string' || typeof err.code === 'number') {
    sanitized.code = err.code;
  }
  return sanitized;
}

/**
 * @typedef {object} EndpointRefusalJson
 * @property {string} name
 * @property {string} code
 * @property {number} httpStatus
 * @property {string} message
 * @property {boolean} retryable
 */

class EndpointRefusal extends Error {
  /**
   * @param {string} code one of `ENDPOINT_REFUSAL_HTTP_STATUS`
   * @param {string} [message] endpoint-side text; when `field` is supplied the EXTERNAL message is
   *   the fixed generic text and this string is retained only as the non-enumerable `detail`
   * @param {object} [options]
   * @param {number} [options.httpStatus] override; defaults to the frozen status for `code`, else 500
   * @param {boolean} [options.retryable]
   * @param {Error} [options.cause] sanitized to a code-only stand-in before it is attached
   * @param {string} [options.field] endpoint-side-only failing field; never serialized
   */
  constructor(code, message, options) {
    const settings = options ?? {};
    const field = settings.field;
    const hasField = field !== undefined && field !== null;
    const specific = message === undefined || message === null ? null : String(message);
    super(hasField ? GENERIC_FIELD_MESSAGE : specific ?? code, {
      cause: sanitizedEndpointCause(settings.cause),
    });
    this.name = 'EndpointRefusal';
    this.code = code;
    this.httpStatus = settings.httpStatus ?? ENDPOINT_REFUSAL_HTTP_STATUS[code] ?? 500;
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
   * @returns {EndpointRefusalJson}
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
 * @returns {boolean} true when `value` is an `EndpointRefusal`
 */
function isEndpointRefusal(value) {
  return value instanceof EndpointRefusal;
}

/**
 * Builds an `EndpointRefusal`.
 * @param {string} code
 * @param {string} message
 * @param {object} [options] see the constructor
 * @returns {EndpointRefusal}
 */
function refusal(code, message, options) {
  return new EndpointRefusal(code, message, options);
}

/** The code of a value that may or may not be an `EndpointRefusal`. */
function refusalCodeOf(value) {
  if (isEndpointRefusal(value)) {
    return value.code;
  }
  if (value !== null && typeof value === 'object' && typeof value.code === 'string') {
    return value.code;
  }
  return null;
}

/** The single safe line a caller may print about a refusal: code + fixed message, never `detail`. */
function describeRefusal(value) {
  const code = refusalCodeOf(value);
  if (code === null) {
    return 'endpoint refused the frame';
  }
  const message = isEndpointRefusal(value) ? value.message : 'endpoint refused the frame';
  return `${code}: ${message}`;
}

module.exports = {
  GENERIC_FIELD_MESSAGE,
  ENDPOINT_REFUSAL_HTTP_STATUS,
  EndpointRefusal,
  isEndpointRefusal,
  refusal,
  refusalCodeOf,
  describeRefusal,
  sanitizedEndpointCause,
};