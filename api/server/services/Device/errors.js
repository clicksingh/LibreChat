const DEVICE_ERROR_CODES = Object.freeze({
  DEVICE_ALREADY_REGISTERED: 409,
  ONE_DEVICE_PER_ACCOUNT: 409,
  DEVICE_IDENTITY_REVOKED: 409,
  DEVICE_ALREADY_PAIRED_USE_RENEW: 409,
  PAIRING_WINDOW_TOO_EARLY: 409,
  LEASE_EXPIRED: 409,
  NOT_OWNER_OR_STALE: 409,
  NOT_OWNER: 403,
  UNKNOWN_DEVICE: 404,
  INVALID_OR_EXPIRED_CODE: 400,
  REQUEST_SUPPLIED_IDENTITY_REJECTED: 400,
  TENANT_MISMATCH: 403,
  CODE_ISSUANCE_EXHAUSTED: 409,
  AUDIT_DELIVERY_UNCERTAIN: 500,
  WRITE_OUTCOME_UNCERTAIN: 500,
  UNCLASSIFIED_DUPLICATE: 500,
  REGISTRATION_TENANT_NOT_PERMITTED: 403,
  ENDPOINT_CONSENT_REQUIRED: 403,
  PAIRING_CEREMONY_STALE: 409,
  PAIRING_CEREMONY_REQUIRED: 400,
  AUDIT_EVENT_SHAPE_INVALID: 500,
});

const DUPLICATE_DISPOSITIONS = Object.freeze({
  TERMINAL: 'terminal',
  OWN_DISLODGE_RETRY: 'owner-dislodge-retry',
  REGENERATE_GRANT: 'regenerate-grant',
  REGENERATE_CODE: 'regenerate-code',
  SUPERSEDE_SESSION: 'supersede-session',
  REGENERATE_CHALLENGE: 'regenerate-challenge',
});

const DUPLICATE_CLASSIFICATIONS = Object.freeze({
  'challengeHash:1': {
    code: 'RETRY_CHALLENGE_DUPLICATE',
    disposition: DUPLICATE_DISPOSITIONS.REGENERATE_CHALLENGE,
    retryable: true,
    message: 'Duplicate challenge hash; bounded challenge regeneration is required',
  },
  'deviceId:1,tenantId:1': {
    code: 'RETRY_PRIOR_SESSION',
    disposition: DUPLICATE_DISPOSITIONS.SUPERSEDE_SESSION,
    retryable: true,
    message: 'Prior non-terminal pairing session for this device; supersede-retry once',
  },
  'deviceKeyId:1,tenantId:1': {
    code: 'DEVICE_ALREADY_REGISTERED',
    disposition: DUPLICATE_DISPOSITIONS.TERMINAL,
    retryable: false,
    message: 'Device key is already registered for this tenant',
  },
  'grantId:1,tenantId:1': {
    code: 'RETRY_GRANT_MINT_DEFECT',
    disposition: DUPLICATE_DISPOSITIONS.REGENERATE_GRANT,
    retryable: true,
    message: 'Grant id duplicate; regenerate the grant id and retry once',
  },
  'lookupTag:1,tenantId:1': {
    code: 'RETRY_CODE_COLLISION',
    disposition: DUPLICATE_DISPOSITIONS.REGENERATE_CODE,
    retryable: true,
    message: 'Pairing code collision; regenerate the code at most three times',
  },
  'ownerId:1,tenantId:1': {
    code: 'ONE_DEVICE_PER_ACCOUNT',
    disposition: DUPLICATE_DISPOSITIONS.OWN_DISLODGE_RETRY,
    retryable: true,
    message: 'Owner already holds a live device lease in this tenant',
  },
});

const UNCERTAIN_ERROR_NAMES = Object.freeze([
  'MongoNetworkError',
  'MongoNetworkTimeoutError',
  'MongoServerSelectionError',
  'MongoNotConnectedError',
  'MongoTopologyClosedError',
  'MongoWriteConcernError',
  'MongoPoolClosedError',
  'MongoExpiredSessionError',
  'PoolClosedError',
  'WaitQueueTimeoutError',
]);

const UNCERTAIN_ERROR_CODES = Object.freeze([
  6,
  7,
  50,
  64,
  89,
  91,
  133,
  189,
  262,
  9001,
  10107,
  11600,
  11602,
  13435,
  13436,
  'ECONNRESET',
  'ECONNREFUSED',
  'ECONNABORTED',
  'EPIPE',
  'ETIMEDOUT',
  'ENOTFOUND',
  'EAI_AGAIN',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'ENETDOWN',
  'ENETRESET',
  'ERR_SOCKET_CLOSED',
  'UND_ERR_SOCKET',
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_HEADERS_TIMEOUT',
  'UND_ERR_BODY_TIMEOUT',
  'WRITE_OUTCOME_UNCERTAIN',
]);

const UNCERTAIN_ERROR_LABELS = Object.freeze([
  'RetryableWriteError',
  'TransientTransactionError',
  'UnknownTransactionCommitResult',
]);

const MAX_CAUSE_DEPTH = 4;

/**
 * @typedef {object} DeviceErrorJson
 * @property {string} name
 * @property {string} code
 * @property {number} httpStatus
 * @property {string} message
 * @property {string} disposition
 * @property {boolean} retryable
 */

/**
 * Device domain error.
 *
 * `detail` is deliberately NOT part of `DeviceErrorJson`. It is server-side-only diagnostic
 * detail (for example the normalized duplicate `keyPattern`), defined non-enumerable on the
 * instance so it can never reach a client through `toJSON()`, `JSON.stringify(err)` or
 * `util.inspect(err)`. Read it explicitly as `err.detail` from server-side code only.
 */
class DeviceError extends Error {
  /**
   * `new DeviceError(code, message, options)` or `new DeviceError(code, options)`.
   * `httpStatus` defaults to the canonical status for `code`, else 500 (fail closed).
   * @param {string} code canonical device error code, or a bounded-retry duplicate classification
   * @param {string} [message] caller-facing message; defaults to `code`
   * @param {object} [options]
   * @param {number} [options.httpStatus]
   * @param {Error} [options.cause]
   * @param {string} [options.disposition] one of DUPLICATE_DISPOSITIONS
   * @param {boolean} [options.retryable]
   * @param {string} [options.detail] server-side-only diagnostic detail; never serialized
   */
  constructor(code, message, options) {
    let resolvedMessage = message;
    let resolvedOptions = options;
    if (resolvedMessage !== null && typeof resolvedMessage === 'object') {
      resolvedOptions = resolvedMessage;
      resolvedMessage = undefined;
    }
    const settings = resolvedOptions ?? {};
    super(resolvedMessage ?? code, { cause: settings.cause });
    this.name = 'DeviceError';
    this.code = code;
    this.httpStatus = settings.httpStatus ?? DEVICE_ERROR_CODES[code] ?? 500;
    this.disposition = settings.disposition ?? DUPLICATE_DISPOSITIONS.TERMINAL;
    this.retryable = settings.retryable ?? false;
    if (settings.detail !== undefined && settings.detail !== null) {
      Object.defineProperty(this, 'detail', {
        value: typeof settings.detail === 'string' ? settings.detail : String(settings.detail),
        enumerable: false,
        writable: false,
      });
    }
  }

  /**
   * Safe serialization: digest values and causes are never included.
   * @returns {DeviceErrorJson}
   */
  toJSON() {
    return {
      name: this.name,
      code: this.code,
      httpStatus: this.httpStatus,
      message: this.message,
      disposition: this.disposition,
      retryable: this.retryable,
    };
  }
}

function isDeviceError(err) {
  return err instanceof DeviceError;
}

function isDuplicateKeyError(err) {
  if (err === null || typeof err !== 'object') {
    return false;
  }
  return err.code === 11000 || err.code === 11001;
}

function describeKeyPattern(keyPattern) {
  if (keyPattern === null || typeof keyPattern !== 'object') {
    return null;
  }
  const entries = Object.entries(keyPattern);
  if (entries.length === 0) {
    return null;
  }
  const parts = [];
  for (const [field, direction] of entries) {
    const numericDirection = Number(direction);
    if (field.length === 0 || !Number.isInteger(numericDirection)) {
      return null;
    }
    parts.push(`${field}:${numericDirection}`);
  }
  return parts.sort().join(',');
}

/**
 * Builds a leak-free stand-in for a raw driver duplicate error.
 *
 * The raw error carries `keyPattern`/`keyValue`, and Node's `util.inspect` prints an
 * `Error#cause` chain, so keeping the raw object as `cause` would still expose the index shape in
 * server-side logs. Only the pieces classification needs are preserved: the numeric duplicate
 * code and a generic message. Nothing about the index shape survives.
 */
function sanitizedDuplicateCause(err) {
  if (err === null || typeof err !== 'object') {
    return undefined;
  }
  const sanitized = new Error('duplicate key');
  sanitized.name = 'MongoDuplicateKeyError';
  sanitized.code = err.code;
  return sanitized;
}

/**
 * Classifies a duplicate-key failure using only the observed `keyPattern` (field order and
 * direction values are normalized; the index name is never consulted). Unrecognized or absent
 * patterns, and non-duplicate input, return `UNCLASSIFIED_DUPLICATE` 500 rather than a guess.
 * The observed normalized pattern is retained ONLY as the non-serialized `detail` field of the
 * returned error (server-side diagnostics); it is never part of the client-facing message, of
 * `toJSON()`, or of the serialized `cause` chain. A `retryable` result permits exactly one
 * bounded recovery by the caller; it never means blind retry of a non-idempotent CAS.
 * @param {object} err surfaced MongoDB/Mongoose error
 * @returns {DeviceError}
 */
function classifyDuplicateKey(err) {
  const observed = describeKeyPattern(
    err === null || typeof err !== 'object' ? null : err.keyPattern,
  );
  const classification = observed === null ? undefined : DUPLICATE_CLASSIFICATIONS[observed];
  const cause = sanitizedDuplicateCause(err);
  if (classification === undefined) {
    const detail = observed === null ? 'absent or unusable' : observed;
    return new DeviceError(
      'UNCLASSIFIED_DUPLICATE',
      'Duplicate key could not be classified; failing closed without guessing',
      { cause, disposition: DUPLICATE_DISPOSITIONS.TERMINAL, retryable: false, detail },
    );
  }
  return new DeviceError(classification.code, classification.message, {
    cause,
    disposition: classification.disposition,
    retryable: classification.retryable,
  });
}

function hasUncertainLabel(err) {
  if (!Array.isArray(err.errorLabels)) {
    return false;
  }
  return err.errorLabels.some((label) => UNCERTAIN_ERROR_LABELS.includes(label));
}

function isUncertainWriteError(err, depth) {
  if (depth > MAX_CAUSE_DEPTH) {
    return false;
  }
  if (UNCERTAIN_ERROR_NAMES.includes(err.name) || hasUncertainLabel(err)) {
    return true;
  }
  if (typeof err.code === 'number' || typeof err.code === 'string') {
    if (UNCERTAIN_ERROR_CODES.includes(err.code)) {
      return true;
    }
  }
  const nested = [err.cause, err.reason];
  for (const candidate of nested) {
    if (candidate !== null && typeof candidate === 'object') {
      if (isUncertainWriteError(candidate, depth + 1)) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Classifies a write failure as `'duplicate'`, `'uncertain'` or `'unknown'`. `'uncertain'` means
 * the outcome after send is indeterminate (network/reset/timeout/transient error): the caller must
 * re-read by `{_id, tenantId}` and compare `epoch`/`grantId`, and must never blind-retry a
 * non-idempotent CAS. There is no success path here: success is the absence of an error.
 * @param {object} err
 * @returns {'duplicate'|'uncertain'|'unknown'}
 */
function classifyWriteOutcome(err) {
  if (err === null || typeof err !== 'object') {
    return 'unknown';
  }
  if (isDuplicateKeyError(err)) {
    return 'duplicate';
  }
  if (isUncertainWriteError(err, 0)) {
    return 'uncertain';
  }
  return 'unknown';
}

module.exports = {
  DeviceError,
  DEVICE_ERROR_CODES,
  DUPLICATE_DISPOSITIONS,
  isDeviceError,
  isDuplicateKeyError,
  classifyDuplicateKey,
  classifyWriteOutcome,
};
