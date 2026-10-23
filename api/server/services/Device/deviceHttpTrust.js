'use strict';

/**
 * Shared HTTP trust helpers for the local device endpoints (task T7, owner-authorized 2026-10-22).
 *
 * LOCAL LAB ONLY. Production G0 remains BLOCKED; nothing here may be mounted on a production host
 * before Governor ratification.
 *
 * TRUST RULES ENFORCED HERE, FOR EVERY DEVICE HTTP HANDLER
 * - The request is read for PROTOCOL VALUES ONLY, and only from an exact per-endpoint allowlist of
 *   flat string fields. Route params, query values, nested objects, arrays and non-string body
 *   values are rejected outright with `400 REQUEST_SUPPLIED_IDENTITY_REJECTED` — before any model
 *   method is touched, so an injected container can never reach a query.
 * - Identity/authority vocabulary (`deviceId`, `ownerId`, `tenantId`, `role`, `principal`,
 *   `authority`, `epoch`, `grantId`, `actor`, `authorization`, ...) is named explicitly and
 *   rejected with the same code even when an endpoint would otherwise ignore it.
 * - Tenant and owner are resolved from the trusted tenant context (ALS) plus the authenticated
 *   session only. A session whose `tenantId` is absent or disagrees with the active ALS tenant is
 *   refused; no request field can influence either value.
 * - A classified `DeviceError` maps to its own frozen HTTP status; the response carries only
 *   `code`, `message` and explicitly whitelisted echo fields. `cause`, `detail`, digests, tickets,
 *   codes, keys and peppers are never serialized.
 */

const { DeviceError } = require('./errors');
const { createMongooseAuditSink } = require('./auditSink');

/** The frozen system tenant: never a usable authority tenant. */
const SYSTEM_TENANT_ID = '__SYSTEM__';

/**
 * Identity/authority vocabulary that must never be read from a request. Container/transport keys
 * are included because a nested raw request container is itself an identity channel.
 */
const IDENTITY_FIELD_NAMES = Object.freeze([
  'actor',
  'actorRole',
  'admin',
  'auth',
  'authorities',
  'authority',
  'authorization',
  'body',
  'capabilities',
  'capability',
  'deviceId',
  'deviceID',
  'deviceKeyId',
  'deviceSessionId',
  'epoch',
  'grantId',
  'headers',
  'isAdmin',
  'isOwner',
  'jti',
  'keyId',
  'lookupTag',
  'owner',
  'ownerId',
  'ownerID',
  'pairingSessionId',
  'params',
  'permissions',
  'principal',
  'principalId',
  'query',
  'req',
  'request',
  'res',
  'role',
  'roles',
  'scope',
  'scopes',
  'sessionId',
  'sessionRef',
  'sessionVersion',
  'sub',
  'subject',
  'tenant',
  'tenantId',
  'tenantID',
  'user',
  'userId',
]);

function isNonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/** True when a container carries at least one own key; `undefined`/`null` count as empty. */
function hasClientInput(container) {
  if (container === null || container === undefined || typeof container !== 'object') {
    return false;
  }
  return Object.keys(container).length > 0;
}

/** Normalizes `req.user.id` / `_id` to a non-empty string, or `null`. Never trusts a request field. */
function principalIdOf(user) {
  const value = user?.id ?? user?._id ?? null;
  if (value === null || value === undefined) {
    return null;
  }
  const normalized = typeof value === 'string' ? value : value.toString?.();
  return isNonEmptyString(normalized) ? normalized : null;
}

/** Narrows an arbitrary value to a finite epoch-millisecond integer, else `null`. */
function toObservedEpoch(value) {
  return Number.isInteger(value) && value >= 0 ? value : null;
}

/** Truthful ISO echo of a stored timestamp; anything unreadable is reported as `null`. */
function toIsoOrNull(value) {
  if (value === null || value === undefined) {
    return null;
  }
  const parsed = value instanceof Date ? value.getTime() : Date.parse(String(value));
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null;
}

function identityRejected(message) {
  return new DeviceError('REQUEST_SUPPLIED_IDENTITY_REJECTED', message);
}

function respondIdentityRejected(res, message) {
  const error = identityRejected(message);
  res.status(error.httpStatus).json({ ok: false, code: error.code, message: error.message });
  return true;
}

/**
 * Rejects any request input that is not one of the endpoint's exact flat string protocol fields.
 * Route params and query values are never accepted by a device endpoint. Returns `true` when the
 * request was rejected and a response has already been sent.
 *
 * @param {object} req Express request (only `params`, `query`, `body` are inspected)
 * @param {object} res Express response
 * @param {{endpoint: string, allowedBodyFields: readonly string[]}} contract
 * @returns {boolean}
 */
function guardRequestInput(req, res, { endpoint, allowedBodyFields } = {}) {
  const label = isNonEmptyString(endpoint) ? endpoint : 'this device endpoint';
  if (hasClientInput(req?.params)) {
    return respondIdentityRejected(
      res,
      `${label} resolves identity and authority server-side and does not accept route parameters`,
    );
  }
  if (hasClientInput(req?.query)) {
    return respondIdentityRejected(
      res,
      `${label} resolves identity and authority server-side and does not accept query parameters`,
    );
  }

  const body = req?.body;
  if (body === undefined || body === null) {
    return false;
  }
  if (!isPlainRecord(body)) {
    return respondIdentityRejected(
      res,
      `${label} accepts only a flat JSON object of protocol fields`,
    );
  }

  const allowed = Array.isArray(allowedBodyFields) ? allowedBodyFields : [];
  for (const field of Object.keys(body)) {
    if (IDENTITY_FIELD_NAMES.includes(field)) {
      return respondIdentityRejected(
        res,
        `${label} resolves "${field}" server-side; client-supplied identity and authority fields are never read`,
      );
    }
    if (!allowed.includes(field)) {
      return respondIdentityRejected(res, `${label} does not accept the request field "${field}"`);
    }
    if (typeof body[field] !== 'string') {
      return respondIdentityRejected(
        res,
        `${label} accepts only flat string protocol fields; "${field}" must be a string`,
      );
    }
  }
  return false;
}

/**
 * Resolves the trusted request context: active tenant from the ALS tenant context, principal from
 * the authenticated session. Fails closed with a classified `DeviceError` (never a request value).
 *
 * @returns {{tenantId: (string|null), principalId: (string|null), error: (DeviceError|null)}}
 */
function resolveTrustedContext({ req, tenantContext } = {}) {
  const unusable = () => ({ tenantId: null, principalId: null, error: null });
  if (
    tenantContext === null ||
    typeof tenantContext !== 'object' ||
    typeof tenantContext.getActiveTenantId !== 'function'
  ) {
    return {
      ...unusable(),
      error: new DeviceError('TENANT_MISMATCH', 'Trusted tenant context is not configured'),
    };
  }

  let tenantId;
  try {
    tenantId = tenantContext.getActiveTenantId();
  } catch {
    return {
      ...unusable(),
      error: new DeviceError('TENANT_MISMATCH', 'Tenant context lookup failed closed'),
    };
  }
  if (!isNonEmptyString(tenantId) || tenantId === SYSTEM_TENANT_ID) {
    return {
      ...unusable(),
      error: new DeviceError(
        'TENANT_MISMATCH',
        'No authenticated tenant is active for this request',
      ),
    };
  }

  const sessionTenantId = req?.user?.tenantId;
  if (!isNonEmptyString(sessionTenantId) || sessionTenantId !== tenantId) {
    return {
      ...unusable(),
      error: new DeviceError(
        'TENANT_MISMATCH',
        'The authenticated session tenant does not match the active tenant',
      ),
    };
  }

  const principalId = principalIdOf(req?.user);
  if (!isNonEmptyString(principalId)) {
    return {
      ...unusable(),
      error: new DeviceError(
        'NOT_OWNER',
        'The authenticated session carries no usable principal id',
      ),
    };
  }
  return { tenantId, principalId, error: null };
}

/**
 * Sends a classified device error. Only `code`/`message`/`httpStatus` and the caller's explicitly
 * whitelisted echo fields are serialized: `detail`, `cause` and every other instance property stay
 * server-side.
 */
function sendClassifiedError(res, error, extra = {}) {
  const status = Number.isInteger(error?.httpStatus) ? error.httpStatus : 500;
  const code = isNonEmptyString(error?.code) ? error.code : 'WRITE_OUTCOME_UNCERTAIN';
  const message = isNonEmptyString(error?.message)
    ? error.message
    : 'The device operation failed closed';
  return res.status(status).json({ ok: false, code, message, ...extra });
}

/** Fixed, payload-free fail-closed response used for unexpected throws. */
function sendFailClosed(res, message) {
  return sendClassifiedError(
    res,
    new DeviceError(
      'WRITE_OUTCOME_UNCERTAIN',
      isNonEmptyString(message) ? message : 'The device operation failed closed',
    ),
  );
}

function isNonEmptyBinary(value) {
  return (Buffer.isBuffer(value) || ArrayBuffer.isView(value)) && value.byteLength > 0;
}

/** The `isUsablePepper` contract of the pairing service, evaluated without touching the request. */
function isUsablePepperValue(value) {
  if (isNonEmptyString(value)) {
    return true;
  }
  if (isNonEmptyBinary(value)) {
    return true;
  }
  return value !== null && typeof value === 'object' && value.type === 'secret';
}

/**
 * Resolves the deployment lookup pepper from server-owned configuration only. A function seam is
 * preferred so the value is read per request (configuration reload, test injection); a static value
 * is accepted for the E1-style harness. Absence fails closed in the caller.
 */
function resolvePepperSeam({ pepperLookup, resolvePepperLookup } = {}) {
  const value = typeof resolvePepperLookup === 'function' ? resolvePepperLookup() : pepperLookup;
  return isUsablePepperValue(value) ? value : null;
}

/**
 * Builds the audit sink accessor. An injected `audit` function is used verbatim; otherwise the
 * accepted Mongoose sink is constructed lazily on first event, so an unusable `AuditEvent` model
 * surfaces as a post-commit `AUDIT_DELIVERY_UNCERTAIN` instead of a load-time crash.
 */
function createAuditAccessor({ db, logger = null, audit } = {}) {
  if (typeof audit === 'function') {
    return audit;
  }
  let sink = null;
  return async function auditThroughMongooseSink(event) {
    if (sink === null) {
      sink = createMongooseAuditSink({ AuditEvent: db?.AuditEvent, logger });
    }
    return sink.audit(event);
  };
}

/** Construction-time contract shared by every device HTTP handler factory. */
function assertHttpHandlerDependencies({ db, tenantContext, label } = {}) {
  const name = isNonEmptyString(label) ? label : 'device HTTP handler';
  if (db === null || typeof db !== 'object') {
    throw new TypeError(`${name} requires Device models`);
  }
  if (
    tenantContext === null ||
    typeof tenantContext !== 'object' ||
    typeof tenantContext.getActiveTenantId !== 'function'
  ) {
    throw new TypeError(`${name} requires trusted tenant context`);
  }
}

module.exports = {
  IDENTITY_FIELD_NAMES,
  SYSTEM_TENANT_ID,
  hasClientInput,
  isNonEmptyString,
  isPlainRecord,
  principalIdOf,
  toObservedEpoch,
  toIsoOrNull,
  guardRequestInput,
  resolveTrustedContext,
  sendClassifiedError,
  sendFailClosed,
  isUsablePepperValue,
  resolvePepperSeam,
  createAuditAccessor,
  assertHttpHandlerDependencies,
};
