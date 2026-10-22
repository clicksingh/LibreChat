'use strict';

/**
 * W3-B R2 S3-B audit sink: the frozen R1-B adapter between the device audit emitters and the
 * genuine Mongoose `AuditEvent` model.
 *
 * Contract (GOVERNOR-W3B-R2-S3-AUDIT-CORE-AUTHORIZATION-20261015, "S3-B exact law"):
 * - `AUDIT_EVENT_KEYS` is the exact ordered 10-key audit event schema.
 * - `projectAuditEvent` rejects every missing/forbidden/shape-invalid input with a `DeviceError`
 *   carrying `AUDIT_EVENT_SHAPE_INVALID` before any write, and otherwise whitelist-projects exactly
 *   the 10 contract keys, preserving literal nulls and never fabricating a value.
 * - `createMongooseAuditSink` returns `{ sinkKind: 'mongoose-AuditEvent', audit }`; `audit` projects
 *   first and then writes with the explicit frozen write concern `{ w: 'majority', j: true }`.
 *   Write failures propagate unchanged; no event payload is ever logged.
 */

const { DeviceError } = require('./errors');

const AUDIT_EVENT_KEYS = Object.freeze([
  'tenantId',
  'deviceId',
  'ownerId',
  'grantId',
  'epoch',
  'seq',
  'kind',
  'ts',
  'actor',
  'reasonCode',
]);

const AUDIT_WRITE_CONCERN = Object.freeze({ w: 'majority', j: true });

const AUDIT_SINK_KIND = 'mongoose-AuditEvent';

const AUDIT_EVENT_SHAPE_INVALID = 'AUDIT_EVENT_SHAPE_INVALID';

const AUDIT_EVENT_KINDS = Object.freeze([
  'register',
  'grant',
  'renew',
  'revoke',
  'expire',
  'retire',
  'release',
  'claim-refused',
]);

const FORBIDDEN_AUDIT_EVENT_KEYS = Object.freeze([
  'lookupTag',
  'code',
  'pairingCode',
  'pepperLookup',
  'pepper',
  'privateKey',
  'challengeNonce',
  'challenge',
  'devicePublicKey',
  'signature',
  'headers',
  'authorization',
  'body',
  'query',
  'params',
  'ip',
  'rawIp',
  'sourceIp',
  'issuedFromSourceHash',
  'localApprovalNonceHash',
]);

const STRING_KEY_NAMES = Object.freeze(['deviceId', 'ownerId', 'grantId', 'actor', 'reasonCode']);

const SEQUENCE_KEY_NAMES = Object.freeze(['epoch', 'seq']);

/**
 * Per-kind F6 shape (R1-B §3.1 / §4.1). `mustBeNull` positions must be literally null; every key
 * present in `mayBeNull` may be null (or a valid value); every remaining key of `AUDIT_EVENT_KEYS`
 * must be non-null. `tenantId`, `kind` and `ts` are validated independently for every kind.
 */
const KIND_SHAPES = Object.freeze({
  register: Object.freeze({
    mustBeNull: Object.freeze(['ownerId', 'grantId', 'actor', 'reasonCode']),
    mayBeNull: Object.freeze(['ownerId', 'grantId', 'actor', 'reasonCode']),
  }),
  grant: Object.freeze({
    mustBeNull: Object.freeze(['reasonCode']),
    mayBeNull: Object.freeze(['reasonCode']),
  }),
  renew: Object.freeze({
    mustBeNull: Object.freeze(['reasonCode']),
    mayBeNull: Object.freeze(['reasonCode']),
  }),
  revoke: Object.freeze({
    mustBeNull: Object.freeze(['reasonCode']),
    mayBeNull: Object.freeze(['reasonCode']),
  }),
  expire: Object.freeze({
    mustBeNull: Object.freeze(['actor', 'reasonCode']),
    mayBeNull: Object.freeze(['actor', 'reasonCode']),
  }),
  retire: Object.freeze({
    mustBeNull: Object.freeze([]),
    mayBeNull: Object.freeze(['ownerId', 'grantId']),
  }),
  release: Object.freeze({
    mustBeNull: Object.freeze(['reasonCode']),
    mayBeNull: Object.freeze(['deviceId', 'ownerId', 'grantId', 'epoch', 'seq', 'reasonCode']),
  }),
  'claim-refused': Object.freeze({
    mustBeNull: Object.freeze([]),
    mayBeNull: Object.freeze(['ownerId', 'grantId', 'epoch', 'seq', 'actor', 'reasonCode']),
  }),
});

function shapeInvalid(detail) {
  return new DeviceError(AUDIT_EVENT_SHAPE_INVALID, `audit event shape invalid: ${detail}`);
}

function isAuditRecord(value) {
  return value !== null && typeof value === 'object' && Array.isArray(value) === false;
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

function isSequenceNumber(value) {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0;
}

function isUsableDate(value) {
  if (value === null || typeof value !== 'object') {
    return false;
  }
  if (value instanceof Date === false && Object.prototype.toString.call(value) !== '[object Date]') {
    return false;
  }
  return Number.isFinite(value.getTime());
}

function assertEnvelope(event) {
  if (isAuditRecord(event) === false) {
    throw shapeInvalid('event must be a non-null object');
  }
  for (const key of Object.keys(event)) {
    if (FORBIDDEN_AUDIT_EVENT_KEYS.includes(key)) {
      throw shapeInvalid(`forbidden key present: ${key}`);
    }
  }
  for (const key of AUDIT_EVENT_KEYS) {
    if (Object.prototype.hasOwnProperty.call(event, key) === false) {
      throw shapeInvalid(`missing key: ${key}`);
    }
  }
  if (isNonEmptyString(event.tenantId) === false) {
    throw shapeInvalid('tenantId must be a non-empty string');
  }
  if (AUDIT_EVENT_KINDS.includes(event.kind) === false) {
    throw shapeInvalid('kind is not an authorized audit event kind');
  }
  if (isUsableDate(event.ts) === false) {
    throw shapeInvalid('ts must be a valid Date');
  }
}

function assertKindField(key, value, shape) {
  if (shape.mustBeNull.includes(key)) {
    if (value !== null) {
      throw shapeInvalid(`kind requires literal null: ${key}`);
    }
    return;
  }
  if (value === null) {
    if (shape.mayBeNull.includes(key) === false) {
      throw shapeInvalid(`kind requires a non-null value: ${key}`);
    }
    return;
  }
  if (STRING_KEY_NAMES.includes(key) && isNonEmptyString(value) === false) {
    throw shapeInvalid(`${key} must be a non-empty string`);
  }
  if (SEQUENCE_KEY_NAMES.includes(key) && isSequenceNumber(value) === false) {
    throw shapeInvalid(`${key} must be a non-negative integer`);
  }
}

function assertKindShape(event) {
  const shape = KIND_SHAPES[event.kind];
  for (const key of AUDIT_EVENT_KEYS) {
    assertKindField(key, event[key], shape);
  }
  if (event.kind === 'register' && (event.epoch !== 0 || event.seq !== 0)) {
    throw shapeInvalid('register requires epoch 0 and seq 0');
  }
  if (event.kind === 'release' && event.epoch !== null && event.seq === null) {
    throw shapeInvalid('release with a non-null epoch requires a non-null seq');
  }
  if (event.kind === 'claim-refused') {
    const epochNull = event.epoch === null;
    const seqNull = event.seq === null;
    if (epochNull !== seqNull) {
      throw shapeInvalid('claim-refused epoch and seq must be jointly null or non-null');
    }
    if (!epochNull && event.epoch !== event.seq) {
      throw shapeInvalid('claim-refused seq must equal known authority epoch');
    }
  }
}

/**
 * Validate the audit event contract and return a fresh object holding exactly `AUDIT_EVENT_KEYS`
 * in canonical order. Benign non-contract keys are dropped, never persisted. Invalid input never
 * reaches a write: every rejection is a `DeviceError` with `AUDIT_EVENT_SHAPE_INVALID`. Error
 * messages name keys only and never carry event values.
 * @param {object} event
 * @returns {object}
 */
function projectAuditEvent(event) {
  assertEnvelope(event);
  assertKindShape(event);
  const projected = {};
  for (const key of AUDIT_EVENT_KEYS) {
    projected[key] = event[key];
  }
  return projected;
}

function hasMongooseModelSurface(AuditEvent) {
  if (AuditEvent === null || AuditEvent === undefined) {
    return false;
  }
  const surfaceType = typeof AuditEvent;
  if (surfaceType !== 'function' && surfaceType !== 'object') {
    return false;
  }
  if (typeof AuditEvent.create !== 'function') {
    return false;
  }
  return AuditEvent.schema !== null && typeof AuditEvent.schema === 'object';
}

function resolveLogger(surface) {
  if (surface.logger !== null && typeof surface.logger === 'object' && typeof surface.logger.warn === 'function') {
    return surface.logger;
  }
  return null;
}

/** Fixed, payload-free failure notice; a throwing logger must never mask the write failure. */
function warnWriteFailed(logger) {
  if (logger === null) {
    return;
  }
  try {
    logger.warn('audit sink write failed');
  } catch {
    /* the original write failure propagates */
  }
}

/**
 * Build the Mongoose-backed audit sink. The supplied surface is used verbatim: the projected event
 * is written through `AuditEvent.create([projected], { writeConcern: AUDIT_WRITE_CONCERN })` and any
 * failure propagates to the caller unchanged.
 * @param {object} surface
 * @param {object} surface.AuditEvent genuine Mongoose `AuditEvent` model surface
 * @param {object} [surface.logger]
 * @returns {{sinkKind: string, audit: (event: object) => Promise<undefined>}}
 */
function createMongooseAuditSink(surface) {
  if (isAuditRecord(surface) === false) {
    throw shapeInvalid('createMongooseAuditSink requires a surface object');
  }
  const { AuditEvent } = surface;
  if (hasMongooseModelSurface(AuditEvent) === false) {
    throw shapeInvalid('createMongooseAuditSink requires an AuditEvent model surface with create and schema');
  }
  const logger = resolveLogger(surface);

  async function audit(event) {
    const projected = projectAuditEvent(event);
    try {
      await AuditEvent.create([projected], { writeConcern: AUDIT_WRITE_CONCERN });
    } catch (err) {
      warnWriteFailed(logger);
      throw err;
    }
    return undefined;
  }

  return { sinkKind: AUDIT_SINK_KIND, audit };
}

module.exports = {
  AUDIT_EVENT_KEYS,
  AUDIT_WRITE_CONCERN,
  projectAuditEvent,
  createMongooseAuditSink,
};
