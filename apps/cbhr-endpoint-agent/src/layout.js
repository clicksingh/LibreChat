'use strict';

/**
 * CBHR ENDPOINT AGENT — the frozen CBHR-RPC-V2 layout, read independently.
 *
 * LAB ARTIFACT (GM-73). This module is the endpoint's OWN reading of the frozen contract
 * (`evidence/gate-closure-002/v24/V24-C-signed-grants.md` F-V24C-4, plus the GM-29 / GM-31 / GM-35
 * rulings), not a reuse of `api/server/services/Device/relay/envelopeCore.js`. GM-54 exists because
 * "the endpoint trusts the sender's own code" proves nothing: if the endpoint imported the backend's
 * field-order array, a backend-side reordering would silently propagate to the verifier that is
 * supposed to pin the byte layout DOWN. So the layout here is written out by hand from the contract
 * text — fifteen properties in the documented order, same names, same encodings — and the golden
 * vector test (`tests/golden.js`) pins it against the published canonical string byte for byte.
 *
 * What this module *does* share with the backend is the ACCEPTED crypto primitive
 * `canonicalEncode` (GM-29/GM-54); both sides must agree on how 0x1F-joined bytes are produced, and
 * the crypto test explicitly allows that reuse. The FIELD SET and ORDER are ours; the JOIN is the
 * shared law.
 */

const { refusal } = require('./errors');
const { canonicalEncode } = require('./vendoredCrypto');

/** Versioned domain separator. Any future field change bumps this tag (contract law). */
const V2_TAG = 'CBHR-RPC-V2';

/** Result-frame domain separator. Distinct from the command tag: one wrong by one byte refuses. */
const RESULT_TAG = 'CBHR-RPC-RESULT-V2';

/** The one separator byte of the canonical law. Never appears inside a field value. */
const UNIT_SEPARATOR = '\u001f';

/** Fifteen core properties, in the exact fixed canonical order. Written from the contract text. */
const FIELD_ORDER = Object.freeze([
  'tag',
  'requestId',
  'nonce',
  'issuedAt',
  'deadlineMs',
  'epoch',
  'grantId',
  'ownerPrincipalId',
  'tenantId',
  'deviceId',
  'deviceKeyId',
  'toolName',
  'opKind',
  'audience',
  'argsDigestHex',
]);

/**
 * Every key a flat incoming wire frame may carry: the fifteen core fields plus the unsigned
 * transport fields (GM-31/GM-35/GM-47). `seq` is relay-assigned delivery metadata (absent on the
 * backend->relay leg); `callId`/`idempotencyKey` correlate retries; `signatureB64u`/`keyId`/
 * `argsB64u` are unsigned per GM-31 and GM-47.
 */
const INCOMING_FRAME_KEYS = Object.freeze([
  ...FIELD_ORDER,
  'signatureB64u',
  'keyId',
  'argsB64u',
  'callId',
  'idempotencyKey',
  'seq',
]);

const HEX64_PATTERN = /^[0-9a-f]{64}$/;
const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DECIMAL_PATTERN = /^(0|[1-9][0-9]*)$/;
const POSITIVE_DECIMAL_PATTERN = /^[1-9][0-9]*$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const BASE64URL_EMPTY_OK_PATTERN = /^[A-Za-z0-9_-]*$/;

const GRANT_ID_BYTES = 16;
const NONCE_BYTES = 16;
const DEVICE_KEY_ID_BYTES = 32;
const SIGNATURE_BYTES = 64;

/** Longest deadline horizon the contract permits: `deadlineMs <= issuedAt + 120 000`. */
const MAX_DEADLINE_HORIZON_MS = 120000;

function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function hasOwn(record, key) {
  return Object.prototype.hasOwnProperty.call(record, key);
}

/**
 * Strict unpadded-base64url decode with a minimum length of one. DECODING ONLY: no
 * canonicalisation, no parsing.
 * @param {unknown} value
 * @returns {Buffer|null} decoded bytes, or null when `value` is not canonical unpadded base64url
 */
function decodeBase64UrlBytes(value) {
  if (typeof value !== 'string' || value.length === 0) {
    return null;
  }
  if (!BASE64URL_PATTERN.test(value) || value.length % 4 === 1) {
    return null;
  }
  let decoded;
  try {
    decoded = Buffer.from(value, 'base64url');
  } catch {
    return null;
  }
  return decoded.toString('base64url') === value ? decoded : null;
}

/**
 * Strict unpadded-base64url decode of transported args bytes, where the EMPTY string is legal (an
 * argument payload may legitimately be empty). DECODING ONLY (GM-29: the endpoint hashes the bytes
 * it actually received, never a re-serialization).
 * @param {unknown} value
 * @returns {Buffer|null}
 */
function decodeArgsBytes(value) {
  if (typeof value !== 'string' || !BASE64URL_EMPTY_OK_PATTERN.test(value)) {
    return null;
  }
  if (value.length % 4 === 1) {
    return null;
  }
  let decoded;
  try {
    decoded = Buffer.from(value, 'base64url');
  } catch {
    return null;
  }
  return decoded.toString('base64url') === value ? decoded : null;
}

/**
 * Narrows a value to a safe epoch-millisecond integer. Accepts a canonical decimal string or a
 * non-negative safe integer number; anything else is `null` (never coerced).
 * @param {unknown} value
 * @returns {number|null}
 */
function parseEpochMs(value) {
  if (typeof value === 'number') {
    return Number.isSafeInteger(value) && value >= 0 ? value : null;
  }
  if (typeof value !== 'string' || !DECIMAL_PATTERN.test(value)) {
    return null;
  }
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
}

function shapeRefusal(property, detail) {
  return refusal('ENDPOINT_ENVELOPE_SHAPE_INVALID', `envelope field "${property}" ${detail}`, {
    field: property,
  });
}

function lengthRefusal(property, bytes) {
  return shapeRefusal(
    property,
    `must be canonical unpadded base64url of exactly ${bytes} bytes`,
  );
}

/**
 * Per-field value-domain check, written from the contract's encoding table (F-V24C-4). Returns
 * `null` when the value satisfies the encoding, else a refusal naming the field (never the value).
 * @param {string} property
 * @param {unknown} value
 * @returns {import('./errors').EndpointRefusal|null}
 */
function checkFieldValue(property, value) {
  if (typeof value !== 'string') {
    return shapeRefusal(property, 'must be a string');
  }
  switch (property) {
    case 'tag':
      return value === V2_TAG ? null : shapeRefusal(property, `must be the literal "${V2_TAG}"`);
    case 'requestId':
      return UUID_V4_PATTERN.test(value)
        ? null
        : shapeRefusal(property, 'must be a canonical lowercase hyphenated UUIDv4');
    case 'nonce': {
      const bytes = decodeBase64UrlBytes(value);
      return bytes !== null && bytes.length === NONCE_BYTES ? null : lengthRefusal(property, NONCE_BYTES);
    }
    case 'issuedAt':
      return parseEpochMs(value) !== null
        ? null
        : shapeRefusal(property, 'must be a canonical decimal epoch-millisecond string');
    case 'deadlineMs':
      return parseEpochMs(value) !== null
        ? null
        : shapeRefusal(property, 'must be a canonical decimal epoch-millisecond string');
    case 'epoch':
      return POSITIVE_DECIMAL_PATTERN.test(value)
        ? null
        : shapeRefusal(property, 'must be a canonical decimal integer >= 1');
    case 'grantId': {
      const bytes = decodeBase64UrlBytes(value);
      return bytes !== null && bytes.length === GRANT_ID_BYTES
        ? null
        : lengthRefusal(property, GRANT_ID_BYTES);
    }
    case 'deviceKeyId': {
      const bytes = decodeBase64UrlBytes(value);
      return bytes !== null && bytes.length === DEVICE_KEY_ID_BYTES
        ? null
        : lengthRefusal(property, DEVICE_KEY_ID_BYTES);
    }
    case 'ownerPrincipalId':
    case 'tenantId':
    case 'deviceId':
    case 'toolName':
      return value.length > 0 ? null : shapeRefusal(property, 'must be a non-empty string');
    case 'opKind':
      return value === 'command' || value === 'cancel' || value === 'resync'
        ? null
        : shapeRefusal(property, 'must be one of command | cancel | resync');
    case 'audience':
      return value === 'endpoint' || value === 'relay'
        ? null
        : shapeRefusal(property, 'must be one of endpoint | relay');
    case 'argsDigestHex':
      return HEX64_PATTERN.test(value)
        ? null
        : shapeRefusal(property, 'must be 64 lowercase hex characters over sha256(args)');
    default:
      return shapeRefusal(property, 'is not a field of the CBHR-RPC-V2 core');
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
  const orderIndex = Number(match[1]) + 1;
  return FIELD_ORDER[orderIndex] === undefined ? `fields[${match[1]}]` : FIELD_ORDER[orderIndex];
}

/**
 * Joins a validated core through the accepted canonical encoder. The join law is shared; the
 * field ORDER (supplied here) is the endpoint's own frozen reading of the contract.
 * @param {object} core validated core (tag + 14 fields)
 * @returns {Buffer} exact signed bytes
 */
function joinCoreFields(core) {
  const fields = FIELD_ORDER.slice(1).map((property) => core[property]);
  try {
    return canonicalEncode({ domainTag: core.tag, fields });
  } catch (err) {
    throw refusal(
      'ENDPOINT_ENVELOPE_FIELD_NOT_CANONICAL',
      `envelope field "${canonicalFieldLabel(err)}" is not canonical under the 0x1F serialization law`,
      { field: canonicalFieldLabel(err), cause: err },
    );
  }
}

/**
 * Validates the core's exact key set, every per-field encoding, the deadline horizon and the
 * 0x1F/well-formed-UTF-16 canonical law.
 * @param {object} core
 * @returns {object} the same core
 */
function assertEnvelopeCore(core) {
  if (!isPlainRecord(core)) {
    throw shapeRefusal('core', 'must be a plain object carrying exactly the 15 core fields');
  }
  for (const key of Object.keys(core)) {
    if (!FIELD_ORDER.includes(key)) {
      throw refusal(
        'ENDPOINT_FRAME_EXTRA_FIELD',
        `envelope field "${key}" is not part of the CBHR-RPC-V2 core (transport metadata never belongs inside the signature)`,
        { field: key },
      );
    }
  }
  for (const property of FIELD_ORDER) {
    if (!hasOwn(core, property)) {
      throw shapeRefusal(property, 'is missing from the core');
    }
    const failure = checkFieldValue(property, core[property]);
    if (failure !== null) {
      throw failure;
    }
  }
  const issuedAt = parseEpochMs(core.issuedAt);
  const deadlineMs = parseEpochMs(core.deadlineMs);
  const horizon = deadlineMs - issuedAt;
  if (horizon < 0) {
    throw shapeRefusal('deadlineMs', 'must not precede issuedAt');
  }
  if (horizon > MAX_DEADLINE_HORIZON_MS) {
    throw refusal(
      'ENDPOINT_DEADLINE_EXCEEDED',
      `envelope field "deadlineMs" exceeds the frozen ${MAX_DEADLINE_HORIZON_MS} ms horizon`,
      { field: 'deadlineMs' },
    );
  }
  joinCoreFields(core);
  return core;
}

/**
 * The exact bytes the backend signs for a given core (the endpoint's independent rebuild of the
 * signing string; step 1 of the verification order).
 * @param {object} core
 * @returns {Buffer}
 */
function canonicalBytesFor(core) {
  return joinCoreFields(assertEnvelopeCore(core));
}

/**
 * Extracts the signed core from a flat wire frame. Rejects missing, extra and non-core keys, so a
 * frame cannot smuggle a field past the signature.
 * @param {object} frame
 * @returns {object} frozen core
 */
function coreFromFrame(frame) {
  if (!isPlainRecord(frame)) {
    throw refusal('ENDPOINT_ENVELOPE_SHAPE_INVALID', 'envelope frame must be a plain object', {
      field: 'frame',
    });
  }
  for (const key of Object.keys(frame)) {
    if (!INCOMING_FRAME_KEYS.includes(key)) {
      throw refusal(
        'ENDPOINT_FRAME_EXTRA_FIELD',
        `envelope field "${key}" is not a permitted wire-frame key`,
        { field: key },
      );
    }
  }
  const core = {};
  for (const property of FIELD_ORDER) {
    if (!hasOwn(frame, property)) {
      throw shapeRefusal(property, 'is missing from the wire frame');
    }
    core[property] = frame[property];
  }
  return Object.freeze(assertEnvelopeCore(core));
}

/** Requires a well-formed 64-byte Ed25519 signature in canonical unpadded base64url. */
function assertSignatureB64u(value) {
  const bytes = decodeBase64UrlBytes(value);
  if (bytes === null || bytes.length !== SIGNATURE_BYTES) {
    throw refusal(
      'ENDPOINT_SIGNATURE_INVALID',
      `envelope field "signatureB64u" must be canonical unpadded base64url of exactly ${SIGNATURE_BYTES} bytes`,
      { field: 'signatureB64u' },
    );
  }
  return value;
}

/** Requires short non-empty transport text without the 0x1F separator. */
function assertTransportText(property, value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 200) {
    throw refusal(property, 'must be a non-empty string of at most 200 characters', {
      field: property,
    });
  }
  if (value.includes(UNIT_SEPARATOR)) {
    throw refusal(property, 'must not contain the 0x1F separator', { field: property });
  }
  return value;
}

module.exports = {
  V2_TAG,
  RESULT_TAG,
  UNIT_SEPARATOR,
  FIELD_ORDER,
  INCOMING_FRAME_KEYS,
  MAX_DEADLINE_HORIZON_MS,
  GRANT_ID_BYTES,
  NONCE_BYTES,
  DEVICE_KEY_ID_BYTES,
  SIGNATURE_BYTES,
  isPlainRecord,
  hasOwn,
  decodeBase64UrlBytes,
  decodeArgsBytes,
  parseEpochMs,
  checkFieldValue,
  assertEnvelopeCore,
  canonicalBytesFor,
  coreFromFrame,
  assertSignatureB64u,
  assertTransportText,
};