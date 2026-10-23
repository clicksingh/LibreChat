'use strict';

/**
 * `CBHR-RPC-V2` envelope core — the FROZEN 15-field signed core (workstream W2).
 *
 * CONTRACT OF RECORD (read-only governance repo):
 * `evidence/gate-closure-002/v24/V24-C-signed-grants.md` §F-V24C-4 ("The v2 signing string") and
 * §"Endpoint verifier invariants". Canonical serialization law:
 * `reports/GATE-CLOSURE-002-PAIRING-BOOTSTRAP.md` §4 — single 0x1F separator between fields, UTF-8
 * field bytes, epoch-ms decimal timestamps, base64url opaque values, no field may contain 0x1F, the
 * leading tag is the versioned domain separator, and any field change forces a tag bump.
 *
 * THE SIGNED STRING, in this exact fixed order (no reordering, no missing field, no extra field):
 *
 *   CBHR-RPC-V2 ‖ requestId ‖ nonce ‖ issuedAt ‖ deadlineMs ‖ epoch ‖ grantId ‖
 *   ownerPrincipalId ‖ tenantId ‖ deviceId ‖ deviceKeyId ‖ toolName ‖ opKind ‖
 *   audience ‖ sha256(args)
 *
 * `‖` is exactly one 0x1F byte; the tag is passed to `crypto.canonicalEncode` as its `domainTag`, so
 * the serialization itself is NOT reimplemented here — this module only fixes the field set, the
 * per-field encodings and the value-domain rules, and delegates the byte layout to the accepted
 * `../crypto` module.
 *
 * WHAT THIS MODULE DOES NOT DO
 * - It never signs and never holds, reads or derives key material. Signing is the injected seam in
 *   `./envelopeSigner`.
 * - It never invents an authorization. It only serializes values a caller already obtained from
 *   trusted server context.
 *
 * FIELD-NAME NOTE. The contract names field 15 `sha256(args)`. That is not a JavaScript identifier,
 * so the property is `argsDigestHex`; `RPC_ENVELOPE_FIELD_LAYOUT` records BOTH names, in order, so
 * the mapping back to the contract is mechanical and reviewable. No other name is renamed.
 */

const deviceCrypto = require('../crypto');
const { relayFailure } = require('./errors');

/** Versioned domain separator. A field change forces a tag bump (contract law). */
const RPC_V2_TAG = 'CBHR-RPC-V2';

/** Audience enum, bound INSIDE the signature (field 14). */
const RPC_ENVELOPE_AUDIENCES = Object.freeze({
  /** Backend-minted commands to the device. */
  ENDPOINT: 'endpoint',
  /** Endpoint-signed replies / cancel-acks travelling endpoint -> relay. */
  RELAY: 'relay',
});

/** Operation-kind enum, bound INSIDE the signature (field 13). */
const RPC_OP_KINDS = Object.freeze({
  COMMAND: 'command',
  CANCEL: 'cancel',
  RESYNC: 'resync',
});

/** Longest deadline horizon the contract permits: `deadlineMs <= issuedAt + 120 000`. */
const MAX_DEADLINE_HORIZON_MS = 120000;

/** The one separator byte of the canonical law. Never appears inside a field value. */
const CANONICAL_SEPARATOR = '\u001f';

const ARGS_DIGEST_HEX_PATTERN = /^[0-9a-f]{64}$/;
const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
/** Canonical unsigned decimal: no sign, no leading zero, no padding. */
const DECIMAL_PATTERN = /^(0|[1-9][0-9]*)$/;
/** Positive decimal for `epoch` (contract: integer >= 1). */
const POSITIVE_DECIMAL_PATTERN = /^[1-9][0-9]*$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
/** The same alphabet permitting the EMPTY string: empty argument bytes are legal (GM-47). */
const BASE64URL_PATTERN_EMPTY_OK = /^[A-Za-z0-9_-]*$/;

/** Byte lengths fixed by the contract: 128-bit grantId/nonce, 256-bit SHA-256 thumbprint. */
const GRANT_ID_BYTES = 16;
const NONCE_BYTES = 16;
const DEVICE_KEY_ID_BYTES = 32;

/**
 * The frozen field set, in canonical order. `contractName` is the contract's name for the field;
 * `property` is the JavaScript property that carries it (identical except for field 15).
 */
const RPC_ENVELOPE_FIELD_LAYOUT = Object.freeze(
  [
    {
      index: 1,
      contractName: 'tag',
      property: 'tag',
      encoding: 'literal UTF-8 versioned domain separator',
    },
    {
      index: 2,
      contractName: 'requestId',
      property: 'requestId',
      encoding: 'UUIDv4 canonical hyphenated lowercase (36 chars)',
    },
    {
      index: 3,
      contractName: 'nonce',
      property: 'nonce',
      encoding: '128-bit CSPRNG, unpadded base64url (22 chars)',
    },
    {
      index: 4,
      contractName: 'issuedAt',
      property: 'issuedAt',
      encoding: 'epoch-ms canonical decimal UTF-8',
    },
    {
      index: 5,
      contractName: 'deadlineMs',
      property: 'deadlineMs',
      encoding: 'epoch-ms canonical decimal UTF-8, <= issuedAt + 120000',
    },
    {
      index: 6,
      contractName: 'epoch',
      property: 'epoch',
      encoding: 'canonical decimal integer >= 1',
    },
    {
      index: 7,
      contractName: 'grantId',
      property: 'grantId',
      encoding: '128-bit, unpadded base64url (22 chars)',
    },
    {
      index: 8,
      contractName: 'ownerPrincipalId',
      property: 'ownerPrincipalId',
      encoding: 'UTF-8 authenticated owner principal id',
    },
    { index: 9, contractName: 'tenantId', property: 'tenantId', encoding: 'UTF-8 tenant id' },
    {
      index: 10,
      contractName: 'deviceId',
      property: 'deviceId',
      encoding: 'UTF-8 server-issued device id',
    },
    {
      index: 11,
      contractName: 'deviceKeyId',
      property: 'deviceKeyId',
      encoding: 'base64url SHA-256 SPKI thumbprint (43 chars)',
    },
    {
      index: 12,
      contractName: 'toolName',
      property: 'toolName',
      encoding: 'UTF-8 exact registered tool name',
    },
    {
      index: 13,
      contractName: 'opKind',
      property: 'opKind',
      encoding: 'enum literal: command | cancel | resync',
    },
    {
      index: 14,
      contractName: 'audience',
      property: 'audience',
      encoding: 'enum literal: endpoint | relay',
    },
    {
      index: 15,
      contractName: 'sha256(args)',
      property: 'argsDigestHex',
      encoding: 'lowercase hex (64 chars) over raw argument bytes',
    },
  ].map((field) => Object.freeze(field)),
);

/** The 15 property names, in canonical order. */
const RPC_ENVELOPE_FIELD_ORDER = Object.freeze(
  RPC_ENVELOPE_FIELD_LAYOUT.map((field) => field.property),
);

/** The 15 contract names, in canonical order (field 15 is the literal `sha256(args)`). */
const RPC_ENVELOPE_CONTRACT_NAMES = Object.freeze(
  RPC_ENVELOPE_FIELD_LAYOUT.map((field) => field.contractName),
);

/**
 * Unsigned transport fields (contract: routing/metadata, never authorization inputs). They live on
 * the wire frame, never inside the signed core.
 *
 * `argsB64u` is the GM-47/GM-48-M1 addition: the exact argument BYTES whose sha256 is the signed
 * field 15. GM-29 requires the endpoint to re-hash "the bytes it actually received", so those bytes
 * must travel with the frame; a signature over a digest whose preimage never travels is not a
 * signature over the payload. It is OUTSIDE the signature exactly like `keyId` (the signature binds
 * `sha256(args)` as field 15, unchanged), it is NOT canonicalised (GM-29 stands: the bytes are the
 * bytes), and the relay never decodes it (GM-9: it stays an opaque byte carrier, which is also what
 * lets GM-10 E2E encryption wrap these bytes later without a protocol change).
 */
const RPC_FRAME_TRANSPORT_FIELDS = Object.freeze([
  'signatureB64u',
  'keyId',
  'argsB64u',
  'seq',
  'idempotencyKey',
  'callId',
]);

/** The transport field carrying the exact args bytes (GM-47). Named once, so it is greppable. */
const ARGS_B64U_FIELD = 'argsB64u';

/** Every key a wire frame may carry: exactly the core plus the transport fields. */
const RPC_FRAME_KEYS = Object.freeze([
  ...RPC_ENVELOPE_FIELD_ORDER,
  ...RPC_FRAME_TRANSPORT_FIELDS,
]);

const ED25519_SIGNATURE_BYTES = 64;

function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasOwn(record, key) {
  return Object.prototype.hasOwnProperty.call(record, key);
}

/**
 * Strict unpadded-base64url decode. This is DECODING ONLY: the canonical field join remains the
 * exclusive property of `crypto.canonicalEncode`. It exists to enforce the contract's fixed byte
 * lengths (128-bit grantId/nonce, 256-bit thumbprint, 64-byte Ed25519 signature).
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
  const decoded = Buffer.from(value, 'base64url');
  return decoded.toString('base64url') === value ? decoded : null;
}

/**
 * Strict unpadded-base64url decode of the transported args bytes (`argsB64u`).
 *
 * This is the ONE difference from `decodeBase64UrlBytes`: the EMPTY byte string is legal, because an
 * argument payload may legitimately be empty (a `resync` carries none) and `sha256('')` is a real,
 * signed digest. Everything else stays canonical: the value must be unpadded base64url whose
 * re-encoding is byte-identical, so two spellings can never denote the same bytes.
 *
 * DECODING ONLY — no canonicalisation, no parsing, no re-serialization of the argument payload
 * (GM-29: the endpoint must hash the bytes it actually received). The relay never calls this.
 * @param {unknown} value
 * @returns {Buffer|null} decoded bytes, or null when `value` is not canonical unpadded base64url
 */
function decodeArgsB64u(value) {
  if (typeof value !== 'string' || !BASE64URL_PATTERN_EMPTY_OK.test(value)) {
    return null;
  }
  if (value.length % 4 === 1) {
    return null;
  }
  const decoded = Buffer.from(value, 'base64url');
  return decoded.toString('base64url') === value ? decoded : null;
}

/**
 * Requires the frame's `argsB64u` transport field (GM-47). Shape only: it never compares the bytes
 * with `argsDigestHex` — that equality is the endpoint-side check in `./argsDigest`.
 * @param {unknown} value
 * @returns {string} the canonical unpadded base64url value
 */
function assertFrameArgsB64u(value) {
  if (value === undefined || value === null) {
    throw shapeFailure(
      ARGS_B64U_FIELD,
      'is required on the wire frame: the endpoint must re-hash the bytes it actually received (GM-47)',
    );
  }
  if (decodeArgsB64u(value) === null) {
    throw shapeFailure(
      ARGS_B64U_FIELD,
      'must be canonical unpadded base64url of the exact args bytes (the empty string for empty args)',
    );
  }
  return value;
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

function shapeFailure(property, reason) {
  return relayFailure(
    'ENVELOPE_SHAPE_INVALID',
    `envelope field "${property}" ${reason}`,
    { field: property },
  );
}

function base64UrlFieldFailure(property, bytes) {
  return shapeFailure(property, `must be canonical unpadded base64url of exactly ${bytes} bytes`);
}

/**
 * Per-field value-domain check. Returns `null` when the value satisfies the contract's stated
 * encoding, else a `RelayError` naming the field (never the value).
 * @param {string} property
 * @param {unknown} value
 * @returns {import('./errors').RelayError|null}
 */
function validateFieldValue(property, value) {
  if (typeof value !== 'string') {
    return shapeFailure(property, 'must be a string');
  }
  switch (property) {
    case 'tag':
      return value === RPC_V2_TAG
        ? null
        : shapeFailure(property, `must be the literal "${RPC_V2_TAG}"`);
    case 'requestId':
      return UUID_V4_PATTERN.test(value)
        ? null
        : shapeFailure(property, 'must be a canonical lowercase hyphenated UUIDv4');
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
    case 'epoch':
      return POSITIVE_DECIMAL_PATTERN.test(value)
        ? null
        : shapeFailure(property, 'must be a canonical decimal integer >= 1');
    case 'grantId': {
      const bytes = decodeBase64UrlBytes(value);
      return bytes !== null && bytes.length === GRANT_ID_BYTES
        ? null
        : base64UrlFieldFailure(property, GRANT_ID_BYTES);
    }
    case 'deviceKeyId': {
      const bytes = decodeBase64UrlBytes(value);
      return bytes !== null && bytes.length === DEVICE_KEY_ID_BYTES
        ? null
        : base64UrlFieldFailure(property, DEVICE_KEY_ID_BYTES);
    }
    case 'ownerPrincipalId':
    case 'tenantId':
    case 'deviceId':
    case 'toolName':
      return value.length > 0 ? null : shapeFailure(property, 'must be a non-empty string');
    case 'opKind':
      return Object.values(RPC_OP_KINDS).includes(value)
        ? null
        : shapeFailure(property, 'must be one of command | cancel | resync');
    case 'audience':
      return Object.values(RPC_ENVELOPE_AUDIENCES).includes(value)
        ? null
        : shapeFailure(property, 'must be one of endpoint | relay');
    case 'argsDigestHex':
      return ARGS_DIGEST_HEX_PATTERN.test(value)
        ? null
        : shapeFailure(property, 'must be 64 lowercase hex characters over sha256(args)');
    default:
      return shapeFailure(property, 'is not a field of the CBHR-RPC-V2 core');
  }
}

/**
 * Maps a `canonicalEncode` rejection back to the contract field name. The accepted crypto module
 * reports `fields[i]` (0-based over the 14 non-tag fields); layout index = i + 2.
 * @param {unknown} err
 * @returns {string}
 */
function canonicalFieldLabel(err) {
  const message = err instanceof Error ? err.message : '';
  if (message.includes('domainTag')) {
    return RPC_ENVELOPE_FIELD_LAYOUT[0].contractName;
  }
  const match = /fields\[(\d+)\]/.exec(message);
  if (match === null) {
    return 'fields';
  }
  const layoutEntry = RPC_ENVELOPE_FIELD_LAYOUT[Number(match[1]) + 1];
  return layoutEntry === undefined ? `fields[${match[1]}]` : layoutEntry.contractName;
}

/**
 * Joins the core through the accepted canonical encoder. `canonicalEncode` is the ONLY
 * implementation of the 0x1F law in this repository; this function supplies the frozen field order
 * and translates its rejection into a typed relay error.
 * @param {object} core validated core (tag + 14 fields)
 * @param {{crypto?: object}} [options]
 * @returns {Buffer} exact signed bytes
 */
function joinCoreFields(core, options = {}) {
  const cryptoModule = options.crypto ?? deviceCrypto;
  const fields = RPC_ENVELOPE_FIELD_ORDER.slice(1).map((property) => core[property]);
  try {
    return cryptoModule.canonicalEncode({ domainTag: core.tag, fields });
  } catch (err) {
    const field = canonicalFieldLabel(err);
    throw relayFailure(
      'ENVELOPE_FIELD_NOT_CANONICAL',
      `envelope field "${field}" is not canonical under the 0x1F serialization law`,
      { field, cause: err },
    );
  }
}

/**
 * Validates the core's shape, its exact key set, every per-field encoding, the deadline horizon and
 * the 0x1F/UTF-16 canonical law (so a minting caller is refused at construction time).
 * @param {object} core
 * @param {{crypto?: object}} [options]
 * @returns {object} the same core
 */
function assertEnvelopeCore(core, options = {}) {
  if (!isPlainRecord(core)) {
    throw shapeFailure('core', 'must be a plain object carrying exactly the 15 core fields');
  }
  for (const key of Object.keys(core)) {
    if (!RPC_ENVELOPE_FIELD_ORDER.includes(key)) {
      throw shapeFailure(
        key,
        'is not part of the CBHR-RPC-V2 core (transport metadata never belongs inside the signature)',
      );
    }
  }
  for (const property of RPC_ENVELOPE_FIELD_ORDER) {
    if (!hasOwn(core, property)) {
      throw shapeFailure(property, 'is missing from the core');
    }
    const failure = validateFieldValue(property, core[property]);
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
      `envelope field "deadlineMs" exceeds the frozen ${MAX_DEADLINE_HORIZON_MS} ms horizon`,
      { field: 'deadlineMs' },
    );
  }
  // Forces the canonical 0x1F / well-formed-UTF-16 law at construction, not only at verification.
  joinCoreFields(core, options);
  return core;
}

/**
 * Builds a frozen, validated core from a plain input object. Every field is a string (the canonical
 * value set, exactly as it will be joined); callers convert server-observed numbers explicitly.
 * @param {object} input core fields; `tag` may be omitted and defaults to `CBHR-RPC-V2`
 * @param {{crypto?: object}} [options]
 * @returns {object} frozen core in canonical field order
 */
function buildEnvelopeCore(input, options = {}) {
  if (!isPlainRecord(input)) {
    throw shapeFailure('core', 'must be a plain object carrying exactly the 15 core fields');
  }
  const core = {};
  for (const property of RPC_ENVELOPE_FIELD_ORDER) {
    if (property === 'tag') {
      core.tag = hasOwn(input, 'tag') ? input.tag : RPC_V2_TAG;
      continue;
    }
    if (!hasOwn(input, property)) {
      throw shapeFailure(property, 'is missing from the core');
    }
    core[property] = input[property];
  }
  for (const key of Object.keys(input)) {
    if (!RPC_ENVELOPE_FIELD_ORDER.includes(key)) {
      throw shapeFailure(
        key,
        'is not part of the CBHR-RPC-V2 core (transport metadata never belongs inside the signature)',
      );
    }
  }
  return Object.freeze(assertEnvelopeCore(core, options));
}

/**
 * The exact bytes the backend signs for a given core.
 * @param {object} core
 * @param {{crypto?: object}} [options]
 * @returns {Buffer}
 */
function canonicalRpcBytes(core, options = {}) {
  return joinCoreFields(assertEnvelopeCore(core, options), options);
}

/**
 * Extracts the signed core from a flat wire frame. Rejects missing, extra and non-core keys, so a
 * frame cannot smuggle a field past the signature.
 * @param {object} frame
 * @returns {object} frozen core
 */
function coreFromWireFrame(frame) {
  if (!isPlainRecord(frame)) {
    throw shapeFailure('frame', 'must be a plain object');
  }
  for (const key of Object.keys(frame)) {
    if (!RPC_FRAME_KEYS.includes(key)) {
      throw shapeFailure(key, 'is not a permitted wire-frame key');
    }
  }
  const core = {};
  for (const property of RPC_ENVELOPE_FIELD_ORDER) {
    if (!hasOwn(frame, property)) {
      throw shapeFailure(property, 'is missing from the wire frame');
    }
    core[property] = frame[property];
  }
  return Object.freeze(assertEnvelopeCore(core));
}

function assertSignatureB64u(value) {
  const bytes = decodeBase64UrlBytes(value);
  if (bytes === null || bytes.length !== ED25519_SIGNATURE_BYTES) {
    throw relayFailure(
      'ENVELOPE_SIGNATURE_INVALID',
      `envelope field "signatureB64u" must be canonical unpadded base64url of exactly ${ED25519_SIGNATURE_BYTES} bytes`,
      { field: 'signatureB64u' },
    );
  }
  return value;
}

function assertTransportText(property, value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 200) {
    throw shapeFailure(property, 'must be a non-empty string of at most 200 characters');
  }
  if (value.includes(CANONICAL_SEPARATOR)) {
    throw shapeFailure(property, 'must not contain the 0x1F separator');
  }
  return value;
}

/**
 * Serializes a signed envelope into the flat wire frame the relay forwards. The frame is FLAT so the
 * relay's keyless per-frame view checks can read `grantId` / `epoch` / `ownerPrincipalId` directly
 * (F-V24C-6), and it carries no identity the core does not already bind.
 *
 * `argsB64u` is REQUIRED (GM-47): a frame that binds `sha256(args)` without transporting the bytes
 * is unverifiable by the endpoint, so the frame cannot be built without them. It is transport data,
 * outside the signature, and this function never hashes or rewrites it.
 * @param {object} params
 * @param {{core: object, signatureB64u: string, keyId: string}} params.signed
 * @param {string} params.argsB64u canonical unpadded base64url of the exact args bytes
 * @param {number} [params.seq] relay ordering counter (unsigned transport field)
 * @param {string} [params.idempotencyKey] unsigned transport field
 * @param {string} [params.callId] unsigned transport field (`replyCorrelationId`)
 * @returns {object} frozen wire frame
 */
function toWireFrame({ signed, argsB64u, seq, idempotencyKey, callId } = {}) {
  if (!isPlainRecord(signed)) {
    throw shapeFailure('signed', 'must be a signed-envelope object');
  }
  const core = assertEnvelopeCore(signed.core);
  assertSignatureB64u(signed.signatureB64u);
  const keyId = assertTransportText('keyId', signed.keyId);
  const argsField = assertFrameArgsB64u(argsB64u);
  const frame = {};
  for (const property of RPC_ENVELOPE_FIELD_ORDER) {
    frame[property] = core[property];
  }
  frame.signatureB64u = signed.signatureB64u;
  frame.keyId = keyId;
  frame.argsB64u = argsField;
  if (seq !== undefined && seq !== null) {
    if (!Number.isInteger(seq) || seq < 1) {
      throw shapeFailure('seq', 'must be an integer >= 1');
    }
    frame.seq = seq;
  }
  if (idempotencyKey !== undefined && idempotencyKey !== null) {
    frame.idempotencyKey = assertTransportText('idempotencyKey', idempotencyKey);
  }
  if (callId !== undefined && callId !== null) {
    frame.callId = assertTransportText('callId', callId);
  }
  return Object.freeze(frame);
}

/**
 * The inverse of `toWireFrame` for a verifier / endpoint receiver.
 *
 * `argsB64u` is validated as canonical unpadded base64url and returned so the endpoint can run the
 * GM-47 digest check (`argsDigest.verifyArgsBytes`). It is NOT compared with `argsDigestHex` here:
 * this module owns the core, and the digest equality belongs to the endpoint admission chain.
 * @param {object} frame
 * @returns {{core: object, signatureB64u: string, keyId: string, argsB64u: string}} frozen envelope
 */
function signedFromWireFrame(frame) {
  const core = coreFromWireFrame(frame);
  assertSignatureB64u(frame.signatureB64u);
  const keyId = assertTransportText('keyId', frame.keyId);
  const argsB64u = assertFrameArgsB64u(frame.argsB64u);
  return Object.freeze({ core, signatureB64u: frame.signatureB64u, keyId, argsB64u });
}

/**
 * Normalizes an in-memory signed envelope (`{ core, signatureB64u, keyId }`), rejecting any extra
 * top-level key so a caller cannot carry unvalidated metadata alongside a signed core.
 * @param {object} signed
 * @returns {{core: object, signatureB64u: string, keyId: string}} frozen signed envelope
 */
function signedFromSignedObject(signed) {
  if (!isPlainRecord(signed)) {
    throw shapeFailure('signed', 'must be a { core, signatureB64u, keyId } object');
  }
  const permitted = ['core', 'signatureB64u', 'keyId'];
  for (const key of Object.keys(signed)) {
    if (!permitted.includes(key)) {
      throw shapeFailure(key, `is not a permitted signed-envelope key (${permitted.join(', ')})`);
    }
  }
  const core = assertEnvelopeCore(signed.core);
  assertSignatureB64u(signed.signatureB64u);
  const keyId = assertTransportText('keyId', signed.keyId);
  return Object.freeze({ core, signatureB64u: signed.signatureB64u, keyId });
}

/**
 * A reviewable, value-free description of the signed layout (contract name, property, encoding).
 * @returns {ReadonlyArray<{index: number, contractName: string, property: string, encoding: string}>}
 */
function describeEnvelopeCoreLayout() {
  return RPC_ENVELOPE_FIELD_LAYOUT.map((field) => ({ ...field }));
}

module.exports = {
  RPC_V2_TAG,
  RPC_ENVELOPE_AUDIENCES,
  RPC_OP_KINDS,
  MAX_DEADLINE_HORIZON_MS,
  CANONICAL_SEPARATOR,
  RPC_ENVELOPE_FIELD_LAYOUT,
  RPC_ENVELOPE_FIELD_ORDER,
  RPC_ENVELOPE_CONTRACT_NAMES,
  RPC_FRAME_TRANSPORT_FIELDS,
  RPC_FRAME_KEYS,
  ARGS_B64U_FIELD,
  ARGS_DIGEST_HEX_PATTERN,
  isPlainRecord,
  decodeBase64UrlBytes,
  decodeArgsB64u,
  assertFrameArgsB64u,
  parseEpochMs,
  validateFieldValue,
  assertEnvelopeCore,
  buildEnvelopeCore,
  canonicalRpcBytes,
  coreFromWireFrame,
  toWireFrame,
  signedFromWireFrame,
  signedFromSignedObject,
  describeEnvelopeCoreLayout,
};
