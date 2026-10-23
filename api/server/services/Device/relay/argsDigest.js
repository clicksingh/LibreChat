'use strict';

/**
 * `sha256(args)` field 15 of the CBHR-RPC-V2 core — workstream W2.
 *
 * The frozen contract fixes this field's encoding as LOWERCASE HEX (64 chars), explicitly so the
 * last field cannot be confused with base64url of `grantId`. The accepted `../crypto` module only
 * exposes base64url digests (`sha256B64u`), so the hex form is produced here.
 *
 * This is a DIGEST ENCODING helper, not a canonicalisation: the 0x1F field join stays exclusively in
 * `crypto.canonicalEncode`. No argument VALUE is ever logged, stored or echoed by this module.
 *
 * The canonicalisation of an arguments OBJECT into bytes is deliberately NOT decided here. The
 * contract says `sha256(args)` "over raw argument bytes" and leaves the arguments preimage to the
 * callers that own it; this module accepts exactly one of the two unambiguous forms below and
 * refuses everything else, so no caller can smuggle a string through as if it were bytes.
 */

const nodeCrypto = require('node:crypto');
const { decodeBase64UrlBytes } = require('./envelopeCore');
const { relayFailure } = require('./errors');

const ARGS_DIGEST_BYTES = 32;

function isBinaryLike(value) {
  return Buffer.isBuffer(value) || ArrayBuffer.isView(value);
}

function argsFailure(message) {
  return relayFailure('ENVELOPE_ARGS_INVALID', message, { field: 'argsDigestHex' });
}

/**
 * @param {Buffer|TypedArray|DataView} bytes raw argument bytes
 * @returns {string} 64 lowercase hex characters
 */
function sha256Hex(bytes) {
  if (!isBinaryLike(bytes)) {
    throw argsFailure('argument bytes must be a Buffer, TypedArray or DataView');
  }
  return nodeCrypto.createHash('sha256').update(bytes).digest('hex');
}

/**
 * Resolves the `sha256(args)` field from exactly one explicit source.
 * @param {object} params
 * @param {Buffer|TypedArray|DataView} [params.bytes] raw argument bytes to hash
 * @param {string} [params.digestB64u] an already-computed unpadded base64url SHA-256 digest
 * @returns {string} 64 lowercase hex characters
 */
function resolveArgsDigestHex(params = {}) {
  const { bytes, digestB64u } = params;
  const hasBytes = bytes !== undefined && bytes !== null;
  const hasDigest = digestB64u !== undefined && digestB64u !== null;
  if (hasBytes === hasDigest) {
    throw argsFailure(
      'exactly one of { bytes } or { digestB64u } must be supplied for sha256(args)',
    );
  }
  if (hasBytes) {
    return sha256Hex(bytes);
  }
  const decoded = decodeBase64UrlBytes(digestB64u);
  if (decoded === null || decoded.length !== ARGS_DIGEST_BYTES) {
    throw argsFailure(
      'digestB64u must be the canonical unpadded base64url form of a 32-byte SHA-256 digest',
    );
  }
  return decoded.toString('hex');
}

module.exports = {
  ARGS_DIGEST_BYTES,
  isBinaryLike,
  sha256Hex,
  resolveArgsDigestHex,
};