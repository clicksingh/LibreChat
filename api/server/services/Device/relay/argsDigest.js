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
 *
 * GM-47 (endpoint side). The frame carries `argsB64u`, the exact bytes whose sha256 is field 15.
 * `verifyArgsBytes()` decodes them, RECOMPUTES sha256 over the decoded bytes (never over a
 * re-serialization of the args) and requires equality with the signed `argsDigestHex` before the
 * endpoint executes anything. It fails closed with `ARGS_DIGEST_MISMATCH`. No canonicalisation
 * happens here either: the bytes are hashed exactly as they arrived (GM-29 stands).
 */

const nodeCrypto = require('node:crypto');
const { decodeBase64UrlBytes, decodeArgsB64u, ARGS_DIGEST_HEX_PATTERN } = require('./envelopeCore');
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
 * The wire form of the exact args bytes: canonical unpadded base64url, byte-for-byte, no
 * canonicalisation of the payload. This is what `argsB64u` carries (GM-47).
 * @param {Buffer|TypedArray|DataView} bytes
 * @returns {string} unpadded base64url (the empty string for empty args)
 */
function argsBytesToB64u(bytes) {
  if (!isBinaryLike(bytes)) {
    throw argsFailure('argument bytes must be a Buffer, TypedArray or DataView');
  }
  const buffer = Buffer.isBuffer(bytes)
    ? bytes
    : Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return buffer.toString('base64url');
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

function argsDigestMismatch(detail) {
  return relayFailure('ARGS_DIGEST_MISMATCH', detail, { field: 'argsB64u' });
}

/**
 * ENDPOINT-SIDE GM-47 CHECK. Decodes `argsB64u`, recomputes sha256 over exactly those bytes and
 * requires equality with the signed `argsDigestHex`. Run this BEFORE executing anything: a valid
 * signature over a digest whose preimage does not match the transported bytes is not authority over
 * the payload.
 *
 * Fails closed (`{ ok: false }` with `ARGS_DIGEST_MISMATCH`) for a missing, non-canonical or
 * non-string `argsB64u`, for an unusable `argsDigestHex`, and for any digest disagreement. The
 * external message is generic (invariant 3); the specific reason is the non-enumerable `detail`.
 *
 * @param {object} params either `{ frame }` (a wire frame) or `{ argsB64u, argsDigestHex }`
 * @returns {{ok: true, argsBytes: Buffer, argsDigestHex: string}
 *   | {ok: false, error: import('./errors').RelayError}}
 */
function verifyArgsBytes(params = {}) {
  const source =
    params !== null && typeof params === 'object' && params.frame !== undefined ? params.frame : params;
  if (source === null || typeof source !== 'object') {
    return {
      ok: false,
      error: argsDigestMismatch('the frame carrying the args bytes is not an object'),
    };
  }
  const argsBytes = decodeArgsB64u(source.argsB64u);
  if (argsBytes === null) {
    return {
      ok: false,
      error: argsDigestMismatch(
        'argsB64u must be canonical unpadded base64url of the exact args bytes the sender hashed',
      ),
    };
  }
  const { argsDigestHex } = source;
  if (typeof argsDigestHex !== 'string' || !ARGS_DIGEST_HEX_PATTERN.test(argsDigestHex)) {
    return {
      ok: false,
      error: argsDigestMismatch(
        'the signed sha256(args) field must be 64 lowercase hex characters before the bytes can be checked',
      ),
    };
  }
  const recomputed = sha256Hex(argsBytes);
  if (recomputed !== argsDigestHex) {
    return {
      ok: false,
      error: argsDigestMismatch('the transported args bytes do not hash to the signed sha256(args)'),
    };
  }
  return { ok: true, argsBytes, argsDigestHex: recomputed };
}

module.exports = {
  ARGS_DIGEST_BYTES,
  isBinaryLike,
  sha256Hex,
  argsBytesToB64u,
  resolveArgsDigestHex,
  verifyArgsBytes,
};