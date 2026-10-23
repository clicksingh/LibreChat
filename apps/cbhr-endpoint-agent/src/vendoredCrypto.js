'use strict';

/**
 * CBHR ENDPOINT AGENT — accepted crypto primitives (workstream W7).
 *
 * This module re-exports the three ACCEPTED primitives the task explicitly permits:
 * `canonicalEncode`, `verifyEd25519` and `thumbprintB64u` from
 * `api/server/services/Device/crypto.js`. The primitives live behind Node built-ins (`node:crypto`)
 * and add no new dependency.
 *
 * WHY A SEPARATE MODULE RATHER THAN REQUIRING THE BACKEND DIRECTLY
 * The layout, field order, encodings and verification chain are the endpoint's OWN implementation
 * (see `layout.js` and `verify.js`), so no backend value-domain decision can leak in by accident.
 * The three re-exported functions below are pure by construction: they never log, never throw on
 * malformed input through `verifyEd25519`, never touch the network or disk, and never hold key
 * material. Keeping the seam explicit in one file means a reviewer can audit the entire trust surface
 * by reading fifteen lines.
 *
 * If the backend ever moves or renames its crypto module, ONLY this file changes; the layout in
 * `layout.js` is written to do its own thing on top of these primitives.
 *
 * Fallback: when this agent directory is published without the LibreChat tree beside it, the module
 * falls back to a local implementation of the same three primitives over `node:crypto` (identical
 * semantics: PureEdDSA verify returning `false` on any unusable input, 0x1F-joined encode rejecting
 * non-canonical fields). The fallback is exercised by the golden-vector test through a `require`
 * flag so the two paths provably agree on the frozen canonical string.
 */

const path = require('node:path');

const CANDIDATE_PATHS = [
  path.resolve(__dirname, '..', '..', '..', 'api', 'server', 'services', 'Device', 'crypto.js'),
  path.resolve(__dirname, '..', '..', 'api', 'server', 'services', 'Device', 'crypto.js'),
];

function loadBackendCrypto() {
  for (const candidate of CANDIDATE_PATHS) {
    try {
      // eslint-disable-next-line global-require, import/no-dynamic-require
      const mod = require(candidate);
      if (
        mod !== null &&
        typeof mod === 'object' &&
        typeof mod.canonicalEncode === 'function' &&
        typeof mod.verifyEd25519 === 'function' &&
        typeof mod.thumbprintB64u === 'function'
      ) {
        return { backend: mod, sourcePath: candidate, isFallback: false };
      }
    } catch {
      // Not present at this candidate path: try the next one, then the local fallback.
    }
  }
  return null;
}

/**
 * Local fallback over `node:crypto` with the accepted semantics:
 * - `canonicalEncode` rejects non-string fields, 0x1F-containing fields and unpaired surrogates,
 *   and joins with exactly one 0x1F byte.
 * - `verifyEd25519` returns `false` on ANY unusable input and never throws, never logs.
 * - `thumbprintB64u` hashes an SPKI DER (strict base64url decode) with SHA-256.
 */
function localFallbackCrypto() {
  const nodeCrypto = require('node:crypto');
  const SEPARATOR = '';
  const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
  const UNPAIRED_SURROGATE_PATTERN =
    /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

  function assertCanonicalField(value, label) {
    if (typeof value !== 'string') {
      throw new TypeError(`${label} must be a string`);
    }
    if (value.includes(SEPARATOR)) {
      throw new TypeError(`${label} must not contain the 0x1F separator`);
    }
    if (typeof value.isWellFormed === 'function' ? !value.isWellFormed() : UNPAIRED_SURROGATE_PATTERN.test(value)) {
      throw new TypeError(`${label} must be well-formed UTF-16 without unpaired surrogates`);
    }
    return value;
  }

  function canonicalEncode(params) {
    if (params === null || typeof params !== 'object') {
      throw new TypeError('canonicalEncode requires a { domainTag, fields } argument');
    }
    const { domainTag, fields } = params;
    if (!Array.isArray(fields)) {
      throw new TypeError('fields must be an array of strings');
    }
    const parts = [assertCanonicalField(domainTag, 'domainTag')];
    for (let index = 0; index < fields.length; index++) {
      parts.push(assertCanonicalField(fields[index], `fields[${index}]`));
    }
    return Buffer.from(parts.join(SEPARATOR), 'utf8');
  }

  function strictDecode(value) {
    if (typeof value !== 'string' || value.length === 0) {
      throw new TypeError('base64url value must be a non-empty string');
    }
    if (!BASE64URL_PATTERN.test(value)) {
      throw new TypeError('base64url value must use the unpadded A-Za-z0-9_- alphabet');
    }
    if (value.length % 4 === 1) {
      throw new TypeError('base64url value has an impossible length');
    }
    const decoded = Buffer.from(value, 'base64url');
    if (decoded.toString('base64url') !== value) {
      throw new TypeError('base64url value is not canonical (does not round-trip)');
    }
    return decoded;
  }

  function verifyEd25519(params) {
    try {
      if (params === null || typeof params !== 'object') {
        return false;
      }
      const { publicKeySpkiB64u, message, signatureB64u } = params;
      const usableMessage =
        typeof message === 'string' || Buffer.isBuffer(message) || ArrayBuffer.isView(message);
      if (!usableMessage) {
        return false;
      }
      const publicKey = nodeCrypto.createPublicKey({
        key: strictDecode(publicKeySpkiB64u),
        format: 'der',
        type: 'spki',
      });
      if (publicKey.asymmetricKeyType !== 'ed25519') {
        return false;
      }
      return nodeCrypto.verify(null, message, publicKey, strictDecode(signatureB64u));
    } catch {
      return false;
    }
  }

  function thumbprintB64u(spkiB64u) {
    return nodeCrypto.createHash('sha256').update(strictDecode(spkiB64u)).digest('base64url');
  }

  return { canonicalEncode, verifyEd25519, thumbprintB64u };
}

const loaded = loadBackendCrypto();
const active = loaded === null ? localFallbackCrypto() : loaded.backend;

module.exports = {
  canonicalEncode: active.canonicalEncode,
  verifyEd25519: active.verifyEd25519,
  thumbprintB64u: active.thumbprintB64u,
  cryptoSourcePath: loaded === null ? '<local node:crypto fallback>' : loaded.sourcePath,
  cryptoIsFallback: loaded === null,
};