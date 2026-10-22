const crypto = require('node:crypto');

const PAIRING_CODE_TAG_DOMAIN = 'cbhr:pairing:codetag:v1';
const CANONICAL_SEPARATOR = '\u001f';
const PAIRING_CODE_DIGITS = 6;
const PAIRING_CODE_SPACE = 1000000;
const GRANT_ID_BYTES = 16;
const CHALLENGE_NONCE_BYTES = 32;
const RANDOM_RANGE_BYTES = 6;
const RANDOM_RANGE_LIMIT = 2 ** (RANDOM_RANGE_BYTES * 8);
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const UNPAIRED_SURROGATE_PATTERN =
  /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function isBinaryLike(value) {
  return typeof value === 'string' || Buffer.isBuffer(value) || ArrayBuffer.isView(value);
}

function toBytes(value) {
  if (typeof value === 'string') {
    return Buffer.from(value, 'utf8');
  }
  if (Buffer.isBuffer(value)) {
    return value;
  }
  return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}

function isWellFormed(value) {
  if (typeof value.isWellFormed === 'function') {
    return value.isWellFormed();
  }
  return !UNPAIRED_SURROGATE_PATTERN.test(value);
}

function assertCanonicalField(value, label) {
  if (typeof value !== 'string') {
    throw new TypeError(`${label} must be a string`);
  }
  if (value.includes(CANONICAL_SEPARATOR)) {
    throw new TypeError(`${label} must not contain the 0x1F separator`);
  }
  if (!isWellFormed(value)) {
    throw new TypeError(`${label} must be well-formed UTF-16 without unpaired surrogates`);
  }
  return value;
}

function decodeBase64UrlStrict(value) {
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

function randomIntUnbiased(range) {
  if (!Number.isSafeInteger(range) || range < 1 || range > RANDOM_RANGE_LIMIT) {
    throw new TypeError('range must be an integer within [1, 2^48]');
  }
  const acceptanceLimit = Math.floor(RANDOM_RANGE_LIMIT / range) * range;
  let sample = crypto.randomBytes(RANDOM_RANGE_BYTES).readUIntBE(0, RANDOM_RANGE_BYTES);
  while (sample >= acceptanceLimit) {
    sample = crypto.randomBytes(RANDOM_RANGE_BYTES).readUIntBE(0, RANDOM_RANGE_BYTES);
  }
  return sample % range;
}

/**
 * Mints a uniform six-digit pairing code from the CSPRNG (rejection-sampled, zero modulo bias).
 * The plaintext code is returned to the caller only; this module never persists or logs it.
 * @returns {string} exactly six ASCII digits, including zero-padded forms
 */
function generatePairingCode() {
  return String(randomIntUnbiased(PAIRING_CODE_SPACE)).padStart(PAIRING_CODE_DIGITS, '0');
}

/**
 * Derives the persisted pairing lookup tag:
 * HMAC-SHA-256(pepperLookup, domainTag ‖ code ‖ tenantId), where `‖` is a single 0x1F byte.
 * The tenant is inside the MAC input, so tags are domain-separated per tenant and per domain
 * tag. Inputs are never logged.
 * @param {object} params
 * @param {string} params.code six-digit pairing code
 * @param {string} params.tenantId tenant the code was issued for
 * @param {Buffer|string|import('node:crypto').KeyObject} params.pepperLookup deployment HMAC key
 * @param {string} [params.domainTag] domain separator; defaults to PAIRING_CODE_TAG_DOMAIN
 * @returns {string} 43-character unpadded base64url HMAC-SHA-256 digest
 */
function computeLookupTag(params) {
  if (params === null || typeof params !== 'object') {
    throw new TypeError('computeLookupTag requires a { code, tenantId, pepperLookup } argument');
  }
  const { code, tenantId, pepperLookup, domainTag = PAIRING_CODE_TAG_DOMAIN } = params;
  const message = canonicalEncode({ domainTag, fields: [code, tenantId] });
  return hmacSha256(pepperLookup, message).toString('base64url');
}

/**
 * Mints a globally-unique grant identity from 16 CSPRNG bytes (128 bits of entropy).
 * @returns {string} 22-character unpadded base64url grant id
 */
function newGrantId() {
  return crypto.randomBytes(GRANT_ID_BYTES).toString('base64url');
}

/**
 * Mints a 256-bit single-use challenge nonce.
 * @returns {string} 43-character unpadded base64url nonce
 */
function newChallengeNonce() {
  return crypto.randomBytes(CHALLENGE_NONCE_BYTES).toString('base64url');
}

/**
 * Hashes a base64url challenge nonce into its storage form.
 * @param {string} nonce unpadded base64url nonce
 * @returns {string} 43-character unpadded base64url SHA-256 digest
 */
function challengeHash(nonce) {
  return sha256B64u(decodeBase64UrlStrict(nonce));
}

/**
 * Builds the unambiguous signed payload: `domainTag` followed by the fields, each pair joined by
 * exactly one 0x1F byte, UTF-8 encoded. Callers pass opaque values already base64url-encoded.
 * Non-string fields, fields containing 0x1F, and unpaired surrogates are rejected, never coerced.
 * @param {object} params
 * @param {string} params.domainTag versioned domain separator
 * @param {string[]} params.fields ordered field values
 * @returns {Buffer} the exact bytes to sign or MAC
 */
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
  return Buffer.from(parts.join(CANONICAL_SEPARATOR), 'utf8');
}

/**
 * Verifies a PureEdDSA (Ed25519) signature over the exact signed bytes. Malformed or unusable
 * input returns `false`; this function never throws and never logs its inputs.
 * @param {object} params
 * @param {string} params.publicKeySpkiB64u unpadded base64url SPKI DER public key
 * @param {Buffer|string} params.message exact signed bytes (a string is UTF-8 encoded)
 * @param {string} params.signatureB64u unpadded base64url Ed25519 signature
 * @returns {boolean}
 */
function verifyEd25519(params) {
  try {
    if (params === null || typeof params !== 'object') {
      return false;
    }
    const { publicKeySpkiB64u, message, signatureB64u } = params;
    if (!isBinaryLike(message)) {
      return false;
    }
    const publicKey = crypto.createPublicKey({
      key: decodeBase64UrlStrict(publicKeySpkiB64u),
      format: 'der',
      type: 'spki',
    });
    if (publicKey.asymmetricKeyType !== 'ed25519') {
      return false;
    }
    return crypto.verify(null, message, publicKey, decodeBase64UrlStrict(signatureB64u));
  } catch {
    return false;
  }
}

/**
 * @param {Buffer|string|Uint8Array|DataView} input bytes to hash
 * @returns {string} unpadded base64url SHA-256 digest
 */
function sha256B64u(input) {
  if (!isBinaryLike(input)) {
    throw new TypeError('input must be a string, Buffer, TypedArray or DataView');
  }
  return crypto.createHash('sha256').update(input).digest('base64url');
}

/**
 * Computes the base64url SHA-256 thumbprint of an SPKI DER public key.
 * @param {string} spkiB64u unpadded base64url SPKI DER
 * @returns {string} unpadded base64url digest
 */
function thumbprintB64u(spkiB64u) {
  return sha256B64u(decodeBase64UrlStrict(spkiB64u));
}

/**
 * @param {Buffer|string|Uint8Array|DataView|import('node:crypto').KeyObject} key HMAC key
 * @param {Buffer|string|Uint8Array|DataView} data message bytes
 * @returns {Buffer} raw HMAC-SHA-256 digest
 */
function hmacSha256(key, data) {
  const keyIsUsable = (isBinaryLike(key) && key.length > 0) || key instanceof crypto.KeyObject;
  if (!keyIsUsable) {
    const message = 'key must be a non-empty string, Buffer, TypedArray, DataView or KeyObject';
    throw new TypeError(message);
  }
  if (!isBinaryLike(data)) {
    throw new TypeError('data must be a string, Buffer, TypedArray or DataView');
  }
  return crypto.createHmac('sha256', key).update(data).digest();
}

/**
 * Constant-time comparison of two byte strings of equal length.
 * @param {Buffer|string|Uint8Array|DataView} a
 * @param {Buffer|string|Uint8Array|DataView} b
 * @returns {boolean} `false` on length mismatch or unusable input
 */
function timingSafeEqual(a, b) {
  if (!isBinaryLike(a) || !isBinaryLike(b)) {
    return false;
  }
  const left = toBytes(a);
  const right = toBytes(b);
  if (left.length !== right.length) {
    return false;
  }
  return crypto.timingSafeEqual(left, right);
}

module.exports = {
  PAIRING_CODE_TAG_DOMAIN,
  generatePairingCode,
  computeLookupTag,
  newGrantId,
  newChallengeNonce,
  challengeHash,
  canonicalEncode,
  verifyEd25519,
  sha256B64u,
  thumbprintB64u,
  hmacSha256,
  timingSafeEqual,
};
