'use strict';

/**
 * CBHR ENDPOINT AGENT — pinned backend verification keys (workstream W7).
 *
 * GM-31 is the reason this file exists as a separate concept: `keyId` on the wire is UNSIGNED
 * transport metadata, deliberately outside the canonical string, and exists only to select WHICH key
 * to verify with — so it can never be authority. A `keyId` naming an unpinned key must fail closed,
 * and the only way to make that checkable is for the endpoint to hold its own pin set, populated
 * out-of-band (at pairing / rotation), never from a frame and never from the relay.
 *
 * PIN PROVENANCE
 * A pin is a public key plus a label. It is established at pairing from a value the owner's machine
 * obtained out-of-band, and rotated only by an explicit local operation. Nothing in this module
 * reads a key out of an inbound frame: `pinned()` is the only reader, and it is given the pin file's
 * records, not network input.
 *
 * ON-DISK FORMAT (`backend-keys.json`, mode 0600, owner-only ACL)
 *   { version: 1, keys: [ { keyId, publicKeySpkiB64u, pinnedAt, label? } ] }
 *
 * `keyId` here is the same 43-character base64url SHA-256 SPKI thumbprint the backend puts in its
 * `keyId` transport field, so a pin is self-verifying: the label must equal the thumbprint of the
 * key it names.
 */

const fs = require('node:fs');
const path = require('node:path');

const { refusal } = require('./errors');
const { thumbprintB64u, verifyEd25519 } = require('./vendoredCrypto');
const { resolveRootDir } = require('./keystore');
const { writeOwnerOnlyFile, ensureOwnerOnlyDir } = require('./permissions');

const BASE64URL_PATTERN = /^[A-Za-z0-9_-]{40,120}$/;

function pinRefusal(detail, cause) {
  return refusal('ENDPOINT_KEY_UNPINNED', detail, { field: 'keyId', cause });
}

function isUsableSpki(value) {
  return typeof value === 'string' && BASE64URL_PATTERN.test(value);
}

/**
 * A frozen pin set. Lookup is by exact label equality; there is no wildcard, no prefix match, no
 * "latest key wins" path, and no fallback to "try every pinned key" (which would turn a rotation into
 * an ambiguity an attacker could steer).
 * @param {Array<{keyId: string, publicKeySpkiB64u: string}>} entries
 * @returns {Readonly<object>}
 */
function buildPinSet(entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
    throw pinRefusal('the endpoint holds no pinned backend key, so nothing can be verified');
  }
  const byKeyId = new Map();
  for (const entry of entries) {
    if (entry === null || typeof entry !== 'object') {
      throw pinRefusal('a pinned backend key record must be an object');
    }
    const { keyId, publicKeySpkiB64u } = entry;
    if (!isUsableSpki(keyId) || !isUsableSpki(publicKeySpkiB64u)) {
      throw pinRefusal('a pinned backend key record is missing a usable key id or SPKI value');
    }
    const derived = thumbprintB64u(publicKeySpkiB64u);
    if (derived !== keyId) {
      throw pinRefusal('a pinned backend key id does not match its own SPKI thumbprint');
    }
    if (byKeyId.has(keyId)) {
      throw pinRefusal('two pinned backend key records share one key id');
    }
    byKeyId.set(keyId, Object.freeze({ keyId, publicKeySpkiB64u }));
  }
  const keyIds = Object.freeze([...byKeyId.keys()]);

  return Object.freeze({
    /** The pinned labels, in declaration order. Safe to log: these are PUBLIC key thumbprints. */
    keyIds: () => keyIds,
    size: () => byKeyId.size,
    /**
     * The pinned key a label names, or `null`. `null` is a refusal at the call site: the caller must
     * never fall back to "some other pinned key".
     */
    pinned: (keyId) => (typeof keyId === 'string' && byKeyId.has(keyId) ? byKeyId.get(keyId) : null),
    /**
     * Ed25519 verification of exact bytes against the key a label names. Returns `false` for an
     * unpinned label, an unusable signature and a bad signature alike — the call site distinguishes
     * "unpinned" from "invalid signature" by asking `pinned()` first, so the taxonomy stays distinct
     * without giving this function two jobs.
     */
    verify: (keyId, bytes, signatureB64u) => {
      const key = byKeyId.get(keyId);
      if (key === undefined) {
        return false;
      }
      return verifyEd25519({
        publicKeySpkiB64u: key.publicKeySpkiB64u,
        message: bytes,
        signatureB64u,
      });
    },
  });
}

function parsePinFile(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw pinRefusal('the pinned backend key file is not valid JSON', err);
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw pinRefusal('the pinned backend key file is not a JSON object');
  }
  if (parsed.version !== 1 || !Array.isArray(parsed.keys)) {
    throw pinRefusal('the pinned backend key file declares an unsupported version or shape');
  }
  return buildPinSet(parsed.keys);
}

/** The default pin file path under the agent root. */
function defaultPinFile(rootDir) {
  return path.join(rootDir ?? resolveRootDir(), 'backend-keys.json');
}

/**
 * Loads the pin set. Fails closed when the file is absent: an endpoint with no pinned key can verify
 * nothing, and silently treating "no pin" as "no constraint" is the failure mode GM-23 names for the
 * relay's empty heap.
 * @param {object} [options]
 * @param {string} [options.rootDir]
 * @param {string} [options.pinFile]
 * @returns {Readonly<object>} the pin set
 */
function loadPinnedBackendKeys(options = {}) {
  const pinFile = options.pinFile ?? defaultPinFile(options.rootDir);
  if (!fs.existsSync(pinFile)) {
    throw pinRefusal('no pinned backend key file exists; the endpoint cannot verify anything yet');
  }
  return parsePinFile(fs.readFileSync(pinFile, 'utf8'));
}

/**
 * Pins (or re-pins) a backend public key. This is a LOCAL operation: it is what the pairing ceremony
 * and a rotation ceremony call. It is never reachable from a frame.
 * @param {object} params
 * @param {string} params.publicKeySpkiB64u
 * @param {string} [params.rootDir]
 * @param {string} [params.pinFile]
 * @param {string} [params.label]
 * @param {boolean} [params.replace] replace the whole pin set instead of adding to it
 * @returns {{keyId: string, pinFile: string, keys: string[], mode: number, acl: string|null}}
 */
function pinBackendKey(params = {}) {
  const { publicKeySpkiB64u, label, replace } = params;
  if (!isUsableSpki(publicKeySpkiB64u)) {
    throw pinRefusal('pinBackendKey requires a base64url SPKI public key value');
  }
  const keyId = thumbprintB64u(publicKeySpkiB64u);
  const pinFile = params.pinFile ?? defaultPinFile(params.rootDir);
  let existing = [];
  if (!replace && fs.existsSync(pinFile)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(pinFile, 'utf8'));
      if (Array.isArray(parsed?.keys)) {
        existing = parsed.keys.filter((entry) => entry?.keyId !== keyId);
      }
    } catch {
      // An unreadable pin file is replaced wholesale rather than merged with guesses.
      existing = [];
    }
  }
  const record = {
    version: 1,
    keys: [
      ...existing,
      {
        keyId,
        publicKeySpkiB64u,
        pinnedAt: new Date().toISOString(),
        ...(typeof label === 'string' && label.length > 0 ? { label } : {}),
      },
    ],
  };
  ensureOwnerOnlyDir(path.dirname(pinFile));
  const written = writeOwnerOnlyFile(pinFile, `${JSON.stringify(record, null, 2)}\n`);
  const set = buildPinSet(record.keys);
  return {
    keyId,
    pinFile,
    keys: set.keyIds(),
    mode: written.mode,
    acl: written.acl,
  };
}

module.exports = {
  buildPinSet,
  loadPinnedBackendKeys,
  pinBackendKey,
  defaultPinFile,
};