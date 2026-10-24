'use strict';

/**
 * CBHR ENDPOINT AGENT — device key store (workstream W7).
 *
 * The endpoint's Ed25519 identity. This is the ONE secret the relay does not have and cannot obtain,
 * so three properties are enforced structurally rather than promised:
 *
 * 1. THE PRIVATE KEY NEVER LEAVES A CLOSURE. `loadDeviceKeystore()` returns an object whose only
 *    key-touching member is `sign(bytes)`. There is no accessor, no `toString`, no enumerable
 *    property and no `toJSON` that can carry key material: `JSON.stringify(keystore)`,
 *    `util.inspect(keystore, {showHidden: true})` and `Object.keys(keystore)` all see the public
 *    label and the paths, never the bytes. `tests/keystore.js` proves that against real encodings.
 *
 * 2. THE FILE IS OWNER-ONLY, AND THE ROOT STAYS OPERABLE. `permissions.js` applies a real restriction
 *    (POSIX mode + Windows ACL) and fails closed when it cannot. Two different objects get two
 *    different ACLs, deliberately and not by accident:
 *
 *      - the KEY FILE (`device-key.json`) is reduced to the owner alone: inheritance broken, one
 *        explicit grant, no group. That is the guarantee this module exists to deliver;
 *      - the ROOT DIRECTORY keeps the owner with full control PLUS `NT AUTHORITY\SYSTEM`,
 *        `BUILTIN\Administrators` and the host's sandbox grant, because the root also holds
 *        `workspace/` — the containment root tools read and write and a harness must provision and
 *        inspect. A root whose only ACE is the owner is not a stronger guarantee, it is a directory
 *        the platform can no longer operate in: it drops those three grants, and a `workspace/`
 *        created before the root was hardened loses its inherited ACEs with them (GM finding
 *        2026-10-23, where the end-to-end harness could not read back the scratch file it had just
 *        provisioned). `ensureOwnerOnlyDir` therefore means "a directory no foreign principal can
 *        reach", not "a directory with one ACE".
 *
 *    Nothing is written into the repository worktree: the default root is under the user profile,
 *    which is exactly what the task requires (a private key inside a git worktree is one `git add -A`
 *    away from being published).
 *
 * 3. ERRORS CARRY NO KEY MATERIAL. Every failure here is an `EndpointRefusal` with a field-naming,
 *    value-free message; a caller-supplied cause is replaced by a code-only stand-in.
 *
 * ON-DISK FORMAT (`device-key.json`, mode 0600, owner-only ACL)
 *   { version: 1, alg: 'Ed25519', keyId, publicKeySpkiB64u, privateKeyPkcs8B64u, createdAt }
 *
 * The stored form is PKCS#8 DER in unpadded base64url, which is the same encoding the backend uses on
 * the wire (`deviceKeyId` is the SHA-256 SPKI thumbprint of `publicKeySpkiB64u`), so no conversion
 * can silently change the identity between pairing and dispatch.
 */

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const nodeCrypto = require('node:crypto');

const { refusal } = require('./errors');
const { thumbprintB64u } = require('./vendoredCrypto');
const { ensureOwnerOnlyDir, writeOwnerOnlyFile, assertOwnerOnlyFile } = require('./permissions');

/** The default root the agent owns, outside any git worktree (task requirement). */
function defaultRootDir() {
  const home = process.env.USERPROFILE ?? process.env.HOME ?? os.homedir();
  return path.join(home, '.cbhr', 'endpoint-agent');
}

/** Resolves a path under the agent root, honouring an explicit override. */
function resolveRootDir(explicit) {
  if (typeof explicit === 'string' && explicit.length > 0) {
    return path.resolve(explicit);
  }
  if (typeof process.env.CBHR_ENDPOINT_AGENT_ROOT === 'string' && process.env.CBHR_ENDPOINT_AGENT_ROOT.length > 0) {
    return path.resolve(process.env.CBHR_ENDPOINT_AGENT_ROOT);
  }
  return defaultRootDir();
}

/**
 * Builds a leak-free refusal for a keystore problem, so no path, no message from `node:crypto` and no
 * key bytes can reach a log through this module.
 */
function keystoreRefusal(detail, cause) {
  return refusal('ENDPOINT_DEVICE_KEY_UNAVAILABLE', detail, { field: 'deviceKey', cause });
}

function keyIdOfPublicKey(publicKeySpkiB64u) {
  const thumbprint = thumbprintB64u(publicKeySpkiB64u);
  const bytes = Buffer.from(thumbprint, 'base64url');
  if (bytes.length !== 32) {
    throw keystoreRefusal('device key id derivation did not produce a 256-bit thumbprint');
  }
  return thumbprint;
}

/** Generates a fresh Ed25519 identity in memory. Callers immediately persist or drop it. */
function generateIdentity() {
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync('ed25519');
  const publicKeySpkiB64u = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const privateKeyPkcs8B64u = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64url');
  return {
    keyId: keyIdOfPublicKey(publicKeySpkiB64u),
    publicKeySpkiB64u,
    privateKeyPkcs8B64u,
  };
}

function parseStoredKey(text, file) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw keystoreRefusal('the stored device key file is not valid JSON', err);
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw keystoreRefusal('the stored device key file is not a JSON object');
  }
  if (parsed.version !== 1 || parsed.alg !== 'Ed25519') {
    throw keystoreRefusal('the stored device key file declares an unsupported version or algorithm');
  }
  for (const field of ['keyId', 'publicKeySpkiB64u', 'privateKeyPkcs8B64u']) {
    if (typeof parsed[field] !== 'string' || parsed[field].length === 0) {
      throw keystoreRefusal('the stored device key file is missing a required string field');
    }
  }
  let derived;
  try {
    derived = keyIdOfPublicKey(parsed.publicKeySpkiB64u);
  } catch (err) {
    throw keystoreRefusal('the stored device public key is not a usable Ed25519 SPKI value', err);
  }
  if (derived !== parsed.keyId) {
    throw keystoreRefusal('the stored device key id does not match its own public key thumbprint');
  }
  return parsed;
}

/**
 * Generates and persists a device identity under an owner-only file.
 *
 * @param {object} [options]
 * @param {string} [options.rootDir] agent root; defaults to `~/.cbhr/endpoint-agent`
 * @param {boolean} [options.force] overwrite an existing identity (re-pairing semantics: a NEW key)
 * @param {Buffer|string} [options.privateKeyPkcs8B64u] import a specific key instead of generating
 * @returns {{keyId: string, publicKeySpkiB64u: string, file: string, createdAt: string,
 *   permission: {mode: number, acl: string|null, principals: string[]}, created: boolean}}
 */
function createDeviceKeystore(options = {}) {
  const rootDir = resolveRootDir(options.rootDir);
  const file = path.join(rootDir, 'device-key.json');
  const exists = fs.existsSync(file);
  if (exists && options.force !== true) {
    const existing = readDeviceKeystoreFile(file);
    return {
      keyId: existing.keyId,
      publicKeySpkiB64u: existing.publicKeySpkiB64u,
      file,
      createdAt: existing.createdAt,
      permission: inspectKeyFilePermissions(file),
      created: false,
    };
  }

  // The ROOT is hardened as a private DIRECTORY — owner full control plus SYSTEM, Administrators and
  // the host's sandbox grant — never as an owner-only FILE. `writeOwnerOnlyFile` below applies the
  // owner-only ACL to `device-key.json` itself, so hardening the root the same way would add nothing to
  // the key's protection and would take the inherited ACEs of `workspace/` (and of every tool that
  // legitimately works in it) away with it.
  ensureOwnerOnlyDir(rootDir);
  const identity =
    typeof options.privateKeyPkcs8B64u === 'string' && options.privateKeyPkcs8B64u.length > 0
      ? (() => {
          const privateKey = nodeCrypto.createPrivateKey({
            key: Buffer.from(options.privateKeyPkcs8B64u, 'base64url'),
            format: 'der',
            type: 'pkcs8',
          });
          const publicKey = nodeCrypto.createPublicKey(privateKey);
          const publicKeySpkiB64u = publicKey
            .export({ type: 'spki', format: 'der' })
            .toString('base64url');
          return {
            keyId: keyIdOfPublicKey(publicKeySpkiB64u),
            publicKeySpkiB64u,
            privateKeyPkcs8B64u: options.privateKeyPkcs8B64u,
          };
        })()
      : generateIdentity();

  const createdAt = new Date().toISOString();
  const record = {
    version: 1,
    alg: 'Ed25519',
    keyId: identity.keyId,
    publicKeySpkiB64u: identity.publicKeySpkiB64u,
    privateKeyPkcs8B64u: identity.privateKeyPkcs8B64u,
    createdAt,
  };
  writeOwnerOnlyFile(file, `${JSON.stringify(record, null, 2)}\n`);

  return {
    keyId: identity.keyId,
    publicKeySpkiB64u: identity.publicKeySpkiB64u,
    file,
    createdAt,
    permission: inspectKeyFilePermissions(file),
    created: true,
  };
}

/** Reads the stored record. Internal: the returned object DOES carry key material. */
function readDeviceKeystoreFile(file) {
  const text = fs.readFileSync(file, 'utf8');
  return parseStoredKey(text, file);
}

/**
 * The permission evidence a caller may store and print: mode, the RAW `icacls` text, the classified
 * principal list, and (on Windows) the platform entries Windows re-adds to every object. Never file
 * content, never key bytes.
 * @param {string} file
 * @returns {{mode: number, acl: string|null, principals: string[], foreign: string[],
 *   acceptablePlatformPrincipals: string[]}}
 */
function inspectKeyFilePermissions(file) {
  const evidence = assertOwnerOnlyFile(file);
  return {
    mode: evidence.mode,
    acl: evidence.acl,
    principals: evidence.principals,
    foreign: evidence.foreign,
    acceptablePlatformPrincipals: evidence.acceptablePlatformPrincipals,
  };
}

/**
 * Loads (or first creates) the device identity and returns the signing surface.
 *
 * @param {object} [options]
 * @param {string} [options.rootDir]
 * @param {boolean} [options.createIfMissing] default true
 * @returns {Readonly<{
 *   keyId: () => string,
 *   publicKeySpkiB64u: () => string,
 *   sign: (bytes: Buffer) => string,
 *   rootDir: () => string,
 *   keyFile: () => string,
 *   permission: () => {mode: number, acl: string|null, principals: string[]},
 *   describe: () => object,
 * }>}
 */
function loadDeviceKeystore(options = {}) {
  const rootDir = resolveRootDir(options.rootDir);
  const keyFile = path.join(rootDir, 'device-key.json');
  const createIfMissing = options.createIfMissing !== false;
  if (!fs.existsSync(keyFile)) {
    if (!createIfMissing) {
      throw keystoreRefusal('no device key exists and createIfMissing was disabled');
    }
    createDeviceKeystore({ ...options, rootDir });
  }

  const record = readDeviceKeystoreFile(keyFile);
  let privateKey;
  try {
    privateKey = nodeCrypto.createPrivateKey({
      key: Buffer.from(record.privateKeyPkcs8B64u, 'base64url'),
      format: 'der',
      type: 'pkcs8',
    });
  } catch (err) {
    throw keystoreRefusal('the stored device private key could not be loaded as PKCS#8 Ed25519', err);
  }
  if (privateKey.asymmetricKeyType !== 'ed25519') {
    throw keystoreRefusal('the stored device private key is not an Ed25519 key');
  }

  // Everything below closes over `privateKey`; nothing exposes it.
  const keyId = record.keyId;
  const publicKeySpkiB64u = record.publicKeySpkiB64u;
  const createdAt = record.createdAt;

  return Object.freeze({
    keyId: () => keyId,
    publicKeySpkiB64u: () => publicKeySpkiB64u,
    /**
     * Signs with PureEdDSA over the exact bytes. Returns unpadded base64url. Never logs.
     * @param {Buffer} bytes
     * @returns {string}
     */
    sign: (bytes) => {
      if (!Buffer.isBuffer(bytes)) {
        throw keystoreRefusal('the device keystore signs Buffers only');
      }
      return nodeCrypto.sign(null, bytes, privateKey).toString('base64url');
    },
    rootDir: () => rootDir,
    keyFile: () => keyFile,
    permission: () => inspectKeyFilePermissions(keyFile),
    /** The safe, serializable description: label and paths, never key material. */
    describe: () => ({
      keyId,
      publicKeySpkiB64u,
      rootDir,
      keyFile,
      createdAt,
    }),
  });
}

module.exports = {
  defaultRootDir,
  resolveRootDir,
  keyIdOfPublicKey,
  generateIdentity,
  createDeviceKeystore,
  readDeviceKeystoreFile,
  inspectKeyFilePermissions,
  loadDeviceKeystore,
  keystoreRefusal,
};