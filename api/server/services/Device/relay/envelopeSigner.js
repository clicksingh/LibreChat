'use strict';

/**
 * INJECTED ENVELOPE SIGNING SEAM — workstream W2 acceptance item 1.
 *
 * GM RULING IN FORCE (R2 / GM-9): the BACKEND signs CBHR-RPC-V2 envelopes; the relay's Durable
 * Object is a mechanically keyless forwarder. This module is the backend half.
 *
 * CUSTODY IS NOT DECIDED HERE, AND THIS MODULE CANNOT DECIDE IT.
 * Signing key custody is an OWNER decision that has not been made. Therefore this module:
 *   - never generates a keypair;
 *   - never reads a key from disk, from the environment, or from any config;
 *   - never stores, caches, wraps or copies key material;
 *   - never logs anything at all (it has no logger);
 *   - accepts the custody implementation ONLY as a two-key surface
 *     `{ sign(canonicalBytes) => signatureB64u, keyId }`
 *     and REFUSES any surface that carries an additional key, so a custody implementation cannot
 *     leak key material through this seam by accident (`SIGNER_SEAM_INVALID`).
 *
 * Swapping custody (process-local key file, OS keystore, HSM, KMS, remote signer) is therefore a
 * caller-side change only: this file never has to be edited. The seam is async by contract, because
 * a remote/HSM signer is a legitimate custody choice — `sign` may return a value or a promise.
 *
 * The `keyId` is an OPAQUE backend signing-key label, bound into the wire frame as transport
 * metadata (it is NOT one of the 15 signed core fields). Custody may choose to label its key by the
 * SPKI thumbprint; `keyIdForPublicKey()` is provided for that choice but does not impose it.
 */

const deviceCrypto = require('../crypto');
const { assertEnvelopeCore, buildEnvelopeCore, canonicalRpcBytes } = require('./envelopeCore');
const { decodeBase64UrlBytes } = require('./envelopeCore');
const { isRelayError, relayFailure } = require('./errors');

/** The ONLY keys the signer seam accepts. Anything else is refused (custody containment). */
const SIGNER_SEAM_KEYS = Object.freeze(['sign', 'keyId']);

const ED25519_SIGNATURE_BYTES = 64;
const MAX_KEY_ID_LENGTH = 200;

function isBinaryLike(value) {
  return Buffer.isBuffer(value) || ArrayBuffer.isView(value);
}

function seamFailure(message, options) {
  return relayFailure('SIGNER_SEAM_INVALID', message, options);
}

function asRelayError(err, code, message) {
  return isRelayError(err) ? err : relayFailure(code, message, { cause: err });
}

/**
 * Validates the injected custody surface.
 *
 * The seam is deliberately narrow. A surface such as `{ sign, keyId, privateKey }` — or any other
 * extra key — is refused by NAME (never by value), which keeps key material out of this module even
 * when a caller tries to hand it over.
 * @param {unknown} surface
 * @returns {{sign: Function, keyId: string}}
 */
function assertSignerSeam(surface) {
  if (surface === null || typeof surface !== 'object' || Array.isArray(surface)) {
    throw seamFailure('the envelope signer seam requires a { sign, keyId } object');
  }
  for (const key of Object.keys(surface)) {
    if (!SIGNER_SEAM_KEYS.includes(key)) {
      throw seamFailure(
        `the envelope signer seam refuses the custody surface key "${key}"; it accepts exactly { sign, keyId } and never holds key material`,
      );
    }
  }
  if (typeof surface.sign !== 'function') {
    throw seamFailure('the envelope signer seam requires sign(canonicalBytes) to be a function');
  }
  if (typeof surface.keyId !== 'string' || surface.keyId.length === 0) {
    throw seamFailure('the envelope signer seam requires a non-empty keyId string');
  }
  if (surface.keyId.length > MAX_KEY_ID_LENGTH) {
    throw seamFailure(`the envelope signer seam requires a keyId of at most ${MAX_KEY_ID_LENGTH}`);
  }
  return { sign: surface.sign, keyId: surface.keyId };
}

/**
 * Builds the backend envelope signer around an INJECTED custody implementation.
 *
 * @param {object} surface exactly `{ sign, keyId }`
 * @param {(canonicalBytes: Buffer) => (string|Promise<string>)} surface.sign receives the exact
 *   canonical bytes; must resolve to an unpadded base64url Ed25519 (PureEdDSA) signature
 * @param {string} surface.keyId opaque backend signing-key label
 * @returns {Readonly<{keyId: string, signBytes: Function, signCore: Function}>}
 */
function createEnvelopeSigner(surface) {
  const seam = assertSignerSeam(surface);

  /**
   * Signs exact bytes through the injected custody implementation. The bytes are handed over
   * unchanged and nothing else is passed; nothing is retained.
   * @param {Buffer|TypedArray|DataView} bytes
   * @returns {Promise<string>} unpadded base64url Ed25519 signature
   */
  async function signBytes(bytes) {
    if (!isBinaryLike(bytes)) {
      throw seamFailure(
        'signBytes requires the exact canonical bytes (Buffer, TypedArray or DataView); strings are refused so no encoding step can diverge',
      );
    }
    const message = Buffer.isBuffer(bytes)
      ? bytes
      : Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let signatureB64u;
    try {
      signatureB64u = await seam.sign(message);
    } catch (err) {
      throw seamFailure('the injected envelope signer failed', { cause: err });
    }
    const decoded = decodeBase64UrlBytes(signatureB64u);
    if (decoded === null || decoded.length !== ED25519_SIGNATURE_BYTES) {
      throw seamFailure(
        'the injected envelope signer must resolve to a canonical unpadded base64url Ed25519 signature',
        { field: 'signatureB64u' },
      );
    }
    return signatureB64u;
  }

  /**
   * Canonicalizes and signs a core, returning the signed envelope.
   * @param {object} coreInput the 15 core fields (tag optional; defaults to CBHR-RPC-V2)
   * @returns {Promise<Readonly<{core: object, signatureB64u: string, keyId: string}>>}
   */
  async function signCore(coreInput) {
    const core = buildEnvelopeCore(coreInput);
    const canonicalBytes = canonicalRpcBytes(core);
    const signatureB64u = await signBytes(canonicalBytes);
    return Object.freeze({ core, signatureB64u, keyId: seam.keyId });
  }

  return Object.freeze({ keyId: seam.keyId, signBytes, signCore });
}

/**
 * Verifies a signed envelope against a PINNED backend public key. Signature verification precedes
 * every semantic check (contract invariant 3); the optional `expectedKeyId` pin is applied after the
 * signature so a wrong key cannot be probed before the cryptographic check.
 *
 * Malformed input never throws: it resolves to `{ ok: false, error }`.
 *
 * @param {object} options
 * @param {string} options.publicKeySpkiB64u unpadded base64url SPKI DER Ed25519 public key
 * @param {string} [options.expectedKeyId] pinned backend signing-key label
 * @param {object} [options.crypto] injected crypto module (defaults to the accepted `../crypto`)
 * @returns {Readonly<{publicKeyThumbprint: string, verifySignature: Function}>}
 */
function createEnvelopeVerifier(options = {}) {
  const { publicKeySpkiB64u, expectedKeyId = null } = options;
  const cryptoModule = options.crypto ?? deviceCrypto;
  if (typeof publicKeySpkiB64u !== 'string' || publicKeySpkiB64u.length === 0) {
    throw seamFailure('the envelope verifier requires an unpadded base64url SPKI public key');
  }
  let publicKeyThumbprint;
  try {
    publicKeyThumbprint = cryptoModule.thumbprintB64u(publicKeySpkiB64u);
  } catch (err) {
    throw seamFailure('the envelope verifier requires a canonical unpadded base64url SPKI key', {
      cause: err,
    });
  }
  if (expectedKeyId !== null && (typeof expectedKeyId !== 'string' || expectedKeyId.length === 0)) {
    throw seamFailure('the envelope verifier expectedKeyId pin must be a non-empty string or null');
  }

  /**
   * @param {{core: object, signatureB64u: string, keyId: string}} signed
   * @returns {{ok: true, core: object, keyId: string}|{ok: false, error: import('./errors').RelayError}}
   */
  function verifySignature(signed) {
    if (signed === null || typeof signed !== 'object') {
      return {
        ok: false,
        error: seamFailure('verifySignature requires a { core, signatureB64u, keyId } object'),
      };
    }
    let core;
    let message;
    try {
      core = assertEnvelopeCore(signed.core);
      message = canonicalRpcBytes(signed.core, { crypto: cryptoModule });
    } catch (err) {
      return { ok: false, error: asRelayError(err, 'ENVELOPE_SHAPE_INVALID', 'envelope core is unusable') };
    }
    let verified = false;
    try {
      verified =
        cryptoModule.verifyEd25519({
          publicKeySpkiB64u,
          message,
          signatureB64u: signed.signatureB64u,
        }) === true;
    } catch {
      verified = false;
    }
    if (!verified) {
      return {
        ok: false,
        error: relayFailure(
          'ENVELOPE_SIGNATURE_INVALID',
          'envelope signature does not verify against the pinned backend key',
          { field: 'signatureB64u' },
        ),
      };
    }
    if (expectedKeyId !== null && signed.keyId !== expectedKeyId) {
      return {
        ok: false,
        error: relayFailure(
          'ENVELOPE_KEY_MISMATCH',
          'envelope keyId does not match the pinned backend signing key',
          { field: 'keyId' },
        ),
      };
    }
    return { ok: true, core, keyId: signed.keyId };
  }

  return Object.freeze({ publicKeyThumbprint, verifySignature });
}

/**
 * The key label a custody implementation would use if it chooses to name keys by their SPKI
 * thumbprint (contract §2.1 form). Provided as a convenience; it does NOT read or derive any key.
 * @param {string} publicKeySpkiB64u unpadded base64url SPKI DER
 * @param {{crypto?: object}} [options]
 * @returns {string} 43-character unpadded base64url thumbprint
 */
function keyIdForPublicKey(publicKeySpkiB64u, options = {}) {
  const cryptoModule = options.crypto ?? deviceCrypto;
  return cryptoModule.thumbprintB64u(publicKeySpkiB64u);
}

module.exports = {
  SIGNER_SEAM_KEYS,
  ED25519_SIGNATURE_BYTES,
  assertSignerSeam,
  createEnvelopeSigner,
  createEnvelopeVerifier,
  keyIdForPublicKey,
};