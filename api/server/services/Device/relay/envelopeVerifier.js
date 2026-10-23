'use strict';

/**
 * REFERENCE ENVELOPE VERIFIER — the composed CBHR-RPC-V2 admission chain (workstream W2).
 *
 * This is the backend-side reference implementation of the frozen verification order
 * (`V24-C` endpoint verifier invariants 1-8), so that:
 *   1. the minting path can prove its own bytes verify (a cheap pre-dispatch self-check), and
 *   2. the endpoint implementor (Tauri) and the independent verifier have an executable reference
 *      for the exact order and the exact rejection taxonomy.
 *
 * ORDER (fixed; each step short-circuits):
 *   1. structural parse + per-field encoding  -> ENVELOPE_SHAPE_INVALID / ENVELOPE_FIELD_NOT_CANONICAL
 *   2. signature against the PINNED backend key -> ENVELOPE_SIGNATURE_INVALID
 *   3. pinned keyId label (optional)           -> ENVELOPE_KEY_MISMATCH
 *   4. audience equals the expected audience   -> ENVELOPE_AUDIENCE_MISMATCH
 *   5. freshness + deadline (dual bound)       -> FRESHNESS_* / DEADLINE_*
 *   6. args bytes re-hash against field 15     -> ARGS_DIGEST_MISMATCH   (GM-47)
 *   7. unseen nonce in the `(grantId, nonce)` ring -> REPLAY_DETECTED
 *
 * Step 6 is the GM-47 requirement made executable: the frame's `argsB64u` is decoded and hashed
 * exactly as received (no canonicalisation, GM-29) and must equal the SIGNED `argsDigestHex`. It runs
 * after the signature, so the digest it compares against is authentic, and before replay, so a
 * payload that cannot be bound never burns a nonce.
 *
 * Step 1 precedes the signature only because the signed bytes must be constructible before they can
 * be verified; it is a parse, never an authority decision, and it leaks nothing beyond a typed code.
 * Step 2 precedes steps 3-7 exactly as the contract requires: no semantic check runs on an
 * unverified envelope, so a forged frame can never burn a nonce or probe a grant pin.
 *
 * The nonce is remembered ONLY after every check passes, so a forged or stale frame cannot consume
 * the nonce of a later genuine one.
 */

const {
  coreFromWireFrame,
  signedFromWireFrame,
  signedFromSignedObject,
  isPlainRecord,
} = require('./envelopeCore');
const { evaluateFreshness } = require('./freshness');
const { verifyArgsBytes } = require('./argsDigest');
const { isRelayError, relayFailure } = require('./errors');

function asRelayError(err, code, message) {
  return isRelayError(err) ? err : relayFailure(code, message, { cause: err });
}

/**
 * Verifies a signed envelope end to end.
 *
 * @param {object} params
 * @param {object} params.signed `{ core, signatureB64u, keyId }` OR a flat wire frame
 * @param {{verifySignature: Function}} params.verifier from `createEnvelopeVerifier`
 * @param {string} params.expectedAudience the audience this receiver accepts
 * @param {number} params.now epoch-ms clock reading
 * @param {boolean} [params.requireArgsBytes] require the frame to carry the args bytes and to match
 *   field 15 (default: true for a wire frame, false for an in-memory `{core, signature, keyId}`)
 * @param {{checkAndRemember: Function}} [params.replayWindow] required to enforce replay rejection
 * @returns {Promise<{ok: true, core: object, keyId: string, windowMs: number}
 *   | {ok: false, error: import('./errors').RelayError}>}
 */
async function verifyEnvelope(params = {}) {
  const {
    signed: input,
    verifier,
    expectedAudience,
    now,
    replayWindow = null,
    requireArgsBytes,
  } = params;

  if (verifier === null || typeof verifier !== 'object' || typeof verifier.verifySignature !== 'function') {
    return {
      ok: false,
      error: relayFailure(
        'SIGNER_SEAM_INVALID',
        'verifyEnvelope requires a verifier with verifySignature()',
      ),
    };
  }

  // 1. structural parse
  let signed;
  try {
    signed = isPlainRecord(input) && isPlainRecord(input.core)
      ? signedFromSignedObject(input)
      : signedFromWireFrame(input);
  } catch (err) {
    return {
      ok: false,
      error: asRelayError(err, 'ENVELOPE_SHAPE_INVALID', 'envelope is not a well-formed wire frame'),
    };
  }

  // 2 + 3. signature, then the pinned keyId label
  const signatureResult = verifier.verifySignature(signed);
  if (signatureResult.ok !== true) {
    return { ok: false, error: signatureResult.error };
  }
  const { core, keyId } = signatureResult;

  // 4. audience binding
  if (core.audience !== expectedAudience) {
    return {
      ok: false,
      error: relayFailure(
        'ENVELOPE_AUDIENCE_MISMATCH',
        'envelope audience does not match the audience this receiver accepts',
        { field: 'audience' },
      ),
    };
  }

  // 5. freshness + deadline
  const freshness = evaluateFreshness({
    audience: core.audience,
    issuedAt: core.issuedAt,
    deadlineMs: core.deadlineMs,
    now,
  });
  if (freshness.ok !== true) {
    return { ok: false, error: freshness.error };
  }

  // 6. args bytes vs the signed sha256(args) (GM-47)
  const isSignedObject = isPlainRecord(input) && isPlainRecord(input.core);
  const carriesArgs = isPlainRecord(input) && Object.prototype.hasOwnProperty.call(input, 'argsB64u');
  const mustCheckArgs =
    requireArgsBytes === undefined ? !isSignedObject : requireArgsBytes === true;
  if (carriesArgs) {
    const argsResult = verifyArgsBytes({
      argsB64u: input.argsB64u,
      argsDigestHex: core.argsDigestHex,
    });
    if (argsResult.ok !== true) {
      return { ok: false, error: argsResult.error };
    }
  } else if (mustCheckArgs) {
    return {
      ok: false,
      error: relayFailure(
        'ARGS_DIGEST_MISMATCH',
        'the envelope does not carry the args bytes, so sha256(args) cannot be re-derived from what was actually received (GM-47)',
        { field: 'argsB64u' },
      ),
    };
  }

  // 7. replay
  if (replayWindow !== null && replayWindow !== undefined) {
    if (typeof replayWindow.checkAndRemember !== 'function') {
      return {
        ok: false,
        error: relayFailure(
          'SIGNER_SEAM_INVALID',
          'the replay window must expose checkAndRemember()',
        ),
      };
    }
    const reservation = await replayWindow.checkAndRemember({
      grantId: core.grantId,
      nonce: core.nonce,
      // The last instant this envelope can still satisfy the freshness law. Pinning the
      // reservation to it is what makes "never forgotten while it could still be fresh" true even
      // for a future-dated envelope and even at the minimum retention (GM-48 m2).
      freshUntilMs: freshness.issuedMs + freshness.windowMs,
    });
    if (reservation.ok !== true) {
      return { ok: false, error: reservation.error };
    }
  }

  return { ok: true, core, keyId, windowMs: freshness.windowMs };
}

/**
 * Extracts the core from a flat wire frame without verifying anything. Intended for keyless
 * consumers (the relay DO's view checks) and for diagnostics; never an admission decision.
 * @param {object} frame
 * @returns {object} frozen core
 */
function peekCoreFromWireFrame(frame) {
  return coreFromWireFrame(frame);
}

module.exports = {
  verifyEnvelope,
  peekCoreFromWireFrame,
};