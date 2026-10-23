'use strict';

/**
 * CBHR ENDPOINT AGENT — the verification chain (workstream W7).
 *
 * This is the module that finally makes "the relay cannot forge" a complete argument. The relay is
 * keyless by construction (`apps/cbhr-relay/src/capability-guard.js` fails closed if the runtime can
 * sign); the missing half was always the RECEIVER: something on the employee's PC that refuses a
 * frame the backend did not sign. That is this file.
 *
 * WHY IT IS NOT `relay/envelopeVerifier.js`
 * The backend ships a reference verifier, and reusing it would be the cheapest possible code. It is
 * deliberately NOT reused: an endpoint whose admission logic is the sender's own module proves
 * nothing about the sender — a bug (or a hostile edit) inside `relay/**` would silently move the
 * endpoint's trust boundary with it. So the field layout, the encodings, the freshness law, the
 * replay window and the args cross-check are all implemented here from the frozen contract text, and
 * the golden-vector test pins the byte layout against the published canonical string rather than
 * against the backend's array. The ONLY shared piece is the accepted `canonicalEncode`/
 * `verifyEd25519`/`thumbprintB64u` primitive, which the task explicitly permits.
 *
 * THE FROZEN ORDER — each step fails closed with a DISTINCT code and NOTHING executes before the last
 * one passes:
 *
 *   | # | check                                            | refusal code                          |
 *   |---|--------------------------------------------------|---------------------------------------|
 *   | 1 | canonical string rebuild (15 fields, 0x1F, UTF-8)| ENDPOINT_ENVELOPE_SHAPE_INVALID       |
 *   |   |   - a non-core key inside the frame              | ENDPOINT_FRAME_EXTRA_FIELD            |
 *   |   |   - a field failing the canonical-encode law      | ENDPOINT_ENVELOPE_FIELD_NOT_CANONICAL |
 *   | 2 | Ed25519 signature vs the PINNED backend key      | ENDPOINT_SIGNATURE_INVALID            |
 *   | 3 | `keyId` names a pinned key (GM-31)               | ENDPOINT_KEY_UNPINNED                 |
 *   | 4 | `audience === 'endpoint'`                        | ENDPOINT_AUDIENCE_MISMATCH            |
 *   | 5 | freshness +/- 60 s, both directions              | ENDPOINT_FRESHNESS_EXPIRED / _NOT_YET_VALID |
 *   | 6 | `deadlineMs` not exceeded                        | ENDPOINT_DEADLINE_EXCEEDED            |
 *   | 7 | `deviceId` / `deviceKeyId` name THIS endpoint    | ENDPOINT_DEVICE_MISMATCH / _DEVICE_KEY_MISMATCH |
 *   | 8 | replay window on `(grantId, nonce)`, durable     | ENDPOINT_REPLAY_DETECTED              |
 *   | 9 | GM-47: `argsB64u` decoded, re-hashed, equal to   | ENDPOINT_ARGS_DIGEST_MISMATCH         |
 *   |   |   the SIGNED `argsDigestHex` (GM-29: no canon.)  |                                       |
 *   |10 | `opKind` admission (only `command` executes)     | ENDPOINT_OPKIND_REFUSED               |
 *
 * Steps 7 and 10 are the endpoint half of the contract's own endpoint-check list (F-V24C-5): a
 * backend-signed command addressed to a DIFFERENT device, or for a different key generation, is a
 * valid signature over the wrong subject, and `deviceKeyId` (field 11, inside the signature) is the
 * binding that matters.
 *
 * WHY THE NONCE IS RESERVED LAST (step 8 after the signature)
 * A forged or stale frame must not be able to burn a nonce and thereby deny the genuine frame that
 * follows. Conversely the reservation is made BEFORE the caller is allowed to execute, and it is
 * durable, so an execution can never happen with an unrecorded nonce.
 *
 * VERIFICATION IS SYNCHRONOUS except for the durable write inside step 8; the function is `async` only
 * for that reason.
 */

const { refusal, refusalCodeOf, isEndpointRefusal } = require('./errors');
const {
  coreFromFrame,
  canonicalBytesFor,
  assertSignatureB64u,
  FIELD_ORDER,
} = require('./layout');
const { evaluateFreshness, verifyArgsBytes } = require('./freshness');

function asRefusal(err, fallbackCode, detail) {
  if (isEndpointRefusal(err)) {
    return err;
  }
  return refusal(fallbackCode, detail, { cause: err });
}

/**
 * Verifies one inbound command frame, in the frozen order, and returns the verified core plus the
 * decoded args bytes. Nothing is executed here; a caller that receives `ok: true` holds an
 * authenticated command.
 *
 * @param {object} params
 * @param {object} params.frame the flat wire frame, exactly as received
 * @param {object} params.pins the pinned backend key set (`pinnedKeys.loadPinnedBackendKeys`)
 * @param {string} params.deviceId this endpoint's server-issued device id
 * @param {string} params.deviceKeyId this endpoint's own key thumbprint
 * @param {() => number} params.now injected clock (epoch-ms)
 * @param {object} params.replayWindow the DURABLE window (`replayWindow.createDurableReplayWindow`)
 * @param {boolean} [params.requireArgsBytes] default true: a wire frame must carry `argsB64u`
 * @returns {Promise<
 *   {ok: true, core: object, keyId: string, argsBytes: Buffer, argsDigestHex: string, ageMs: number}
 *   | {ok: false, error: import('./errors').EndpointRefusal}>}
 */
async function verifyCommandFrame(params = {}) {
  const { frame, pins, deviceId, deviceKeyId, now, replayWindow, requireArgsBytes = true } = params;

  if (pins === null || typeof pins !== 'object' || typeof pins.verify !== 'function') {
    return {
      ok: false,
      error: refusal('ENDPOINT_KEY_UNPINNED', 'the endpoint holds no usable pinned backend key set', {
        field: 'keyId',
      }),
    };
  }
  if (typeof now !== 'function') {
    return {
      ok: false,
      error: refusal('ENDPOINT_CLOCK_UNUSABLE', 'frame verification requires a now() clock'),
    };
  }

  // ---- 1. canonical string rebuild -------------------------------------------------------------
  let core;
  try {
    core = coreFromFrame(frame);
    canonicalBytesFor(core);
  } catch (err) {
    return { ok: false, error: asRefusal(err, 'ENDPOINT_ENVELOPE_SHAPE_INVALID', 'the frame is not a well-formed CBHR-RPC-V2 wire frame') };
  }

  // The signature transport field is part of the frame's shape, so a malformed one is refused here
  // rather than at the crypto call (which would only return `false`).
  try {
    assertSignatureB64u(frame.signatureB64u);
  } catch (err) {
    return { ok: false, error: asRefusal(err, 'ENDPOINT_SIGNATURE_INVALID', 'the frame signature is not well formed') };
  }

  // ---- 2 + 3. signature against the PINNED key, then the pinned-label check --------------------
  //
  // Order note. GM-31 makes `keyId` selection metadata rather than authority, and the contract puts
  // signature verification BEFORE every other check (invariant 3). Both are satisfied by: resolve the
  // label to a pinned key, refuse an unpinned label (3), and only then verify against that key (2).
  // A frame naming an unpinned key therefore never reaches the crypto call at all — it cannot probe
  // for a key that is pinned under a different label. The two refusals stay distinct so a local
  // operator can tell a rotation mistake from a forgery.
  const pinned = pins.pinned(frame.keyId);
  if (pinned === null) {
    return {
      ok: false,
      error: refusal(
        'ENDPOINT_KEY_UNPINNED',
        'the frame names a key id that this endpoint has not pinned; failing closed (GM-31)',
        { field: 'keyId' },
      ),
    };
  }
  let canonicalBytes;
  try {
    canonicalBytes = canonicalBytesFor(core);
  } catch (err) {
    return { ok: false, error: asRefusal(err, 'ENDPOINT_ENVELOPE_FIELD_NOT_CANONICAL', 'the frame is not canonical') };
  }
  const signatureOk = pins.verify(frame.keyId, canonicalBytes, frame.signatureB64u);
  if (signatureOk !== true) {
    return {
      ok: false,
      error: refusal(
        'ENDPOINT_SIGNATURE_INVALID',
        'the frame signature does not verify against the pinned backend key for that key id',
        { field: 'signatureB64u' },
      ),
    };
  }

  // ---- 4. audience binding ---------------------------------------------------------------------
  if (core.audience !== 'endpoint') {
    return {
      ok: false,
      error: refusal(
        'ENDPOINT_AUDIENCE_MISMATCH',
        'the frame audience is not the audience this endpoint accepts',
        { field: 'audience' },
      ),
    };
  }

  // ---- 5 + 6. freshness (dual bound) and the deadline ------------------------------------------
  const observedAt = now();
  const freshness = evaluateFreshness({
    audience: core.audience,
    issuedAt: core.issuedAt,
    deadlineMs: core.deadlineMs,
    now: observedAt,
  });
  if (freshness.ok !== true) {
    return { ok: false, error: freshness.error };
  }

  // ---- 7. the endpoint is the addressee (contract F-V24C-5 endpoint checks) --------------------
  if (typeof deviceId !== 'string' || deviceId.length === 0) {
    return {
      ok: false,
      error: refusal('ENDPOINT_DEVICE_MISMATCH', 'the endpoint did not declare its own device id', {
        field: 'deviceId',
      }),
    };
  }
  if (core.deviceId !== deviceId) {
    return {
      ok: false,
      error: refusal(
        'ENDPOINT_DEVICE_MISMATCH',
        'the frame is addressed to a different device id than this endpoint',
        { field: 'deviceId' },
      ),
    };
  }
  if (typeof deviceKeyId !== 'string' || deviceKeyId.length === 0) {
    return {
      ok: false,
      error: refusal(
        'ENDPOINT_DEVICE_KEY_MISMATCH',
        'the endpoint did not declare its own device key id',
        { field: 'deviceKeyId' },
      ),
    };
  }
  if (core.deviceKeyId !== deviceKeyId) {
    return {
      ok: false,
      error: refusal(
        'ENDPOINT_DEVICE_KEY_MISMATCH',
        'the frame binds a different device key generation than the one this endpoint holds',
        { field: 'deviceKeyId' },
      ),
    };
  }

  // ---- 8. durable replay window on (grantId, nonce) --------------------------------------------
  if (replayWindow === null || typeof replayWindow !== 'object' || typeof replayWindow.checkAndRemember !== 'function') {
    return {
      ok: false,
      error: refusal(
        'ENDPOINT_REPLAY_STORE_UNAVAILABLE',
        'no durable replay window was supplied, so a replayed nonce could not be detected',
        { field: 'replayWindow' },
      ),
    };
  }
  const reservation = await replayWindow.checkAndRemember({
    grantId: core.grantId,
    nonce: core.nonce,
    // The last instant this frame can still satisfy the freshness law. Pinning the reservation to
    // that horizon keeps "never forgotten while it could still be fresh" true even for a frame
    // admitted while future-dated.
    freshUntilMs: freshness.issuedMs + freshness.windowMs,
  });
  if (reservation.ok !== true) {
    return { ok: false, error: reservation.error };
  }

  // ---- 9. GM-47: the transported args bytes must hash to the SIGNED digest ---------------------
  const carriesArgs = frame !== null && typeof frame === 'object' && Object.prototype.hasOwnProperty.call(frame, 'argsB64u');
  if (!carriesArgs && requireArgsBytes) {
    return {
      ok: false,
      error: refusal(
        'ENDPOINT_ARGS_DIGEST_MISMATCH',
        'the frame does not carry the args bytes, so sha256(args) cannot be re-derived from what was actually received (GM-47)',
        { field: 'argsB64u' },
      ),
    };
  }
  let argsBytes = Buffer.alloc(0);
  if (carriesArgs) {
    const argsCheck = verifyArgsBytes({ argsB64u: frame.argsB64u, argsDigestHex: core.argsDigestHex });
    if (argsCheck.ok !== true) {
      return { ok: false, error: argsCheck.error };
    }
    argsBytes = argsCheck.argsBytes;
  }

  // ---- 10. opKind admission --------------------------------------------------------------------
  if (core.opKind !== 'command') {
    return {
      ok: false,
      error: refusal(
        'ENDPOINT_OPKIND_REFUSED',
        'this endpoint executes opKind "command" only; cancel and resync have their own paths',
        { field: 'opKind' },
      ),
    };
  }

  return {
    ok: true,
    core,
    keyId: frame.keyId,
    argsBytes,
    argsDigestHex: core.argsDigestHex,
    ageMs: freshness.ageMs,
  };
}

/**
 * A value-free description of the frozen order, for review and for the agent's own `describe()`
 * output. Keeping it in code next to the checks is what stops the two drifting apart.
 * @returns {ReadonlyArray<{step: number, check: string, refusalCodes: string[]}>}
 */
function describeVerificationOrder() {
  return Object.freeze([
    Object.freeze({
      step: 1,
      check: 'canonical string rebuild + per-field encodings (15 fields, 0x1F, UTF-8)',
      refusalCodes: ['ENDPOINT_ENVELOPE_SHAPE_INVALID', 'ENDPOINT_FRAME_EXTRA_FIELD', 'ENDPOINT_ENVELOPE_FIELD_NOT_CANONICAL'],
    }),
    Object.freeze({ step: 2, check: 'Ed25519 signature against the pinned backend key', refusalCodes: ['ENDPOINT_SIGNATURE_INVALID'] }),
    Object.freeze({ step: 3, check: 'keyId names a pinned key (GM-31)', refusalCodes: ['ENDPOINT_KEY_UNPINNED'] }),
    Object.freeze({ step: 4, check: "audience === 'endpoint'", refusalCodes: ['ENDPOINT_AUDIENCE_MISMATCH'] }),
    Object.freeze({
      step: 5,
      check: 'freshness |now - issuedAt| <= 60 s in both directions',
      refusalCodes: ['ENDPOINT_FRESHNESS_EXPIRED', 'ENDPOINT_FRESHNESS_NOT_YET_VALID'],
    }),
    Object.freeze({ step: 6, check: 'deadlineMs not exceeded (now <= deadlineMs)', refusalCodes: ['ENDPOINT_DEADLINE_EXCEEDED'] }),
    Object.freeze({
      step: 7,
      check: 'deviceId and deviceKeyId name this endpoint',
      refusalCodes: ['ENDPOINT_DEVICE_MISMATCH', 'ENDPOINT_DEVICE_KEY_MISMATCH'],
    }),
    Object.freeze({ step: 8, check: 'durable replay window on (grantId, nonce)', refusalCodes: ['ENDPOINT_REPLAY_DETECTED'] }),
    Object.freeze({ step: 9, check: 'GM-47 argsB64u re-hash equals the signed argsDigestHex', refusalCodes: ['ENDPOINT_ARGS_DIGEST_MISMATCH'] }),
    Object.freeze({ step: 10, check: "opKind admission (only 'command' executes here)", refusalCodes: ['ENDPOINT_OPKIND_REFUSED'] }),
  ]);
}

module.exports = {
  verifyCommandFrame,
  describeVerificationOrder,
  FIELD_ORDER,
  refusalCodeOf,
};