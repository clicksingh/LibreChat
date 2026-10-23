'use strict';

/**
 * CBHR ENDPOINT AGENT — freshness, deadline and the GM-47 args re-hash (workstream W7).
 *
 * Both laws are implemented here from the frozen contract, not imported:
 *
 *   FRESHNESS (F-V24C-4 field 4/5, invariant 7) — "freshness is dual":
 *     endpoint audience: `|now - issuedAt| <= 60 000` ms  (BOTH directions)
 *     relay audience:    `|now - issuedAt| <= 120 000` ms (BOTH directions)
 *     always, additionally: `now <= deadlineMs`
 *     mint-time bound: `deadlineMs <= issuedAt + 120 000`
 *
 *   Why the LOWER bound is enforced: a future-dated `issuedAt` is not "more valid". Without it, a
 *   signer bug or a skewed custody clock mints envelopes that stay admissible for the whole deadline
 *   horizon, so a captured envelope could simply be held. GM-32 then confirms the asymmetry is
 *   deliberate: the leg carrying commands to an employee's PC gets 60 s, the reply leg 120 s.
 *
 *   Why `deadlineMs` is checked separately even though it is inside the signature: the signature
 *   stops an attacker extending it, but the deadine is still the contract's second, independent
 *   condition (`now <= deadlineMs`), and a frame can be inside the freshness window while past its
 *   deadline when the backend minted a shorter deadline than `issuedAt + 60 s`.
 *
 *   GM-47 ARGS CHECK — decode `argsB64u`, recompute `sha256` over EXACTLY those bytes and require
 *   equality with the signed `argsDigestHex`, before anything executes. GM-29 forbids canonicalising
 *   the arguments anywhere, so the bytes hashed are the bytes received and nothing else. A valid
 *   signature over a digest whose preimage does not match the transported bytes is not authority over
 *   the payload.
 */

const nodeCrypto = require('node:crypto');

const { refusal } = require('./errors');
const { parseEpochMs, decodeArgsBytes, MAX_DEADLINE_HORIZON_MS } = require('./layout');

/** The frozen per-audience freshness windows (contract: 60 s endpoint, 120 s relay). */
const FRESHNESS_WINDOWS_MS = Object.freeze({
  endpoint: 60000,
  relay: 120000,
});

/** The endpoint audience is the only audience a command frame may carry. */
const ENDPOINT_WINDOW_MS = FRESHNESS_WINDOWS_MS.endpoint;

/**
 * The endpoint's frozen freshness law for one frame at one instant.
 *
 * Returns distinct refusal codes per failure so a *local* diagnosis is exact, while the frame's
 * sender-facing message stays generic (endpoint-verifier invariant 3).
 *
 * @param {object} params
 * @param {string} params.audience the SIGNED audience, never a request value
 * @param {string|number} params.issuedAt epoch-ms as signed
 * @param {string|number} params.deadlineMs epoch-ms as signed
 * @param {number} params.now endpoint clock reading in epoch-ms
 * @returns {{ok: true, windowMs: number, ageMs: number, issuedMs: number, deadlineEpochMs: number}
 *   | {ok: false, error: import('./errors').EndpointRefusal}}
 */
function evaluateFreshness(params = {}) {
  const { audience, issuedAt, deadlineMs, now } = params;

  if (audience !== 'endpoint') {
    // The endpoint only ever applies the endpoint window; a relay-audience frame is refused on
    // audience grounds before this runs. Reaching here means the caller bypassed that check.
    return {
      ok: false,
      error: refusal(
        'ENDPOINT_AUDIENCE_MISMATCH',
        'freshness was evaluated for an audience the endpoint does not accept',
        { field: 'audience' },
      ),
    };
  }
  if (!Number.isSafeInteger(now) || now < 0) {
    return {
      ok: false,
      error: refusal('ENDPOINT_CLOCK_UNUSABLE', 'the endpoint clock did not return epoch milliseconds', {
        field: 'now',
      }),
    };
  }
  const issuedMs = parseEpochMs(issuedAt);
  if (issuedMs === null) {
    return {
      ok: false,
      error: refusal(
        'ENDPOINT_ENVELOPE_SHAPE_INVALID',
        'envelope field "issuedAt" must be a canonical decimal epoch-millisecond value',
        { field: 'issuedAt' },
      ),
    };
  }
  const deadlineEpochMs = parseEpochMs(deadlineMs);
  if (deadlineEpochMs === null) {
    return {
      ok: false,
      error: refusal(
        'ENDPOINT_ENVELOPE_SHAPE_INVALID',
        'envelope field "deadlineMs" must be a canonical decimal epoch-millisecond value',
        { field: 'deadlineMs' },
      ),
    };
  }
  const horizon = deadlineEpochMs - issuedMs;
  if (horizon < 0) {
    return {
      ok: false,
      error: refusal('ENDPOINT_ENVELOPE_SHAPE_INVALID', 'envelope field "deadlineMs" must not precede issuedAt', {
        field: 'deadlineMs',
      }),
    };
  }
  if (horizon > MAX_DEADLINE_HORIZON_MS) {
    return {
      ok: false,
      error: refusal(
        'ENDPOINT_DEADLINE_EXCEEDED',
        `envelope field "deadlineMs" exceeds the frozen ${MAX_DEADLINE_HORIZON_MS} ms horizon`,
        { field: 'deadlineMs' },
      ),
    };
  }

  const ageMs = now - issuedMs;
  if (ageMs > ENDPOINT_WINDOW_MS) {
    return {
      ok: false,
      error: refusal(
        'ENDPOINT_FRESHNESS_EXPIRED',
        `envelope is older than the frozen ${ENDPOINT_WINDOW_MS} ms endpoint freshness window`,
        { field: 'issuedAt' },
      ),
    };
  }
  if (-ageMs > ENDPOINT_WINDOW_MS) {
    return {
      ok: false,
      error: refusal(
        'ENDPOINT_FRESHNESS_NOT_YET_VALID',
        `envelope is dated more than the frozen ${ENDPOINT_WINDOW_MS} ms endpoint freshness window in the future`,
        { field: 'issuedAt' },
      ),
    };
  }
  if (now > deadlineEpochMs) {
    return {
      ok: false,
      error: refusal(
        'ENDPOINT_DEADLINE_EXCEEDED',
        'envelope deadline has passed (deadlineMs is inside the signature and cannot be extended)',
        { field: 'deadlineMs' },
      ),
    };
  }

  return { ok: true, windowMs: ENDPOINT_WINDOW_MS, ageMs, issuedMs, deadlineEpochMs };
}

/** sha256, lowercase hex, over exactly the bytes given (GM-29: no canonicalisation). */
function sha256Hex(bytes) {
  return nodeCrypto.createHash('sha256').update(bytes).digest('hex');
}

/**
 * The GM-47 check. Runs AFTER the signature, so the digest it compares against is authentic, and
 * BEFORE replay, so a payload that cannot be bound never burns a nonce.
 *
 * @param {object} params
 * @param {unknown} params.argsB64u the transported bytes, exactly as received
 * @param {unknown} params.argsDigestHex field 15 of the SIGNED core
 * @returns {{ok: true, argsBytes: Buffer, argsDigestHex: string}
 *   | {ok: false, error: import('./errors').EndpointRefusal}}
 */
function verifyArgsBytes(params = {}) {
  const argsBytes = decodeArgsBytes(params.argsB64u);
  if (argsBytes === null) {
    return {
      ok: false,
      error: refusal(
        'ENDPOINT_ARGS_DIGEST_MISMATCH',
        'argsB64u must be canonical unpadded base64url of the exact args bytes the sender hashed',
        { field: 'argsB64u' },
      ),
    };
  }
  const { argsDigestHex } = params;
  if (typeof argsDigestHex !== 'string' || !/^[0-9a-f]{64}$/.test(argsDigestHex)) {
    return {
      ok: false,
      error: refusal(
        'ENDPOINT_ARGS_DIGEST_MISMATCH',
        'the signed args digest must be 64 lowercase hex characters before the bytes can be checked',
        { field: 'argsDigestHex' },
      ),
    };
  }
  const recomputed = sha256Hex(argsBytes);
  if (recomputed !== argsDigestHex) {
    return {
      ok: false,
      error: refusal(
        'ENDPOINT_ARGS_DIGEST_MISMATCH',
        'the transported args bytes do not hash to the signed args digest',
        { field: 'argsB64u' },
      ),
    };
  }
  return { ok: true, argsBytes, argsDigestHex: recomputed };
}

module.exports = {
  FRESHNESS_WINDOWS_MS,
  ENDPOINT_WINDOW_MS,
  evaluateFreshness,
  sha256Hex,
  verifyArgsBytes,
};