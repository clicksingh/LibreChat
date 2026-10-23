'use strict';

/**
 * FRESHNESS AND DEADLINE ENFORCEMENT — workstream W2 acceptance item 2.
 *
 * Frozen contract (`evidence/gate-closure-002/v24/V24-C-signed-grants.md` F-V24C-4 field 5 and
 * F-V24C-5, endpoint invariant 7):
 *   - endpoint audience: `|now - issuedAt| <= 60 000` ms  (BOTH directions)
 *   - relay audience:    `|now - issuedAt| <= 120 000` ms (BOTH directions)
 *   - in addition, always: `now <= deadlineMs`
 *   - and the mint-time bound: `deadlineMs <= issuedAt + 120 000`
 *
 * Why the second direction matters: a future-dated `issuedAt` is not "more valid". Without the
 * lower bound, a signer bug (or a custody implementation using a skewed clock) would mint envelopes
 * that stay admissible for up to `deadlineMs`, and any captured envelope could be held and replayed
 * after a clock step. Both directions are therefore rejected, with distinct codes so the failure is
 * diagnosable server-side while the client-facing message stays uniform.
 *
 * `deadlineMs` is INSIDE the signature, so an attacker cannot extend an envelope's validity window;
 * the horizon check here exists to catch a MINT defect (the contract caps the horizon at 120 s), not
 * to defend against tampering (the signature already covers the value).
 */

const { MAX_DEADLINE_HORIZON_MS, parseEpochMs } = require('./envelopeCore');
const { relayFailure } = require('./errors');

/** Frozen per-audience freshness windows (contract: 60 s endpoint, 120 s relay). */
const AUDIENCE_FRESHNESS_WINDOWS_MS = Object.freeze({
  endpoint: 60000,
  relay: 120000,
});

/** The widest window any audience may use; replay retention may never be shorter than this. */
const MAX_FRESHNESS_WINDOW_MS = Math.max(...Object.values(AUDIENCE_FRESHNESS_WINDOWS_MS));

/**
 * @param {unknown} audience
 * @returns {number|null} the frozen window for `audience`, or null when the audience is not bound
 */
function freshnessWindowMsFor(audience) {
  return Object.prototype.hasOwnProperty.call(AUDIENCE_FRESHNESS_WINDOWS_MS, audience)
    ? AUDIENCE_FRESHNESS_WINDOWS_MS[audience]
    : null;
}

/**
 * Evaluates the frozen freshness law for one envelope at one instant.
 *
 * @param {object} params
 * @param {string} params.audience `endpoint` | `relay` (the signed audience, never a request value)
 * @param {string|number} params.issuedAt epoch-ms (canonical decimal string, as signed)
 * @param {string|number} params.deadlineMs epoch-ms (canonical decimal string, as signed)
 * @param {number} params.now server clock reading in epoch-ms
 * @returns {{ok: true, windowMs: number, ageMs: number, deadlineMs: number, issuedMs: number}
 *   | {ok: false, error: import('./errors').RelayError}}
 */
function evaluateFreshness(params = {}) {
  const { audience, issuedAt, deadlineMs, now } = params;

  const windowMs = freshnessWindowMsFor(audience);
  if (windowMs === null) {
    return {
      ok: false,
      error: relayFailure(
        'ENVELOPE_AUDIENCE_MISMATCH',
        'envelope audience is not a bound CBHR-RPC-V2 audience, so no freshness window applies',
        { field: 'audience' },
      ),
    };
  }
  if (!Number.isSafeInteger(now) || now < 0) {
    return {
      ok: false,
      error: relayFailure('CLOCK_UNUSABLE', 'the verifying clock did not return epoch milliseconds', {
        field: 'now',
      }),
    };
  }
  const issuedMs = parseEpochMs(issuedAt);
  const deadlineEpochMs = parseEpochMs(deadlineMs);
  if (issuedMs === null) {
    return {
      ok: false,
      error: relayFailure(
        'ENVELOPE_SHAPE_INVALID',
        'envelope field "issuedAt" must be a canonical decimal epoch-millisecond value',
        { field: 'issuedAt' },
      ),
    };
  }
  if (deadlineEpochMs === null) {
    return {
      ok: false,
      error: relayFailure(
        'ENVELOPE_SHAPE_INVALID',
        'envelope field "deadlineMs" must be a canonical decimal epoch-millisecond value',
        { field: 'deadlineMs' },
      ),
    };
  }
  const horizon = deadlineEpochMs - issuedMs;
  if (horizon < 0) {
    return {
      ok: false,
      error: relayFailure(
        'ENVELOPE_SHAPE_INVALID',
        'envelope field "deadlineMs" must not precede issuedAt',
        { field: 'deadlineMs' },
      ),
    };
  }
  if (horizon > MAX_DEADLINE_HORIZON_MS) {
    return {
      ok: false,
      error: relayFailure(
        'DEADLINE_OUT_OF_BOUND',
        `envelope field "deadlineMs" exceeds the frozen ${MAX_DEADLINE_HORIZON_MS} ms horizon`,
        { field: 'deadlineMs' },
      ),
    };
  }

  const ageMs = now - issuedMs;
  if (ageMs > windowMs) {
    return {
      ok: false,
      error: relayFailure(
        'FRESHNESS_EXPIRED',
        `envelope is older than the frozen ${windowMs} ms ${audience} freshness window`,
        { field: 'issuedAt' },
      ),
    };
  }
  if (-ageMs > windowMs) {
    return {
      ok: false,
      error: relayFailure(
        'FRESHNESS_NOT_YET_VALID',
        `envelope is dated more than the frozen ${windowMs} ms ${audience} freshness window in the future`,
        { field: 'issuedAt' },
      ),
    };
  }
  if (now > deadlineEpochMs) {
    return {
      ok: false,
      error: relayFailure(
        'DEADLINE_EXCEEDED',
        'envelope deadline has passed (deadlineMs is inside the signature and cannot be extended)',
        { field: 'deadlineMs' },
      ),
    };
  }

  return { ok: true, windowMs, ageMs, deadlineMs: deadlineEpochMs, issuedMs };
}

module.exports = {
  AUDIENCE_FRESHNESS_WINDOWS_MS,
  MAX_FRESHNESS_WINDOW_MS,
  freshnessWindowMsFor,
  evaluateFreshness,
};