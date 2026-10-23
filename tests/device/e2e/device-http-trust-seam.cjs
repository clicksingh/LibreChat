'use strict';

/**
 * W9 — the DISCLOSED server-owned pepper seam for the REAL `api/server/routes/devices.js` router.
 *
 * WHY THIS FILE EXISTS. `api/server/routes/devices.js` constructs the pairing handlers WITHOUT a
 * `pepperLookup`:
 *
 *   const pairingChallenge = createPairingChallengeHandler({ db, tenantContext, domainTag });
 *
 * The accepted handlers read that seam through `deviceHttpTrust.resolvePepperSeam()`, which returns
 * `null` when no server configuration supplies a pepper — and then the ceremony FAILS CLOSED with
 * `WRITE_OUTCOME_UNCERTAIN` ("No pairing lookup pepper is configured server-side"). Measured, not
 * assumed: the first full run of this harness reached exactly that refusal on
 * `POST /api/devices/pairing/challenge`.
 *
 * The jest suite that covers these routes injects the pepper through its module mock
 * (`devices.spec.js`: `pepperLookup: LAB_PEPPER`). This harness reproduces the same injection at the
 * same boundary WITHOUT editing the product file, by re-exporting the genuine `deviceHttpTrust`
 * module with exactly ONE function wrapped: `resolvePepperSeam`. The wrapper honours the caller's own
 * seam first and only falls back to the harness's server-side pepper, so a handler that was given a
 * pepper keeps using it.
 *
 * WHAT IS AND IS NOT A SUBSTITUTION. The pepper is a server-side VALUE, not behaviour: the HMAC
 * lookup-tag law, the failure ordering and every check stay in the accepted product bytes. The
 * pepper itself is a lab value generated per run; it is never written into the worktree, never
 * logged, and the evidence records only its presence and length. If no pepper were injected, the
 * ceremony could not run at all — so this is a wiring gap in the local lab, reported as such rather
 * than hidden.
 */

const path = require('node:path');

const REPO = path.resolve(__dirname, '..', '..', '..');
const genuine = require(path.join(REPO, 'api', 'server', 'services', 'Device', 'deviceHttpTrust.js'));

/** Set by the runner before the router is required. Never logged, never persisted, never in evidence. */
let seamPepper = null;
const stats = { calls: 0, usedCallerSeam: 0, usedHarnessSeam: 0, returnedNull: 0 };

function setSeamPepper(value) {
  seamPepper = value ?? null;
}

function resolvePepperSeam(args) {
  stats.calls += 1;
  const value = typeof args?.resolvePepperLookup === 'function' ? args.resolvePepperLookup() : args?.pepperLookup;
  if (value !== undefined && value !== null) {
    stats.usedCallerSeam += 1;
    return value;
  }
  if (seamPepper !== null && seamPepper !== undefined) {
    stats.usedHarnessSeam += 1;
    return seamPepper;
  }
  stats.returnedNull += 1;
  return null;
}

module.exports = { ...genuine, resolvePepperSeam, __seam: { setSeamPepper, stats } };