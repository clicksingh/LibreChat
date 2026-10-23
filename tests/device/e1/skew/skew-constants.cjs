'use strict';

/**
 * Two-clock skew fixture constants (test-only, lane additions, PHASE1-LOCAL-AUTHORITY-001).
 *
 * New files only. Nothing in this directory edits or weakens an existing fixture.
 *
 * Reference timeline
 * ------------------
 * The fixture owns a single deterministic REFERENCE timeline, `TRUE_NOW_MS`. It is carried by
 * the "correct" writer's injected clock (offset 0). The offset writer's injected clock reads
 * `TRUE_NOW_MS + offsetMs`. Every lease predicate under test therefore compares a row's
 * `expiresAt` against a writer-local `now` that is skewed from the reference timeline by exactly
 * `offsetMs`.
 *
 * This mirrors GM ruling R9 / GM-16: the transport clocks are pinned (endpoint +-60 s, relay
 * +-120 s, inter-host skew budget 5000 ms) but the MONGO-SIDE WRITERS that decide lease state
 * have no pinned clock discipline, so a writer may carry any offset. No `Date.now()` participates
 * in any decision or assertion: both clocks are injected and deterministic.
 *
 * Model of the H01 counterexample (evidence/gate-closure-002/reviews/H01-authorization-concurrency.md,
 * finding F-H01-4 / F-H01-1):
 *   - servers S1 (fast by delta) and S2 (correct) write the same lease rows;
 *   - B holds a lease with `expiresAt = TRUE_NOW + epsilon`, i.e. still live by `epsilon` ms on
 *     the reference timeline;
 *   - a claim / lazy-release / renewal CAS issued by the skewed writer uses ITS OWN `now` in the
 *     lapsed/expiry predicate, so a fast writer matches a still-live lease `delta - SKEW_MARGIN`
 *     ms early (over-release) and a slow writer accepts a renewal past true expiry.
 */

const env = require('../w3a/env.cjs');

/** Reference timeline: the injected clock value of the CORRECT writer (never a wall-clock read). */
const TRUE_NOW_MS = env.constants.EPOCH_BASE_MS;

/** H01's counterexample offset: S1 fast by delta = 5 minutes. */
const DELTA_MS = 300000;

/** Remaining reference-timeline life of the boundary lease: live by 1000 ms at TRUE_NOW. */
const EPSILON_MS = 1000;

/** Frozen margin the product subtracts from the writer's own clock in every lapsed predicate. */
const SKEW_MARGIN_MS = env.constants.SKEW_MARGIN_MS;

/** Frozen authority lease duration: exactly 48 h. */
const LEASE_TTL_MS = env.constants.LEASE_TTL_MS;

/**
 * The predicate-derived crossover: a fast writer matches a still-live lease iff
 * `epsilon <= delta - SKEW_MARGIN_MS`. The boundary sweep measures this empirically instead of
 * assuming it.
 */
const PREDICTED_OVER_RELEASE_HORIZON_MS = DELTA_MS - SKEW_MARGIN_MS;

/** Remaining-life grid for the boundary sweep (crosses the predicted crossover from both sides). */
const SWEEP_GRID_MS = [1000, 100000, 200000, 294999, 295000, 295001, 300000, 300001];

const OWNER_A = env.OWNER_A;
const OWNER_B = env.OWNER_B;
const OWNER_C = env.OWNER_C;
const TENANT = env.TENANT;

/** Bounded barrier/child budgets; the child itself never sleeps inside a CAS. */
const BARRIER_TIMEOUT_MS = 60000;
const CHILD_TIMEOUT_MS = 240000;

module.exports = {
  TRUE_NOW_MS,
  DELTA_MS,
  EPSILON_MS,
  SKEW_MARGIN_MS,
  LEASE_TTL_MS,
  PREDICTED_OVER_RELEASE_HORIZON_MS,
  SWEEP_GRID_MS,
  OWNER_A,
  OWNER_B,
  OWNER_C,
  TENANT,
  BARRIER_TIMEOUT_MS,
  CHILD_TIMEOUT_MS,
};