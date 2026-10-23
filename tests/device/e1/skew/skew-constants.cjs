'use strict';

/**
 * Two-arm skew fixture constants (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Reference timeline
 * ------------------
 * The fixture does NOT own a timeline constant anymore. The ABSOLUTE epoch (`TRUE_NOW` ≈ 20 days
 * past) was retired by GM-69: under database-time predicates "live on the reference timeline" only
 * means something when it is decided against the DATABASE clock. The reference instant is therefore
 * read from the replica set itself (`hello.localTime`, millisecond precision) by the parent at
 * release time, published to both writer arms in the go file, and waited out on the database clock
 * by each writer — that is the only anchoring under which "live" is a property of the database
 * rather than of a fixture constant. A fixture regressing to the absolute epoch would seed rows
 * that are already dead in database time and prove nothing; `verifyNoFixedAnchor` in the fixture
 * pins the construction so the regression cannot slip back in.
 *
 * Model of the H01 counterexample (evidence/gate-closure-002/reviews/H01-authorization-concurrency.md,
 * finding F-H01-4 / F-H01-1) as re-based by GM-69:
 *   - two real OS processes, each writes its own lease arm with its own INJECTED clock
 *     (correct at the reference instant; skewed by exactly `offsetMs`), on the SAME cluster;
 *   - an arm is live on the reference timeline iff `expiresAt = referenceNowMs + life` is still in
 *     the future at the instant the product decides;
 *   - the control arm (offset 0) and the treatment arm (offset ±delta) are judged against the SAME
 *     database-time law: identical behaviour under both clocks proves the writer's clock decides
 *     nothing; any asymmetry against a live row is the finding.
 *
 * Frozen time constants (never changed by this lane):
 *   - the GM-16 frozen skew margin: a lease is lapsed by the margin-carrying predicates iff its
 *     remaining life is at most `-SKEW_MARGIN_MS` at the decision instant;
 *   - the renewal CAS releases only strictly before expiry by the margin (life > +SKEW_MARGIN_MS);
 *   - the admission axis (`isLiveLease`) is margin-free: live is life > 0.
 */

const env = require('../w3a/env.cjs');

/** H01's counterexample offset: the treatment writer is fast/slow by 5 minutes. */
const DELTA_MS = 300000;

/** Remaining budget-lease life of the bare boundary rows: live (or dead) by 1000 ms. */
const EPSILON_MS = 1000;

/** Frozen margin the product subtracts from its own comparison in every margin-carrying predicate. */
const SKEW_MARGIN_MS = env.constants.SKEW_MARGIN_MS;

/** Frozen authority lease duration: exactly 48 h. */
const LEASE_TTL_MS = env.constants.LEASE_TTL_MS;

/**
 * The treatment arm under a writer-clock predicate transitions a live lease iff
 * `life <= delta - SKEW_MARGIN_MS`: the fast writer decides against `clock - SKEW_MARGIN_MS`. This
 * is the empirical crossover the SKEW-03 sweep measures: in DATABASE mode the measured horizon must
 * be EMPTY (no row may be transitioned at any remaining life). If the seam ever regressed to the
 * writer's clock, the horizon would reappear at exactly this value.
 */
const PREDICTED_OVER_RELEASE_HORIZON_MS = DELTA_MS - SKEW_MARGIN_MS;

/**
 * Remaining-life grid for the boundary sweep. Every entry is a `claimAuthority` probe judged
 * against the same database-time law: 0-match (refused as live-or-inside-margin) iff
 * `life > -SKEW_MARGIN_MS`, and 1-match (genuinely lapsed) iff `life <= -SKEW_MARGIN_MS`. The live
 * side crosses the predicted delta - SKEW_MARGIN crossover from both sides; the dead side carries
 * the margin-precise edge (-5000 must match, -1000 must not) so a silent margin drift would fail
 * this fixture rather than drift with it.
 *
 * The last element of each span is deliberately at the exact equality edge (`2 == 1 + 1` style):
 * claims at life == -SKEW_MARGIN_MS must match (the product's `$lte` is inclusive).
 */
const SWEEP_GRID_MS = [1000, 100000, 200000, 294999, 295000, 295001, 300000, 300001, -1000, -5000, -5001, -300001];

/**
 * The ARM lead, in milliseconds (GM-69 database-clock wait).
 *
 * The reference instant is published to both writers AFTER they are armed at the file barrier, and
 * it is placed `ARM_LEAD_MS` beyond the LATER of two database-clock readings: the parent's own
 * reading at release time and each writer's reading taken after its whole fixture context is built
 * (published in its ready file). Both writers then wait the lead out on the DATABASE clock, so the
 * wait is real, and the reserve is large enough that each writer still seeds its preimage and
 * decides every probe before the instant even on a loaded host. A writer that was armed before the
 * parent's release reading can therefore never find the reference instant already past; if one
 * still does (an extreme host stall), the GATE ledger reports it as HARNESS_FAIL rather than
 * measuring against a stale anchor.
 */
const ARM_LEAD_MS = 30000;

/**
 * The declared post-instant window, in milliseconds, inside which every probe must decide.
 *
 * A decision at `dbNowAtProbeMs > referenceNowMs + DECISION_SLOP_MS` can prove nothing about a
 * 1000 ms boundary row and voids the fixture's premise, so the parent fails that probe as a GATE
 * (harness-credibility) failure instead of crediting it as either law side. 500 ms is generous for
 * a lockstep arm whose preimage is already seeded; the writers are still expected to decide at
 * ≈ 10-30 ms past the instant.
 */
const DECISION_SLOP_MS = 500;

const OWNER_A = env.OWNER_A;
const OWNER_B = env.OWNER_B;
const OWNER_C = env.OWNER_C;
const TENANT = env.TENANT;

/** Bounded barrier/child budgets; the child itself never sleeps inside a CAS. */
const BARRIER_TIMEOUT_MS = 60000;
const CHILD_TIMEOUT_MS = 240000;

module.exports = {
  DELTA_MS,
  EPSILON_MS,
  ARM_LEAD_MS,
  DECISION_SLOP_MS,
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
