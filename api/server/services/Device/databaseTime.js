'use strict';

/**
 * DATABASE-TIME SOURCE for lease-state and TTL decisions (GM-44 / GM-45).
 *
 * WHY THIS EXISTS
 * Every predicate that decides lease state or a TTL must be evaluated against DATABASE time. A
 * predicate computed from the writer's own clock (`new Date(now - SKEW_MARGIN_MS)` built in Node)
 * is wrong whenever two writers disagree: a fast writer dislodges a still-live lease, and a slow
 * writer accepts a renewal past true expiry. The margin only bounds that error to `skew - margin`,
 * which is larger than zero for every margin-free site.
 *
 * THE TWO MECHANISMS
 *   1. In-query predicates use `$$NOW` (the server-side aggregation variable) inside `$expr`, so the
 *      comparison happens IN MongoDB against the server's own clock and the writer's clock never
 *      participates. Nothing in this module is needed for that: it is a property of the filter bytes.
 *   2. Where a decision cannot be expressed as a single predicate (a pre-check that must run before
 *      a write, or the classification of a CAS miss), the caller reads the database clock once with
 *      `readDatabaseNowMs()` and compares against THAT value. `$$NOW` is not available to a plain
 *      Node comparison, so the value is measured from the server instead of assumed.
 *
 * `readDatabaseNowMs` is a READ. It never writes, never mutates a row, and it cannot change a lease
 * decision by itself: the authoritative predicates are the `$expr` filters.
 *
 * DEFENCE IN DEPTH (GM-44 rule 3, NOT the primary control)
 * `createClockSkewGuard` compares the host clock with database time and fails closed when
 * `|skew| > SKEW_BUDGET_MS`. Correctness does NOT depend on it: the `$expr` predicates are already
 * clock-independent. The guard exists because a wildly wrong clock also corrupts audit timestamps,
 * freshness checks and response fields, so a process that cannot prove its clock is sane must not
 * serve lease-state writes.
 *
 * THE TEST-ONLY PREDICATE ANCHOR (GM-64 / GM-65 — `predicateAnchor`)
 * ------------------------------------------------------------------
 * The two mechanisms above make the predicate independent of the WRITER's clock, which is the
 * security property. It also means a fixture can no longer simulate the 48 h / 300 s boundaries by
 * moving its injected clock: the comparison happens against the database's clock, so a row stamped
 * at a fixture epoch is already dead. GM-64 resolves that collision with ONE seam.
 *
 *   - With no seam configured (PRODUCTION, and every real composition) `resolvePredicateAnchor`
 *     returns the `$$NOW` marker, so the comparison is evaluated by MongoDB against the database's
 *     own clock. This is the GM-44 behaviour and it is non-negotiable.
 *   - A test may supply `predicateAnchor` explicitly: a concrete `Date` (or a finite epoch-ms
 *     number, or a zero-argument provider returning either) that is substituted for the `$$NOW`
 *     reference in the same `$expr` shape, and that also stands in for the measured database clock
 *     where a decision cannot be one predicate. A fixture can then place the comparison anywhere on
 *     the timeline without waiting 48 hours.
 *
 * The seam is named `predicateAnchor` so a reviewer can grep it and see immediately that it is a
 * test affordance. It is read ONCE at service construction from server-owned dependencies; it is
 * NEVER read from a request, a stored row, a session or any caller-supplied value, so no request or
 * row can influence which clock a predicate compares against. **Tests only; production must omit.**
 * Any non-test construction of a Device service that passes it is a review event (GM-65).
 *
 * The injected `clock` seam is a DIFFERENT seam and stays: it supplies the values written into rows
 * (audit timestamps, `issuedAt`/`expiresAt`/`consumedAt`) and response fields. It never decides a
 * lease state or a TTL. Do not conflate the two.
 */

const { DeviceError } = require('./errors');

/** The GM-65 seam name, exported so a pin test can assert it rather than hard-code a string. */
const PREDICATE_ANCHOR_SEAM = 'predicateAnchor';
/** The production marker: MongoDB's own clock, evaluated server-side inside `$expr`. */
const DB_NOW_MARKER = '$$NOW';

/** Frozen inter-host skew budget: exactly 5 seconds (matches `SKEW_MARGIN_MS`). */
const SKEW_BUDGET_MS = 5000;
/** How long a measured skew verdict is reused, so a burst of writes costs one measurement. */
const DEFAULT_SKEW_CACHE_MS = 1000;

/**
 * Collections that exist wherever a device lease exists, in preference order. `$collStats` is the
 * cheapest stage that can run at the head of a collection pipeline and is still evaluated by the
 * server, which is what makes `$$NOW` available without reading a single document.
 */
const TIME_HOST_MODELS = Object.freeze([
  'DeviceAuthority',
  'Challenge',
  'PairingSession',
  'AuditEvent',
]);

function toFiniteMs(value) {
  if (value instanceof Date) {
    return value.getTime();
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === 'string') {
    const parsed = Date.parse(value);
    return Number.isNaN(parsed) ? null : parsed;
  }
  return null;
}

/**
 * Validates the SHAPE of the test-only `predicateAnchor` seam at construction time.
 *
 * A supplied seam must be a `Date`, a finite epoch-millisecond number, or a zero-argument provider
 * returning one of those. A provider is NOT called here: a fixture constructs its handlers before
 * its clock has a value, so the value is resolved per predicate instead (see
 * `resolvePredicateAnchor`). Only the form is checked, so a construction defect still fails loudly
 * at the seam instead of surfacing as a wrong comparison deep inside a call.
 *
 * @param {*} predicateAnchor the seam value, or `undefined`/`null` for production
 * @returns {boolean} `true` when a test anchor is configured
 * @throws {TypeError} when a value is supplied that is not a usable anchor
 */
function assertPredicateAnchorShape(predicateAnchor) {
  if (predicateAnchor === undefined || predicateAnchor === null) {
    return false;
  }
  if (typeof predicateAnchor === 'function') {
    return true;
  }
  if (predicateAnchor instanceof Date) {
    if (!Number.isFinite(predicateAnchor.getTime())) {
      throw new TypeError(`${PREDICATE_ANCHOR_SEAM} must be a valid Date when supplied`);
    }
    return true;
  }
  if (typeof predicateAnchor === 'number' && Number.isFinite(predicateAnchor)) {
    return true;
  }
  throw new TypeError(
    `${PREDICATE_ANCHOR_SEAM} must be a Date, a finite epoch-ms number or a provider (tests only; production must omit)`,
  );
}

/**
 * THE single place that decides anchor-vs-`$$NOW` (GM-64 rules 1-2, GM-65).
 *
 * Returns `$$NOW` — the production marker — unless a test anchor was explicitly supplied. Every
 * lease-state / TTL predicate and every measured database-clock comparison in the Device services
 * goes through this function (directly, or through `expiryPredicate` / `readAnchorNowMs`), so the
 * branch exists exactly once.
 *
 * @param {*} predicateAnchor the test seam (`Date`, epoch-ms, or provider); omit in production
 * @returns {string|Date} the `$$NOW` marker, or a defensive copy of the concrete anchor
 * @throws {TypeError} when a supplied seam does not resolve to a usable instant
 */
function resolvePredicateAnchor(predicateAnchor) {
  if (predicateAnchor === undefined || predicateAnchor === null) {
    return DB_NOW_MARKER;
  }
  let value = predicateAnchor;
  if (typeof predicateAnchor === 'function') {
    try {
      value = predicateAnchor();
    } catch (err) {
      throw new TypeError(`${PREDICATE_ANCHOR_SEAM} provider failed; refusing to guess a clock`, {
        cause: err,
      });
    }
  }
  if (value instanceof Date) {
    if (!Number.isFinite(value.getTime())) {
      throw new TypeError(`${PREDICATE_ANCHOR_SEAM} resolved to an invalid Date`);
    }
    return new Date(value.getTime());
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return new Date(value);
  }
  throw new TypeError(
    `${PREDICATE_ANCHOR_SEAM} must resolve to a Date or a finite epoch-ms number (tests only; production must omit)`,
  );
}

/**
 * Builds the ONE `$expr` document used by every lease-state / TTL expiry predicate.
 *
 * Production shape (unchanged from GM-44, byte for byte):
 *   `{ $gt: ['$expiresAt', '$$NOW'] }`                          — margin-free live test
 *   `{ $gt: ['$expiresAt', { $add: ['$$NOW', 5000] }] }`         — live, outside the renewal margin
 *   `{ $lte: ['$expiresAt', { $subtract: ['$$NOW', 5000] }] }`   — lapsed, past the skew margin
 *
 * Test shape: the `$$NOW` operand is replaced by the concrete anchor `Date` in the SAME expression,
 * which MongoDB accepts in a find filter and in an update filter alike.
 *
 * @param {object} options
 * @param {*} options.predicateAnchor the GM-65 test seam; omit in production
 * @param {'$gt'|'$lte'} options.operator `$gt` = "still live", `$lte` = "already lapsed"
 * @param {number} [options.marginMs] margin magnitude (0 = margin-free site)
 * @returns {object} the `$expr` document
 */
function expiryPredicate({ predicateAnchor, operator, marginMs = 0 } = {}) {
  if (operator !== '$gt' && operator !== '$lte') {
    throw new TypeError('expiryPredicate requires operator $gt or $lte');
  }
  if (typeof marginMs !== 'number' || !Number.isFinite(marginMs) || marginMs < 0) {
    throw new TypeError('expiryPredicate requires a finite, non-negative marginMs');
  }
  const anchor = resolvePredicateAnchor(predicateAnchor);
  if (marginMs === 0) {
    return { [operator]: ['$expiresAt', anchor] };
  }
  // `$add`/`$subtract` with a Date and a number treats the number as milliseconds, so a concrete
  // anchor keeps the exact shape and semantics of the `$$NOW` operand it replaces.
  return {
    [operator]: ['$expiresAt', { [operator === '$gt' ? '$add' : '$subtract']: [anchor, marginMs] }],
  };
}

/**
 * Reads the comparison anchor in epoch milliseconds: the test anchor when one is configured, and
 * the measured database clock otherwise. Used where a decision cannot be a single predicate (a
 * pre-check before a write, or the classification of a CAS miss).
 *
 * @param {object} db model surface used for the server-time read
 * @param {*} predicateAnchor the GM-65 test seam; omit in production
 * @returns {Promise<number|null>} epoch-ms, or `null` when the database clock cannot be measured
 */
async function readAnchorNowMs(db, predicateAnchor) {
  const anchor = resolvePredicateAnchor(predicateAnchor);
  if (anchor !== DB_NOW_MARKER) {
    return anchor.getTime();
  }
  return readDatabaseNowMs(db);
}

/**
 * Reads the MongoDB server clock, in epoch milliseconds, without touching a document.
 *
 * `$collStats` requires an existing collection, so the candidate list is tried in order and the
 * first collection that exists wins. A caller that has just read a row from `DeviceAuthority` is
 * therefore guaranteed a value.
 *
 * @param {object} db model surface exposing Mongoose models (aggregate)
 * @returns {Promise<number|null>} server epoch-ms, or `null` when no candidate can answer
 */
async function readDatabaseNowMs(db) {
  if (db === null || typeof db !== 'object') {
    return null;
  }
  for (const key of TIME_HOST_MODELS) {
    const model = db[key];
    // A genuine Mongoose model is a FUNCTION; the frozen `db` contract also admits an object
    // facade. Both are valid surfaces, so accept either shape.
    if (
      model === null ||
      (typeof model !== 'object' && typeof model !== 'function') ||
      typeof model.aggregate !== 'function'
    ) {
      continue;
    }
    try {
      // eslint-disable-next-line no-await-in-loop
      const rows = await model.aggregate([
        { $collStats: { count: {} } },
        { $project: { _id: 0, now: '$$NOW' } },
      ]);
      const value = Array.isArray(rows) && rows.length > 0 ? rows[0].now : null;
      const nowMs = toFiniteMs(value);
      if (nowMs !== null) {
        return nowMs;
      }
    } catch {
      /* collection absent or unreadable: try the next candidate */
    }
  }
  return null;
}

/**
 * Builds the clock-skew guard (GM-44 rule 3).
 *
 * `check()` resolves to `{ok, skewMs, measured, databaseNowMs, budgetMs, error}`. `ok:false` means
 * the caller must refuse to proceed and fail closed. A measurement that cannot be taken at all
 * (`databaseNowMs === null`) is also `ok:false`: an unprovable clock is not a passing clock.
 *
 * @param {object} options
 * @param {object} options.db model surface used for the server-time read
 * @param {() => number} [options.hostNow] the host clock under test; defaults to `Date.now`.
 *   Injected explicitly so a test can prove the guard refuses a skewed writer.
 * @param {number} [options.budgetMs] frozen skew budget (5000 ms)
 * @param {number} [options.cacheMs] reuse window for a verdict; `0` measures every call
 * @param {(level: string, message: string, meta: object) => void} [options.logger]
 */
function createClockSkewGuard(options = {}) {
  const {
    db,
    hostNow = () => Date.now(),
    budgetMs = SKEW_BUDGET_MS,
    cacheMs = DEFAULT_SKEW_CACHE_MS,
    logger = null,
  } = options;

  let cached = null;

  function safeLog(level, message, meta) {
    if (logger === null || typeof logger !== 'object' || typeof logger[level] !== 'function') {
      return;
    }
    try {
      logger[level](message, meta);
    } catch {
      /* a logger failure must never change a lease decision */
    }
  }

  async function check() {
    let host;
    try {
      host = hostNow();
    } catch (err) {
      return {
        ok: false,
        skewMs: null,
        measured: false,
        databaseNowMs: null,
        budgetMs,
        error: new DeviceError(
          'CLOCK_SKEW_EXCEEDED',
          'The host clock could not be read; lease-state writes fail closed',
          { cause: err },
        ),
      };
    }
    if (!Number.isFinite(host)) {
      return {
        ok: false,
        skewMs: null,
        measured: false,
        databaseNowMs: null,
        budgetMs,
        error: new DeviceError(
          'CLOCK_SKEW_EXCEEDED',
          'The host clock is not a finite epoch-millisecond value; lease-state writes fail closed',
        ),
      };
    }
    if (cached !== null && cacheMs > 0 && Math.abs(host - cached.at) < cacheMs) {
      return cached.verdict;
    }

    const databaseNowMs = await readDatabaseNowMs(db);
    let verdict;
    if (databaseNowMs === null) {
      verdict = {
        ok: false,
        skewMs: null,
        measured: false,
        databaseNowMs: null,
        budgetMs,
        error: new DeviceError(
          'CLOCK_SKEW_EXCEEDED',
          'Database time could not be measured; lease-state writes fail closed',
        ),
      };
    } else {
      const skewMs = host - databaseNowMs;
      const ok = Math.abs(skewMs) <= budgetMs;
      verdict = {
        ok,
        skewMs,
        measured: true,
        databaseNowMs,
        budgetMs,
        error: ok
          ? null
          : new DeviceError(
              'CLOCK_SKEW_EXCEEDED',
              `Host clock differs from database time by ${skewMs} ms, outside the ${budgetMs} ms budget; lease-state writes fail closed`,
            ),
      };
    }
    if (verdict.ok !== true) {
      safeLog('error', 'clock skew outside budget; lease-state writes refused', {
        skewMs: verdict.skewMs,
        measured: verdict.measured,
        budgetMs,
      });
    }
    cached = { at: host, verdict };
    return verdict;
  }

  return {
    kind: 'database-time-skew-guard',
    budgetMs,
    check,
    reset: () => {
      cached = null;
    },
  };
}

module.exports = {
  SKEW_BUDGET_MS,
  DEFAULT_SKEW_CACHE_MS,
  TIME_HOST_MODELS,
  PREDICATE_ANCHOR_SEAM,
  DB_NOW_MARKER,
  readDatabaseNowMs,
  assertPredicateAnchorShape,
  resolvePredicateAnchor,
  expiryPredicate,
  readAnchorNowMs,
  createClockSkewGuard,
};
