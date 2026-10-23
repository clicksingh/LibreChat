'use strict';

/**
 * Device surface rate limits — GM-6 ("bound the pairing surface"), W4 pilot hardening.
 *
 * OWNER-AUTHORIZED SCOPE (2026-10-23, LOCAL LAB ONLY; production G0 remains BLOCKED).
 *
 * WHY THIS FILE EXISTS
 * `MAX_CODE_ATTEMPTS` / `MAX_CODE_REGENERATIONS` already bound the pairing *ceremony* inside the
 * accepted services, but nothing bounds the *surface*: an unauthenticated peer can mint challenges,
 * an authenticated one can redeem codes, and an enrolled endpoint can poll completion without any
 * server-side cost limit. GM-6 requires per-principal, per-device and per-source limits on the
 * pairing and device endpoints, with the uniform `INVALID_OR_EXPIRED_CODE` miss preserved so that
 * **a limiter never becomes a code oracle**.
 *
 * THE ORACLE RULE (the load-bearing property of this module)
 * For every surface that can reveal whether a pairing code/session exists (`pairing/challenge`,
 * `pairing/issue`, `pairing/approve`, `pairing/complete`) the denial response is the *same* status,
 * the *same* body bytes and the *same* headers as that surface's own uniform miss, so a caller
 * cannot tell "your code was wrong" from "you are over the limit". That is deliberate: the
 * alternative (a distinguishable 429) lets an attacker separate "throttled because the code
 * exists" from "not throttled because it does not", which is exactly the oracle GM-6 forbids.
 * The miss bodies below are measured from the real handlers, not assumed — see the note above
 * `UNIFORM_MISS_BODIES` and the end-to-end oracle test in `devices.hardening.spec.js`.
 * Non-code surfaces (`current`, `current/renew`, `current/retire`) reveal nothing about code
 * existence and answer an honest 429.
 *
 * CONVENTIONS FOLLOWED FROM `api/server/middleware/limiters/`
 * - `express-rate-limit` v8 with an options object, a `keyGenerator` per principal dimension and a
 *   custom `handler` that owns the response body (see `loginLimiter.js`, `forkLimiters.js`).
 * - A factory (`createDeviceRateLimiters`) plus a module singleton, so the route module imports
 *   one frozen object and tests can build an isolated instance with different windows/limits.
 * - Windows and limits are *data* (`DEVICE_RATE_LIMIT_POLICY`), never literals scattered in code.
 *
 * DELIBERATE DEVIATIONS FROM THAT DIRECTORY (each one is a defect if reverted)
 * 1. **No `@librechat/api` / `limiterCache` import.** That workspace package is unbuilt in this
 *    worktree (`node_modules/@librechat/api/dist/index.cjs` is absent), and this module is on the
 *    `routes/devices.js` import graph, so importing it would break the entire device route suite at
 *    module load. It also pulls in Redis, which the local lab does not run. The in-memory store
 *    below is therefore the primitive, with a bounded map instead of an unbounded one.
 * 2. **No `logViolation`.** `~/cache/logViolation` reaches the same unbuilt package, and it also
 *    persists a violation record per hit — a side channel an attacker can amplify. Denials are
 *    counted in-process instead (`stats()`), with no request data retained.
 * 3. **No rate-limit headers on the uniform-miss surfaces.** `legacyHeaders` defaults to `true` in
 *    express-rate-limit v8, which would put `X-RateLimit-Remaining: 0` on a denial and a non-zero
 *    value on a miss — a header-level oracle. Those surfaces disable both header families so a
 *    denial is byte-identical to a miss. `current*` keeps the defaults.
 *
 * WHAT IS NEVER DONE HERE
 * - No request value is treated as identity or authority. The submitted `devicePublicKey` is only
 *   ever hashed into an opaque bucket label; it is never stored, logged, compared or trusted.
 * - No clock is read for anything but the bucket window; this module never decides lease state.
 * - No denial is written to the database, so a limiter cannot be used to mutate device state.
 */

const crypto = require('node:crypto');
const rateLimit = require('express-rate-limit');

const { ipKeyGenerator } = rateLimit;

/** Bounded accepted length for a submitted endpoint public key (protocol value, never identity). */
const MAX_DEVICE_KEY_CHARS = 4096;

/** Fallback bucket when a request carries no usable source address (never expected in production). */
const UNKNOWN_SOURCE = 'unknown';

/** Label used when a device-keyed limiter is reached with no key: it must still count somewhere. */
const DEVICE_ABSENT_KEY = 'dev:absent';

/** Default bounded-map capacity per limiter; a Map larger than this is an attack, not traffic. */
const DEFAULT_MAX_KEYS = 5000;

/** How many entries a single increment may scan for expiry, so the sweep stays O(1)-ish. */
const SWEEP_BUDGET = 32;

/** The two denial behaviours. Chosen per surface, as data. */
const DENIAL_MODES = Object.freeze({
  /** Byte-identical to the surface's own uniform miss. Required wherever a code could leak. */
  UNIFORM_MISS: 'uniform-miss',
  /** Honest 429. Only for surfaces where no pairing code/session existence can be inferred. */
  THROTTLED: 'throttled',
});

/**
 * The uniform-miss bodies, MEASURED from the accepted handlers rather than assumed. Key order
 * matters: `JSON.stringify` preserves insertion order and the denial must be byte-identical to the
 * genuine miss.
 *
 * Measured on 2026-10-23 by mounting each real handler over stub models and sending an unusable
 * request (see the end-to-end oracle test in `devices.hardening.spec.js`, which re-measures this):
 *
 *   POST /pairing/approve  400 {"ok":false,"code":"INVALID_OR_EXPIRED_CODE",
 *                               "message":"The supplied pairing code or session cannot be used"}
 *   POST /pairing/challenge 400 {…,"message":"The supplied pairing values cannot be used"}
 *   POST /pairing/issue     400 {…,"message":"The supplied pairing values cannot be used"}
 *   POST /pairing/complete  400 {…,"message":"The supplied device values cannot be used"}
 *
 * THE `approve` VARIANT IS NOT THE HANDLER'S OWN `uniformMiss()` CONSTANT, and that distinction is
 * load-bearing. `pairingHttpHandler.uniformMiss()` reads "The supplied pairing values cannot be
 * used", but on the approve path it is only a rare fallback: the normal miss is the service's
 * `DeviceError('INVALID_OR_EXPIRED_CODE', …)` surfaced through `sendClassifiedError`, whose message
 * is "The supplied pairing code or session cannot be used". Emitting the fallback text on a
 * throttle would make throttled and wrong-code responses differ by one string — a code oracle in
 * the weak form GM-6 forbids. `approve` therefore mirrors the SERVICE miss, the shape a caller
 * actually gets for a wrong code.
 */
const UNIFORM_MISS_BODIES = Object.freeze({
  challenge: Object.freeze({
    ok: false,
    code: 'INVALID_OR_EXPIRED_CODE',
    message: 'The supplied pairing values cannot be used',
  }),
  issue: Object.freeze({
    ok: false,
    code: 'INVALID_OR_EXPIRED_CODE',
    message: 'The supplied pairing values cannot be used',
  }),
  approve: Object.freeze({
    ok: false,
    code: 'INVALID_OR_EXPIRED_CODE',
    message: 'The supplied pairing code or session cannot be used',
  }),
  complete: Object.freeze({
    ok: false,
    code: 'INVALID_OR_EXPIRED_CODE',
    message: 'The supplied device values cannot be used',
  }),
});

/** The canonical status of `INVALID_OR_EXPIRED_CODE` in `services/Device/errors.js`. */
const UNIFORM_MISS_STATUS = 400;

/** Honest throttled body for the non-code surfaces. Carries no device or code information. */
const THROTTLED_BODY = Object.freeze({
  ok: false,
  code: 'RATE_LIMITED',
  message: 'Too many requests. Try again later',
});
const THROTTLED_STATUS = 429;

/** The dimensions a limiter can key on. Every one is a bucket label, never an authority claim. */
const KEY_DIMENSIONS = Object.freeze(['source', 'principal', 'device']);

/**
 * PILOT DEFAULTS — windows and limits as data.
 *
 * Rationale for each number, so a reviewer can argue with it instead of guessing:
 * - `pairingChallenge` 12/min per source and per principal: an endpoint pairs once; a human retries
 *   at most a handful of times. 12 is generous for a real employee and useless for a spray.
 * - `pairingIssue` 6/min: issuance is the expensive leg (challenge spend + code mint + HMAC tag).
 *   In-service regeneration is already capped at three; this caps the whole path.
 * - `pairingApprove` 10/min per principal and per source: a 6-digit code is 10^6 values, and
 *   `MAX_CODE_ATTEMPTS` kills the session long before a 10/min ceiling could be walked; the limiter
 *   exists so the *server* bounds it rather than trusting the client's retry discipline.
 * - `pairingComplete` 30/min per source and per device: this is the device poll loop (the endpoint
 *   polls until the browser approves), so it must be comfortable — every two seconds is well above
 *   the intended cadence and still bounds a hot loop.
 * - `currentStatus` 120/min per principal: the panel's lease countdown polls; one per second with
 *   headroom.
 * - `currentRenew` 12/min per principal and per device: renewal is a once-per-48h ceremony with one
 *   local click; 12 covers a retry burst and stops a signing loop.
 * - `currentRetire` 6/min per principal: a destructive, deliberate action.
 *
 * Every window is 60 s: short enough that a false positive clears in a minute during a pilot, long
 * enough that the ceiling is meaningful.
 */
const DEVICE_RATE_LIMIT_POLICY = deepFreeze({
  pairingChallenge: {
    label: 'POST /api/devices/pairing/challenge',
    windowMs: 60 * 1000,
    denial: DENIAL_MODES.UNIFORM_MISS,
    miss: 'challenge',
    limits: { source: 12, principal: 12 },
  },
  pairingIssue: {
    label: 'POST /api/devices/pairing/issue',
    windowMs: 60 * 1000,
    denial: DENIAL_MODES.UNIFORM_MISS,
    miss: 'issue',
    limits: { source: 6, principal: 6, device: 6 },
  },
  pairingApprove: {
    label: 'POST /api/devices/pairing/approve',
    windowMs: 60 * 1000,
    denial: DENIAL_MODES.UNIFORM_MISS,
    miss: 'approve',
    limits: { source: 10, principal: 10 },
  },
  pairingComplete: {
    label: 'POST /api/devices/pairing/complete',
    windowMs: 60 * 1000,
    denial: DENIAL_MODES.UNIFORM_MISS,
    miss: 'complete',
    limits: { source: 30, device: 30 },
  },
  currentStatus: {
    label: 'GET /api/devices/current',
    windowMs: 60 * 1000,
    denial: DENIAL_MODES.THROTTLED,
    limits: { principal: 120 },
  },
  currentRenew: {
    label: 'POST /api/devices/current/renew',
    windowMs: 60 * 1000,
    denial: DENIAL_MODES.THROTTLED,
    limits: { principal: 12, device: 12 },
  },
  currentRetire: {
    label: 'POST /api/devices/current/retire',
    windowMs: 60 * 1000,
    denial: DENIAL_MODES.THROTTLED,
    limits: { principal: 6 },
  },
});

/** Frozen surface names, in policy order. */
const DEVICE_RATE_LIMIT_SURFACES = Object.freeze(Object.keys(DEVICE_RATE_LIMIT_POLICY));

/** Deep-freezes a plain data object so a route module can never mutate the policy at runtime. */
function deepFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) {
    return value;
  }
  for (const key of Object.keys(value)) {
    deepFreeze(value[key]);
  }
  return Object.freeze(value);
}

/**
 * Bounded in-memory store implementing the express-rate-limit v8 Store contract.
 *
 * Why not the library's `MemoryStore`: it keeps one unbounded `Map` and only clears it wholesale on
 * a global timer. A pairing surface is exposed to unauthenticated peers, so an attacker who varies
 * the bucket label (source addresses, key material) would grow the map without limit — a slow
 * memory exhaustion. This store:
 * - caps the map at `maxKeys` and evicts the least-recently-touched bucket first (LRU by Map order);
 * - reuses an expired bucket in place instead of allocating a new one;
 * - sweeps a bounded number of expired buckets per call, so no timer is needed;
 * - exposes `size`/`evictions` so the bound is observable in a test rather than asserted.
 *
 * `now` is injectable so a spec can prove window behaviour deterministically without sleeping.
 */
class BoundedMemoryStore {
  constructor({ windowMs, maxKeys = DEFAULT_MAX_KEYS, now = () => Date.now() } = {}) {
    if (!Number.isInteger(windowMs) || windowMs < 1) {
      throw new TypeError('BoundedMemoryStore requires a positive integer windowMs');
    }
    if (!Number.isInteger(maxKeys) || maxKeys < 1) {
      throw new TypeError('BoundedMemoryStore requires a positive integer maxKeys');
    }
    if (typeof now !== 'function') {
      throw new TypeError('BoundedMemoryStore requires a now() clock seam');
    }
    this.windowMs = windowMs;
    this.maxKeys = maxKeys;
    this.now = now;
    /**
     * express-rate-limit reads `localKeys` to decide key prefixing and to exempt an instance-scoped
     * store from the shared-store reuse validation. Buckets are per-process, so this is true.
     */
    this.localKeys = true;
    this.entries = new Map();
    this.evictions = 0;
    this.expiredSweeps = 0;
  }

  /** express-rate-limit calls this once with the resolved options. */
  init(options) {
    if (options && Number.isInteger(options.windowMs) && options.windowMs > 0) {
      this.windowMs = options.windowMs;
    }
  }

  get size() {
    return this.entries.size;
  }

  /** Drops a bounded number of expired buckets. No early exit: Map order is LRU, not expiry order. */
  _sweepExpired(now) {
    let scanned = 0;
    for (const [key, entry] of this.entries) {
      if (scanned >= SWEEP_BUDGET) {
        return;
      }
      scanned += 1;
      if (entry.resetTime <= now) {
        this.entries.delete(key);
        this.expiredSweeps += 1;
      }
    }
  }

  _evictLeastRecentlyTouched() {
    const oldest = this.entries.keys().next();
    if (!oldest.done) {
      this.entries.delete(oldest.value);
      this.evictions += 1;
    }
  }

  increment(key) {
    const now = this.now();
    this._sweepExpired(now);

    let entry = this.entries.get(key);
    if (entry === undefined) {
      if (this.entries.size >= this.maxKeys) {
        this._evictLeastRecentlyTouched();
      }
      entry = { totalHits: 0, resetTime: now + this.windowMs };
    } else {
      // Re-inserting moves the bucket to the MRU end of the Map (LRU eviction relies on this).
      this.entries.delete(key);
      if (entry.resetTime <= now) {
        entry.totalHits = 0;
        entry.resetTime = now + this.windowMs;
      }
    }

    entry.totalHits += 1;
    this.entries.set(key, entry);
    return { totalHits: entry.totalHits, resetTime: new Date(entry.resetTime) };
  }

  decrement(key) {
    const entry = this.entries.get(key);
    if (entry !== undefined && entry.totalHits > 0) {
      entry.totalHits -= 1;
    }
  }

  resetKey(key) {
    this.entries.delete(key);
  }

  resetAll() {
    this.entries.clear();
    this.evictions = 0;
    this.expiredSweeps = 0;
  }
}

/** True when the request carries an authenticated principal id (set by `requireJwtAuth`). */
function hasPrincipal(req) {
  return typeof req?.user?.id === 'string' && req.user.id.length > 0;
}

/**
 * True when the request carries a plausible endpoint public key. This is a *shape* check only: the
 * value is never validated, trusted or treated as identity — it is hashed into a bucket label.
 */
function hasDeviceKey(req) {
  const value = req?.body?.devicePublicKey;
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_DEVICE_KEY_CHARS;
}

/** Stable, opaque bucket label for a submitted public key. The raw key is never retained. */
function deviceBucket(key) {
  return `dev:${crypto.createHash('sha256').update(key, 'utf8').digest('base64url').slice(0, 22)}`;
}

/**
 * Per-source bucket. `ipKeyGenerator` is the v8-blessed helper: it normalises IPv6 to its /56
 * subnet so a caller cannot rotate through addresses inside one allocation to evade the limit.
 */
function sourceKeyGenerator(req) {
  const ip = typeof req.ip === 'string' && req.ip.length > 0 ? req.ip : UNKNOWN_SOURCE;
  return `src:${ipKeyGenerator(ip)}`;
}

/** Per-principal bucket. Only reachable after `requireJwtAuth`, so `req.user.id` is server-set. */
function principalKeyGenerator(req) {
  return `usr:${req.user.id}`;
}

/** Per-device bucket: a hash of the protocol value, never the value itself. */
function deviceKeyGenerator(req) {
  return hasDeviceKey(req) ? deviceBucket(req.body.devicePublicKey) : DEVICE_ABSENT_KEY;
}

/** Dimensions that cannot be keyed are skipped entirely rather than collapsed into one bucket. */
const KEY_GENERATORS = Object.freeze({
  source: { keyGenerator: sourceKeyGenerator, skip: () => false },
  principal: { keyGenerator: principalKeyGenerator, skip: (req) => !hasPrincipal(req) },
  device: { keyGenerator: deviceKeyGenerator, skip: (req) => !hasDeviceKey(req) },
});

/** Builds the responder for one surface, per its configured denial mode. */
function createDenialResponder(config) {
  if (config.denial === DENIAL_MODES.UNIFORM_MISS) {
    const body = UNIFORM_MISS_BODIES[config.miss];
    if (body === undefined) {
      throw new TypeError(`Unknown uniform-miss body "${config.miss}" for ${config.label}`);
    }
    return (_req, res) => res.status(UNIFORM_MISS_STATUS).json({ ...body });
  }
  return (_req, res) => res.status(THROTTLED_STATUS).json({ ...THROTTLED_BODY });
}

/** Validates one surface's data. Fails at construction, never mid-request. */
function assertSurfaceConfig(name, config) {
  if (config === null || typeof config !== 'object') {
    throw new TypeError(`Device rate limit surface "${name}" must be an object`);
  }
  if (!Number.isInteger(config.windowMs) || config.windowMs < 1) {
    throw new TypeError(`Device rate limit surface "${name}" needs a positive integer windowMs`);
  }
  if (config.denial !== DENIAL_MODES.UNIFORM_MISS && config.denial !== DENIAL_MODES.THROTTLED) {
    throw new TypeError(`Device rate limit surface "${name}" has an unknown denial mode`);
  }
  if (config.denial === DENIAL_MODES.UNIFORM_MISS && UNIFORM_MISS_BODIES[config.miss] === undefined) {
    throw new TypeError(`Device rate limit surface "${name}" needs a known uniform-miss body`);
  }
  const dimensions = Object.keys(config.limits ?? {});
  if (dimensions.length === 0) {
    throw new TypeError(`Device rate limit surface "${name}" declares no limits`);
  }
  for (const dimension of dimensions) {
    if (!KEY_DIMENSIONS.includes(dimension)) {
      throw new TypeError(`Device rate limit surface "${name}" has unknown dimension "${dimension}"`);
    }
    const limit = config.limits[dimension];
    if (!Number.isInteger(limit) || limit < 1) {
      throw new TypeError(`Device rate limit surface "${name}" needs a positive "${dimension}" limit`);
    }
  }
}

/** Merges `{ surface: { windowMs?, limits? } }` overrides over the frozen pilot defaults. */
function resolvePolicy(overrides) {
  if (overrides === undefined || overrides === null) {
    return DEVICE_RATE_LIMIT_POLICY;
  }
  if (typeof overrides !== 'object') {
    throw new TypeError('Device rate limit overrides must be an object');
  }
  const merged = {};
  for (const [name, config] of Object.entries(DEVICE_RATE_LIMIT_POLICY)) {
    merged[name] = config;
  }
  for (const [name, override] of Object.entries(overrides)) {
    if (DEVICE_RATE_LIMIT_POLICY[name] === undefined) {
      throw new TypeError(`Unknown device rate limit surface "${name}" in overrides`);
    }
    merged[name] = {
      ...DEVICE_RATE_LIMIT_POLICY[name],
      ...override,
      limits: {
        ...DEVICE_RATE_LIMIT_POLICY[name].limits,
        ...(override?.limits ?? {}),
      },
    };
  }
  return merged;
}

/**
 * Builds one limiter set. Returns a frozen object of `{ surface: { dimension: middleware } }`
 * plus `reset()` and `stats()` bound to the instance's own stores.
 *
 * @param {object} [options]
 * @param {object} [options.overrides] per-surface `{ windowMs?, limits? }` overrides (tests).
 * @param {number} [options.maxKeys] bounded-map capacity for every store in this instance.
 * @param {() => number} [options.now] clock seam for the stores (tests).
 * @returns {object} limiter set
 */
function createDeviceRateLimiters(options = {}) {
  const { overrides, maxKeys = DEFAULT_MAX_KEYS, now } = options;
  const policy = resolvePolicy(overrides);

  const limiters = {};
  const stores = [];
  const counters = {};

  for (const surface of Object.keys(policy)) {
    const config = policy[surface];
    assertSurfaceConfig(surface, config);
    counters[surface] = { denied: 0, byDimension: { source: 0, principal: 0, device: 0 } };
    const responder = createDenialResponder(config);
    const perDimension = {};

    for (const dimension of Object.keys(config.limits)) {
      const { keyGenerator, skip } = KEY_GENERATORS[dimension];
      const store = new BoundedMemoryStore({
        windowMs: config.windowMs,
        maxKeys,
        ...(now === undefined ? {} : { now }),
      });
      stores.push(store);

      perDimension[dimension] = rateLimit({
        windowMs: config.windowMs,
        limit: config.limits[dimension],
        keyGenerator,
        skip,
        store,
        /**
         * Both header families are off so a denial cannot be told apart from a miss by a
         * `X-RateLimit-Remaining: 0` tell. Observability comes from `stats()` instead.
         */
        standardHeaders: false,
        legacyHeaders: false,
        handler: (_req, res) => {
          counters[surface].denied += 1;
          counters[surface].byDimension[dimension] += 1;
          return responder(_req, res);
        },
      });
    }

    limiters[surface] = Object.freeze(perDimension);
  }

  Object.defineProperty(limiters, 'reset', {
    value: () => {
      for (const store of stores) {
        store.resetAll();
      }
      for (const surface of Object.keys(counters)) {
        counters[surface].denied = 0;
        for (const dimension of KEY_DIMENSIONS) {
          counters[surface].byDimension[dimension] = 0;
        }
      }
    },
    enumerable: false,
  });

  Object.defineProperty(limiters, 'stats', {
    value: () => {
      const snapshot = {};
      for (const [surface, counter] of Object.entries(counters)) {
        snapshot[surface] = {
          denied: counter.denied,
          byDimension: { ...counter.byDimension },
        };
      }
      return snapshot;
    },
    enumerable: false,
  });

  Object.defineProperty(limiters, 'storeSizes', {
    value: () => stores.map((store) => ({ size: store.size, evictions: store.evictions })),
    enumerable: false,
  });

  return Object.freeze(limiters);
}

/** The module singleton the device router wires in. */
const deviceRateLimiters = createDeviceRateLimiters();

/** Clears every bucket and counter of the singleton. Used by the hardening spec only. */
function resetDeviceRateLimits() {
  deviceRateLimiters.reset();
}

/** Denial counters of the singleton, per surface and per dimension. */
function getDeviceRateLimitStats() {
  return deviceRateLimiters.stats();
}

module.exports = {
  DEVICE_RATE_LIMIT_POLICY,
  DEVICE_RATE_LIMIT_SURFACES,
  DENIAL_MODES,
  KEY_DIMENSIONS,
  UNIFORM_MISS_BODIES,
  UNIFORM_MISS_STATUS,
  THROTTLED_BODY,
  THROTTLED_STATUS,
  BoundedMemoryStore,
  createDeviceRateLimiters,
  deviceRateLimiters,
  resetDeviceRateLimits,
  getDeviceRateLimitStats,
};
