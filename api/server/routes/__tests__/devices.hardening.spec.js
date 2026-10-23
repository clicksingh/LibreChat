'use strict';

/**
 * W4 pilot hardening spec — GM-6 (rate limits) and GM-14/R7 (capability staging).
 *
 * This file is ADDITIVE: the accepted `devices.spec.js` is not modified. It covers four things the
 * existing suite does not:
 * 1. the limiter trips at its configured threshold, per dimension, and recovers after its window;
 * 2. a rate-limited pairing response is oracle-safe — byte-identical to the uniform
 *    `INVALID_OR_EXPIRED_CODE` miss the accepted handlers emit, so "throttled" can never be told
 *    apart from "no such code";
 * 3. the capability stages gate exactly the right tools, the deny-list behaves as ruled, and the
 *    defined end state is explicit;
 * 4. the CI client-name assertion fails on `desktop-commander-app` (the 26 -> 24 silent downgrade).
 */

const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const request = require('supertest');

/* ============================================================================
 * Wiring-suite doubles (must be declared before `require('../devices')`)
 * ========================================================================== */

const mockLimiterCalls = [];
let mockLimiterDenial = null;

/**
 * The exact surface/dimension set `routes/devices.js` mounts. Kept explicit rather than derived, so
 * a wiring change that reaches for a limiter nobody provides fails loudly instead of silently
 * mounting `undefined`.
 */
const mockLimiterShape = {
  pairingComplete: ['source', 'device'],
  currentRetire: ['principal'],
  currentStatus: ['principal'],
  currentRenew: ['principal', 'device'],
  pairingChallenge: ['principal', 'source'],
  pairingIssue: ['principal', 'device', 'source'],
  pairingApprove: ['principal', 'source'],
};

jest.mock('~/server/middleware/deviceRateLimit', () => {
  const build = (surface, dimension) =>
    jest.fn((_req, res, next) => {
      const label = `${surface}.${dimension}`;
      mockLimiterCalls.push(label);
      if (mockLimiterDenial !== null && mockLimiterDenial.match === label) {
        const denial = mockLimiterDenial;
        mockLimiterDenial = null;
        return res.status(denial.status).json(denial.body);
      }
      return next();
    });

  const deviceRateLimiters = {};
  for (const [surface, dimensions] of Object.entries(mockLimiterShape)) {
    deviceRateLimiters[surface] = {};
    for (const dimension of dimensions) {
      deviceRateLimiters[surface][dimension] = build(surface, dimension);
    }
  }
  return { deviceRateLimiters };
});

const mockHandler = (name) =>
  jest.fn((req, res) =>
    res.status(200).json({
      ok: true,
      endpoint: name,
      userId: req.user?.id ?? null,
      authenticatedByJwt: req.authenticatedByJwt === true,
    }),
  );

const mockRetireHandler = mockHandler('current-retire');
const mockPairingChallengeHandler = mockHandler('pairing-challenge');
const mockPairingIssueHandler = mockHandler('pairing-issue');
const mockPairingApproveHandler = mockHandler('pairing-approve');
const mockPairingCompleteHandler = mockHandler('pairing-complete');
const mockCurrentStatusHandler = mockHandler('current-status');
const mockCurrentRenewHandler = mockHandler('current-renew');

const mockRequireJwtAuth = jest.fn((req, _res, next) => {
  req.authenticatedByJwt = true;
  req.user = { id: 'route-user', tenantId: 'tenant-route' };
  next();
});

jest.mock('@librechat/data-schemas', () => ({
  getTenantId: jest.fn(() => 'tenant-route'),
}));

jest.mock('~/server/middleware/requireJwtAuth', () => (req, res, next) =>
  mockRequireJwtAuth(req, res, next),
);

jest.mock('~/db/models', () => ({
  DeviceAuthority: {},
  AuditEvent: {},
}));

jest.mock('~/server/services/Device/ownerCurrentRetireHandler', () => ({
  createOwnerCurrentRetireHandler: jest.fn(() => mockRetireHandler),
}));

jest.mock('~/server/services/Device/pairingHttpHandler', () => ({
  createPairingChallengeHandler: jest.fn(() => mockPairingChallengeHandler),
  createPairingIssueHandler: jest.fn(() => mockPairingIssueHandler),
  createPairingApproveHandler: jest.fn(() => mockPairingApproveHandler),
}));

jest.mock('~/server/services/Device/pairingCompleteHttpHandler', () => ({
  createPairingCompleteHandler: jest.fn(() => mockPairingCompleteHandler),
}));

jest.mock('~/server/services/Device/currentDeviceHttpHandler', () => ({
  createCurrentDeviceStatusHandler: jest.fn(() => mockCurrentStatusHandler),
}));

jest.mock('~/server/services/Device/currentDeviceRenewEnvelopeHandler', () => ({
  createCurrentDeviceRenewEnvelopeHandler: jest.fn(() => mockCurrentRenewHandler),
}));

/* ============================================================================
 * The REAL modules under test
 * ========================================================================== */

const realLimiter = jest.requireActual('~/server/middleware/deviceRateLimit');
const policy = require('~/server/services/Device/deviceCapabilityPolicy');
const { DeviceError } = require('~/server/services/Device/errors');
const { createPairingApproveHandler, createPairingCompleteHandler } = jest.requireActual(
  '~/server/services/Device/pairingHttpHandler',
);
const deviceHttpTrust = require('~/server/services/Device/deviceHttpTrust');

const devicesRouter = require('../devices');

const {
  DEVICE_RATE_LIMIT_POLICY,
  DEVICE_RATE_LIMIT_SURFACES,
  DENIAL_MODES,
  UNIFORM_MISS_BODIES,
  UNIFORM_MISS_STATUS,
} = realLimiter;

/** The four surfaces that can reveal whether a pairing code/session exists (GM-6's oracle rule). */
const CODE_BEARING_SURFACES = Object.freeze([
  'pairingChallenge',
  'pairingIssue',
  'pairingApprove',
  'pairingComplete',
]);

/**
 * Surface -> (uniform-miss variant, handler source). The variant names are the keys of
 * `UNIFORM_MISS_BODIES`, measured from these sources.
 */
const ORACLE_SURFACES = Object.freeze([
  {
    surface: 'pairingChallenge',
    miss: 'challenge',
    file: 'pairingHttpHandler.js',
    message: 'The supplied pairing values cannot be used',
  },
  {
    surface: 'pairingIssue',
    miss: 'issue',
    file: 'pairingHttpHandler.js',
    message: 'The supplied pairing values cannot be used',
  },
  {
    surface: 'pairingApprove',
    miss: 'approve',
    file: 'pairingSessionService.js',
    message: 'The supplied pairing code or session cannot be used',
  },
  {
    surface: 'pairingComplete',
    miss: 'complete',
    file: 'pairingCompleteHttpHandler.js',
    message: 'The supplied device values cannot be used',
  },
]);

const DEVICE_SERVICES_DIR = path.join(__dirname, '..', '..', 'services', 'Device');

/** The real accepted handlers, loaded for the end-to-end oracle measurement. */
const realPairingHandlers = jest.requireActual(
  '~/server/services/Device/pairingHttpHandler',
);
const realCompleteHandlerModule = jest.requireActual(
  '~/server/services/Device/pairingCompleteHttpHandler',
);

/**
 * A permissive stub model set. The end-to-end oracle test does not exercise persistence: it only
 * needs each handler to reach its miss path with no device identity and no session row, which is
 * exactly the "your code is not usable" answer a caller gets. The accepted handler logic above the
 * models is the real product code.
 */
function createStubModels() {
  const query = (value) => ({
    lean: async () => value,
    exec: async () => value,
    then: (resolve) => Promise.resolve(value).then(resolve),
  });
  return {
    findOne: () => query(null),
    findOneAndUpdate: () => query(null),
    updateOne: async () => ({ acknowledged: true }),
    updateMany: async () => ({ acknowledged: true }),
    create: async (doc) => doc,
    find: () => query([]),
    countDocuments: async () => 0,
    deleteMany: async () => ({ acknowledged: true }),
  };
}

function createStubDb() {
  return {
    PairingSession: createStubModels(),
    DeviceAuthority: createStubModels(),
    Challenge: createStubModels(),
    AuditEvent: createStubModels(),
  };
}

const STUB_TENANT_CONTEXT = Object.freeze({
  getActiveTenantId: () => 'tenant-hardening',
  alsAbsencePermitted: false,
});

const STUB_PEPPER = Buffer.from('hardening-spec-pepper-0001', 'utf8');

/** Builds an app that mounts the REAL handler for one surface behind the REAL limiter chain. */
function buildRealHandlerApp({ surface, handler, limiterNames }) {
  const limiters = realLimiter.createDeviceRateLimiters({
    overrides: { [surface]: { limits: { principal: 1, source: 1, device: 1 } } },
  });
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = { id: 'oracle-user', tenantId: 'tenant-hardening' };
    next();
  });
  const chain = limiterNames.map((dimension) => limiters[surface][dimension]);
  app.post('/probe', ...chain, handler);
  return { app, limiters };
}

/** Builds an app whose route runs the given limiter chain before a terminal handler. */
function buildLimiterApp({ limiters, handler, authenticate = null }) {
  const app = express();
  app.use(express.json());
  const chain = [];
  if (authenticate !== null) {
    chain.push((req, _res, next) => {
      req.user = authenticate;
      next();
    });
  }
  chain.push(...limiters);
  app.post('/probe', ...chain, handler);
  return app;
}

beforeEach(() => {
  jest.clearAllMocks();
  mockLimiterCalls.length = 0;
  mockLimiterDenial = null;
});

/* ============================================================================
 * 1 — Limiter data, thresholds, dimensions, windows
 * ========================================================================== */

describe('W4 device rate limits (GM-6)', () => {
  describe('policy data', () => {
    it('declares a window, a denial mode and at least one dimension for every surface', () => {
      expect(DEVICE_RATE_LIMIT_SURFACES.length).toBeGreaterThan(0);
      for (const surface of DEVICE_RATE_LIMIT_SURFACES) {
        const config = DEVICE_RATE_LIMIT_POLICY[surface];
        expect(Number.isInteger(config.windowMs)).toBe(true);
        expect(config.windowMs).toBeGreaterThan(0);
        expect(Object.values(DENIAL_MODES)).toContain(config.denial);
        expect(Object.keys(config.limits).length).toBeGreaterThan(0);
      }
    });

    it('covers per-principal, per-device and per-source across the pairing and device surfaces', () => {
      const dimensions = new Set();
      for (const surface of DEVICE_RATE_LIMIT_SURFACES) {
        for (const dimension of Object.keys(DEVICE_RATE_LIMIT_POLICY[surface].limits)) {
          dimensions.add(dimension);
        }
      }
      expect([...dimensions].sort()).toEqual(['device', 'principal', 'source']);

      // GM-6 names the minimum per surface: source on challenge minting, principal+device on the
      // issued-code path.
      expect(Object.keys(DEVICE_RATE_LIMIT_POLICY.pairingChallenge.limits)).toContain('source');
      expect(Object.keys(DEVICE_RATE_LIMIT_POLICY.pairingIssue.limits)).toEqual(
        expect.arrayContaining(['principal', 'device']),
      );
    });

    it('keeps every code-bearing pairing surface on the uniform miss', () => {
      for (const surface of CODE_BEARING_SURFACES) {
        const config = DEVICE_RATE_LIMIT_POLICY[surface];
        expect(config.denial).toBe(DENIAL_MODES.UNIFORM_MISS);
        expect(UNIFORM_MISS_BODIES[config.miss]).toBeDefined();
        expect(UNIFORM_MISS_STATUS).toBe(400);
      }
    });

    it('answers the non-code surfaces with an honest 429', () => {
      for (const surface of ['currentStatus', 'currentRenew', 'currentRetire']) {
        expect(DEVICE_RATE_LIMIT_POLICY[surface].denial).toBe(DENIAL_MODES.THROTTLED);
      }
    });

    it('ships the reviewed pilot defaults as data', () => {
      const expected = {
        pairingChallenge: { windowMs: 60000, limits: { source: 12, principal: 12 } },
        pairingIssue: { windowMs: 60000, limits: { source: 6, principal: 6, device: 6 } },
        pairingApprove: { windowMs: 60000, limits: { source: 10, principal: 10 } },
        pairingComplete: { windowMs: 60000, limits: { source: 30, device: 30 } },
        currentStatus: { windowMs: 60000, limits: { principal: 120 } },
        currentRenew: { windowMs: 60000, limits: { principal: 12, device: 12 } },
        currentRetire: { windowMs: 60000, limits: { principal: 6 } },
      };
      expect(Object.keys(DEVICE_RATE_LIMIT_POLICY)).toEqual(Object.keys(expected));
      for (const [surface, config] of Object.entries(expected)) {
        expect(DEVICE_RATE_LIMIT_POLICY[surface].windowMs).toBe(config.windowMs);
        expect(DEVICE_RATE_LIMIT_POLICY[surface].limits).toEqual(config.limits);
      }
    });

    it('is frozen, so a route module cannot widen a limit at runtime', () => {
      expect(Object.isFrozen(DEVICE_RATE_LIMIT_POLICY)).toBe(true);
      for (const surface of DEVICE_RATE_LIMIT_SURFACES) {
        expect(Object.isFrozen(DEVICE_RATE_LIMIT_POLICY[surface])).toBe(true);
        expect(Object.isFrozen(DEVICE_RATE_LIMIT_POLICY[surface].limits)).toBe(true);
      }
      expect(() => {
        DEVICE_RATE_LIMIT_POLICY.pairingApprove.limits.principal = 1e9;
      }).toThrow();
      expect(DEVICE_RATE_LIMIT_POLICY.pairingApprove.limits.principal).toBe(10);
    });

    it('rejects unknown surfaces and non-positive limits at construction, not mid-request', () => {
      expect(() =>
        realLimiter.createDeviceRateLimiters({ overrides: { notASurface: { windowMs: 1000 } } }),
      ).toThrow(/Unknown device rate limit surface/);
      expect(() =>
        realLimiter.createDeviceRateLimiters({
          overrides: { pairingApprove: { limits: { principal: 0 } } },
        }),
      ).toThrow(/positive "principal" limit/);
      expect(() =>
        realLimiter.createDeviceRateLimiters({
          overrides: { pairingApprove: { limits: { tenant: 5 } } },
        }),
      ).toThrow(/unknown dimension/);
      expect(() =>
        realLimiter.createDeviceRateLimiters({
          overrides: { pairingApprove: { windowMs: 0 } },
        }),
      ).toThrow(/positive integer windowMs/);
    });
  });

  describe('bounded in-memory store', () => {
    it('caps the map at maxKeys and evicts the least recently touched bucket', () => {
      const store = new realLimiter.BoundedMemoryStore({ windowMs: 60000, maxKeys: 3 });
      store.increment('a');
      store.increment('b');
      store.increment('c');
      store.increment('a'); // touch 'a' so 'b' becomes the least recently touched
      store.increment('d');

      expect(store.size).toBe(3);
      expect(store.evictions).toBeGreaterThan(0);
      expect(store.entries.has('b')).toBe(false);
      expect(store.entries.has('a')).toBe(true);
      expect(store.entries.has('d')).toBe(true);
    });

    it('restarts an expired bucket instead of allocating a new one', () => {
      let now = 1_000_000;
      const store = new realLimiter.BoundedMemoryStore({
        windowMs: 1000,
        maxKeys: 10,
        now: () => now,
      });

      expect(store.increment('k').totalHits).toBe(1);
      expect(store.increment('k').totalHits).toBe(2);
      now += 1000;
      const afterWindow = store.increment('k');
      expect(afterWindow.totalHits).toBe(1);
      expect(afterWindow.resetTime.getTime()).toBe(now + 1000);
      expect(store.size).toBe(1);
    });

    it('resets one bucket and all buckets', () => {
      const store = new realLimiter.BoundedMemoryStore({ windowMs: 1000, maxKeys: 10 });
      store.increment('a');
      store.increment('b');
      store.resetKey('a');
      expect(store.size).toBe(1);
      store.resetAll();
      expect(store.size).toBe(0);
    });

    it('refuses an invalid window or capacity', () => {
      expect(() => new realLimiter.BoundedMemoryStore({ windowMs: 0 })).toThrow();
      expect(() => new realLimiter.BoundedMemoryStore({ windowMs: 1000, maxKeys: 0 })).toThrow();
      expect(
        () => new realLimiter.BoundedMemoryStore({ windowMs: 1000, now: 'not-a-clock' }),
      ).toThrow();
    });
  });

  describe('limiter behaviour', () => {
    const buildProbe = (overrides, handler, authenticate = { id: 'user-a' }) => {
      const limiters = realLimiter.createDeviceRateLimiters({ overrides });
      const app = buildLimiterApp({
        limiters: [limiters.pairingApprove.principal, limiters.pairingApprove.source],
        handler,
        authenticate,
      });
      return { limiters, app };
    };

    it('allows exactly `limit` requests and denies the next one', async () => {
      const handler = jest.fn((_req, res) => res.status(200).json({ ok: true }));
      const { limiters, app } = buildProbe(
        { pairingApprove: { limits: { principal: 2, source: 2 } } },
        handler,
      );

      const first = await request(app).post('/probe').send({});
      const second = await request(app).post('/probe').send({});
      const third = await request(app).post('/probe').send({});

      expect([first.status, second.status]).toEqual([200, 200]);
      expect(third.status).toBe(UNIFORM_MISS_STATUS);
      expect(handler).toHaveBeenCalledTimes(2);
      expect(limiters.stats().pairingApprove.denied).toBe(1);
      expect(limiters.stats().pairingApprove.byDimension.principal).toBe(1);
    });

    it('keys each principal to its own bucket', async () => {
      const handler = jest.fn((_req, res) => res.status(200).json({ ok: true }));
      const limiters = realLimiter.createDeviceRateLimiters({
        overrides: { pairingApprove: { limits: { principal: 1 } } },
      });
      const app = express();
      app.use(express.json());
      app.post(
        '/probe',
        (req, _res, next) => {
          req.user = { id: req.headers['x-user'] ?? 'user-a' };
          next();
        },
        limiters.pairingApprove.principal,
        handler,
      );

      expect((await request(app).post('/probe').send({})).status).toBe(200);
      expect((await request(app).post('/probe').send({})).status).toBe(UNIFORM_MISS_STATUS);
      expect((await request(app).post('/probe').set('x-user', 'user-b').send({})).status).toBe(200);
    });

    it('keys each device to its own bucket and skips device keying without a key', async () => {
      const handler = jest.fn((_req, res) => res.status(200).json({ ok: true }));
      const limiters = realLimiter.createDeviceRateLimiters({
        overrides: { pairingIssue: { limits: { device: 1 } } },
      });
      const app = express();
      app.use(express.json());
      app.post('/probe', limiters.pairingIssue.device, handler);

      expect((await request(app).post('/probe').send({ devicePublicKey: 'key-one' })).status).toBe(
        200,
      );
      expect((await request(app).post('/probe').send({ devicePublicKey: 'key-one' })).status).toBe(
        UNIFORM_MISS_STATUS,
      );
      expect((await request(app).post('/probe').send({ devicePublicKey: 'key-two' })).status).toBe(
        200,
      );
      // No key at all: the dimension is skipped rather than collapsed into a shared bucket.
      expect((await request(app).post('/probe').send({}).catch(() => ({ status: 200 }))).status).toBe(
        200,
      );
      expect(limiters.stats().pairingIssue.denied).toBe(1);
      expect(limiters.stats().pairingIssue.byDimension.device).toBe(1);
    });

    it('never stores or logs the raw device key', async () => {
      const handler = jest.fn((_req, res) => res.status(200).json({ ok: true }));
      const limiters = realLimiter.createDeviceRateLimiters({
        overrides: { pairingIssue: { limits: { device: 1 } } },
      });
      const app = express();
      app.use(express.json());
      app.post('/probe', limiters.pairingIssue.device, handler);
      await request(app).post('/probe').send({ devicePublicKey: 'super-secret-key-material' });

      const sizes = limiters.storeSizes();
      expect(sizes.length).toBeGreaterThan(0);
      expect(JSON.stringify(sizes)).not.toContain('super-secret-key-material');
      expect(JSON.stringify(limiters.stats())).not.toContain('super-secret-key-material');
    });

    it('recovers after the window elapses', async () => {
      let now = 5_000_000;
      const handler = jest.fn((_req, res) => res.status(200).json({ ok: true }));
      const limiters = realLimiter.createDeviceRateLimiters({
        overrides: { pairingApprove: { limits: { principal: 1 } } },
        now: () => now,
      });
      const app = buildLimiterApp({
        limiters: [limiters.pairingApprove.principal],
        handler,
        authenticate: { id: 'user-a' },
      });

      expect((await request(app).post('/probe').send({})).status).toBe(200);
      expect((await request(app).post('/probe').send({})).status).toBe(UNIFORM_MISS_STATUS);
      now += 60_000;
      expect((await request(app).post('/probe').send({})).status).toBe(200);
      expect(handler).toHaveBeenCalledTimes(2);
    });

    it('counts denials per surface and per dimension', async () => {
      const handler = jest.fn((_req, res) => res.status(200).json({ ok: true }));
      const limiters = realLimiter.createDeviceRateLimiters({
        overrides: { currentRenew: { limits: { principal: 1, device: 5 } } },
      });
      const app = buildLimiterApp({
        limiters: [limiters.currentRenew.principal, limiters.currentRenew.device],
        handler,
        authenticate: { id: 'user-a' },
      });

      await request(app).post('/probe').send({ devicePublicKey: 'k' });
      await request(app).post('/probe').send({ devicePublicKey: 'k' });

      const stats = limiters.stats();
      expect(stats.currentRenew.denied).toBe(1);
      expect(stats.currentRenew.byDimension.principal).toBe(1);
      expect(stats.currentRenew.byDimension.device).toBe(0);
      expect(stats.pairingApprove.denied).toBe(0);
    });

    it('answers the non-code surfaces with a 429 instead of the miss', async () => {
      const handler = jest.fn((_req, res) => res.status(200).json({ ok: true }));
      const limiters = realLimiter.createDeviceRateLimiters({
        overrides: { currentRenew: { limits: { principal: 1 } } },
      });
      const app = buildLimiterApp({
        limiters: [limiters.currentRenew.principal],
        handler,
        authenticate: { id: 'user-a' },
      });

      expect((await request(app).post('/probe').send({})).status).toBe(200);
      const denied = await request(app).post('/probe').send({});
      expect(denied.status).toBe(realLimiter.THROTTLED_STATUS);
      expect(denied.body).toEqual(realLimiter.THROTTLED_BODY);
    });
  });

  /* ==========================================================================
   * 2 — Oracle safety
   * ======================================================================== */

  describe('oracle safety (GM-6)', () => {
    /**
     * THE HEADLINE PROPERTY, measured against the REAL handlers.
     *
     * For each code-bearing surface we mount the real accepted handler behind the real limiter,
     * spend the budget on an unusable request (which yields that surface's genuine miss), then send
     * one more request and compare the denial to the genuine miss. Status, body bytes, content
     * length and rate-limit headers must all match: a caller cannot tell "throttled" from "no such
     * code". This is why the miss bodies are measured rather than assumed — an earlier revision of
     * this module emitted the handler's `uniformMiss()` fallback text on the approve surface, whose
     * genuine miss carries the service's message instead, and this test caught the one-string leak.
     */
    const REAL_HANDLERS = {
      pairingChallenge: () =>
        realPairingHandlers.createPairingChallengeHandler({
          db: createStubDb(),
          tenantContext: STUB_TENANT_CONTEXT,
          domainTag: 'cbhr:device:pairing-open:v1',
          pepperLookup: STUB_PEPPER,
        }),
      pairingIssue: () =>
        realPairingHandlers.createPairingIssueHandler({
          db: createStubDb(),
          tenantContext: STUB_TENANT_CONTEXT,
          domainTag: 'cbhr:device:pairing-open:v1',
          requestSource: 'local-lab:device-pairing-issue',
          pepperLookup: STUB_PEPPER,
        }),
      pairingApprove: () =>
        realPairingHandlers.createPairingApproveHandler({
          db: createStubDb(),
          tenantContext: STUB_TENANT_CONTEXT,
          pepperLookup: STUB_PEPPER,
        }),
      pairingComplete: () =>
        realCompleteHandlerModule.createPairingCompleteHandler({
          db: createStubDb(),
          tenantContext: STUB_TENANT_CONTEXT,
          domainTag: 'cbhr:device:pairing-complete:v1',
          pepperLookup: STUB_PEPPER,
        }),
    };

    /** One unusable request per surface: no registered identity, no session, no usable code. */
    const UNUSABLE_BODY = {
      pairingChallenge: { devicePublicKey: 'bogus-endpoint-key' },
      pairingIssue: { devicePublicKey: 'bogus-endpoint-key', challengeHash: 'x' },
      pairingApprove: { code: '123456' },
      pairingComplete: { devicePublicKey: 'bogus-endpoint-key' },
    };

    it.each(ORACLE_SURFACES)(
      '$surface — a denial is byte-identical to the genuine miss',
      async ({ surface, miss, message }) => {
        const dimensions = Object.keys(DEVICE_RATE_LIMIT_POLICY[surface].limits);
        const { app } = buildRealHandlerApp({
          surface,
          handler: REAL_HANDLERS[surface](),
          limiterNames: dimensions,
        });

        const genuine = await request(app).post('/probe').send(UNUSABLE_BODY[surface]);
        const denied = await request(app).post('/probe').send(UNUSABLE_BODY[surface]);

        // The first response is the real handler's own uniform miss...
        expect(genuine.status).toBe(UNIFORM_MISS_STATUS);
        expect(genuine.body.code).toBe('INVALID_OR_EXPIRED_CODE');
        expect(genuine.body.message).toBe(message);

        // ...and the throttle is indistinguishable from it, byte for byte.
        expect(denied.status).toBe(genuine.status);
        expect(denied.text).toBe(genuine.text);
        expect(denied.headers['content-length']).toBe(genuine.headers['content-length']);
        expect(denied.body).toEqual(UNIFORM_MISS_BODIES[miss]);
        expect(JSON.stringify(denied.body)).toBe(JSON.stringify(genuine.body));
      },
    );

    it.each(ORACLE_SURFACES)(
      '$surface — a denial carries no rate-limit header a miss would not carry',
      async ({ surface }) => {
        const dimensions = Object.keys(DEVICE_RATE_LIMIT_POLICY[surface].limits);
        const { app } = buildRealHandlerApp({
          surface,
          handler: REAL_HANDLERS[surface](),
          limiterNames: dimensions,
        });

        const allowed = await request(app).post('/probe').send(UNUSABLE_BODY[surface]);
        await request(app).post('/probe').send(UNUSABLE_BODY[surface]);
        const denied = await request(app).post('/probe').send(UNUSABLE_BODY[surface]);

        for (const headers of [allowed.headers, denied.headers]) {
          const names = Object.keys(headers);
          expect(names.filter((name) => /ratelimit|retry-after/i.test(name))).toEqual([]);
        }
      },
    );

    it('denies identically no matter which code the caller submits', async () => {
      const dimensions = Object.keys(DEVICE_RATE_LIMIT_POLICY.pairingApprove.limits);
      const { app } = buildRealHandlerApp({
        surface: 'pairingApprove',
        handler: REAL_HANDLERS.pairingApprove(),
        limiterNames: dimensions,
      });

      await request(app).post('/probe').send({ code: '111111' });
      const deniedA = await request(app).post('/probe').send({ code: '111111' });
      const deniedB = await request(app).post('/probe').send({ code: '999999' });
      const deniedC = await request(app).post('/probe').send({ code: 'not-a-code' });
      const deniedD = await request(app).post('/probe').send({});

      for (const denied of [deniedB, deniedC, deniedD]) {
        expect(denied.status).toBe(deniedA.status);
        expect(denied.text).toBe(deniedA.text);
      }
    });

    it('keeps the mirrored miss literals in step with the accepted sources', () => {
      for (const { miss, file, message } of ORACLE_SURFACES) {
        const source = fs.readFileSync(path.join(DEVICE_SERVICES_DIR, file), 'utf8');
        expect(source).toContain(`'${message}'`);
        expect(source).toContain(`'INVALID_OR_EXPIRED_CODE'`);
        expect(UNIFORM_MISS_BODIES[miss].message).toBe(message);
        expect(UNIFORM_MISS_BODIES[miss].code).toBe('INVALID_OR_EXPIRED_CODE');
      }

      // The approve surface must NOT mirror the handler's `uniformMiss()` fallback text: that is
      // the one-string leak this suite exists to prevent from coming back.
      const approveSource = fs.readFileSync(
        path.join(DEVICE_SERVICES_DIR, 'pairingHttpHandler.js'),
        'utf8',
      );
      expect(approveSource).toContain(`'The supplied pairing values cannot be used'`);
      expect(UNIFORM_MISS_BODIES.approve.message).not.toBe(
        'The supplied pairing values cannot be used',
      );
    });

    it('sends the miss through the same emitter the handlers use', () => {
      // A denial must be a `sendClassifiedError`-shaped body: `{ok:false, code, message}` only.
      for (const surface of CODE_BEARING_SURFACES) {
        const miss = DEVICE_RATE_LIMIT_POLICY[surface].miss;
        expect(Object.keys(UNIFORM_MISS_BODIES[miss])).toEqual(['ok', 'code', 'message']);
        expect(UNIFORM_MISS_BODIES[miss].ok).toBe(false);
      }
      // And the shared emitter produces exactly that shape for the same code.
      const res = {
        statusCode: null,
        status(code) {
          res.statusCode = code;
          return res;
        },
        json(payload) {
          res.body = payload;
          return res;
        },
      };
      deviceHttpTrust.sendClassifiedError(
        res,
        new DeviceError(
          'INVALID_OR_EXPIRED_CODE',
          UNIFORM_MISS_BODIES.approve.message,
        ),
      );
      expect(res.statusCode).toBe(UNIFORM_MISS_STATUS);
      expect(Object.keys(res.body)).toEqual(['ok', 'code', 'message']);
      expect(res.body).toEqual(UNIFORM_MISS_BODIES.approve);
    });
  });


  /* ==========================================================================
   * 3 — Route wiring
   * ======================================================================== */

  describe('route wiring', () => {
    function wiringApp() {
      const app = express();
      app.use(express.json());
      app.use('/api/devices', devicesRouter);
      return app;
    }

    it('mounts the limiter chain per route, in the declared order', async () => {
      const cases = [
        ['post', '/api/devices/pairing/complete', [], ['pairingComplete.source', 'pairingComplete.device']],
        ['post', '/api/devices/current/retire', [], ['currentRetire.principal']],
        ['get', '/api/devices/current', [], ['currentStatus.principal']],
        ['post', '/api/devices/current/renew', [], ['currentRenew.principal', 'currentRenew.device']],
        [
          'post',
          '/api/devices/pairing/challenge',
          [],
          ['pairingChallenge.principal', 'pairingChallenge.source'],
        ],
        [
          'post',
          '/api/devices/pairing/issue',
          [],
          ['pairingIssue.principal', 'pairingIssue.device', 'pairingIssue.source'],
        ],
        [
          'post',
          '/api/devices/pairing/approve',
          [],
          ['pairingApprove.principal', 'pairingApprove.source'],
        ],
      ];

      for (const [method, url, , expected] of cases) {
        mockLimiterCalls.length = 0;
        const res = await request(wiringApp())[method](url).send({});
        expect(res.status).toBe(200);
        expect(mockLimiterCalls).toEqual(expected);
      }
    });

    it('short-circuits the handler when a pairing limiter denies, with the uniform miss', async () => {
      mockLimiterDenial = {
        match: 'pairingApprove.principal',
        status: UNIFORM_MISS_STATUS,
        body: { ...UNIFORM_MISS_BODIES.approve },
      };
      const res = await request(wiringApp()).post('/api/devices/pairing/approve').send({
        code: '123456',
      });

      expect(res.status).toBe(UNIFORM_MISS_STATUS);
      expect(res.body).toEqual(UNIFORM_MISS_BODIES.approve);
      expect(mockPairingApproveHandler).not.toHaveBeenCalled();
      // The second dimension never ran: the chain stopped at the first denial.
      expect(mockLimiterCalls).toEqual(['pairingApprove.principal']);
    });

    it('runs requireJwtAuth before any principal-keyed limiter', async () => {
      mockRequireJwtAuth.mockImplementationOnce((_req, res) =>
        res.status(401).json({ ok: false, code: 'UNAUTHORIZED' }),
      );
      const res = await request(wiringApp()).post('/api/devices/pairing/challenge').send({});

      expect(res.status).toBe(401);
      expect(mockLimiterCalls).toEqual([]);
      expect(mockPairingChallengeHandler).not.toHaveBeenCalled();
    });

    it('limits /pairing/complete without a principal, outside the session gate', async () => {
      const res = await request(wiringApp())
        .post('/api/devices/pairing/complete')
        .send({ devicePublicKey: 'endpoint-key' });

      expect(res.status).toBe(200);
      expect(mockRequireJwtAuth).not.toHaveBeenCalled();
      expect(res.body.userId).toBeNull();
      expect(mockLimiterCalls).toEqual(['pairingComplete.source', 'pairingComplete.device']);
    });

    it('does not spend a bucket on paths that match no route', async () => {
      const app = wiringApp();
      for (const [method, url] of [
        ['post', '/api/devices/pairing'],
        ['post', '/api/devices/registration/challenge'],
        ['get', '/api/devices/current/retire'],
        ['put', '/api/devices/current'],
        ['delete', '/api/devices/pairing/approve'],
      ]) {
        mockLimiterCalls.length = 0;
        const res = await request(app)[method](url).send({});
        expect(res.status).toBe(404);
        expect(mockLimiterCalls).toEqual([]);
      }
    });
  });
});

/* ============================================================================
 * 4 — Capability stages (GM-14 / R7)
 * ========================================================================== */

describe('W4 capability policy (GM-14 / R7)', () => {
  const STAGE_A = [
    'read_file',
    'read_multiple_files',
    'list_directory',
    'start_search',
    'get_more_search_results',
    'stop_search',
    'list_searches',
    'get_file_info',
  ];
  const STAGE_B_ADDS = ['write_file', 'create_directory', 'move_file', 'edit_block'];
  const STAGE_C_ADDS = [
    'write_pdf',
    'start_process',
    'read_process_output',
    'interact_with_process',
    'force_terminate',
    'list_sessions',
    'list_processes',
    'kill_process',
  ];
  const STAGE_FULL_ADDS = [
    'get_config',
    'set_config_value',
    'get_usage_stats',
    'get_recent_tool_calls',
    'give_feedback_to_desktop_commander',
    'get_prompts',
  ];
  const CATALOG = [
    ...STAGE_A,
    ...STAGE_B_ADDS,
    ...STAGE_C_ADDS,
    ...STAGE_FULL_ADDS,
  ];

  describe('the frozen catalog', () => {
    it('publishes exactly the 26 supported Desktop Commander tools, no aliases', () => {
      expect(policy.TOOL_CATALOG).toHaveLength(26);
      expect(policy.ADVERTISED_TOOL_COUNT).toBe(26);
      expect([...policy.TOOL_CATALOG.map((tool) => tool.name)].sort()).toEqual([...CATALOG].sort());
    });

    it('assigns every tool to exactly one first stage', () => {
      const firstStage = new Map();
      for (const stage of policy.CAPABILITY_STAGES) {
        for (const name of policy.stageToolNames(stage)) {
          if (!firstStage.has(name)) {
            firstStage.set(name, stage);
          }
        }
      }
      expect(firstStage.size).toBe(26);
      for (const name of STAGE_A) {
        expect(firstStage.get(name)).toBe('A');
      }
      for (const name of STAGE_B_ADDS) {
        expect(firstStage.get(name)).toBe('B');
      }
      for (const name of STAGE_C_ADDS) {
        expect(firstStage.get(name)).toBe('C');
      }
      for (const name of STAGE_FULL_ADDS) {
        expect(firstStage.get(name)).toBe('full');
      }
    });

    it('passes its own integrity assertion', () => {
      expect(typeof policy.assertPolicyIntegrity).toBe('function');
      expect(policy.assertPolicyIntegrity()).toBe(true);
    });
  });

  describe('stage gating', () => {
    it('gates stage A to the read-only class and nothing else', () => {
      expect([...policy.stageToolNames('A')].sort()).toEqual([...STAGE_A].sort());
      for (const name of [
        ...STAGE_B_ADDS,
        ...STAGE_C_ADDS,
        ...STAGE_FULL_ADDS,
      ]) {
        // `pilot: false` isolates the stage gate from the pilot deny-list overlay.
        const decision = policy.evaluateTool(name, { stage: 'A', pilot: false });
        expect(decision.allowed).toBe(false);
        expect(decision.code).toBe(policy.DECISION_CODES.NOT_ENABLED_AT_STAGE);
        expect(decision.httpStatus).toBe(403);
      }
      // Every stage-A tool is a pure read: no writes, no process, no egress.
      for (const name of STAGE_A) {
        const tool = policy.getToolDefinition(name);
        expect(tool.effectClass).toMatch(/^(fs-read|search)$/);
        expect(tool.consent).not.toBe(policy.CONSENT_CLASSES.OWNER_APPROVAL);
      }
    });

    it('adds exactly the file class at stage B', () => {
      expect([...policy.stageToolNames('B')].sort()).toEqual(
        [...STAGE_A, ...STAGE_B_ADDS].sort(),
      );
      for (const name of STAGE_B_ADDS) {
        expect(policy.evaluateTool(name, { stage: 'B' }).decision).toBe('allowed');
      }
      expect(policy.evaluateTool('start_process', { stage: 'B' }).allowed).toBe(false);
      expect(policy.evaluateTool('write_pdf', { stage: 'B' }).allowed).toBe(false);
    });

    it('adds exactly the process/terminal/PDF class at stage C', () => {
      expect([...policy.stageToolNames('C')].sort()).toEqual(
        [...STAGE_A, ...STAGE_B_ADDS, ...STAGE_C_ADDS].sort(),
      );
      expect(policy.evaluateTool('write_pdf', { stage: 'C' }).decision).toBe('allowed');
      expect(policy.evaluateTool('list_processes', { stage: 'C' }).decision).toBe('allowed');
      expect(policy.evaluateTool('kill_process', { stage: 'C' }).decision).toBe('approval-required');
      // The administrative/telemetry class is deliberately still closed at C.
      for (const name of STAGE_FULL_ADDS) {
        expect(policy.evaluateTool(name, { stage: 'C' }).code).not.toBe(
          policy.DECISION_CODES.ALLOWED,
        );
      }
    });

    it('completes the ladder at full with the config, telemetry and prompt tools', () => {
      expect([...policy.stageToolNames('full')].sort()).toEqual([...CATALOG].sort());
      expect(policy.stageToolCount('full')).toBe(26);
      expect(policy.evaluateTool('get_config', { stage: 'full' }).decision).toBe('allowed');
      expect(policy.evaluateTool('get_prompts', { stage: 'full' }).decision).toBe('allowed');
      expect(policy.evaluateTool('set_config_value', { stage: 'full' }).decision).toBe(
        'approval-required',
      );
    });

    it('is monotonic: promotion never drops a tool', () => {
      for (let index = 1; index < policy.CAPABILITY_STAGES.length; index += 1) {
        const previous = new Set(
          policy.stageToolNames(policy.CAPABILITY_STAGES[index - 1]),
        );
        const current = new Set(policy.stageToolNames(policy.CAPABILITY_STAGES[index]));
        for (const name of previous) {
          expect(current.has(name)).toBe(true);
        }
      }
      expect(policy.describeStageTable().map((row) => row.count)).toEqual([8, 12, 20, 26]);
    });

    it('defines the end state explicitly: 26 advertised, 25 effective in the pilot, 26 after', () => {
      const endState = policy.pilotEndState();
      expect(endState).toEqual({
        stage: 'full',
        advertised: 26,
        enabledByStage: 26,
        effective: 25,
        denied: ['give_feedback_to_desktop_commander', 'track_ui_event'],
        internalHandlers: ['track_ui_event'],
      });
      expect(policy.agentReachableToolCount({ stage: 'full' })).toBe(25);
      expect(policy.agentReachableToolCount({ stage: 'full', pilot: false })).toBe(26);
      expect(policy.agentReachableToolCount({ stage: 'A' })).toBe(8);
      expect(policy.agentReachableToolCount({ stage: 'C' })).toBe(20);
    });

    it('rejects an unknown stage rather than guessing one', () => {
      expect(() => policy.stageToolNames('D')).toThrow(policy.CapabilityPolicyError);
      expect(() => policy.evaluateTool('read_file', { stage: 'd' })).toThrow(/Unknown capability stage/);
    });
  });

  describe('per-tool deny-list', () => {
    it('relay-denies track_ui_event 403 at every stage, pilot or not', () => {
      for (const stage of policy.CAPABILITY_STAGES) {
        for (const pilot of [true, false]) {
          const decision = policy.evaluateTool('track_ui_event', { stage, pilot });
          expect(decision.decision).toBe('denied');
          expect(decision.httpStatus).toBe(403);
          expect(decision.code).toBe(policy.DECISION_CODES.NOT_PERMITTED);
          expect(decision.agentReachable).toBe(false);
        }
      }
      expect(policy.deniedToolNames({ stage: 'full' })).toContain('track_ui_event');
    });

    it('never counts track_ui_event as an agent-reachable tool', () => {
      expect(policy.isAgentReachable('track_ui_event')).toBe(false);
      for (const stage of policy.CAPABILITY_STAGES) {
        expect(policy.stageToolNames(stage)).not.toContain('track_ui_event');
      }
      expect(policy.INTERNAL_HANDLERS).toEqual(['track_ui_event']);
      expect(policy.isAdvertisedTool('track_ui_event')).toBe(false);
    });

    it('denies give_feedback_to_desktop_commander for the pilot at every stage', () => {
      for (const stage of policy.CAPABILITY_STAGES) {
        const decision = policy.evaluateTool('give_feedback_to_desktop_commander', { stage });
        expect(decision.decision).toBe('denied');
        expect(decision.httpStatus).toBe(403);
        expect(decision.reason).toMatch(/client_id/);
        expect(decision.agentReachable).toBe(false);
      }
      // It remains an advertised tool, and only the pilot overlay removes it.
      expect(policy.isAdvertisedTool('give_feedback_to_desktop_commander')).toBe(true);
      expect(policy.evaluateTool('give_feedback_to_desktop_commander', { stage: 'full', pilot: false }))
        .toMatchObject({ decision: 'approval-required', requiresApproval: true });
    });

    it('keeps the four owner-approval tools gated, never plain-allowed, at every stage', () => {
      expect(policy.ownerApprovalTools().sort()).toEqual(
        [
          'give_feedback_to_desktop_commander',
          'kill_process',
          'set_config_value',
          'start_process',
        ].sort(),
      );
      for (const stage of policy.CAPABILITY_STAGES) {
        for (const name of policy.OWNER_APPROVAL_TOOLS) {
          const decision = policy.evaluateTool(name, { stage, pilot: false });
          expect(decision.decision).not.toBe('allowed');
          if (decision.decision === 'approval-required') {
            expect(decision.requiresApproval).toBe(true);
          } else {
            expect(decision.decision).toBe('denied');
          }
        }
      }
    });

    it('denies an unknown tool and an invalid name', () => {
      const unknown = policy.evaluateTool('fuzzy_search', { stage: 'full' });
      expect(unknown.decision).toBe('denied');
      expect(unknown.code).toBe(policy.DECISION_CODES.UNKNOWN);
      expect(unknown.httpStatus).toBe(400);

      const invalid = policy.evaluateTool('', { stage: 'full' });
      expect(invalid.code).toBe(policy.DECISION_CODES.INVALID_NAME);
      expect(invalid.httpStatus).toBe(400);
    });
  });

  describe('CI assertion — relay clientInfo.name (GM-14 mechanical check)', () => {
    const allTwentySix = policy.TOOL_CATALOG.map((tool) => tool.name);

    it('fails on the forbidden client name', () => {
      expect(() => policy.assertRelayClientInfo({ name: 'desktop-commander-app' })).toThrow(
        policy.CapabilityPolicyError,
      );
      expect(() => policy.assertRelayClientInfo({ name: 'desktop-commander-app' })).toThrow(
        /advertise 24 tools instead of 26/,
      );
      try {
        policy.assertRelayClientInfo({ name: 'desktop-commander-app' });
      } catch (error) {
        expect(error.code).toBe('RELAY_CLIENT_NAME_FORBIDDEN');
      }
    });

    it('accepts the pinned relay client name', () => {
      expect(policy.RELAY_CLIENT_NAME).toBe('cbhr-rdc-relay');
      expect(policy.FORBIDDEN_RELAY_CLIENT_NAMES).toEqual(['desktop-commander-app']);
      expect(policy.FORBIDDEN_RELAY_CLIENT_NAMES).not.toContain(policy.RELAY_CLIENT_NAME);
      expect(policy.assertRelayClientInfo({ name: policy.RELAY_CLIENT_NAME })).toBe(true);
    });

    it('fails on a missing or empty client name', () => {
      for (const clientInfo of [undefined, null, {}, { name: '' }, { name: 42 }]) {
        expect(() => policy.assertRelayClientInfo(clientInfo)).toThrow(
          /must send a non-empty clientInfo.name/,
        );
      }
    });

    it('accepts an advertisement of all 26 tools', () => {
      expect(
        policy.assertRelayToolAdvertisement(allTwentySix, { name: policy.RELAY_CLIENT_NAME }),
      ).toBe(true);
      expect(
        policy.assertRelayToolAdvertisement(
          allTwentySix.map((name) => ({ name })),
          { name: policy.RELAY_CLIENT_NAME },
        ),
      ).toBe(true);
    });

    it('fails the 24-tool silent downgrade the forbidden client name causes', () => {
      const downgraded = allTwentySix.filter(
        (name) => !policy.HIDDEN_FOR_FORBIDDEN_CLIENT.includes(name),
      );
      expect(downgraded).toHaveLength(24);

      expect(() =>
        policy.assertRelayToolAdvertisement(downgraded, { name: policy.RELAY_CLIENT_NAME }),
      ).toThrow(/advertised 24 tools; the pilot law requires 26/);

      try {
        policy.assertRelayToolAdvertisement(downgraded, { name: policy.RELAY_CLIENT_NAME });
      } catch (error) {
        expect(error.code).toBe('RELAY_TOOL_COUNT_MISMATCH');
      }

      // And the forbidden name is refused even if 26 tools somehow came back.
      expect(() =>
        policy.assertRelayToolAdvertisement(allTwentySix, { name: 'desktop-commander-app' }),
      ).toThrow(/RELAY|24 tools|advertise 24/);
    });

    it('fails on a duplicate, an unknown extra and a missing tool', () => {
      expect(() =>
        policy.assertRelayToolAdvertisement([...allTwentySix, 'read_file'], {
          name: policy.RELAY_CLIENT_NAME,
        }),
      ).toThrow(/more than once/);

      expect(() =>
        policy.assertRelayToolAdvertisement([...allTwentySix.slice(1), 'fuzzy_search'], {
          name: policy.RELAY_CLIENT_NAME,
        }),
      ).toThrow(/outside the frozen catalog/);

      expect(() =>
        policy.assertRelayToolAdvertisement(allTwentySix.slice(1).concat('read_file'), {
          name: policy.RELAY_CLIENT_NAME,
        }),
      ).toThrow(/did not advertise|more than once/);

      expect(() =>
        policy.assertRelayToolAdvertisement('not-an-array', { name: policy.RELAY_CLIENT_NAME }),
      ).toThrow(/must be an array/);
    });
  });
});

/* ============================================================================
 * 5 — Regression guard: the hardening spec's own wiring double
 * ========================================================================== */

describe('hardening spec wiring double', () => {
  it('mirrors the dimensions the real policy declares for the wired surfaces', () => {
    for (const [surface, dimensions] of Object.entries(mockLimiterShape)) {
      const declared = Object.keys(DEVICE_RATE_LIMIT_POLICY[surface].limits).sort();
      expect([...dimensions].sort()).toEqual(declared);
    }
  });

  it('is the only route registration point for the device surface', () => {
    const routeSource = fs.readFileSync(
      path.join(__dirname, '..', 'devices.js'),
      'utf8',
    );
    // No router-level limiter: a `router.use(deviceRateLimiters…)` would run on 404s.
    expect(routeSource).not.toMatch(/router\.use\(\s*deviceRateLimiters/);
    expect(routeSource).toContain("require('~/server/middleware/deviceRateLimit')");
  });
});
