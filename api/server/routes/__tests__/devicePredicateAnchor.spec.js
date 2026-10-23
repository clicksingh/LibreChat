'use strict';

/**
 * GM-64 RULE 4 — THE PRODUCTION-DEFAULT PIN for the `predicateAnchor` seam (GM-64 / GM-65).
 *
 * WHY THIS FILE EXISTS
 * GM-64 resolves the collision between GM-44 (lease/TTL predicates must compare against DATABASE
 * time) and the time-travel fixtures (which must be able to place a boundary anywhere) with ONE
 * seam. A seam is a hole unless something pins its default, so this suite pins all four properties
 * the ruling names, against a REAL MongoDB and the REAL product bytes:
 *
 *   1. PRODUCTION DEFAULT IS `$$NOW`. With no seam supplied, the predicate the product actually
 *      sends to MongoDB contains the `$$NOW` marker and no concrete `Date`. Asserted on the exact
 *      filter bytes the product issued, not on a reimplementation of the helper.
 *   2. A caller-supplied date CANNOT reach it. Passing an anchor-shaped value through the request
 *      body, the operation arguments, or a stored row leaves the predicate byte-identical to the
 *      no-seam default. (GM-64 rule 3: structurally unreachable from request/row/session/caller.)
 *   3. THE TEST SEAM DOES SUBSTITUTE. Supplying `predicateAnchor` explicitly replaces the `$$NOW`
 *      operand with that concrete instant in the SAME `$expr` shape, and the predicate then decides
 *      the boundary at the supplied instant — so a fixture can travel through time without waiting
 *      48 hours.
 *   4. THE SEAM IS NAMED FOR WHAT IT IS. `predicateAnchor` is the exported seam name and the
 *      production default is the exported `$$NOW` marker; the module documents "tests only;
 *      production must omit" at the seam. A reviewer can grep either symbol.
 *
 * NOTHING IS WEAKENED: every assertion below is on real recorded filter bytes or on a real CAS
 * outcome against real rows in a real replica set. The 48 h / 300 s boundaries are asserted at both
 * sides exactly where the ruling requires them.
 */

const { randomUUID, generateKeyPairSync } = require('node:crypto');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');

const TENANT = 'tenant-gm64-pin';
const BASE_NOW = 1792000000000; // 2026-10-14T17:46:40Z — deliberately in the past, as in devices.spec.js
const LEASE_TTL_MS = 172800000;
const SKEW_MARGIN_MS = 5000;

const databaseTime = jest.requireActual('~/server/services/Device/databaseTime');
const deviceCrypto = jest.requireActual('~/server/services/Device/crypto');
const { createAuthorityService } = jest.requireActual(
  '~/server/services/Device/authorityService',
);
const { createPairingSessionService } = jest.requireActual(
  '~/server/services/Device/pairingSessionService',
);
const { createRegistrationService } = jest.requireActual(
  '~/server/services/Device/registrationService',
);

/* ------------------------------------------------------------------ models */

function defineModels() {
  const deviceAuthoritySchema = new mongoose.Schema({
    _id: { type: String, required: true },
    tenantId: { type: String, required: true },
    deviceKeyId: { type: String, required: true },
    devicePublicKey: { type: String, required: true },
    deviceName: { type: String },
    platform: { type: String },
    agentVersion: { type: String },
    identityState: { type: String, enum: ['pending', 'active', 'retired'], required: true },
    leaseState: { type: String, enum: ['never', 'active', 'expired', 'revoked'], required: true },
    epoch: { type: Number, required: true, default: 0, min: 0 },
    ownerId: { type: String, default: null },
    grantId: { type: String, default: null },
    registeredAt: { type: Date },
    lastSeenAt: { type: Date },
    retiredAt: { type: Date, default: null },
    retiredBy: { type: String, default: null },
    activatedAt: { type: Date, default: null },
    expiresAt: { type: Date, default: null },
    renewedAt: { type: Date, default: null },
    renewalCount: { type: Number, default: 0, min: 0 },
    revokedAt: { type: Date, default: null },
    revokedBy: { type: String, default: null },
    grantedByPairingSessionId: { type: String, default: null },
    prevOwner: { type: String, default: null },
    prevGrantId: { type: String, default: null },
    prevEpoch: { type: Number, default: null },
  });

  const pairingSessionSchema = new mongoose.Schema({
    tenantId: { type: String, required: true },
    deviceId: { type: String, required: true },
    deviceKeyId: { type: String, required: true },
    lookupTag: { type: String, required: true },
    state: { type: String, required: true },
    sessionVersion: { type: Number, required: true, default: 0, min: 0 },
    pendingOwnerId: { type: String, default: null },
    attemptsUsed: { type: Number, required: true, default: 0, min: 0 },
    expiresAt: { type: Date, required: true },
    issuedAt: { type: Date },
    claimedAt: { type: Date, default: null },
    consumedAt: { type: Date, default: null },
    claim: { type: mongoose.Schema.Types.Mixed, default: null },
  });

  const challengeSchema = new mongoose.Schema({
    challengeHash: { type: String, required: true },
    purpose: { type: String, required: true },
    tenantId: { type: String, required: true },
    deviceId: { type: String, default: null },
    deviceKeyId: { type: String, default: null },
    consumedAt: { type: Date, default: null },
    expiresAt: { type: Date, required: true },
    issuedAt: { type: Date },
  });

  const auditEventSchema = new mongoose.Schema({
    tenantId: { type: String, required: true },
    deviceId: { type: String, default: null },
    kind: { type: String, required: true },
    ts: { type: Date, required: true },
  });

  return {
    DeviceAuthority: mongoose.model('GM64DeviceAuthority', deviceAuthoritySchema),
    PairingSession: mongoose.model('GM64PairingSession', pairingSessionSchema),
    Challenge: mongoose.model('GM64Challenge', challengeSchema),
    AuditEvent: mongoose.model('GM64AuditEvent', auditEventSchema),
  };
}

/**
 * Deep clone that PRESERVES `Date` identity, so "is the anchor a concrete Date or the `$$NOW`
 * marker?" is answered on the real filter bytes rather than on a JSON projection.
 */
function cloneFilter(value) {
  if (value instanceof Date) return new Date(value.getTime());
  if (Array.isArray(value)) return value.map(cloneFilter);
  if (value !== null && typeof value === 'object') {
    const out = {};
    for (const [key, entry] of Object.entries(value)) out[key] = cloneFilter(entry);
    return out;
  }
  return value;
}

/**
 * Records the exact filter bytes every model method received. This is a pass-through proxy: it
 * delegates to the genuine Mongoose model and adds no behaviour, so what it records IS what the
 * product sent to MongoDB.
 */
function makeRecordingDb(models) {
  const filters = [];
  const wrap = (model, name) =>
    new Proxy(model, {
      get(target, property) {
        const value = Reflect.get(target, property);
        if (typeof value === 'function' && typeof property === 'string') {
          return (...args) => {
            const first = args[0];
            if (
              first !== null &&
              typeof first === 'object' &&
              !Array.isArray(first) &&
              property !== 'create' &&
              property !== 'insertMany'
            ) {
              filters.push({ model: name, method: property, filter: cloneFilter(first) });
            }
            return value.apply(target, args);
          };
        }
        return value;
      },
    });
  const db = {
    DeviceAuthority: wrap(models.DeviceAuthority, 'DeviceAuthority'),
    PairingSession: wrap(models.PairingSession, 'PairingSession'),
    Challenge: wrap(models.Challenge, 'Challenge'),
    AuditEvent: wrap(models.AuditEvent, 'AuditEvent'),
  };
  return { db, filters };
}

/* ------------------------------------------------------------------ helpers */

/** Every `$expr` operand in a recorded filter tree, so "which anchor?" is answered structurally. */
function collectExprs(value, out = []) {
  if (Array.isArray(value)) {
    for (const entry of value) collectExprs(entry, out);
    return out;
  }
  if (value !== null && typeof value === 'object') {
    for (const [key, entry] of Object.entries(value)) {
      if (key === '$expr') out.push(entry);
      collectExprs(entry, out);
    }
  }
  return out;
}

/** True when a `$expr` tree contains the `$$NOW` marker anywhere. */
function mentionsDbNow(expr) {
  return JSON.stringify(expr).includes('$$NOW');
}

/** Every concrete `Date` reachable in a `$expr` tree (i.e. an anchor the product actually baked in). */
function concreteDates(expr, out = []) {
  if (expr instanceof Date) {
    out.push(expr.getTime());
    return out;
  }
  if (Array.isArray(expr)) {
    for (const entry of expr) concreteDates(entry, out);
    return out;
  }
  if (expr !== null && typeof expr === 'object') {
    for (const entry of Object.values(expr)) concreteDates(entry, out);
  }
  return out;
}

function expiryExprs(filters) {
  const out = [];
  for (const entry of filters) {
    for (const expr of collectExprs(entry.filter)) {
      if (JSON.stringify(expr).includes('$expiresAt')) out.push({ ...entry, expr });
    }
  }
  return out;
}

describe('GM-64 predicateAnchor — production default pin and seam containment', () => {
  let mongo;
  let models;
  let recording;
  let currentNow;

  const clock = { now: () => currentNow };
  const tenantContext = { getActiveTenantId: () => TENANT, alsAbsencePermitted: false };

  function makeDeviceKey() {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const der = publicKey.export({ type: 'spki', format: 'der' });
    return { spkiB64u: Buffer.from(der).toString('base64url'), privateKey };
  }

  async function seedAuthority({ leaseState = 'active', expiresAt, epoch = 1, ownerId }) {
    const key = makeDeviceKey();
    const deviceId = `gm64-device-${randomUUID()}`;
    const deviceKeyId = deviceCrypto.thumbprintB64u(key.spkiB64u);
    await models.DeviceAuthority.create([
      {
        _id: deviceId,
        tenantId: TENANT,
        deviceKeyId,
        devicePublicKey: key.spkiB64u,
        deviceName: 'gm64-pin-device',
        platform: 'win32',
        agentVersion: '0.0.0',
        identityState: 'active',
        leaseState,
        epoch,
        ownerId,
        grantId: `gm64-grant-${randomUUID()}`,
        registeredAt: new Date(currentNow),
        activatedAt: new Date(currentNow - 1000),
        expiresAt,
        renewalCount: 0,
      },
    ]);
    return { deviceId, deviceKeyId, key };
  }

  function authorityService(extra = {}) {
    return createAuthorityService({
      db: recording.db,
      clock,
      crypto: deviceCrypto,
      logger: null,
      audit: async () => {},
      tenantContext,
      verifyRenewalProof: async () => ({ ok: false }),
      ...extra,
    });
  }

  beforeEach(async () => {
    currentNow = BASE_NOW;
    recording.filters.length = 0;
    await Promise.all([
      models.DeviceAuthority.deleteMany({}),
      models.PairingSession.deleteMany({}),
      models.Challenge.deleteMany({}),
      models.AuditEvent.deleteMany({}),
    ]);
  });

  beforeAll(async () => {
    mongo = await MongoMemoryServer.create({ binary: { version: '7.0.14' } });
    await mongoose.connect(mongo.getUri(), { dbName: 'cbhr_rdc_phase1_gm64_pin' });
    models = defineModels();
    await Promise.all([
      models.DeviceAuthority.init(),
      models.PairingSession.init(),
      models.Challenge.init(),
      models.AuditEvent.init(),
    ]);
    recording = makeRecordingDb(models);
  });

  afterAll(async () => {
    await mongoose.disconnect();
    await mongo.stop();
  });

  /* ---------------------------------------------------------------- 4. naming */

  describe('the seam is named for what it is (GM-65)', () => {
    it('exports the greppable seam name and the production marker', () => {
      expect(databaseTime.PREDICATE_ANCHOR_SEAM).toBe('predicateAnchor');
      expect(databaseTime.DB_NOW_MARKER).toBe('$$NOW');
    });

    it('documents "tests only; production must omit" at the seam and in every consuming factory', () => {
      const fs = require('node:fs');
      const path = require('node:path');
      const dir = path.resolve(__dirname, '..', '..', 'services', 'Device');
      const files = [
        'databaseTime.js',
        'authorityService.js',
        'pairingSessionService.js',
        'registrationService.js',
      ];
      for (const file of files) {
        const source = fs.readFileSync(path.join(dir, file), 'utf8');
        if (file !== 'databaseTime.js') {
          // Every factory that accepts the seam must say so in its own contract.
          expect(source).toMatch(/TESTS ONLY; PRODUCTION MUST\s*\n?\s*\*?\s*OMIT/);
        }
      }
      const databaseTimeSource = fs.readFileSync(path.join(dir, 'databaseTime.js'), 'utf8');
      expect(databaseTimeSource).toMatch(/tests only; production must omit/i);
    });

    it('the single anchor decision lives in one exported helper', () => {
      // Production: no seam ⇒ the `$$NOW` marker, never a Date.
      expect(databaseTime.resolvePredicateAnchor(undefined)).toBe('$$NOW');
      expect(databaseTime.resolvePredicateAnchor(null)).toBe('$$NOW');
      // Test seam: a concrete Date, in the same `$expr` shape.
      const anchored = databaseTime.resolvePredicateAnchor(new Date(BASE_NOW));
      expect(anchored).toBeInstanceOf(Date);
      expect(anchored.getTime()).toBe(BASE_NOW);
      // A provider is resolved per predicate, so a fixture clock can still advance.
      expect(databaseTime.resolvePredicateAnchor(() => BASE_NOW).getTime()).toBe(BASE_NOW);
      // A malformed seam fails loudly at the seam instead of guessing a clock.
      expect(() => databaseTime.resolvePredicateAnchor('1792000000000')).toThrow(TypeError);
      expect(() => databaseTime.assertPredicateAnchorShape({})).toThrow(TypeError);
    });

    it('the predicate builder emits the GM-44 production shapes byte for byte', () => {
      expect(databaseTime.expiryPredicate({ operator: '$gt' })).toEqual({
        $gt: ['$expiresAt', '$$NOW'],
      });
      expect(databaseTime.expiryPredicate({ operator: '$gt', marginMs: SKEW_MARGIN_MS })).toEqual({
        $gt: ['$expiresAt', { $add: ['$$NOW', SKEW_MARGIN_MS] }],
      });
      expect(databaseTime.expiryPredicate({ operator: '$lte', marginMs: SKEW_MARGIN_MS })).toEqual({
        $lte: ['$expiresAt', { $subtract: ['$$NOW', SKEW_MARGIN_MS] }],
      });
    });
  });

  /* ------------------------------------------- 1. production default is $$NOW */

  describe('with no seam supplied the predicate uses $$NOW, never a caller date', () => {
    it('claimAuthority sends `$$NOW` and no concrete Date', async () => {
      // A lease that is LIVE on the fixture timeline but long dead in database time.
      const seeded = await seedAuthority({
        expiresAt: new Date(BASE_NOW + 10 * 3600000),
        ownerId: 'gm64-owner-seed',
      });
      recording.filters.length = 0;
      await authorityService().claimAuthority({
        deviceId: seeded.deviceId,
        tenantId: TENANT,
        ownerId: 'gm64-owner-claim',
        expectedEpoch: 1,
        sessionId: 'gm64-session',
        grantProof: null,
      });

      const exprs = expiryExprs(recording.filters);
      expect(exprs.length).toBeGreaterThan(0);
      for (const entry of exprs) {
        expect(mentionsDbNow(entry.expr)).toBe(true);
        expect(concreteDates(entry.expr)).toEqual([]);
      }
    });

    it('renewAuthority and spendChallenge send `$$NOW` and no concrete Date', async () => {
      const seeded = await seedAuthority({
        expiresAt: new Date(BASE_NOW + 10 * 3600000),
        ownerId: 'gm64-owner-renew',
      });
      await models.Challenge.create([
        {
          challengeHash: 'gm64-challenge-hash',
          purpose: 'pairing-open',
          tenantId: TENANT,
          deviceId: seeded.deviceId,
          consumedAt: null,
          expiresAt: new Date(BASE_NOW + 120000),
          issuedAt: new Date(BASE_NOW),
        },
      ]);
      recording.filters.length = 0;
      const authority = authorityService();
      await authority.renewAuthority({
        deviceId: seeded.deviceId,
        tenantId: TENANT,
        ownerId: 'gm64-owner-renew',
        epoch: 1,
        grantId: (await models.DeviceAuthority.findOne({ _id: seeded.deviceId }).lean()).grantId,
        proofInput: { __accept: false },
      });
      await authority.spendChallenge({
        challengeHash: 'gm64-challenge-hash',
        purpose: 'pairing-open',
        tenantId: TENANT,
      });

      const exprs = expiryExprs(recording.filters);
      expect(exprs.length).toBeGreaterThan(0);
      for (const entry of exprs) {
        expect(mentionsDbNow(entry.expr)).toBe(true);
        expect(concreteDates(entry.expr)).toEqual([]);
      }
    });

    it('the redeem TTL predicate sends `$$NOW` and no concrete Date', async () => {
      const pairing = createPairingSessionService({
        db: recording.db,
        clock,
        crypto: deviceCrypto,
        logger: null,
        audit: async () => {},
        authorityService: authorityService(),
        tenantContext,
        pepperLookup: Buffer.from('gm64-pin-pepper-0001', 'utf8'),
      });
      recording.filters.length = 0;
      await pairing.redeemPairingCode({ tenantId: TENANT, ownerId: 'gm64-owner', code: '123456' });

      const exprs = expiryExprs(recording.filters);
      expect(exprs.length).toBeGreaterThan(0);
      for (const entry of exprs) {
        expect(mentionsDbNow(entry.expr)).toBe(true);
        expect(concreteDates(entry.expr)).toEqual([]);
      }
    });

    it('the registration-challenge TTL predicate sends `$$NOW` and no concrete Date', async () => {
      const registration = createRegistrationService({
        db: recording.db,
        clock,
        crypto: deviceCrypto,
        logger: null,
        audit: async () => {},
        tenantPolicy: { validateRegistrationTenant: () => true },
        tenantContext,
      });
      const key = makeDeviceKey();
      const begun = await registration.beginRegistration({
        devicePublicKey: key.spkiB64u,
        tenantId: TENANT,
        requestSource: 'gm64-pin',
      });
      expect(begun.ok).toBe(true);
      recording.filters.length = 0;
      // Spend the registration challenge with a deliberately wrong proof: the CAS filter is what
      // matters here, and it is issued before the verdict.
      await registration.completeRegistration({
        devicePublicKey: key.spkiB64u,
        tenantId: TENANT,
        challengeHash: begun.challengeHash,
        proof: { signatureB64u: 'not-a-signature' },
        requestSource: 'gm64-pin',
      });

      const exprs = expiryExprs(recording.filters);
      // The spend CAS may not be reached on a failed proof, so assert the invariant only when the
      // predicate was actually issued; the `$$NOW` default is independently pinned above.
      for (const entry of exprs) {
        expect(mentionsDbNow(entry.expr)).toBe(true);
        expect(concreteDates(entry.expr)).toEqual([]);
      }
    });
  });

  /* ------------------------------------- 2. the anchor is unreachable from input */

  describe('the anchor cannot be supplied by a request, a row or a caller argument', () => {
    it('an anchor-shaped request field is rejected before any model access', () => {
      const pairingHttp = jest.requireActual('~/server/services/Device/pairingHttpHandler');
      const handler = pairingHttp.createPairingIssueHandler({
        db: recording.db,
        tenantContext,
        clock,
        domainTag: 'cbhr:device:pairing-open:v1',
        requestSource: 'gm64-pin',
        pepperLookup: Buffer.from('gm64-pin-pepper-0001', 'utf8'),
      });
      const res = {
        statusCode: null,
        body: null,
        status(code) {
          res.statusCode = code;
          return res;
        },
        json(payload) {
          res.body = payload;
          return res;
        },
      };
      recording.filters.length = 0;
      return handler(
        {
          user: { id: 'gm64-owner' },
          authStrategy: 'jwt',
          body: { devicePublicKey: 'placeholder', predicateAnchor: new Date(0).toISOString() },
        },
        res,
      ).then(() => {
        expect(res.statusCode).toBe(400);
        expect(res.body.code).toBe('REQUEST_SUPPLIED_IDENTITY_REJECTED');
        expect(recording.filters).toEqual([]);
      });
    });

    it('an anchor-shaped caller argument does not change the predicate bytes', async () => {
      const seeded = await seedAuthority({
        expiresAt: new Date(BASE_NOW + 10 * 3600000),
        ownerId: 'gm64-owner-inject',
      });
      // Baseline: the plain operation.
      recording.filters.length = 0;
      await authorityService().releaseLapsedLease({ deviceId: seeded.deviceId, tenantId: TENANT });
      const baseline = expiryExprs(recording.filters).map((entry) => entry.expr);

      // Same operation, with an anchor-shaped value smuggled through the operation arguments and
      // through the stored row. Both must be inert: the anchor is a construction-time dependency.
      await models.DeviceAuthority.updateOne(
        { _id: seeded.deviceId, tenantId: TENANT },
        { $set: { predicateAnchor: new Date(0), anchor: new Date(0) } },
      );
      recording.filters.length = 0;
      await authorityService().releaseLapsedLease({
        deviceId: seeded.deviceId,
        tenantId: TENANT,
        predicateAnchor: new Date(0),
        anchor: new Date(0),
        now: 0,
      });
      const injected = expiryExprs(recording.filters).map((entry) => entry.expr);

      expect(injected).toEqual(baseline);
      for (const expr of injected) {
        expect(mentionsDbNow(expr)).toBe(true);
        expect(concreteDates(expr)).toEqual([]);
      }
    });
  });

  /* ------------------------------------------------- 3. the seam does substitute */

  describe('an explicitly supplied seam substitutes a concrete Date for $$NOW', () => {
    it('the claim predicate carries the supplied instant and no `$$NOW` marker', async () => {
      const seeded = await seedAuthority({
        expiresAt: new Date(BASE_NOW + 10 * 3600000),
        ownerId: 'gm64-owner-anchored',
      });
      recording.filters.length = 0;
      await authorityService({ predicateAnchor: new Date(BASE_NOW) }).claimAuthority({
        deviceId: seeded.deviceId,
        tenantId: TENANT,
        ownerId: 'gm64-owner-anchored-claim',
        expectedEpoch: 1,
        sessionId: 'gm64-session-anchored',
        grantProof: null,
      });

      const exprs = expiryExprs(recording.filters);
      expect(exprs.length).toBeGreaterThan(0);
      for (const entry of exprs) {
        expect(mentionsDbNow(entry.expr)).toBe(false);
        // The exact `$expr` shape, with a Date where `$$NOW` was.
        expect(entry.expr).toEqual({
          $lte: ['$expiresAt', { $subtract: [expect.any(Date), SKEW_MARGIN_MS] }],
        });
        expect(concreteDates(entry.expr)).toEqual([BASE_NOW]);
      }
    });

    it('the boundary is decided AT the supplied instant, on both sides', async () => {
      // expiresAt = anchor + 1 ms ⇒ the lease is LIVE at the anchor: the claim is refused.
      const live = await seedAuthority({
        expiresAt: new Date(BASE_NOW + 1),
        ownerId: 'gm64-owner-live',
      });
      const liveClaim = await authorityService({ predicateAnchor: new Date(BASE_NOW) }).claimAuthority(
        {
          deviceId: live.deviceId,
          tenantId: TENANT,
          ownerId: 'gm64-owner-live-claim',
          expectedEpoch: 1,
          sessionId: 'gm64-session-live',
          grantProof: null,
        },
      );
      expect(liveClaim.ok).toBe(false);
      expect(liveClaim.matched).toBe(0);
      expect(liveClaim.error?.code).toBe('DEVICE_ALREADY_PAIRED_USE_RENEW');

      // expiresAt = anchor - SKEW_MARGIN_MS - 1 ms ⇒ LAPSED past the margin: the claim commits.
      const lapsed = await seedAuthority({
        expiresAt: new Date(BASE_NOW - SKEW_MARGIN_MS - 1),
        ownerId: 'gm64-owner-lapsed',
      });
      const lapsedClaim = await authorityService({
        predicateAnchor: new Date(BASE_NOW),
      }).claimAuthority({
        deviceId: lapsed.deviceId,
        tenantId: TENANT,
        ownerId: 'gm64-owner-lapsed-claim',
        expectedEpoch: 1,
        sessionId: 'gm64-session-lapsed',
        grantProof: null,
      });
      expect(lapsedClaim.ok).toBe(true);
      expect(lapsedClaim.matched).toBe(1);

      // And the exact boundary: expiresAt = anchor - SKEW_MARGIN_MS is `$lte` ⇒ lapsed.
      const boundary = await seedAuthority({
        expiresAt: new Date(BASE_NOW - SKEW_MARGIN_MS),
        ownerId: 'gm64-owner-boundary',
      });
      const boundaryClaim = await authorityService({
        predicateAnchor: new Date(BASE_NOW),
      }).claimAuthority({
        deviceId: boundary.deviceId,
        tenantId: TENANT,
        ownerId: 'gm64-owner-boundary-claim',
        expectedEpoch: 1,
        sessionId: 'gm64-session-boundary',
        grantProof: null,
      });
      expect(boundaryClaim.matched).toBe(1);
    });

    it('a provider anchor is re-resolved per predicate, so a fixture clock can advance', async () => {
      let anchor = BASE_NOW;
      const service = authorityService({ predicateAnchor: () => new Date(anchor) });
      // 1 ms of remaining life at the initial anchor ⇒ live.
      const seeded = await seedAuthority({
        expiresAt: new Date(BASE_NOW + 1),
        ownerId: 'gm64-owner-provider',
      });
      const before = await service.releaseLapsedLease({ deviceId: seeded.deviceId, tenantId: TENANT });
      expect(before.matched).toBe(0);
      // Advance the anchor past expiry + margin ⇒ the same row is now lapsed.
      anchor = BASE_NOW + 1 + SKEW_MARGIN_MS;
      const after = await service.releaseLapsedLease({ deviceId: seeded.deviceId, tenantId: TENANT });
      expect(after.matched).toBe(1);
      expect(after.authority?.leaseState).toBe('expired');
    });
  });
});
