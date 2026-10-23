const express = require('express');
const request = require('supertest');

/* ============================================================================
 * Suite A — router wiring (handlers mocked)
 * ========================================================================== */

const mockRetireHandler = jest.fn((req, res) =>
  res.status(200).json({
    ok: true,
    authenticated: req.authenticatedByJwt === true,
    userId: req.user?.id ?? null,
  }),
);
const mockRequireJwtAuth = jest.fn((req, _res, next) => {
  req.authenticatedByJwt = true;
  req.user = { id: 'route-user', tenantId: 'tenant-route' };
  req.authStrategy = 'jwt';
  next();
});

// Track handler creation calls
let handlerCreationCalls = [];
const mockCreateHandler = jest.fn((deps) => {
  handlerCreationCalls.push(deps);
  return mockRetireHandler;
});

// Creation records and handlers for the pairing / current-device endpoints (task T7).
const mockPairingCreationCalls = [];
const mockCurrentCreationCalls = [];
const mockPairingChallengeHandler = jest.fn((req, res) =>
  res.status(200).json({ ok: true, endpoint: 'pairing-challenge', userId: req.user?.id ?? null }),
);
const mockPairingIssueHandler = jest.fn((req, res) =>
  res.status(200).json({ ok: true, endpoint: 'pairing-issue', userId: req.user?.id ?? null }),
);
const mockPairingApproveHandler = jest.fn((req, res) =>
  res.status(200).json({ ok: true, endpoint: 'pairing-approve', userId: req.user?.id ?? null }),
);
const mockCurrentStatusHandler = jest.fn((req, res) =>
  res.status(200).json({ ok: true, endpoint: 'current-status', userId: req.user?.id ?? null }),
);
const mockCurrentRenewHandler = jest.fn((req, res) =>
  res.status(200).json({ ok: true, endpoint: 'current-renew', userId: req.user?.id ?? null }),
);

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

// Mock must return the handler factory inline
jest.mock('~/server/services/Device/ownerCurrentRetireHandler', () => ({
  createOwnerCurrentRetireHandler: jest.fn((deps) => {
    handlerCreationCalls.push(deps);
    return mockRetireHandler;
  }),
}));

jest.mock('~/server/services/Device/pairingHttpHandler', () => ({
  createPairingChallengeHandler: jest.fn((deps) => {
    mockPairingCreationCalls.push({ kind: 'challenge', deps });
    return mockPairingChallengeHandler;
  }),
  createPairingIssueHandler: jest.fn((deps) => {
    mockPairingCreationCalls.push({ kind: 'issue', deps });
    return mockPairingIssueHandler;
  }),
  createPairingApproveHandler: jest.fn((deps) => {
    mockPairingCreationCalls.push({ kind: 'approve', deps });
    return mockPairingApproveHandler;
  }),
}));

jest.mock('~/server/services/Device/currentDeviceHttpHandler', () => ({
  createCurrentDeviceStatusHandler: jest.fn((deps) => {
    mockCurrentCreationCalls.push({ kind: 'status', deps });
    return mockCurrentStatusHandler;
  }),
  createCurrentDeviceRenewHandler: jest.fn((deps) => {
    mockCurrentCreationCalls.push({ kind: 'renew', deps });
    return mockCurrentRenewHandler;
  }),
}));

const devicesRouter = require('../devices');

function createApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/devices', devicesRouter);
  return app;
}

beforeEach(() => {
  jest.clearAllMocks();
});

describe('Device owner routes', () => {
  it('runs JWT auth before POST /current/retire handler', async () => {
    const res = await request(createApp()).post('/api/devices/current/retire').send({});
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      ok: true,
      authenticated: true,
      userId: 'route-user',
    });
    expect(mockRequireJwtAuth).toHaveBeenCalledTimes(1);
    expect(mockRetireHandler).toHaveBeenCalledTimes(1);
  });

  it('rejects unauthenticated requests before the retire handler runs', async () => {
    // A denying auth middleware stands in for an expired/invalid token.
    mockRequireJwtAuth.mockImplementationOnce((_req, res) =>
      res.status(401).json({ ok: false, code: 'UNAUTHORIZED' }),
    );
    const res = await request(createApp()).post('/api/devices/current/retire').send({});
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ ok: false, code: 'UNAUTHORIZED' });
    expect(mockRetireHandler).not.toHaveBeenCalled();
  });

  it('exposes only POST /current/retire and no other verb or device endpoint', async () => {
    const app = createApp();
    for (const method of ['get', 'put', 'patch', 'delete']) {
      const res = await request(app)[method]('/api/devices/current/retire');
      expect(res.status).toBe(404);
    }
    expect(mockRetireHandler).not.toHaveBeenCalled();

    const unknown = await request(app).post('/api/devices/currentregister').send({});
    expect(unknown.status).toBe(404);
    expect(mockRetireHandler).not.toHaveBeenCalled();
  });

  it('does not expose GET /current/retire', async () => {
    const res = await request(createApp()).get('/api/devices/current/retire');
    expect(res.status).toBe(404);
    expect(mockRetireHandler).not.toHaveBeenCalled();
  });

  it('constructs the handler once with server-owned dependencies', () => {
    expect(handlerCreationCalls).toHaveLength(1);
    const deps = handlerCreationCalls[0];
    expect(deps).toHaveProperty('db');
    expect(deps).toHaveProperty('tenantContext');
    expect(typeof deps.tenantContext.getActiveTenantId).toBe('function');
    expect(deps.tenantContext.alsAbsencePermitted).toBe(false);
  });
});

describe('Device pairing and current-device routes', () => {
  const ENDPOINTS = [
    ['post', '/api/devices/pairing/challenge', () => mockPairingChallengeHandler],
    ['post', '/api/devices/pairing/issue', () => mockPairingIssueHandler],
    ['post', '/api/devices/pairing/approve', () => mockPairingApproveHandler],
    ['get', '/api/devices/current', () => mockCurrentStatusHandler],
    ['post', '/api/devices/current/renew', () => mockCurrentRenewHandler],
  ];

  it.each(ENDPOINTS)('runs JWT auth before the %s %s handler', async (method, path, handlerOf) => {
    const res = await request(createApp())[method](path).send({});
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.userId).toBe('route-user');
    expect(mockRequireJwtAuth).toHaveBeenCalledTimes(1);
    expect(handlerOf()).toHaveBeenCalledTimes(1);
  });

  it.each(ENDPOINTS)(
    'rejects unauthenticated %s %s before the handler runs',
    async (method, path, handlerOf) => {
      mockRequireJwtAuth.mockImplementationOnce((_req, res) =>
        res.status(401).json({ ok: false, code: 'UNAUTHORIZED' }),
      );
      const res = await request(createApp())[method](path).send({});
      expect(res.status).toBe(401);
      expect(res.body).toEqual({ ok: false, code: 'UNAUTHORIZED' });
      expect(handlerOf()).not.toHaveBeenCalled();
    },
  );

  it('keeps the retirement endpoint and adds no registration surface', async () => {
    const app = createApp();
    for (const path of [
      '/api/devices/registration/challenge',
      '/api/devices/registration/complete',
      '/api/devices/pairing',
      '/api/devices/pair',
      '/api/devices/current/status',
    ]) {
      const res = await request(app).post(path).send({});
      expect(res.status).toBe(404);
    }
    expect(mockPairingChallengeHandler).not.toHaveBeenCalled();
    expect(mockPairingIssueHandler).not.toHaveBeenCalled();
    expect(mockPairingApproveHandler).not.toHaveBeenCalled();
    expect(mockCurrentStatusHandler).not.toHaveBeenCalled();
    expect(mockCurrentRenewHandler).not.toHaveBeenCalled();
  });

  it('rejects unsupported verbs on the new endpoints', async () => {
    const app = createApp();
    for (const method of ['put', 'patch', 'delete']) {
      const res = await request(app)[method]('/api/devices/current').send({});
      expect(res.status).toBe(404);
      const pairing = await request(app)[method]('/api/devices/pairing/issue').send({});
      expect(pairing.status).toBe(404);
    }
    expect(mockCurrentStatusHandler).not.toHaveBeenCalled();
    expect(mockPairingIssueHandler).not.toHaveBeenCalled();
  });

  it('constructs every new handler once with server-owned seams only', () => {
    expect(mockPairingCreationCalls.map((entry) => entry.kind)).toEqual([
      'challenge',
      'issue',
      'approve',
    ]);
    expect(mockCurrentCreationCalls.map((entry) => entry.kind)).toEqual(['status', 'renew']);

    for (const { deps } of [...mockPairingCreationCalls, ...mockCurrentCreationCalls]) {
      expect(deps).toHaveProperty('db');
      expect(deps).toHaveProperty('tenantContext');
      expect(typeof deps.tenantContext.getActiveTenantId).toBe('function');
      expect(deps.tenantContext.alsAbsencePermitted).toBe(false);
      // No request container is ever captured at construction time.
      for (const forbidden of ['req', 'request', 'res', 'body', 'query', 'params', 'headers']) {
        expect(deps).not.toHaveProperty(forbidden);
      }
    }

    // Frozen canonical domain separator and a server-derived source descriptor are injected by the
    // route module; the accepted services never hard-code them.
    const challenge = mockPairingCreationCalls.find((entry) => entry.kind === 'challenge').deps;
    expect(challenge.domainTag).toBe('cbhr:device:pairing-open:v1');

    const issue = mockPairingCreationCalls.find((entry) => entry.kind === 'issue').deps;
    expect(issue.domainTag).toBe('cbhr:device:pairing-open:v1');
    expect(typeof issue.requestSource).toBe('string');
    expect(issue.requestSource.length).toBeGreaterThan(0);
  });
});

/* ============================================================================
 * Suite B — real handlers + real accepted services over a real MongoDB
 *
 * The genuine `@librechat/data-schemas` model registry cannot be loaded under Jest in this
 * worktree (the workspace packages are unbuilt: `librechat-data-provider/dist` is absent), so the
 * four models below are a DISCLOSED test double that mirrors the frozen schema files field for
 * field. Everything above the models is product code: the real `pairingSessionService`,
 * `authorityService`, `crypto`, `currentOwnerDeviceResolver`, `auditSink` and the real HTTP
 * handlers under test. The real-registry path is covered by the E1 harness (`tests/device/e1/**`).
 * ========================================================================== */

const { randomUUID, generateKeyPairSync, sign } = require('node:crypto');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');

const TENANT = 'tenant-t7-lab';
const OTHER_TENANT = 'tenant-t7-foreign';
const USER_A = 'user-t7-owner-a';
const USER_B = 'user-t7-owner-b';
const BASE_NOW = 1792000000000;
const PAIRING_OPEN_DOMAIN = 'cbhr:device:pairing-open:v1';
const PAIRING_ISSUE_SOURCE = 'local-lab:device-pairing-issue';
const LAB_PEPPER = Buffer.from('t7-lab-only-lookup-pepper-0001', 'utf8');
const LEASE_TTL_MS = 172800000;
const CODE_TTL_MS = 300000;

function defineModels() {
  const deviceAuthoritySchema = new mongoose.Schema({
    _id: { type: String, required: true },
    tenantId: { type: String, required: true },
    deviceKeyId: { type: String, required: true },
    devicePublicKey: { type: String, required: true },
    deviceName: { type: String },
    platform: { type: String },
    agentVersion: { type: String },
    identityState: {
      type: String,
      enum: ['pending', 'active', 'retired'],
      required: true,
    },
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
    grantProof: {
      ownerConfirmedAt: { type: Date, default: null },
      endpointSignatureVerifiedAt: { type: Date, default: null },
      verifiedKeyId: { type: String, default: null },
      localApprovalNonceHash: { type: String, default: null },
    },
    prevOwner: { type: String, default: null },
    prevGrantId: { type: String, default: null },
    prevEpoch: { type: Number, default: null },
  });
  deviceAuthoritySchema.index({ deviceKeyId: 1, tenantId: 1 }, { unique: true });
  deviceAuthoritySchema.index(
    { ownerId: 1, tenantId: 1 },
    { unique: true, partialFilterExpression: { leaseState: 'active' } },
  );

  const pairingSessionSchema = new mongoose.Schema({
    tenantId: { type: String, required: true },
    deviceId: { type: String, required: true },
    deviceKeyId: { type: String, required: true },
    lookupTag: { type: String, required: true },
    state: {
      type: String,
      required: true,
      enum: [
        'open',
        'claim_pending',
        'consumed',
        'denied',
        'failed',
        'expired',
        'superseded',
        'exhausted',
      ],
    },
    sessionVersion: { type: Number, required: true, default: 0, min: 0 },
    pendingOwnerId: { type: String, default: null },
    attemptsUsed: { type: Number, required: true, default: 0, min: 0 },
    issuedAt: { type: Date, required: true },
    expiresAt: { type: Date, required: true },
    claimedAt: { type: Date, default: null },
    claim: {
      challengeRef: { type: String, default: null },
      openedAt: { type: Date, default: null },
      expectedEpoch: { type: Number, default: null, min: 0 },
    },
    consumedAt: { type: Date, default: null },
    grantedGrantId: { type: String, default: null },
    issuedFromSourceHash: { type: String, default: null },
    deviceSessionId: { type: String, default: null },
  });
  pairingSessionSchema.index(
    { tenantId: 1, lookupTag: 1 },
    { unique: true, partialFilterExpression: { state: { $in: ['open', 'claim_pending'] } } },
  );
  pairingSessionSchema.index(
    { deviceId: 1, tenantId: 1 },
    { unique: true, partialFilterExpression: { state: { $in: ['open', 'claim_pending'] } } },
  );

  const challengeSchema = new mongoose.Schema({
    challengeHash: { type: String, required: true },
    purpose: {
      type: String,
      enum: ['registration', 'pairing-open', 'pairing-claim', 'renewal'],
      required: true,
    },
    deviceId: { type: String, default: null },
    deviceKeyId: { type: String, default: null },
    tenantId: { type: String, required: true },
    boundPairingSessionId: { type: String, default: null },
    boundOwnerId: { type: String, default: null },
    boundGrantId: { type: String, default: null },
    boundEpoch: { type: Number, default: null, min: 0 },
    boundSessionVersion: { type: Number, default: null, min: 0 },
    issuedAt: { type: Date, required: true },
    expiresAt: { type: Date, required: true },
    consumedAt: { type: Date, default: null },
  });
  challengeSchema.index({ challengeHash: 1 }, { unique: true });

  const auditEventSchema = new mongoose.Schema({
    tenantId: { type: String, required: true },
    deviceId: { type: String, default: null },
    ownerId: { type: String, default: null },
    grantId: { type: String, default: null },
    epoch: { type: Number, default: null },
    seq: { type: Number, default: null },
    kind: {
      type: String,
      enum: [
        'register',
        'grant',
        'renew',
        'revoke',
        'expire',
        'retire',
        'release',
        'claim-refused',
      ],
      required: true,
    },
    ts: { type: Date, required: true },
    actor: { type: String, default: null },
    reasonCode: { type: String, default: null },
  });
  auditEventSchema.index(
    { tenantId: 1, deviceId: 1, epoch: 1, seq: 1 },
    {
      unique: true,
      partialFilterExpression: {
        deviceId: { $type: 'string' },
        epoch: { $type: 'number' },
        seq: { $type: 'number' },
      },
    },
  );

  return {
    DeviceAuthority: mongoose.model('T7DeviceAuthority', deviceAuthoritySchema),
    PairingSession: mongoose.model('T7PairingSession', pairingSessionSchema),
    Challenge: mongoose.model('T7Challenge', challengeSchema),
    AuditEvent: mongoose.model('T7AuditEvent', auditEventSchema),
  };
}

/** Wraps every model in a counting proxy so "zero model calls" is observable per request. */
function makeCountingDb(models) {
  const calls = [];
  const wrap = (model, name) =>
    new Proxy(model, {
      get(target, property) {
        const value = Reflect.get(target, property);
        if (typeof value === 'function' && typeof property === 'string') {
          return (...args) => {
            calls.push(`${name}.${property}`);
            return value.apply(target, args);
          };
        }
        return value;
      },
    });
  return {
    calls,
    db: {
      DeviceAuthority: wrap(models.DeviceAuthority, 'DeviceAuthority'),
      PairingSession: wrap(models.PairingSession, 'PairingSession'),
      Challenge: wrap(models.Challenge, 'Challenge'),
      AuditEvent: wrap(models.AuditEvent, 'AuditEvent'),
    },
  };
}

function makeMockRes() {
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
  return res;
}

describe('Device pairing and current-device HTTP handlers (real services, real MongoDB)', () => {
  let mongo;
  let models;
  let counting;
  let app;
  let handlers;
  let currentUser;
  let currentTenant;
  let currentNow;
  const deviceCrypto = jest.requireActual('~/server/services/Device/crypto');

  const clock = { now: () => currentNow };
  const tenantContext = {
    getActiveTenantId: () => currentTenant,
    alsAbsencePermitted: false,
  };

  function makeDeviceKey() {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const der = publicKey.export({ type: 'spki', format: 'der' });
    return { spkiB64u: Buffer.from(der).toString('base64url'), privateKey };
  }

  function signPairingOpen({ key, tenantId, deviceId, deviceKeyId, challengeHash, issuedAt }) {
    const message = deviceCrypto.canonicalEncode({
      domainTag: PAIRING_OPEN_DOMAIN,
      fields: ['pairing-open', tenantId, deviceId, deviceKeyId, challengeHash, issuedAt],
    });
    return sign(null, message, key.privateKey).toString('base64url');
  }

  async function seedDevice({
    key,
    tenantId = TENANT,
    ownerId = null,
    identityState = 'pending',
    leaseState = 'never',
    epoch = 0,
    grantId = null,
    expiresAt = null,
    renewalCount = 0,
  }) {
    const deviceKeyId = deviceCrypto.thumbprintB64u(key.spkiB64u);
    const deviceId = `device-${randomUUID()}`;
    await models.DeviceAuthority.create(
      [
        {
          _id: deviceId,
          tenantId,
          deviceKeyId,
          devicePublicKey: key.spkiB64u,
          deviceName: 't7-test-device',
          platform: 'win32',
          agentVersion: '0.0.1',
          identityState,
          leaseState,
          epoch,
          ownerId,
          grantId,
          registeredAt: new Date(currentNow),
          expiresAt,
          renewalCount,
        },
      ],
      { writeConcern: { w: 'majority', j: true } },
    );
    return { deviceId, deviceKeyId };
  }

  async function clearCollections() {
    await Promise.all([
      models.DeviceAuthority.deleteMany({}),
      models.PairingSession.deleteMany({}),
      models.Challenge.deleteMany({}),
      models.AuditEvent.deleteMany({}),
    ]);
  }

  /** Runs the real challenge + issue HTTP legs for one tenant and returns both responses. */
  async function issueCode(key, seeded, tenantId = TENANT) {
    const challenge = await request(app)
      .post('/api/devices/pairing/challenge')
      .send({ devicePublicKey: key.spkiB64u });
    expect(challenge.status).toBe(200);
    const issued = await request(app)
      .post('/api/devices/pairing/issue')
      .send({
        devicePublicKey: key.spkiB64u,
        challengeHash: challenge.body.challengeHash,
        signatureB64u: signPairingOpen({
          key,
          tenantId,
          deviceId: seeded.deviceId,
          deviceKeyId: seeded.deviceKeyId,
          challengeHash: challenge.body.challengeHash,
          issuedAt: challenge.body.issuedAt,
        }),
      });
    return { challenge, issued };
  }

  beforeAll(async () => {
    mongo = await MongoMemoryServer.create({ binary: { version: '7.0.14' } });
    await mongoose.connect(mongo.getUri(), { dbName: 'cbhr_rdc_phase1_t7_http' });
    models = defineModels();
    await Promise.all([
      models.DeviceAuthority.init(),
      models.PairingSession.init(),
      models.Challenge.init(),
      models.AuditEvent.init(),
    ]);
    counting = makeCountingDb(models);

    const pairingHttp = jest.requireActual('~/server/services/Device/pairingHttpHandler');
    const currentHttp = jest.requireActual('~/server/services/Device/currentDeviceHttpHandler');
    handlers = {
      challenge: pairingHttp.createPairingChallengeHandler({
        db: counting.db,
        tenantContext,
        clock,
        domainTag: PAIRING_OPEN_DOMAIN,
        pepperLookup: LAB_PEPPER,
      }),
      issue: pairingHttp.createPairingIssueHandler({
        db: counting.db,
        tenantContext,
        clock,
        domainTag: PAIRING_OPEN_DOMAIN,
        requestSource: PAIRING_ISSUE_SOURCE,
        pepperLookup: LAB_PEPPER,
      }),
      approve: pairingHttp.createPairingApproveHandler({
        db: counting.db,
        tenantContext,
        clock,
        pepperLookup: LAB_PEPPER,
      }),
      status: currentHttp.createCurrentDeviceStatusHandler({
        db: counting.db,
        tenantContext,
        clock,
      }),
      renew: currentHttp.createCurrentDeviceRenewHandler({
        db: counting.db,
        tenantContext,
        clock,
      }),
    };

    app = express();
    app.use(express.json());
    app.use((req, _res, next) => {
      req.user = currentUser;
      req.authStrategy = 'jwt';
      next();
    });
    app.get('/api/devices/current', handlers.status);
    app.post('/api/devices/current/renew', handlers.renew);
    app.post('/api/devices/pairing/challenge', handlers.challenge);
    app.post('/api/devices/pairing/issue', handlers.issue);
    app.post('/api/devices/pairing/approve', handlers.approve);
  });

  afterAll(async () => {
    await mongoose.disconnect();
    await mongo.stop();
  });

  beforeEach(async () => {
    currentUser = { id: USER_A, tenantId: TENANT };
    currentTenant = TENANT;
    currentNow = BASE_NOW;
    counting.calls.length = 0;
    await clearCollections();
  });

  describe('identity and authority injection is rejected before any model access', () => {
    const INJECTIONS = [
      { devicePublicKey: 'placeholder', deviceId: 'injected-device' },
      { devicePublicKey: 'placeholder', ownerId: 'injected-owner' },
      { devicePublicKey: 'placeholder', tenantId: OTHER_TENANT },
      { devicePublicKey: 'placeholder', role: 'admin' },
      { devicePublicKey: 'placeholder', principal: 'injected-principal' },
      { devicePublicKey: 'placeholder', authority: 'injected-authority' },
      { devicePublicKey: 'placeholder', epoch: 7 },
      { devicePublicKey: 'placeholder', grantId: 'injected-grant' },
      { devicePublicKey: 'placeholder', proof: { signatureB64u: 'injected' } },
      { code: '123456', deviceId: 'injected-device' },
      { code: '123456', ownerId: 'injected-owner' },
    ];

    it.each(INJECTIONS)('POST /pairing/issue rejects %j with zero model calls', async (body) => {
      const res = await request(app).post('/api/devices/pairing/issue').send(body);
      expect(res.status).toBe(400);
      expect(res.body).toEqual({
        ok: false,
        code: 'REQUEST_SUPPLIED_IDENTITY_REJECTED',
        message: expect.any(String),
      });
      expect(counting.calls).toEqual([]);
    });

    it.each(INJECTIONS)('POST /pairing/approve rejects %j with zero model calls', async (body) => {
      const res = await request(app).post('/api/devices/pairing/approve').send(body);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('REQUEST_SUPPLIED_IDENTITY_REJECTED');
      expect(counting.calls).toEqual([]);
    });

    it('rejects identity injection in the body of challenge, current and renew', async () => {
      const challenge = await request(app)
        .post('/api/devices/pairing/challenge')
        .send({ devicePublicKey: 'placeholder', deviceId: 'injected-device' });
      expect(challenge.status).toBe(400);
      expect(challenge.body.code).toBe('REQUEST_SUPPLIED_IDENTITY_REJECTED');

      const status = await request(app).get('/api/devices/current').send({ ownerId: USER_B });
      expect(status.status).toBe(400);
      expect(status.body.code).toBe('REQUEST_SUPPLIED_IDENTITY_REJECTED');

      const renew = await request(app)
        .post('/api/devices/current/renew')
        .send({ deviceId: 'injected-device' });
      expect(renew.status).toBe(400);
      expect(renew.body.code).toBe('REQUEST_SUPPLIED_IDENTITY_REJECTED');

      expect(counting.calls).toEqual([]);
    });

    it('rejects identity injection in the query string with zero model calls', async () => {
      const status = await request(app).get('/api/devices/current?deviceId=injected-device');
      expect(status.status).toBe(400);
      expect(status.body.code).toBe('REQUEST_SUPPLIED_IDENTITY_REJECTED');

      const renew = await request(app).post(`/api/devices/current/renew?tenantId=${OTHER_TENANT}`);
      expect(renew.status).toBe(400);
      expect(renew.body.code).toBe('REQUEST_SUPPLIED_IDENTITY_REJECTED');

      const challenge = await request(app).post('/api/devices/pairing/challenge?ownerId=someone');
      expect(challenge.status).toBe(400);
      expect(challenge.body.code).toBe('REQUEST_SUPPLIED_IDENTITY_REJECTED');

      const issue = await request(app).post('/api/devices/pairing/issue?challengeHash=abc');
      expect(issue.status).toBe(400);
      expect(issue.body.code).toBe('REQUEST_SUPPLIED_IDENTITY_REJECTED');

      const approve = await request(app).post('/api/devices/pairing/approve?grantId=x');
      expect(approve.status).toBe(400);
      expect(approve.body.code).toBe('REQUEST_SUPPLIED_IDENTITY_REJECTED');

      expect(counting.calls).toEqual([]);
    });

    it('rejects route params on every handler with zero model calls', async () => {
      for (const handler of Object.values(handlers)) {
        const res = makeMockRes();
        await handler(
          { params: { deviceId: 'injected-device' }, query: {}, body: {}, user: currentUser },
          res,
        );
        expect(res.statusCode).toBe(400);
        expect(res.body.code).toBe('REQUEST_SUPPLIED_IDENTITY_REJECTED');
      }
      expect(counting.calls).toEqual([]);
    });

    it('rejects a nested container that hides identity in a protocol-shaped field', async () => {
      const res = await request(app)
        .post('/api/devices/pairing/approve')
        .send({ code: { $ne: null } });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('REQUEST_SUPPLIED_IDENTITY_REJECTED');
      expect(counting.calls).toEqual([]);
    });
  });

  describe('server-side tenant and principal resolution', () => {
    it('fails closed on a session/tenant mismatch with zero model calls', async () => {
      currentUser = { id: USER_A, tenantId: OTHER_TENANT };
      const res = await request(app).get('/api/devices/current');
      expect(res.status).toBe(403);
      expect(res.body).toEqual({
        ok: false,
        code: 'TENANT_MISMATCH',
        message: expect.any(String),
      });
      expect(counting.calls).toEqual([]);
    });

    it('fails closed when the authenticated session carries no principal', async () => {
      currentUser = { tenantId: TENANT };
      const res = await request(app).post('/api/devices/current/renew');
      expect(res.status).toBe(403);
      expect(res.body.code).toBe('NOT_OWNER');
      expect(counting.calls).toEqual([]);
    });

    it('fails closed when no tenant is active', async () => {
      currentTenant = null;
      const res = await request(app).post('/api/devices/pairing/approve').send({ code: '123456' });
      expect(res.status).toBe(403);
      expect(res.body.code).toBe('TENANT_MISMATCH');
      expect(counting.calls).toEqual([]);
    });

    it('never reads a device identity from the request: only the session principal resolves', async () => {
      const key = makeDeviceKey();
      const seeded = await seedDevice({
        key,
        ownerId: USER_B,
        identityState: 'active',
        leaseState: 'active',
        epoch: 3,
        grantId: 'grant-b',
        expiresAt: new Date(currentNow + 10 * 3600000),
      });
      const res = await request(app).get('/api/devices/current');
      expect(res.status).toBe(404);
      expect(res.body.code).toBe('UNKNOWN_DEVICE');
      expect(JSON.stringify(res.body)).not.toContain(seeded.deviceId);
    });
  });

  describe('POST /api/devices/pairing/challenge', () => {
    it('mints a single-use pairing-open challenge for a registered endpoint', async () => {
      const key = makeDeviceKey();
      const seeded = await seedDevice({ key });

      const res = await request(app)
        .post('/api/devices/pairing/challenge')
        .send({ devicePublicKey: key.spkiB64u });

      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
      expect(res.body.challengeHash).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(res.body.issuedAt).toMatch(/^\d+$/);
      expect(res.body.issuedAt).toBe(String(currentNow));
      expect(new Date(res.body.expiresAt).getTime()).toBe(currentNow + 120000);
      expect(res.body).not.toHaveProperty('challenge');
      expect(res.body).not.toHaveProperty('deviceId');

      const row = await models.Challenge.findOne({
        challengeHash: res.body.challengeHash,
        tenantId: TENANT,
        purpose: 'pairing-open',
      }).lean();
      expect(row).not.toBeNull();
      expect(row.deviceId).toBe(seeded.deviceId);
      expect(row.deviceKeyId).toBe(seeded.deviceKeyId);
      expect(row.consumedAt).toBeNull();
    });

    it('uniformly rejects malformed key material', async () => {
      const res = await request(app)
        .post('/api/devices/pairing/challenge')
        .send({ devicePublicKey: 'not-a-base64url-key!' });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('INVALID_OR_EXPIRED_CODE');
      expect(await models.Challenge.countDocuments({})).toBe(0);
    });

    it('reports UNKNOWN_DEVICE for a well-formed key with no registered identity', async () => {
      const key = makeDeviceKey();
      const res = await request(app)
        .post('/api/devices/pairing/challenge')
        .send({ devicePublicKey: key.spkiB64u });
      expect(res.status).toBe(404);
      expect(res.body.code).toBe('UNKNOWN_DEVICE');
      expect(await models.Challenge.countDocuments({})).toBe(0);
    });

    it('refuses a retired identity', async () => {
      const key = makeDeviceKey();
      await seedDevice({ key, identityState: 'retired', leaseState: 'revoked' });
      const res = await request(app)
        .post('/api/devices/pairing/challenge')
        .send({ devicePublicKey: key.spkiB64u });
      expect(res.status).toBe(409);
      expect(res.body.code).toBe('DEVICE_IDENTITY_REVOKED');
      expect(await models.Challenge.countDocuments({})).toBe(0);
    });

    it('fails closed when no lookup pepper is configured server-side', async () => {
      const pairingHttp = jest.requireActual('~/server/services/Device/pairingHttpHandler');
      const handler = pairingHttp.createPairingChallengeHandler({
        db: counting.db,
        tenantContext,
        clock,
        domainTag: PAIRING_OPEN_DOMAIN,
      });
      const key = makeDeviceKey();
      const res = makeMockRes();
      await handler(
        { params: {}, query: {}, body: { devicePublicKey: key.spkiB64u }, user: currentUser },
        res,
      );
      expect(res.statusCode).toBe(500);
      expect(res.body.code).toBe('WRITE_OUTCOME_UNCERTAIN');
      expect(counting.calls).toEqual([]);
    });
  });

  describe('POST /api/devices/pairing/issue', () => {
    it('issues a six-digit single-use code and persists only its HMAC lookup tag', async () => {
      const key = makeDeviceKey();
      const seeded = await seedDevice({ key });
      const { challenge, issued } = await issueCode(key, seeded);

      expect(challenge.status).toBe(200);
      expect(issued.status).toBe(200);
      expect(issued.body.ok).toBe(true);
      expect(issued.body.code).toMatch(/^\d{6}$/);
      expect(issued.body.state).toBe('open');
      expect(issued.body.pairingSessionId).toEqual(expect.any(String));
      expect(issued.body).not.toHaveProperty('lookupTag');

      const rows = await models.PairingSession.find({ tenantId: TENANT }).lean();
      expect(rows).toHaveLength(1);
      const row = rows[0];
      expect(row.deviceId).toBe(seeded.deviceId);
      expect(row.deviceKeyId).toBe(seeded.deviceKeyId);
      expect(row.lookupTag).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(row.expiresAt.getTime() - row.issuedAt.getTime()).toBe(CODE_TTL_MS);
      // The plaintext code is never persisted anywhere on the session row.
      expect(JSON.stringify(row)).not.toContain(issued.body.code);
      // The tag is exactly the tenant-bound HMAC of the returned code.
      expect(
        deviceCrypto.computeLookupTag({
          code: issued.body.code,
          tenantId: TENANT,
          pepperLookup: LAB_PEPPER,
        }),
      ).toBe(row.lookupTag);
      // The pairing-open challenge was spent exactly once.
      const spent = await models.Challenge.findOne({
        challengeHash: challenge.body.challengeHash,
      }).lean();
      expect(spent.consumedAt).toBeInstanceOf(Date);
    });

    it('uniformly rejects a proof that does not verify, with no session row', async () => {
      const key = makeDeviceKey();
      await seedDevice({ key });
      const challenge = await request(app)
        .post('/api/devices/pairing/challenge')
        .send({ devicePublicKey: key.spkiB64u });
      expect(challenge.status).toBe(200);

      const res = await request(app)
        .post('/api/devices/pairing/issue')
        .send({
          devicePublicKey: key.spkiB64u,
          challengeHash: challenge.body.challengeHash,
          signatureB64u: 'A'.repeat(86),
        });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('INVALID_OR_EXPIRED_CODE');
      expect(await models.PairingSession.countDocuments({})).toBe(0);
    });

    it('uniformly rejects an unknown challenge hash', async () => {
      const key = makeDeviceKey();
      await seedDevice({ key });
      const res = await request(app)
        .post('/api/devices/pairing/issue')
        .send({
          devicePublicKey: key.spkiB64u,
          challengeHash: deviceCrypto.challengeHash(deviceCrypto.newChallengeNonce()),
          signatureB64u: 'A'.repeat(86),
        });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('INVALID_OR_EXPIRED_CODE');
      expect(await models.PairingSession.countDocuments({})).toBe(0);
    });

    it('refuses issuance while a live lease is held', async () => {
      const key = makeDeviceKey();
      const seeded = await seedDevice({
        key,
        ownerId: USER_A,
        identityState: 'active',
        leaseState: 'active',
        epoch: 2,
        grantId: 'grant-live',
        expiresAt: new Date(currentNow + 3600000),
      });
      const { issued } = await issueCode(key, seeded);
      expect(issued.status).toBe(409);
      expect(issued.body.code).toBe('DEVICE_ALREADY_PAIRED_USE_RENEW');
      expect(await models.PairingSession.countDocuments({})).toBe(0);
    });
  });

  describe('POST /api/devices/pairing/approve', () => {
    it('binds the pending session to the authenticated owner and grants no authority', async () => {
      const key = makeDeviceKey();
      const seeded = await seedDevice({ key });
      const { issued } = await issueCode(key, seeded);
      expect(issued.status).toBe(200);

      const res = await request(app)
        .post('/api/devices/pairing/approve')
        .send({ code: issued.body.code });

      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
      expect(res.body.state).toBe('claim_pending');
      expect(res.body.deviceKeyId).toBe(seeded.deviceKeyId);
      expect(res.body).not.toHaveProperty('code');

      const row = await models.PairingSession.findOne({ tenantId: TENANT }).lean();
      expect(row.state).toBe('claim_pending');
      expect(row.pendingOwnerId).toBe(USER_A);
      expect(row.attemptsUsed).toBe(1);

      // Approve is LP-2 only: no identity/lease change, no grant, no grant id.
      const authority = await models.DeviceAuthority.findOne({ _id: seeded.deviceId }).lean();
      expect(authority.identityState).toBe('pending');
      expect(authority.leaseState).toBe('never');
      expect(authority.ownerId).toBeNull();
      expect(authority.grantId).toBeNull();
      expect(authority.epoch).toBe(0);
    });

    it('returns the uniform miss for an unknown code and for an expired code', async () => {
      const key = makeDeviceKey();
      const seeded = await seedDevice({ key });
      const { issued } = await issueCode(key, seeded);
      expect(issued.status).toBe(200);

      const unknownCode = issued.body.code === '000000' ? '111111' : '000000';
      const unknown = await request(app)
        .post('/api/devices/pairing/approve')
        .send({ code: unknownCode });
      expect(unknown.status).toBe(400);

      currentNow = BASE_NOW + CODE_TTL_MS;
      const expired = await request(app)
        .post('/api/devices/pairing/approve')
        .send({ code: issued.body.code });
      expect(expired.status).toBe(400);

      expect(unknown.body).toEqual(expired.body);
      expect(unknown.body.code).toBe('INVALID_OR_EXPIRED_CODE');

      const row = await models.PairingSession.findOne({ tenantId: TENANT }).lean();
      expect(row.state).toBe('open');
      expect(row.pendingOwnerId).toBeNull();
    });

    it('treats a malformed code as the uniform miss', async () => {
      const res = await request(app)
        .post('/api/devices/pairing/approve')
        .send({ code: 'not-a-code' });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('INVALID_OR_EXPIRED_CODE');
    });

    it('never resolves a code issued for another tenant', async () => {
      const key = makeDeviceKey();
      const seeded = await seedDevice({ key, tenantId: OTHER_TENANT });
      currentUser = { id: USER_A, tenantId: OTHER_TENANT };
      currentTenant = OTHER_TENANT;
      const { issued } = await issueCode(key, seeded, OTHER_TENANT);
      expect(issued.status).toBe(200);

      currentUser = { id: USER_A, tenantId: TENANT };
      currentTenant = TENANT;
      const res = await request(app)
        .post('/api/devices/pairing/approve')
        .send({ code: issued.body.code });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('INVALID_OR_EXPIRED_CODE');
    });
  });

  describe('GET /api/devices/current', () => {
    it('returns only the safe status projection of the caller own device', async () => {
      const key = makeDeviceKey();
      const seeded = await seedDevice({
        key,
        ownerId: USER_A,
        identityState: 'active',
        leaseState: 'active',
        epoch: 4,
        grantId: 'grant-a',
        expiresAt: new Date(currentNow + 5 * 3600000),
        renewalCount: 2,
      });

      const res = await request(app).get('/api/devices/current');

      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        ok: true,
        tenantId: TENANT,
        deviceId: seeded.deviceId,
        identityState: 'active',
        leaseState: 'active',
        epoch: 4,
        expiresAt: new Date(currentNow + 5 * 3600000).toISOString(),
      });
      const serialized = JSON.stringify(res.body);
      for (const secretField of [
        'devicePublicKey',
        'deviceKeyId',
        'lookupTag',
        'grantId',
        'grantProof',
        'prevGrantId',
        'prevOwner',
      ]) {
        expect(serialized).not.toContain(secretField);
      }
    });

    it('reports UNKNOWN_DEVICE when the caller holds no current active device', async () => {
      const key = makeDeviceKey();
      await seedDevice({ key, identityState: 'active', leaseState: 'expired', epoch: 9 });

      const res = await request(app).get('/api/devices/current');
      expect(res.status).toBe(404);
      expect(res.body).toEqual({
        ok: false,
        code: 'UNKNOWN_DEVICE',
        message: expect.any(String),
      });
    });
  });

  describe('POST /api/devices/current/renew', () => {
    async function seedLiveLease({ expiresInMs = 10 * 3600000, epoch = 5 } = {}) {
      const key = makeDeviceKey();
      const seeded = await seedDevice({
        key,
        ownerId: USER_A,
        identityState: 'active',
        leaseState: 'active',
        epoch,
        grantId: `grant-${epoch}`,
        expiresAt: new Date(currentNow + expiresInMs),
        renewalCount: 0,
      });
      return { key, ...seeded };
    }

    it('renews strictly before expiry and extends the lease by exactly 48 hours', async () => {
      const seeded = await seedLiveLease({ expiresInMs: 10 * 3600000, epoch: 5 });

      const res = await request(app).post('/api/devices/current/renew');

      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
      expect(res.body.renewed).toBe(true);
      expect(res.body.deviceId).toBe(seeded.deviceId);
      expect(res.body.epoch).toBe(6);
      expect(res.body.renewalCount).toBe(1);
      expect(new Date(res.body.expiresAt).getTime()).toBe(currentNow + LEASE_TTL_MS);

      const row = await models.DeviceAuthority.findOne({ _id: seeded.deviceId }).lean();
      expect(row.epoch).toBe(6);
      expect(row.leaseState).toBe('active');
      expect(row.renewalCount).toBe(1);
      expect(row.grantId).not.toBe('grant-5');
      expect(row.expiresAt.getTime()).toBe(currentNow + LEASE_TTL_MS);
      expect(row.ownerId).toBe(USER_A);

      const audit = await models.AuditEvent.findOne({
        tenantId: TENANT,
        deviceId: seeded.deviceId,
        kind: 'renew',
      }).lean();
      expect(audit).not.toBeNull();
      expect(audit.epoch).toBe(6);
      expect(audit.ownerId).toBe(USER_A);
    });

    it('refuses a renewal inside the frozen five-second margin and commits nothing', async () => {
      const seeded = await seedLiveLease({ expiresInMs: 2000, epoch: 7 });

      const res = await request(app).post('/api/devices/current/renew');

      expect(res.status).toBe(409);
      expect(res.body).toEqual({
        ok: false,
        code: 'LEASE_EXPIRED',
        message: expect.any(String),
        committed: false,
        deviceId: seeded.deviceId,
        epoch: 7,
        expiresAt: new Date(currentNow + 2000).toISOString(),
      });

      const row = await models.DeviceAuthority.findOne({ _id: seeded.deviceId }).lean();
      expect(row.epoch).toBe(7);
      expect(row.renewalCount).toBe(0);
      expect(row.grantId).toBe('grant-7');
    });

    it('refuses a renewal after expiry and commits nothing', async () => {
      const seeded = await seedLiveLease({ expiresInMs: -1000, epoch: 8 });

      const res = await request(app).post('/api/devices/current/renew');

      expect(res.status).toBe(409);
      expect(res.body.code).toBe('LEASE_EXPIRED');
      expect(res.body.committed).toBe(false);

      const row = await models.DeviceAuthority.findOne({ _id: seeded.deviceId }).lean();
      expect(row.epoch).toBe(8);
      expect(row.renewalCount).toBe(0);
    });

    it('reports UNKNOWN_DEVICE when the caller holds no current device', async () => {
      const res = await request(app).post('/api/devices/current/renew');
      expect(res.status).toBe(404);
      expect(res.body.code).toBe('UNKNOWN_DEVICE');
    });

    it('never renews another principal device', async () => {
      const key = makeDeviceKey();
      const seeded = await seedDevice({
        key,
        ownerId: USER_B,
        identityState: 'active',
        leaseState: 'active',
        epoch: 3,
        grantId: 'grant-b',
        expiresAt: new Date(currentNow + 10 * 3600000),
      });

      const res = await request(app).post('/api/devices/current/renew');

      expect(res.status).toBe(404);
      expect(res.body.code).toBe('UNKNOWN_DEVICE');
      const row = await models.DeviceAuthority.findOne({ _id: seeded.deviceId }).lean();
      expect(row.epoch).toBe(3);
      expect(row.renewalCount).toBe(0);
      expect(row.ownerId).toBe(USER_B);
    });
  });
});
