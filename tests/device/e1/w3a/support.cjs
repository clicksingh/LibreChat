'use strict';

/**
 * W3-A / I11 shared fixture support (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Everything here is harness scaffolding: assertions, read-back helpers, a disclosed harness
 * admission-predicate oracle, and artifact plumbing. No product behaviour is implemented or
 * substituted here.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const fence = require('./fence.cjs');
const env = require('./env.cjs');

function currentRunKey() {
  return process.env.CBHR_W3A_RUN_KEY ?? 'run-unset';
}

function runsRoot() {
  return path.resolve(__dirname, '..', '..', '_phase1_evidence', 'w3', 'I11-runs');
}

/** Resolved lazily so a runner can set CBHR_W3A_RUN_KEY after requiring this module. */
function runDir(runKey) {
  return path.join(runsRoot(), runKey ?? currentRunKey());
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/** Creates a directory that is guaranteed free of stale files from an earlier run. */
function freshDir(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeJson(dir, name, value) {
  ensureDir(dir);
  const file = path.join(dir, name);
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  return file;
}

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex').toUpperCase();
}

function sha256Json(value) {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex').toUpperCase();
}

/** Explicit assertion ledger; every fixture reports each check with its observed value. */
function makeChecks() {
  const checks = [];
  return {
    checks,
    ok(name, condition, observed) {
      const pass = condition === true;
      checks.push({ name, ok: pass, observed: observed === undefined ? null : observed });
      return pass;
    },
    eq(name, actual, expected) {
      const pass = JSON.stringify(actual) === JSON.stringify(expected);
      checks.push({ name, ok: pass, observed: actual === undefined ? null : actual, expected });
      return pass;
    },
    fail(name, observed, expected) {
      checks.push({ name, ok: false, observed: observed === undefined ? null : observed, expected });
      return false;
    },
    failed() {
      return checks.filter((entry) => !entry.ok);
    },
    passed() {
      return checks.filter((entry) => entry.ok);
    },
  };
}

function statusFromChecks(checks, { productClaim = true } = {}) {
  const failed = checks.filter((entry) => !entry.ok);
  return {
    status: failed.length === 0 ? 'PASS' : 'PRODUCT_FAIL',
    productClaim,
    failedCount: failed.length,
    passedCount: checks.length - failed.length,
    failedAssertions: failed,
  };
}

/** Basic provenance block recorded with every fixture result. */
function provenance(context, extra = {}) {
  return {
    productFiles: env.PRODUCT_FILES,
    frozenRegistryModels: {
      path: context.modelInfo.barrelPath,
      registryKeys: context.modelInfo.keys,
      modelTypeof: context.facadeProvenance,
    },
    dbFacade: {
      kind: context.facadeKind,
      dbMode: context.dbMode,
      disclosure:
        context.dbMode === 'raw-registry'
          ? 'No db adapter: the services receive the genuine createModels(mongoose) registry (instrumented with a pass-through recording Proxy that delegates every call to the real Mongoose model and adds no behaviour).'
          : 'Test-only behaviour-free plain-object adapter over the genuine createModels(mongoose) models; it forwards every method to the real Mongoose model and adds no logic or fallback.',
    },
    trustedTenant: env.TENANT,
    foreignTenant: env.OTHER_TENANT,
    tenantPolicy: { kind: context.tenantPolicy.kind, allowed: context.tenantPolicy.allowed },
    localConsent: { kind: context.consent.kind, granted: context.consent.granted },
    injectedClock: { kind: context.clock.kind, base: env.constants.EPOCH_BASE_MS, valueNow: context.clock.now() },
    auditSink: { kind: context.audit.kind },
    mongoUri: fence.FROZEN_URI,
    sweepKnob: process.env.CBHR_PHASE1_SWEEP ?? 'unset',
    ...extra,
  };
}

/** Deterministic, hash-stable projection of a DeviceError (no secrets, no causes). */
function errorView(error) {
  if (!error) {
    return null;
  }
  return {
    name: error.name ?? null,
    code: error.code ?? null,
    httpStatus: error.httpStatus ?? null,
    disposition: error.disposition ?? null,
    retryable: error.retryable ?? null,
    message: error.message ?? null,
  };
}

/**
 * Harness-side evaluation of the frozen admission predicate over a real DB row.
 * This is a DISCLOSED ORACLE over product-produced state, never a product call.
 * frozen rule: allowed iff leaseState==='active' AND now < expiresAt AND
 * ownerId===owner AND epoch===epoch AND grantId===grantId AND identityState!=='retired'.
 */
function authorizePredicate(authority, { ownerId, epoch, grantId, now }) {
  if (authority === null || authority === undefined) {
    return { allowed: false, reason: 'NO_AUTHORITY_ROW' };
  }
  if (authority.identityState === 'retired') {
    return { allowed: false, reason: 'IDENTITY_RETIRED' };
  }
  if (authority.leaseState !== 'active') {
    return { allowed: false, reason: `LEASE_${String(authority.leaseState).toUpperCase()}` };
  }
  const expiresAt = authority.expiresAt ? new Date(authority.expiresAt).getTime() : null;
  if (expiresAt === null || !(now < expiresAt)) {
    return { allowed: false, reason: 'LEASE_EXPIRED_BARE' };
  }
  if (ownerId !== undefined && authority.ownerId !== ownerId) {
    return { allowed: false, reason: 'NOT_OWNER' };
  }
  if (epoch !== undefined && authority.epoch !== epoch) {
    return { allowed: false, reason: 'STALE_EPOCH' };
  }
  if (grantId !== undefined && authority.grantId !== grantId) {
    return { allowed: false, reason: 'STALE_GRANT' };
  }
  return { allowed: true, reason: 'LIVE_LEASE_MATCH' };
}

/** Public projection of an authority row for decision vectors (no secrets). */
function authorityView(authority, now) {
  if (!authority) {
    return null;
  }
  return {
    identityState: authority.identityState,
    leaseState: authority.leaseState,
    epoch: authority.epoch,
    ownerId: authority.ownerId,
    grantIdIssued: typeof authority.grantId === 'string' && authority.grantId.length > 0,
    grantIdLength: typeof authority.grantId === 'string' ? authority.grantId.length : 0,
    expiresAt: authority.expiresAt ? new Date(authority.expiresAt).toISOString() : null,
    activatedAt: authority.activatedAt ? new Date(authority.activatedAt).toISOString() : null,
    ttlMs:
      authority.expiresAt && authority.activatedAt
        ? new Date(authority.expiresAt).getTime() - new Date(authority.activatedAt).getTime()
        : null,
    renewalCount: authority.renewalCount ?? null,
    prevOwner: authority.prevOwner ?? null,
    prevGrantIdIssued: typeof authority.prevGrantId === 'string' && authority.prevGrantId.length > 0,
    prevEpoch: authority.prevEpoch ?? null,
    grantedByPairingSessionId: authority.grantedByPairingSessionId ?? null,
    authorizedNow: now === undefined ? null : authorizePredicate(authority, { now }).allowed,
  };
}

/** Real-model read-back (tenant-scoped, exact). */
async function readAuthorityRaw(models, deviceId, tenantId) {
  return models.DeviceAuthority.findOne({ _id: deviceId, tenantId }).lean();
}

async function countActiveOwners(models, ownerId, tenantId) {
  return models.DeviceAuthority.countDocuments({ ownerId, tenantId, leaseState: 'active' });
}

/**
 * Injectable DURABLE audit sink: writes the emitted event VERBATIM (including its null fields)
 * into the real `deviceauthorityevents` collection with the frozen majority+journal write
 * concern. Disclosed as a harness-provided sink; it adds or removes no field.
 */
function makeDurableRawAuditSink(client, dbName) {
  const events = [];
  const writes = [];
  return {
    kind: 'raw-driver-verbatim-durable-sink',
    events,
    writes,
    async audit(event) {
      const normalized = { ...event };
      events.push(normalized);
      const result = await client
        .db(dbName)
        .collection('deviceauthorityevents')
        .insertOne(normalized, { writeConcern: { w: 'majority', j: true } });
      writes.push({ acknowledged: result.acknowledged === true, insertedId: String(result.insertedId) });
    },
  };
}

/** Audit sink that persists through the REAL Mongoose AuditEvent model (used to expose G-5 drift). */
function makeModelAuditSink(models) {
  const events = [];
  const outcomes = [];
  return {
    kind: 'real-AuditEvent-model-sink',
    events,
    outcomes,
    async audit(event) {
      events.push({ ...event });
      try {
        await models.AuditEvent.create(event);
        outcomes.push({ ok: true, error: null });
      } catch (err) {
        outcomes.push({ ok: false, error: { name: err.name, message: err.message, paths: Object.keys(err.errors ?? {}) } });
        throw err;
      }
    },
  };
}

function makeThrowingAuditSink() {
  const events = [];
  return {
    kind: 'throwing-sink-after-commit',
    events,
    async audit(event) {
      events.push({ ...event });
      throw new Error('LAB_INJECTED_AUDIT_SINK_FAILURE');
    },
  };
}

/**
 * Builds the trusted-tenant context seam from the FIXED harness-lab trust only.
 *
 * Identity source disclosure: the tenant/user/device triple is taken from the
 * fixture's own written parameters, never from a request container. This is the
 * harness analogue of the server resolving ALS + the authenticated session: the
 * fixed lab principal and lab tenant play both roles, deterministically.
 */
function makeTenantContext({ tenantId = env.TENANT, principalId, deviceId } = {}) {
  const state = {
    kind: 'fixed-trusted-lab-tenant-context',
    tenantId,
    principalId: principalId ?? env.OWNER_A,
    deviceId: deviceId ?? null,
  };
  return {
    kind: state.kind,
    state,
    getActiveTenantId() {
      if (!isActiveTenant(state.tenantId)) {
        throw new Error('LAB_TENANT_CONTEXT_INACTIVE');
      }
      return state.tenantId;
    },
    alsAbsencePermitted: true,
  };
}

/** True when the lab tenant context still points at the fixture's trusted tenant. */
function isActiveTenant(tenantId) {
  return typeof tenantId === 'string' && tenantId.length > 0 && tenantId !== '__SYSTEM__';
}

/**
 * Builds one fixture context: its own w3 database, the real model registry, a recording model
 * facade, an injected clock and (optionally) a tenant-policy/consent pair.
 *
 * Options:
 *   mode: 'recorded-facade' (default, disclosed test adapter described above) or
 *         'raw-registry' (the genuine createModels(mongoose) object with no adapter; proves
 *         that the product factories run the frozen contract with zero test object seams).
 */
async function makeContext({ tag, point = null, auditSink = 'durable-raw', dbName: providedDbName = null, syncIndexes = true, dropOnTeardown = true, tenantId = env.TENANT, principalId = env.OWNER_A, deviceId = null, mode = 'recorded-facade', predicateAnchor: predicateAnchorMode = 'clock' } = {}) {
  const dbName = providedDbName ?? fence.createDbName(tag);
  const { client } = await fence.connectGuarded({ dbName, appName: `cbhr-phase1-w3a-${tag}`.slice(0, 60) });
  const modelInfo = env.loadModels();
  const four = {
    DeviceAuthority: modelInfo.registry.DeviceAuthority,
    PairingSession: modelInfo.registry.PairingSession,
    Challenge: modelInfo.registry.Challenge,
    AuditEvent: modelInfo.registry.AuditEvent,
  };
  await env.connectMongoose({ uri: fence.FROZEN_URI, dbName });
  const syncReport = syncIndexes ? await env.syncDeclaredIndexes(four) : null;
  const recorder = env.makeRecorder();
  const facade = env.makeDbFacade(four, recorder.entries);
  const instrumentedRegistry = env.instrumentModels(modelInfo.registry, recorder.entries);
  const clock = env.makeClock();
  const cryptoSurface = env.makeCrypto();
  const tenantPolicy = env.makeTenantPolicy();
  const consent = env.makeLocalConsent({ clock });
  const tenantContext = makeTenantContext({ tenantId, principalId, deviceId });

  // The retire CAS resolves its trusted principal through the REAL product trust
  // adapter, not through caller fields: resolveRetirePrincipal/verifyRetireAuthorization
  // are the frozen seams and they see the same lab tenant context every service sees.
  const retireTrust = env.product.createOwnerRetireTrust({
    authenticatedUser: { id: principalId, tenantId },
    authStrategy: 'authenticated',
    tenantContext,
    serverResolvedDeviceId: deviceId,
  });

  let audit;
  if (auditSink === 'real-model') {
    audit = makeModelAuditSink(four);
  } else if (auditSink === 'throwing') {
    audit = makeThrowingAuditSink();
  } else {
    audit = makeDurableRawAuditSink(client, dbName);
  }

  const context = {
    tag,
    point,
    dbName,
    client,
    models: four,
    registry: modelInfo.registry,
    modelInfo,
    syncIndexes: syncReport,
    recorder,
    db: mode === 'raw-registry' ? instrumentedRegistry : facade.db,
    rawDb: instrumentedRegistry,
    facadeDb: facade.db,
    facadeProvenance: facade.provenance,
    facadeKind: mode === 'raw-registry' ? 'genuine-createModels-registry-no-adapter' : facade.kind,
    dbMode: mode,
    clock,
    crypto: cryptoSurface,
    tenantPolicy,
    consent,
    audit,
    labKey: env.labKey,
    leaseTtlMs: env.constants.LEASE_TTL_MS,
    skewMarginMs: env.constants.SKEW_MARGIN_MS,
    codeTtlMs: env.constants.CODE_TTL_MS,
    tenantContext,
    retireTrust,
    retireDeviceId: deviceId,
    tenantId,
    principalId,
    created: [],
  };

  /** Re-binds the trusted context + retire trust to a fixture-chosen device/owner. */
  context.bindTrust = ({ tenantId: nextTenant, principalId: nextPrincipal, deviceId: nextDevice } = {}) => {
    const tenant = nextTenant ?? tenantId;
    const principal = nextPrincipal ?? principalId;
    const device = nextDevice ?? context.retireDeviceId ?? deviceId ?? null;
    context.retireDeviceId = device;
    context.tenantContext = makeTenantContext({ tenantId: tenant, principalId: principal, deviceId: device });
    context.retireTrust = env.product.createOwnerRetireTrust({
      authenticatedUser: { id: principal, tenantId: tenant },
      authStrategy: 'authenticated',
      tenantContext: context.tenantContext,
      serverResolvedDeviceId: device,
    });
    return context.tenantContext;
  };

  /* The service db is either the genuine instrumented registry or the disclosed recording facade. */
  const serviceDb = () => (mode === 'raw-registry' ? instrumentedRegistry : facade.db);

  /**
   * GM-64 / GM-65 TEST-ONLY `predicateAnchor` SEAM, threaded explicitly.
   *
   * `predicateAnchorMode`:
   *   'clock'    (default, every time-travelling fixture) — the predicate comparison anchor follows
   *              this fixture's injected deterministic clock, so a fixture can place the 48 h / 300 s
   *              boundary anywhere on the timeline. This substitutes the COMPARISON ANCHOR only; the
   *              product predicate is still the product predicate, and the writer's own clock still
   *              never decides a lease state or a TTL through a `Date` baked into a filter.
   *   'database' — NO seam is supplied. Every predicate is the production `$$NOW` form, decided by
   *              MongoDB's own clock. The two-clock skew oracle MUST use this mode: with an injected
   *              anchor its result would be void as skew evidence (GM-64 rule 5).
   *
   * Production never constructs a Device service with this seam at all (GM-65: "tests only;
   * production must omit"); a non-test caller that passes it is a review event.
   */
  const anchorSeam =
    predicateAnchorMode === 'clock' ? { predicateAnchor: () => clock.now() } : {};
  context.predicateAnchorMode = predicateAnchorMode;
  context.predicateAnchorSeam = anchorSeam;

  context.authorityService = (overrides = {}) =>
    env.product.createAuthorityService({
      db: serviceDb(),
      clock,
      crypto: cryptoSurface,
      logger: null,
      audit: audit.audit,
      tenantContext: context.tenantContext,
      resolveRetirePrincipal: context.retireTrust.resolveRetirePrincipal,
      verifyRetireAuthorization: context.retireTrust.verifyRetireAuthorization,
      verifyRenewalProof: async () => ({ ok: false }),
      ...anchorSeam,
      ...overrides,
    });

  context.registrationService = (overrides = {}) =>
    env.product.createRegistrationService({
      db: serviceDb(),
      clock,
      crypto: cryptoSurface,
      logger: null,
      audit: audit.audit,
      tenantPolicy,
      tenantContext: context.tenantContext,
      ...anchorSeam,
      ...overrides,
    });

  context.pairingService = (overrides = {}) =>
    env.product.createPairingSessionService({
      db: serviceDb(),
      clock,
      crypto: cryptoSurface,
      logger: null,
      audit: audit.audit,
      authorityService: overrides.authorityService ?? context.authorityService(),
      tenantPolicy,
      verifyLocalConsent: consent.verify.bind(consent),
      pepperLookup: env.LAB_PEPPER,
      tenantContext: context.tenantContext,
      ...anchorSeam,
      ...overrides,
    });

  context.teardown = async () => {
    await env.mongoose.disconnect().catch(() => {});
    const dropped = dropOnTeardown
      ? await fence.dropOwnDatabase(client, dbName)
      : { dropped: false, dbName, reason: 'dropOnTeardown=false (crash child must leave state durable)' };
    await client.close().catch(() => {});
    return dropped;
  };

  return context;
}

/** Harness setup write: raw driver, explicit majority+journal. Never a product call. */
async function rawInsert(context, collection, docs) {
  const result = await context.client
    .db(context.dbName)
    .collection(collection)
    .insertMany(Array.isArray(docs) ? docs : [docs], { writeConcern: { w: 'majority', j: true } });
  return { acknowledged: result.acknowledged === true, insertedCount: result.insertedCount };
}

/** Seeds one authority row (setup only; the raw driver pins majority+journal). */
async function seedAuthority(context, overrides) {
  const row = {
    tenantId: env.TENANT,
    deviceKeyId: `key-${overrides._id}`,
    devicePublicKey: context.labKey.spkiB64u,
    identityState: 'pending',
    leaseState: 'never',
    epoch: 0,
    ownerId: null,
    grantId: null,
    retiredAt: null,
    retiredBy: null,
    activatedAt: null,
    expiresAt: null,
    renewedAt: null,
    renewalCount: 0,
    revokedAt: null,
    revokedBy: null,
    grantedByPairingSessionId: null,
    grantProof: null,
    prevOwner: null,
    prevGrantId: null,
    prevEpoch: null,
    registeredAt: new Date(context.clock.now()),
    ...overrides,
  };
  const write = await rawInsert(context, 'deviceauthorities', row);
  context.created.push({ collection: 'deviceauthorities', _id: row._id, setup: 'harness-raw-driver' });
  return { row, write };
}

/** Real product registration ceremony for one device, returning the granted identity. */
async function registerDevice(context, { deviceName = 'w3a-device', platform = 'win32', agentVersion = '0.0.1', key = context.labKey } = {}) {
  const registration = context.registrationService();
  const begin = await registration.beginRegistration({
    tenantId: env.TENANT,
    requestSource: 'w3a-harness',
  });
  if (!begin.ok) {
    return { ok: false, begin, error: begin.error };
  }
  const nonce = crypto.randomBytes(16).toString('base64url');
  const issuedAt = String(context.clock.now());
  const message = context.crypto.canonicalEncode({
    domainTag: env.constants.REGISTRATION_DOMAIN,
    fields: [
      env.TENANT,
      begin.challenge,
      key.spkiB64u,
      context.crypto.thumbprintB64u(key.spkiB64u),
      deviceName,
      platform,
      agentVersion,
      nonce,
      issuedAt,
    ],
  });
  const complete = await registration.completeRegistration({
    tenantId: env.TENANT,
    devicePublicKey: key.spkiB64u,
    deviceName,
    platform,
    agentVersion,
    domainTag: env.constants.REGISTRATION_DOMAIN,
    requestSource: 'w3a-harness',
    proof: {
      challenge: begin.challenge,
      nonce,
      issuedAt,
      signatureB64u: env.sign(key, message),
    },
  });
  return { ok: complete.ok, begin, complete, error: complete.error, deviceId: complete.deviceId, deviceKeyId: complete.deviceKeyId };
}

/**
 * Seeds one deterministic device descriptor plus its authority row.
 * A distinct per-device lab key keeps `{deviceKeyId,tenantId}` unique inside one tenant.
 */
async function seedDevice(context, tag, overrides = {}) {
  const key = overrides.key ?? env.makeDeviceKey(tag);
  const deviceId = overrides._id ?? `w3a-device-${tag}`;
  const deviceKeyId = overrides.deviceKeyId ?? context.crypto.thumbprintB64u(key.spkiB64u);
  const seeded = await seedAuthority(context, {
    _id: deviceId,
    deviceKeyId,
    devicePublicKey: key.spkiB64u,
    ...overrides,
  });
  return { tag: String(tag), deviceId, deviceKeyId, key, row: seeded.row, write: seeded.write };
}

/** Canonical-message epoch milliseconds: accepts a Date, a number or a numeric string. */
function canonicalIssuedAt(value, fallbackMs) {
  if (value instanceof Date) return String(value.getTime());
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  if (typeof value === 'string' && /^\d+$/.test(value)) return value;
  const parsed = Date.parse(String(value));
  if (!Number.isNaN(parsed)) return String(parsed);
  return String(fallbackMs);
}

/**
 * Signs the CURRENT frozen pairing-open message for one device, using the server-minted
 * challenge hash returned by `mintPairingOpenChallenge`.
 *
 * Canonical fields (pairingSessionService.buildIssuanceMessage):
 *   [purpose='pairing-open', tenantId, deviceId, deviceKeyId, challengeHash, issuedAt]
 * This is the device-side half of the real protocol (the server verifies the same bytes).
 */
function pairingOpenProof(context, options = {}) {
  // Legacy call shape: pairingOpenProof(ctx, deviceDescriptor) with no server-minted challenge.
  const legacy = options.deviceId !== undefined && options.challengeHash === undefined;
  const deviceId = legacy ? options.deviceId : options.deviceId;
  const deviceKeyId = legacy ? options.deviceKeyId : options.deviceKeyId;
  const key = legacy ? options.key : options.key;
  const challengeHash = legacy ? context.crypto.challengeHash(crypto.randomBytes(32).toString('base64url')) : options.challengeHash;
  const issuedAtValue = canonicalIssuedAt(options.issuedAt, context.clock.now());
  const message = context.crypto.canonicalEncode({
    domainTag: env.constants.PAIRING_OPEN_DOMAIN,
    fields: ['pairing-open', env.TENANT, deviceId, deviceKeyId, challengeHash, issuedAtValue],
  });
  return {
    challengeHash,
    issuedAt: issuedAtValue,
    signatureB64u: env.sign(key, message),
    domainTag: env.constants.PAIRING_OPEN_DOMAIN,
  };
}

/**
 * Signs the CURRENT frozen pairing-claim message for one pending session.
 *
 * Canonical fields (pairingSessionService.buildClaimChallengeMessage):
 *   [purpose='pairing-claim', tenantId, ownerId, deviceId, deviceKeyId, challengeHash,
 *    pairingSessionId, issuedAt]
 */
function pairingClaimProof(context, options = {}) {
  const legacy = Object.prototype.hasOwnProperty.call(options, 'challenge');
  const challengeHash = legacy
    ? context.crypto.challengeHash(options.challenge)
    : options.challengeHash;
  const issuedAtValue = canonicalIssuedAt(options.issuedAt, context.clock.now());
  const message = context.crypto.canonicalEncode({
    domainTag: env.constants.PAIRING_CLAIM_DOMAIN,
    fields: legacy
      ? [
          env.TENANT,
          options.ownerId,
          String(options.session._id),
          options.session.deviceId,
          options.session.deviceKeyId,
          String(options.challenge),
          String(new Date(options.session.issuedAt).getTime()),
          String(options.nonce ?? ''),
        ]
      : [
          'pairing-claim',
          env.TENANT,
          options.ownerId,
          options.session.deviceId,
          options.session.deviceKeyId,
          challengeHash,
          String(options.session._id),
          issuedAtValue,
        ],
  });
  return {
    challengeHash,
    issuedAt: issuedAtValue,
    ownerId: options.ownerId,
    signatureB64u: env.sign(options.key, message),
    domainTag: env.constants.PAIRING_CLAIM_DOMAIN,
    ...(legacy ? { nonce: options.nonce ?? null, challenge: options.challenge } : {}),
  };
}

/**
 * Legacy harness seeding of a `pairing-claim` challenge row. Retained ONLY so the separate W3-A
 * runner keeps its previous behaviour; the T1 product fixtures never use it (both challenges are
 * minted by the product).
 */
async function seedClaimChallenge(context, { session, ownerId, challenge }) {
  const challengeHash = context.crypto.challengeHash(challenge);
  await rawInsert(context, 'challenges', {
    challengeHash,
    purpose: 'pairing-claim',
    deviceId: session.deviceId,
    deviceKeyId: session.deviceKeyId,
    tenantId: env.TENANT,
    boundPairingSessionId: String(session._id),
    boundOwnerId: ownerId,
    boundGrantId: null,
    issuedAt: new Date(context.clock.now()),
    expiresAt: new Date(context.clock.now() + 120000),
    consumedAt: null,
  });
  return challengeHash;
}

/**
 * One full, real pairing ceremony through product bytes only:
 *   mintPairingOpenChallenge -> issuePairingSession -> redeemPairingCode
 *   -> mintPairingClaimChallenge -> approvePairingClaim (device PoP + local consent).
 *
 * No challenge row is seeded by the harness: both challenges are minted by the product.
 */
async function runPairingCeremony(context, { deviceId, deviceKeyId, ownerId, localConsent, key = context.labKey }) {
  const pairing = context.pairingService();
  const openChallenge = await pairing.mintPairingOpenChallenge({
    tenantId: env.TENANT,
    deviceId,
    deviceKeyId,
  });
  if (!openChallenge.ok) {
    return { ok: false, stage: 'mint-open-challenge', error: openChallenge.error, openChallenge };
  }
  const issue = await pairing.issuePairingSession({
    tenantId: env.TENANT,
    deviceId,
    deviceKeyId,
    domainTag: env.constants.PAIRING_OPEN_DOMAIN,
    requestSource: 'w3a-harness',
    challengeHash: openChallenge.challengeHash,
    proof: pairingOpenProof(context, {
      deviceId,
      deviceKeyId,
      key,
      challengeHash: openChallenge.challengeHash,
      issuedAt: openChallenge.issuedAt,
    }),
  });
  if (!issue.ok) {
    return { ok: false, stage: 'issue', issue, openChallenge };
  }
  const redeem = await pairing.redeemPairingCode({ code: issue.code, tenantId: env.TENANT, ownerId });
  if (!redeem.ok) {
    return { ok: false, stage: 'redeem', issue, redeem, openChallenge };
  }
  const session = await context.models.PairingSession.findOne({ _id: redeem.pairingSession._id, tenantId: env.TENANT }).lean();
  const claimChallenge = await pairing.mintPairingClaimChallenge({
    pairingSessionId: String(session._id),
    tenantId: env.TENANT,
    ownerId,
  });
  if (!claimChallenge.ok) {
    return { ok: false, stage: 'mint-claim-challenge', issue, redeem, claimChallenge };
  }
  const proof = pairingClaimProof(context, {
    session,
    ownerId,
    challengeHash: claimChallenge.challengeHash,
    key,
    issuedAt: claimChallenge.issuedAt,
  });
  const approve = await pairing.approvePairingClaim({
    pairingSessionId: String(session._id),
    tenantId: env.TENANT,
    ownerId,
    domainTag: env.constants.PAIRING_CLAIM_DOMAIN,
    localConsent: localConsent ?? { nonce: 'lab-consent-nonce-0001' },
    proof,
  });
  return {
    ok: approve.ok,
    stage: approve.ok ? 'done' : 'approve',
    issue,
    redeem,
    approve,
    openChallenge,
    claimChallenge,
    sessionId: String(session._id),
  };
}

/**
 * The full pairing ceremony with a raw-device-visible challenge: used by fixtures that need
 * the exact challenge hashes. Identical product path as `runPairingCeremony`.
 */
async function runPairingCeremonyDetailed(context, options) {
  return runPairingCeremony(context, options);
}

/** Serializes every document in the four Phase-1 collections for secret-leak scanning. */
async function dumpAllFourCollections(client, dbName) {
  const out = {};
  for (const collection of ['deviceauthorities', 'pairingsessions', 'challenges', 'deviceauthorityevents']) {
    out[collection] = await client.db(dbName).collection(collection).find({}).toArray();
  }
  return out;
}

function findBySerializedValue(dump, needle) {
  const found = [];
  for (const [collection, rows] of Object.entries(dump)) {
    for (const row of rows) {
      const text = JSON.stringify(row);
      if (text.includes(String(needle))) {
        found.push({ collection, _id: row._id === undefined ? null : String(row._id) });
      }
    }
  }
  return found;
}

/**
 * Reads the DATABASE server clock in epoch milliseconds from the replica-set primary's own
 * `hello.localTime`. Never a wall-clock read of this process, so a fixture that anchors its
 * reference timeline to it is anchored to the same clock the production `$$NOW` predicates use.
 */
async function serverNowMs(client) {
  const hello = await client.db('admin').command({ hello: 1 });
  const parsed = Date.parse(hello.localTime);
  if (!Number.isFinite(parsed)) {
    throw new Error('serverNowMs: hello.localTime is not a parseable instant');
  }
  return parsed;
}

module.exports = {
  currentRunKey,
  runsRoot,
  runDir,
  ensureDir,
  freshDir,
  writeJson,
  sha256File,
  sha256Json,
  makeChecks,
  statusFromChecks,
  serverNowMs,
  provenance,
  errorView,
  authorizePredicate,
  authorityView,
  readAuthorityRaw,
  countActiveOwners,
  makeDurableRawAuditSink,
  makeModelAuditSink,
  makeThrowingAuditSink,
  makeContext,
  makeTenantContext,
  rawInsert,
  seedAuthority,
  seedDevice,
  registerDevice,
  pairingOpenProof,
  pairingClaimProof,
  seedClaimChallenge,
  canonicalIssuedAt,
  runPairingCeremony,
  runPairingCeremonyDetailed,
  dumpAllFourCollections,
  findBySerializedValue,
  fence,
  env,
};