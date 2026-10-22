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
      disclosure:
        'Test-only behaviour-free plain-object facade over the genuine createModels(mongoose) models; required because I6/I5 assertDependencies require typeof db.<Model> === "object" while genuine Mongoose models are functions (see finding I11-F1).',
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
 * Builds one fixture context: its own w3 database, the real model registry, a recording model
 * facade, an injected clock and (optionally) a tenant-policy/consent pair.
 */
async function makeContext({ tag, point = null, auditSink = 'durable-raw', dbName: providedDbName = null, syncIndexes = true, dropOnTeardown = true } = {}) {
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
  const clock = env.makeClock();
  const cryptoSurface = env.makeCrypto();
  const tenantPolicy = env.makeTenantPolicy();
  const consent = env.makeLocalConsent();

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
    db: facade.db,
    facadeProvenance: facade.provenance,
    facadeKind: facade.kind,
    clock,
    crypto: cryptoSurface,
    tenantPolicy,
    consent,
    audit,
    labKey: env.labKey,
    leaseTtlMs: env.constants.LEASE_TTL_MS,
    skewMarginMs: env.constants.SKEW_MARGIN_MS,
    codeTtlMs: env.constants.CODE_TTL_MS,
    created: [],
  };

  context.authorityService = (overrides = {}) =>
    env.product.createAuthorityService({
      db: facade.db,
      clock,
      crypto: cryptoSurface,
      logger: null,
      audit: audit.audit,
      verifyRenewalProof: async () => ({ ok: false }),
      ...overrides,
    });

  context.registrationService = (overrides = {}) =>
    env.product.createRegistrationService({
      db: facade.db,
      clock,
      crypto: cryptoSurface,
      logger: null,
      audit: audit.audit,
      tenantPolicy,
      ...overrides,
    });

  context.pairingService = (overrides = {}) =>
    env.product.createPairingSessionService({
      db: facade.db,
      clock,
      crypto: cryptoSurface,
      logger: null,
      audit: audit.audit,
      authorityService: context.authorityService(),
      tenantPolicy,
      verifyLocalConsent: consent.verify.bind(consent),
      pepperLookup: env.LAB_PEPPER,
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

/** Signs the frozen pairing-open message for one device. */
function pairingOpenProof(context, { deviceId, deviceKeyId, key }) {
  const nonce = crypto.randomBytes(16).toString('base64url');
  const issuedAt = String(context.clock.now());
  const message = context.crypto.canonicalEncode({
    domainTag: env.constants.PAIRING_OPEN_DOMAIN,
    fields: [env.TENANT, deviceId, deviceKeyId, nonce, issuedAt],
  });
  return {
    nonce,
    issuedAt,
    signatureB64u: env.sign(key, message),
    domainTag: env.constants.PAIRING_OPEN_DOMAIN,
  };
}

/** Signs the frozen pairing-claim message for one pending session. */
function pairingClaimProof(context, { session, ownerId, challenge, key }) {
  const nonce = crypto.randomBytes(16).toString('base64url');
  const issuedAt = String(context.clock.now());
  const message = context.crypto.canonicalEncode({
    domainTag: env.constants.PAIRING_CLAIM_DOMAIN,
    fields: [
      env.TENANT,
      ownerId,
      String(session._id),
      session.deviceId,
      session.deviceKeyId,
      String(challenge),
      String(new Date(session.issuedAt).getTime()),
      nonce,
    ],
  });
  return {
    nonce,
    issuedAt,
    challenge,
    ownerId,
    signatureB64u: env.sign(key, message),
    domainTag: env.constants.PAIRING_CLAIM_DOMAIN,
  };
}

/**
 * Seeds a `pairing-claim` challenge row (the frozen §9 surface has no claim-challenge mint
 * operation; W2-D acceptance item (2) explicitly allows the harness to seed it in its own DB).
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
 * One full, real pairing ceremony: issue → redeem → claim-approve, all through product bytes.
 * Returns the durable facts the fixtures assert on.
 */
async function runPairingCeremony(context, { deviceId, deviceKeyId, ownerId, localConsent, key = context.labKey }) {
  const pairing = context.pairingService();
  const issue = await pairing.issuePairingSession({
    tenantId: env.TENANT,
    deviceId,
    deviceKeyId,
    domainTag: env.constants.PAIRING_OPEN_DOMAIN,
    requestSource: 'w3a-harness',
    proof: pairingOpenProof(context, { deviceId, deviceKeyId, key }),
  });
  if (!issue.ok) {
    return { ok: false, stage: 'issue', issue };
  }
  const redeem = await pairing.redeemPairingCode({ code: issue.code, tenantId: env.TENANT, ownerId });
  if (!redeem.ok) {
    return { ok: false, stage: 'redeem', issue, redeem };
  }
  const session = await context.models.PairingSession.findOne({ _id: redeem.pairingSession._id, tenantId: env.TENANT }).lean();
  const challenge = crypto.randomBytes(32).toString('base64url');
  await seedClaimChallenge(context, { session, ownerId, challenge });
  const proof = pairingClaimProof(context, { session, ownerId, challenge, key });
  const approve = await pairing.approvePairingClaim({
    pairingSessionId: String(session._id),
    tenantId: env.TENANT,
    ownerId,
    domainTag: env.constants.PAIRING_CLAIM_DOMAIN,
    localConsent: localConsent ?? { nonce: 'lab-consent-nonce-0001' },
    proof,
  });
  return { ok: approve.ok, stage: approve.ok ? 'done' : 'approve', issue, redeem, approve, sessionId: String(session._id) };
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
  rawInsert,
  seedAuthority,
  seedDevice,
  registerDevice,
  pairingOpenProof,
  pairingClaimProof,
  seedClaimChallenge,
  runPairingCeremony,
  dumpAllFourCollections,
  findBySerializedValue,
  fence,
  env,
};