'use strict';

/**
 * W3-B R2 T2-F4 per-row harness (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Per row:
 *   - the database name is fenced (`cbhr_rdc_phase1_r2_t2f4_*`) BEFORE the MongoClient factory is
 *     invoked, with an explicit construction counter proving the ordering;
 *   - the genuine `createModels(mongoose)` registry is handed to the frozen product factories
 *     DIRECTLY (no facade, no proxy, no shim) together with the frozen F4 `tenantContext` trusted
 *     dependency bound to the REAL `getTenantId` of the frozen tenantContext.ts module;
 *   - real AsyncLocalStorage: rows enter tenant contexts only through the frozen module's
 *     `tenantStorage.run()`;
 *   - genuine model statics are wrapped ONLY to count invocations and are restored before read-back;
 *   - the audit sink is the genuine product `auditSink.js` adapter writing through the genuine
 *     `AuditEvent` Mongoose model;
 *   - teardown is unconditional: counter restoration, mongoose disconnect, `dropDatabase()` of the
 *     owned database, client close.
 */

const path = require('node:path');

const expected = require('./expected.cjs');
const fence = require('./fence.cjs');
const als = require('./als.cjs');
const { ModelCallCounter } = require('./counter.cjs');

// eslint-disable-next-line global-require, import/no-dynamic-require
const durabilityEnv = require(path.resolve(__dirname, '..', 'durability', 'env.cjs'));

const w3a = durabilityEnv.w3a;
const WORKTREE = durabilityEnv.WORKTREE;
const WRITE_CONCERN = durabilityEnv.WRITE_CONCERN;

/** Genuine product models whose invocations are counted for the frozen "zero model calls" law. */
const COUNTED_MODELS = Object.freeze(['DeviceAuthority', 'PairingSession', 'Challenge']);
const AUTHORITY_MUTATION_MODELS = Object.freeze(['DeviceAuthority', 'Challenge']);
const PAIRING_PATH_MODELS = Object.freeze(['DeviceAuthority', 'PairingSession']);
const REGISTRATION_MODELS = Object.freeze(['Challenge']);

/** Fixture-defect failure: the only source of HARNESS_FAIL produced by this module. */
class HarnessFail extends Error {
  constructor(message, detail) {
    super(message);
    this.name = 'HarnessFail';
    this.code = 'HARNESS_FAIL';
    this.status = expected.STATUS.HARNESS_FAIL;
    this.detail = detail ?? null;
  }
}

function errorView(err) {
  if (err === null || err === undefined) {
    return { name: null, code: null, message: null, httpStatus: null, disposition: null };
  }
  return {
    name: err.name ?? null,
    code: err.code ?? null,
    message: err.message ?? String(err),
    httpStatus: typeof err.httpStatus === 'number' ? err.httpStatus : null,
    disposition: err.disposition ?? null,
    retryable: err.retryable ?? null,
  };
}

/** Truth-shaped view of a frozen product envelope. */
function envelopeView(envelope) {
  if (envelope === null || typeof envelope !== 'object') {
    return { raw: envelope ?? null };
  }
  const authority = envelope.authority ?? null;
  const pairingSession = envelope.pairingSession ?? null;
  return {
    ok: envelope.ok === true,
    matched: typeof envelope.matched === 'number' ? envelope.matched : (envelope.matched ?? null),
    code: typeof envelope.code === 'string' ? `[redacted:${envelope.code.length}ch]` : (envelope.code ?? null),
    challengeHash: envelope.challengeHash ?? null,
    deviceId: envelope.deviceId ?? null,
    deviceKeyId: envelope.deviceKeyId ?? null,
    error: envelope.error ? errorView(envelope.error) : null,
    authority:
      authority === null || typeof authority !== 'object'
        ? null
        : {
            _id: authority._id !== undefined ? String(authority._id) : null,
            tenantId: authority.tenantId ?? null,
            epoch: authority.epoch ?? null,
            leaseState: authority.leaseState ?? null,
            identityState: authority.identityState ?? null,
            ownerId: authority.ownerId ?? null,
            grantId: authority.grantId ?? null,
            deviceKeyId: authority.deviceKeyId ?? null,
          },
    pairingSession:
      pairingSession === null || typeof pairingSession !== 'object'
        ? null
        : {
            _id: pairingSession._id !== undefined ? String(pairingSession._id) : null,
            state: pairingSession.state ?? null,
            tenantId: pairingSession.tenantId ?? null,
          },
  };
}

/** JSON-stable projection of a raw driver document, so before/after comparisons are exact. */
function stableDocView(doc) {
  if (doc === null || doc === undefined) {
    return null;
  }
  const value = (field) => {
    const raw = doc[field];
    if (raw === undefined) {
      return null;
    }
    if (raw instanceof Date) {
      return raw.toISOString();
    }
    if (raw !== null && typeof raw === 'object' && typeof raw.toHexString === 'function') {
      return raw.toHexString();
    }
    if (raw !== null && typeof raw === 'object' && !Array.isArray(raw)) {
      return JSON.parse(JSON.stringify(raw));
    }
    return raw;
  };
  const fields = [
    '_id',
    'tenantId',
    'deviceKeyId',
    'identityState',
    'leaseState',
    'epoch',
    'ownerId',
    'grantId',
    'prevEpoch',
    'prevGrantId',
    'renewalCount',
    'renewedAt',
    'activatedAt',
    'expiresAt',
    'retiredAt',
    'retiredBy',
    'revokedAt',
    'revokedBy',
    'challengeHash',
    'purpose',
    'boundPairingSessionId',
    'boundOwnerId',
    'boundGrantId',
    'boundEpoch',
    'issuedAt',
    'consumedAt',
    'state',
    'pendingOwnerId',
    'attemptsUsed',
    'lookupTag',
  ];
  const projected = {};
  for (const field of fields) {
    if (Object.prototype.hasOwnProperty.call(doc, field)) {
      projected[field] = value(field);
    }
  }
  return projected;
}

function sameDoc(before, after) {
  return JSON.stringify(before) === JSON.stringify(after);
}

async function withRowDb(tag, body) {
  const dbName = fence.createDbName(tag);
  const problems = fence.checkDbName(dbName);
  const fenceDecision = {
    dbName,
    problems,
    checkedBeforeClient: true,
    clientConstructionsBeforeConnect: 0,
    clientConstructionsAfterConnect: null,
    fenceEvaluatedBeforeConstruction: false,
  };
  if (problems.length > 0) {
    throw new fence.T2F4FenceViolation(problems, { dbName, phase: 'row-pre-connect' });
  }

  const connector = fence.makeConnector({ uri: fence.FROZEN_URI });
  fenceDecision.clientConstructionsBeforeConnect = connector.state.clientConstructions;
  const guarded = await fence.connectGuarded({
    dbName,
    appName: `cbhr-r2-t2f4-${tag}`,
    connector,
  });
  fenceDecision.clientConstructionsAfterConnect = connector.state.clientConstructions;
  fenceDecision.fenceEvaluatedBeforeConstruction =
    connector.state.fenceEvaluations.length === 1 &&
    connector.state.clientConstructions === 1 &&
    fenceDecision.clientConstructionsBeforeConnect === 0;

  const { client, topology, driver } = guarded;
  const loaded = durabilityEnv.loadRegistry();
  const models = loaded.registry;
  const clock = w3a.makeClock();
  const counter = new ModelCallCounter();
  const patchedStatics = counter.patchModels(models, COUNTED_MODELS);
  const auditSink = durabilityEnv.makeProductAuditSink({ AuditEvent: models.AuditEvent });

  const ctx = {
    tag,
    dbName,
    uri: fence.FROZEN_URI,
    client,
    topology,
    driverVersion: driver.version,
    fenceDecision,
    registry: models,
    shape: loaded.shape,
    models,
    clock,
    cryptoSurface: w3a.makeCrypto(),
    tenantPolicy: w3a.makeTenantPolicy(),
    makeTenantPolicy: w3a.makeTenantPolicy,
    consent: w3a.makeLocalConsent(),
    pepperLookup: w3a.LAB_PEPPER,
    labKey: w3a.labKey,
    sign: w3a.sign,
    als,
    alsStorage: als.tenantStorage,
    counter,
    patchedStatics,
    auditSink,
    TENANT: w3a.TENANT,
    OTHER_TENANT: w3a.OTHER_TENANT,
    OWNER_A: w3a.OWNER_A,
    OWNER_B: w3a.OWNER_B,
    OWNER_C: w3a.OWNER_C,
    WRITE_CONCERN,
    constants: w3a.constants,
    COUNTED_MODELS,
    AUTHORITY_MUTATION_MODELS,
    PAIRING_PATH_MODELS,
    REGISTRATION_MODELS,
    observations: {},
  };

  ctx.tenantContextFor = (alsAbsencePermitted) =>
    als.makeTenantContextDependency(alsAbsencePermitted);

  ctx.composeAuthority = ({ tenantContext, audit = ctx.auditSink, verifyRenewalProof } = {}) =>
    w3a.product.createAuthorityService({
      db: models,
      clock,
      crypto: ctx.cryptoSurface,
      logger: null,
      audit: audit.audit,
      verifyRenewalProof: verifyRenewalProof ?? (async () => ({ ok: false })),
      tenantContext,
    });

  ctx.composeRegistration = ({ tenantContext, tenantPolicy = ctx.tenantPolicy, audit = ctx.auditSink } = {}) =>
    w3a.product.createRegistrationService({
      db: models,
      clock,
      crypto: ctx.cryptoSurface,
      logger: null,
      audit: audit.audit,
      tenantPolicy,
      tenantContext,
    });

  ctx.composePairing = ({ tenantContext, authority = null, audit = ctx.auditSink } = {}) =>
    w3a.product.createPairingSessionService({
      db: models,
      clock,
      crypto: ctx.cryptoSurface,
      logger: null,
      audit: audit.audit,
      authorityService: authority ?? ctx.composeAuthority({ tenantContext, audit }),
      tenantPolicy: ctx.tenantPolicy,
      verifyLocalConsent: ctx.consent.verify.bind(ctx.consent),
      pepperLookup: ctx.pepperLookup,
      tenantContext,
    });

  ctx.seedAuthority = async (overrides = {}) => {
    const doc = {
      tenantId: ctx.TENANT,
      deviceKeyId: `key-${overrides._id}`,
      devicePublicKey: w3a.labKey.spkiB64u,
      identityState: 'pending',
      leaseState: 'never',
      epoch: 0,
      ownerId: null,
      grantId: null,
      activatedAt: null,
      expiresAt: null,
      retiredAt: null,
      retiredBy: null,
      revokedAt: null,
      revokedBy: null,
      renewalCount: 0,
      renewedAt: null,
      grantedByPairingSessionId: null,
      grantProof: null,
      prevOwner: null,
      prevGrantId: null,
      prevEpoch: null,
      ...overrides,
    };
    const docs = await models.DeviceAuthority.create([doc], { writeConcern: WRITE_CONCERN });
    return docs[0];
  };

  /**
   * Fixture challenge row. `boundEpoch` is set explicitly because the frozen challenge schema
   * declares `boundEpoch` with a `Number.isInteger` validator against a `null` default.
   */
  ctx.seedChallenge = async (overrides = {}) => {
    const now = clock.now();
    const doc = {
      challengeHash: ctx.cryptoSurface.challengeHash(ctx.cryptoSurface.newChallengeNonce()),
      purpose: 'registration',
      deviceId: null,
      deviceKeyId: null,
      tenantId: ctx.TENANT,
      boundPairingSessionId: null,
      boundOwnerId: null,
      boundGrantId: null,
      boundEpoch: 0,
      issuedAt: new Date(now),
      expiresAt: new Date(now + ctx.constants.REGISTRATION_CHALLENGE_TTL_MS),
      consumedAt: null,
      ...overrides,
    };
    const docs = await models.Challenge.create([doc], { writeConcern: WRITE_CONCERN });
    return docs[0];
  };

  ctx.rawDoc = async (collection, filter) =>
    client.db(dbName).collection(collection).findOne(filter);

  ctx.rawDocView = async (collection, filter) => stableDocView(await ctx.rawDoc(collection, filter));

  ctx.countCollection = async (collection) =>
    client.db(dbName).collection(collection).countDocuments({});

  ctx.collectionCounts = async () => {
    const out = {};
    for (const key of Object.keys(models)) {
      const name = models[key].collection ? models[key].collection.name : null;
      if (name === null) {
        continue;
      }
      out[name] = await client.db(dbName).collection(name).countDocuments({});
    }
    return out;
  };

  ctx.countsSince = (mark, modelNames = COUNTED_MODELS) =>
    counter.countsAcross(counter.since(mark), modelNames);

  let dropped = null;
  let outcome = null;
  let dbReadBack = null;

  try {
    await durabilityEnv.connectMongoose({ uri: fence.FROZEN_URI, dbName });

    ctx.observations.registryShapeFunctions = Object.keys(models)
      .filter((key) => typeof models[key] === 'function')
      .sort();
    ctx.observations.registryShapeObjects = Object.keys(models)
      .filter((key) => typeof models[key] !== 'function')
      .sort();
    ctx.observations.patchedStatics = patchedStatics;
    ctx.observations.auditSinkKind = auditSink.kind;
    ctx.observations.alsStorageIsNative = als.storageIsNativeAsyncLocalStorage;

    outcome = await body(ctx);
    ctx.observations.counterRestoredBeforeReadBack = counter.restoreAll();
    dbReadBack = {
      dbName,
      collectionCounts: await ctx.collectionCounts(),
      counterRestored: counter.allRestored(),
      counterPatchedStatics: patchedStatics,
      counterRecords: counter.calls.length,
      alsModuleKind: als.moduleKind,
      alsStorageIsNative: als.storageIsNativeAsyncLocalStorage,
      tenantContextSha256: als.tenantContextSha256,
      tenantIsolationSha256: als.tenantIsolationSha256,
      observations: ctx.observations,
    };
  } finally {
    counter.restoreAll();
    await w3a.mongoose.disconnect().catch(() => {});
    dropped = await fence.dropOwnDatabase(client, dbName);
    await client.close().catch(() => {});
    ctx.dropped = dropped;
  }
  if (dbReadBack !== null) {
    dbReadBack.dropped = dropped;
  }
  return { outcome, dbReadBack, dbName, dropped, topology, ctx, fenceDecision, errorView, envelopeView, sameDoc, stableDocView };
}

module.exports = {
  HarnessFail,
  WORKTREE,
  WRITE_CONCERN,
  COUNTED_MODELS,
  AUTHORITY_MUTATION_MODELS,
  PAIRING_PATH_MODELS,
  REGISTRATION_MODELS,
  als,
  fence,
  expected,
  w3a,
  errorView,
  envelopeView,
  stableDocView,
  sameDoc,
  withRowDb,
  trustDir: __dirname,
};