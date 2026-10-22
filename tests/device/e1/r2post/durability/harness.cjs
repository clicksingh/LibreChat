'use strict';

/**
 * W3-B R2 S4T per-row harness (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Per row:
 *   - the database name is fenced (`cbhr_rdc_phase1_r2_s4t_*`) BEFORE the MongoClient factory is
 *     invoked, with an explicit construction counter proving the ordering;
 *   - the genuine `createModels(mongoose)` registry is loaded and handed to the frozen product
 *     factories DIRECTLY (no facade), with the genuine product `auditSink.js` adapter as the only
 *     audit sink;
 *   - a row-scoped `ModelCapture` records the real arguments of the genuine write statics;
 *   - teardown is unconditional: capture restoration, mongoose disconnect, `dropDatabase()` of the
 *     owned database, client close.
 */

const path = require('node:path');

const env = require('./env.cjs');
const fence = require('./fence.cjs');
const ledger = require('./ledger.cjs');
const { ModelCapture } = require('./capture.cjs');

const w3a = env.w3a;

/** Fixture-defect failure: the only source of HARNESS_FAIL. */
class HarnessFail extends Error {
  constructor(message, detail) {
    super(message);
    this.name = 'HarnessFail';
    this.code = 'HARNESS_FAIL';
    this.status = ledger.STATUS.HARNESS_FAIL;
    this.detail = detail ?? null;
  }
}

function errorView(err) {
  if (err === null || err === undefined) {
    return { name: null, code: null, message: null, httpStatus: null };
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
  return {
    ok: envelope.ok === true,
    matched: typeof envelope.matched === 'number' ? envelope.matched : (envelope.matched ?? null),
    code: envelope.code ?? null,
    deviceId: envelope.deviceId ?? null,
    deviceKeyId: envelope.deviceKeyId ?? null,
    error: envelope.error ? errorView(envelope.error) : null,
    authority:
      authority === null || typeof authority !== 'object'
        ? null
        : {
            _id: authority._id ?? null,
            tenantId: authority.tenantId ?? null,
            epoch: authority.epoch ?? null,
            leaseState: authority.leaseState ?? null,
            identityState: authority.identityState ?? null,
            ownerId: authority.ownerId ?? null,
            grantId: authority.grantId ?? null,
            deviceKeyId: authority.deviceKeyId ?? null,
          },
    pairingSession:
      envelope.pairingSession === null || envelope.pairingSession === undefined
        ? null
        : {
            _id: envelope.pairingSession._id !== undefined ? String(envelope.pairingSession._id) : null,
            state: envelope.pairingSession.state ?? null,
          },
  };
}

const AUTHORITY_PROJECTION = {
  _id: 1,
  tenantId: 1,
  epoch: 1,
  leaseState: 1,
  identityState: 1,
  ownerId: 1,
  grantId: 1,
  prevEpoch: 1,
  prevGrantId: 1,
  deviceKeyId: 1,
  expiresAt: 1,
  consumedAt: 1,
  state: 1,
  lookupTag: 1,
  challengeHash: 1,
  purpose: 1,
  kind: 1,
  ts: 1,
};

async function withRowDb(tag, body) {
  const dbName = fence.createDbName(tag);
  const problems = fence.checkDbName(dbName);
  const fenceDecision = {
    dbName,
    problems,
    checkedBeforeClient: true,
    clientConstructionsBeforeConnect: 0,
    clientConstructionsAfterConnect: null,
  };
  if (problems.length > 0) {
    throw new fence.S4TFenceViolation(problems, { dbName, phase: 'row-pre-connect' });
  }

  const connector = fence.makeConnector({ uri: fence.FROZEN_URI });
  fenceDecision.clientConstructionsBeforeConnect = connector.state.clientConstructions;
  const guarded = await fence.connectGuarded({
    dbName,
    appName: `cbhr-r2-s4t-${tag}`,
    connector,
  });
  fenceDecision.clientConstructionsAfterConnect = connector.state.clientConstructions;
  fenceDecision.fenceEvaluatedBeforeConstruction =
    connector.state.fenceEvaluations.length === 1 &&
    connector.state.clientConstructions === 1 &&
    fenceDecision.clientConstructionsBeforeConnect === 0;

  const { client, topology, driver } = guarded;
  const loaded = env.loadRegistry();
  const models = loaded.registry;
  const clock = w3a.makeClock();
  const capture = new ModelCapture();

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
    consent: w3a.makeLocalConsent(),
    pepperLookup: w3a.LAB_PEPPER,
    capture,
    TENANT: w3a.TENANT,
    OTHER_TENANT: w3a.OTHER_TENANT,
    OWNER_A: w3a.OWNER_A,
    OWNER_B: w3a.OWNER_B,
    OWNER_C: w3a.OWNER_C,
    WRITE_CONCERN: env.WRITE_CONCERN,
    constants: w3a.constants,
    audit: null,
    compositionPrecondition: null,
    observations: {},
  };

  let dropped = null;
  let outcome = null;
  let dbReadBack = null;

  // The real AuditEvent create path is captured for every row as supplementary F8 evidence.
  capture.patch(models.AuditEvent, 'create', 'real-audit-event-create');
  ctx.audit = env.makeProductAuditSink({ AuditEvent: models.AuditEvent });

  try {
    await env.connectMongoose({ uri: fence.FROZEN_URI, dbName });

    ctx.compositionPrecondition = env.attemptComposition(models, {
      clock,
      cryptoSurface: ctx.cryptoSurface,
      audit: ctx.audit,
      tenantPolicy: ctx.tenantPolicy,
      consent: ctx.consent.verify.bind(ctx.consent),
      pepperLookup: ctx.pepperLookup,
    });
    const rejected = ctx.compositionPrecondition.filter((attempt) => attempt.accepted !== true);
    if (rejected.length > 0) {
      throw new HarnessFail(
        `product factory composition rejected the genuine raw registry: ${rejected
          .map((attempt) => `${attempt.factory} -> ${attempt.error && attempt.error.message}`)
          .join(' | ')}`,
        { compositionPrecondition: ctx.compositionPrecondition, dbName },
      );
    }

    ctx.composeAuthority = ({ audit = ctx.audit, verifyRenewalProof } = {}) =>
      w3a.product.createAuthorityService({
        db: models,
        clock,
        crypto: ctx.cryptoSurface,
        logger: null,
        audit: audit.audit,
        verifyRenewalProof: verifyRenewalProof ?? (async () => ({ ok: false })),
      });

    ctx.composeRegistration = ({ audit = ctx.audit } = {}) =>
      w3a.product.createRegistrationService({
        db: models,
        clock,
        crypto: ctx.cryptoSurface,
        logger: null,
        audit: audit.audit,
        tenantPolicy: ctx.tenantPolicy,
      });

    ctx.composePairing = ({ audit = ctx.audit, authority = null } = {}) =>
      w3a.product.createPairingSessionService({
        db: models,
        clock,
        crypto: ctx.cryptoSurface,
        logger: null,
        audit: audit.audit,
        authorityService: authority ?? ctx.composeAuthority({ audit }),
        tenantPolicy: ctx.tenantPolicy,
        verifyLocalConsent: ctx.consent.verify.bind(ctx.consent),
        pepperLookup: ctx.pepperLookup,
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
      const docs = await models.DeviceAuthority.create([doc], {
        writeConcern: env.WRITE_CONCERN,
      });
      return docs[0];
    };

    /**
     * Fixture challenge row. `boundEpoch` is set explicitly because the frozen challenge schema
     * declares `boundEpoch: {type: Number, default: null, validate: Number.isInteger}` and Mongoose
     * runs that validator against the `null` default, so a row that omits the field is rejected.
     * That rejection is the observed S4T-01 blocker; fixtures must therefore set the field.
     */
    ctx.seedChallenge = async (overrides = {}) => {
      const now = clock.now();
      const doc = {
        challengeHash: `s4t-seed-challenge-${overrides.challengeHash ?? 'default'}`,
        purpose: 'registration',
        deviceId: null,
        deviceKeyId: null,
        tenantId: ctx.TENANT,
        boundPairingSessionId: null,
        boundOwnerId: null,
        boundGrantId: null,
        boundEpoch: 0,
        issuedAt: new Date(now),
        expiresAt: new Date(now + 120000),
        consumedAt: null,
        ...overrides,
      };
      const docs = await models.Challenge.create([doc], { writeConcern: env.WRITE_CONCERN });
      return docs[0];
    };

    /**
     * Fixture pairing-session row. `claim.expectedEpoch` is set explicitly for the same reason as
     * `boundEpoch` above (frozen `Number.isInteger` validator against a `null` default).
     */
    ctx.seedPairingSession = async (overrides = {}) => {
      const now = clock.now();
      const doc = {
        tenantId: ctx.TENANT,
        deviceId: 's4t-seed-device',
        deviceKeyId: 's4t-seed-device-key',
        lookupTag: 's4t-seed-lookup-tag',
        state: 'open',
        pendingOwnerId: null,
        attemptsUsed: 0,
        issuedAt: new Date(now),
        expiresAt: new Date(now + 300000),
        claimedAt: null,
        claim: { challengeRef: null, openedAt: null, expectedEpoch: 0 },
        consumedAt: null,
        grantedGrantId: null,
        issuedFromSourceHash: null,
        deviceSessionId: null,
        ...overrides,
      };
      const docs = await models.PairingSession.create([doc], { writeConcern: env.WRITE_CONCERN });
      return docs[0];
    };

    ctx.readAuthorityRow = async (deviceId) =>
      client.db(dbName).collection(models.DeviceAuthority.collection.name).findOne({ _id: deviceId });

    ctx.readRawDoc = async (collection, filter) => env.readRawDoc(client, dbName, collection, filter);

    ctx.readBack = async () => ({
      dbName,
      collectionCounts: await env.collectionCounts(client, dbName),
      mongooseDatabaseName: w3a.mongoose.connection.db ? w3a.mongoose.connection.db.databaseName : null,
      auditSinkKind: ctx.audit.kind,
      auditSinkCollection: ctx.audit.collection,
      auditSinkOutcomes: ctx.audit.outcomes,
      auditSinkEventCount: ctx.audit.events.length,
      captureRecords: capture.records.length,
      captureLabels: Array.from(new Set(capture.records.map((record) => record.label))).sort(),
      captureRestored: capture.allRestored(),
      observations: ctx.observations,
    });

    outcome = await body(ctx);
    capture.restoreAll();
    ctx.observations.captureRestoredBeforeReadBack = capture.allRestored();
    dbReadBack = await ctx.readBack();
  } finally {
    capture.restoreAll();
    await w3a.mongoose.disconnect().catch(() => {});
    dropped = await fence.dropOwnDatabase(client, dbName);
    await client.close().catch(() => {});
    ctx.dropped = dropped;
  }
  if (dbReadBack !== null) {
    dbReadBack.dropped = dropped;
  }
  return { outcome, dbReadBack, dbName, dropped, topology, ctx, fenceDecision };
}

/** Connection/server write-concern probe (S4T-07): is any connection default masking the write sites? */
async function connectionWriteConcernProbe({ client, uri, mongoose }) {
  const driverOptions = client.options ?? {};
  const connection = mongoose.connection;
  let connectionOptions = {};
  try {
    connectionOptions = connection.options ?? {};
  } catch {
    connectionOptions = {};
  }
  let serverRw = null;
  let serverRwError = null;
  try {
    serverRw = await client.db('admin').command({ getDefaultRWConcern: 1 });
  } catch (err) {
    serverRwError = { name: err.name ?? null, code: err.code ?? null, message: err.message ?? null };
  }
  const serverDefault =
    serverRw !== null && serverRw.defaultWriteConcern ? serverRw.defaultWriteConcern : null;
  const driverWc = driverOptions.writeConcern ?? null;
  const connectionWc = connectionOptions.writeConcern ?? null;
  const uriCarriesWriteConcernParam = /[?&](w|journal|j)=/i.test(uri);
  return {
    uri,
    uriCarriesWriteConcernParam,
    driverClientOptionsWriteConcern: driverWc,
    mongooseConnectionOptionsWriteConcern: connectionWc,
    resolvedServerDefaultWriteConcern: serverDefault,
    serverRwError,
    serverDefaultJournalTrue: serverDefault !== null && serverDefault.j === true,
    connectionLevelWriteConcernAbsent:
      driverWc === null && connectionWc === null && uriCarriesWriteConcernParam === false,
    connectionLevelMajorityJournalResolved:
      (driverWc !== null && driverWc.w === 'majority' && driverWc.j === true) ||
      (connectionWc !== null && connectionWc.w === 'majority' && connectionWc.j === true) ||
      (serverDefault !== null && serverDefault.w === 'majority' && serverDefault.j === true),
  };
}

module.exports = {
  HarnessFail,
  env,
  fence,
  ledger,
  w3a,
  errorView,
  envelopeView,
  withRowDb,
  connectionWriteConcernProbe,
  AUTHORITY_PROJECTION,
  durabilityDir: __dirname,
  artifactsDir: path.join(__dirname, 'artifacts'),
};
