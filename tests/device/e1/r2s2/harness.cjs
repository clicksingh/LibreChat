'use strict';

/**
 * W3-B R2 S2-T per-row harness (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Reuses the proven R2-T0 primitives read-only (`../r2/fence.cjs`, `../r2/env.cjs` -> w3a) and adds
 * only what S2-T needs:
 *   - an `cbhr_rdc_phase1_r2_s2t_*` fenced database per row (see ./fence.cjs);
 *   - the genuine `createModels(mongoose)` registry handed to the product factories DIRECTLY
 *     (no plain-object facade), with the real `AuditEvent` model as the only audit sink;
 *   - a real driver read-back and a real `dropDatabase()` teardown.
 *
 * This module never calls `compositionBlocked()`/`compositionFailView()`.
 */

const path = require('node:path');

const fence = require('./fence.cjs');
const ledger = require('./ledger.cjs');

// eslint-disable-next-line global-require, import/no-dynamic-require
const env = require(path.resolve(__dirname, '..', 'r2', 'env.cjs'));

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

/** Marshals an arbitrary thrown value into a truth-shaped observation. */
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

/** Truth-shaped view of a frozen authority envelope ({ok, matched, authority, error}). */
function envelopeView(envelope) {
  if (envelope === null || typeof envelope !== 'object') {
    return { raw: envelope ?? null };
  }
  return {
    ok: envelope.ok === true,
    matched: typeof envelope.matched === 'number' ? envelope.matched : (envelope.matched ?? null),
    error: envelope.error ? errorView(envelope.error) : null,
    authority: envelope.authority === null || envelope.authority === undefined
      ? null
      : {
          _id: envelope.authority._id ?? null,
          epoch: envelope.authority.epoch ?? null,
          leaseState: envelope.authority.leaseState ?? null,
          identityState: envelope.authority.identityState ?? null,
          ownerId: envelope.authority.ownerId ?? null,
          grantId: envelope.authority.grantId ?? null,
          prevEpoch: envelope.authority.prevEpoch ?? null,
          prevGrantId: envelope.authority.prevGrantId ?? null,
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
  prevOwner: 1,
  expiresAt: 1,
  grantedByPairingSessionId: 1,
  grantProof: 1,
};

const AUDIT_PROJECTION = {
  _id: 1,
  tenantId: 1,
  deviceId: 1,
  ownerId: 1,
  grantId: 1,
  epoch: 1,
  seq: 1,
  kind: 1,
  ts: 1,
  actor: 1,
  reasonCode: 1,
};

async function withRowDb(tag, body) {
  const dbName = fence.createDbName(tag);
  const fenceDecision = { dbName, problems: fence.checkDbName(dbName), checkedBeforeClient: true };
  if (fenceDecision.problems.length > 0) {
    throw new fence.S2TFenceViolation(fenceDecision.problems, { dbName, phase: 'row-pre-connect' });
  }
  const { client, topology, driver } = await fence.connectGuarded({
    dbName,
    appName: `cbhr-r2-s2t-${tag}`,
  });

  const loaded = env.loadRegistry();
  const models = {
    DeviceAuthority: loaded.registry.DeviceAuthority,
    PairingSession: loaded.registry.PairingSession,
    Challenge: loaded.registry.Challenge,
    AuditEvent: loaded.registry.AuditEvent,
  };
  const clock = w3a.makeClock();
  const ctx = {
    tag,
    dbName,
    client,
    topology,
    driverVersion: driver.version,
    fenceDecision,
    registry: loaded.registry,
    shape: loaded.shape,
    models,
    clock,
    cryptoSurface: w3a.makeCrypto(),
    tenantPolicy: w3a.makeTenantPolicy(),
    consent: w3a.makeLocalConsent(),
    pepperLookup: w3a.LAB_PEPPER,
    TENANT: w3a.TENANT,
    OTHER_TENANT: w3a.OTHER_TENANT,
    OWNER_A: w3a.OWNER_A,
    OWNER_B: w3a.OWNER_B,
    OWNER_C: w3a.OWNER_C,
    WRITE_CONCERN: env.WRITE_CONCERN,
    constants: w3a.constants,
    audit: null,
    syncReport: null,
    compositionPrecondition: null,
  };

  let dropped = null;
  let outcome = null;
  let dbReadBack = null;
  try {
    await env.connectMongoose({ uri: fence.FROZEN_URI, dbName, appName: `cbhr-r2-s2t-${tag}` });
    ctx.audit = env.makeRealAuditSink(models, clock);
    ctx.syncReport = await env.syncDeclaredIndexes(models);

    /** Composition precondition: S1 is frozen accepted, so a rejection is a HARNESS_FAIL. */
    ctx.compositionPrecondition = env.attemptComposition(loaded.registry, {
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
        `factory composition rejected genuine Mongoose model constructors: ${rejected
          .map((attempt) => `${attempt.factory} -> ${attempt.error && attempt.error.message}`)
          .join(' | ')}`,
        { compositionPrecondition: ctx.compositionPrecondition, dbName },
      );
    }

    ctx.composeAuthority = ({ registry = ctx.registry, audit = ctx.audit, verifyRenewalProof } = {}) =>
      w3a.product.createAuthorityService({
        db: registry,
        clock: ctx.clock,
        crypto: ctx.cryptoSurface,
        logger: null,
        audit: audit.audit,
        verifyRenewalProof: verifyRenewalProof ?? (async () => ({ ok: false })),
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

    ctx.readAuthorityRow = async (deviceId) =>
      client.db(dbName).collection(models.DeviceAuthority.collection.name).findOne({ _id: deviceId });

    ctx.readBack = async () => ({
      dbName,
      counts: await env.collectionCounts(client, dbName),
      authorityRows: await client
        .db(dbName)
        .collection(models.DeviceAuthority.collection.name)
        .find({}, { projection: AUTHORITY_PROJECTION })
        .toArray(),
      auditRows: await client
        .db(dbName)
        .collection(models.AuditEvent.collection.name)
        .find({}, { projection: AUDIT_PROJECTION })
        .toArray(),
      auditSinkKind: ctx.audit.kind,
      auditSinkCollection: ctx.audit.collection,
      auditSinkOutcomes: ctx.audit.outcomes,
      auditSinkEventCount: ctx.audit.events.length,
      syncIndexes: ctx.syncReport,
    });

    outcome = await body(ctx);
    dbReadBack = await ctx.readBack();
  } finally {
    await w3a.mongoose.disconnect().catch(() => {});
    dropped = await fence.dropOwnDatabase(client, dbName);
    await client.close().catch(() => {});
    ctx.dropped = dropped;
  }
  if (dbReadBack !== null) {
    dbReadBack.dropped = dropped;
  }
  return { outcome, dbReadBack, dbName, dropped, topology, ctx };
}

/** Real driver namespace counts for one collection name on one row database. */
async function countCollection(client, dbName, collection) {
  return client.db(dbName).collection(collection).countDocuments({});
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
  countCollection,
  AUTHORITY_PROJECTION,
  AUDIT_PROJECTION,
};