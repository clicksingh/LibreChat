'use strict';

/**
 * W3-B R2-T0A per-row context (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Every row gets:
 *   - its own fenced database `cbhr_rdc_phase1_r2_t0a_<unique>` (fence before any client);
 *   - a guarded real driver connection and the real Mongoose connection;
 *   - the real `createModels(mongoose)` registry (genuine Model constructors);
 *   - the real `AuditEvent` model as the ONLY audit sink;
 *   - a DB read-back and a teardown that drops only its own database.
 */

const fence = require('./fence.cjs');
const env = require('./env.cjs');
const results = require('./results.cjs');

async function withFixture(tag, body, { syncIndexes = true, dropOnTeardown = true, clock = null } = {}) {
  const dbName = fence.createDbName(tag);
  const fenceDecision = { dbName, problems: fence.checkDbName(dbName), checkedBeforeClient: true };
  if (fenceDecision.problems.length > 0) {
    throw new fence.R2aFenceViolation(fenceDecision.problems, { dbName, phase: 'row-pre-connect' });
  }
  const { client, topology } = await fence.connectGuarded({ dbName, appName: `cbhr-r2-t0a-${tag}` });
  const context = {
    tag,
    dbName,
    client,
    topology,
    fenceDecision,
    models: null,
    shape: null,
    syncReport: null,
    clock: clock ?? env.w3a.makeClock(),
    cryptoSurface: env.w3a.makeCrypto(),
    tenantPolicy: env.w3a.makeTenantPolicy(),
    consent: env.w3a.makeLocalConsent(),
  };
  try {
    const loaded = env.loadRegistry();
    context.registry = loaded.registry;
    context.shape = env.registryModelTypeof(loaded.registry);
    context.models = {
      DeviceAuthority: loaded.registry.DeviceAuthority,
      PairingSession: loaded.registry.PairingSession,
      Challenge: loaded.registry.Challenge,
      AuditEvent: loaded.registry.AuditEvent,
    };
    await env.connectMongoose({ uri: fence.FROZEN_URI, dbName }).catch(() => null);
    context.audit = env.makeRealAuditSink(context.models, context.clock);
    context.syncReport = syncIndexes ? await env.syncDeclaredIndexes(context.models) : null;

    /** Composes the three frozen factories with the RAW genuine registry; no facade, no retry. */
    context.compose = (overrides = {}) =>
      env.attemptComposition(context.registry, {
        clock: context.clock,
        cryptoSurface: context.cryptoSurface,
        audit: context.audit,
        tenantPolicy: context.tenantPolicy,
        consent: context.consent.verify.bind(context.consent),
        pepperLookup: env.w3a.LAB_PEPPER,
        ...overrides,
      });

    context.counts = () => env.collectionCounts(client, dbName);
    context.authorityRows = () => env.readAuthorityRows(client, dbName);

    /**
     * Genuine-sink control: one real AuditEvent write + read-back proves the sink is real. The
     * null-actor/reason probe is recorded because the frozen schema marks both required — the same
     * genuine validation the product registration path hits when it emits actor:null.
     */
    context.auditControl = async () => {
      const base = {
        tenantId: env.w3a.TENANT,
        deviceId: 't0a-harness-control',
        ownerId: null,
        grantId: null,
        epoch: 0,
        seq: 0,
        kind: 'register',
        ts: new Date(context.clock.now()),
        actor: null,
        reasonCode: null,
      };
      let nullShapeError = null;
      try {
        await context.models.AuditEvent.create([base], { writeConcern: env.WRITE_CONCERN });
      } catch (err) {
        nullShapeError = { name: err.name, paths: Object.keys(err.errors ?? {}) };
      }
      const valid = { ...base, actor: 't0a-harness-control', reasonCode: 'harness-control' };
      const docs = await context.models.AuditEvent.create([valid], { writeConcern: env.WRITE_CONCERN });
      const readBack = await client
        .db(dbName)
        .collection('deviceauthorityevents')
        .findOne({ _id: docs[0]._id });
      return {
        sinkKind: context.audit.kind,
        collection: context.audit.collection,
        insertedId: String(docs[0]._id),
        writeConcern: env.WRITE_CONCERN,
        readBackFound: readBack !== null,
        modelTypeof: typeof context.models.AuditEvent,
        nullActorAndReasonRejectedByRealSchema: nullShapeError,
      };
    };

    const outcome = await body(context);
    const dbReadBack = {
      dbName,
      counts: await context.counts(),
      authorityRows: await context.authorityRows(),
      auditSinkKind: context.audit.kind,
      auditSinkCollection: context.audit.collection,
      auditOutcomeCount: context.audit.outcomes.length,
      syncIndexes: context.syncReport,
    };
    return { outcome, dbReadBack, dbName, context };
  } finally {
    await env.w3a.mongoose.disconnect().catch(() => {});
    const dropped = dropOnTeardown
      ? await fence.dropOwnDatabase(client, dbName)
      : { dropped: false, dbName, reason: 'dropOnTeardown=false' };
    await client.close().catch(() => {});
    context.dropped = dropped;
  }
}

/**
 * Shared shape for a genuine-model-gated E1 row: the first truthful failure is factory
 * composition, so the row is EXPECTED_RED / FACTORY_COMPOSITION_FAIL and the downstream frozen
 * oracle is preserved as `pendingOracle`.
 */
function compositionBlocked(ctx, { pendingOracle, extraActual = {}, sourceAnchors = [], components = [], gateExtra = {} }) {
  const composition = ctx.compose();
  const view = env.compositionFailView(composition, pendingOracle, extraActual);
  const rejected = composition.filter((c) => c.accepted === false);
  return {
    status: results.STATUS.EXPECTED_RED,
    tierExecuted: 'E1',
    blockedAtFactoryComposition: rejected.length > 0,
    actual: view,
    components,
    sourceAnchors: [...new Set([...sourceAnchors, ...rejected.map((c) => c.guardAnchor)])],
    plannerOnly: gateExtra.plannerOnly ?? null,
  };
}

async function seedAuthority(ctx, overrides = {}) {
  const doc = {
    tenantId: env.w3a.TENANT,
    deviceKeyId: `key-${overrides._id}`,
    devicePublicKey: env.w3a.labKey.spkiB64u,
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
    ...overrides,
  };
  const docs = await ctx.models.DeviceAuthority.create([doc], { writeConcern: env.WRITE_CONCERN });
  return docs[0];
}

async function seedPairingSession(ctx, overrides = {}) {
  const now = ctx.clock.now();
  const doc = {
    tenantId: env.w3a.TENANT,
    deviceId: 't0a-device',
    deviceKeyId: 't0a-device-key',
    lookupTag: 't0a-lookup-tag-0000000000000000000000000000000000000000',
    state: 'claim_pending',
    pendingOwnerId: env.w3a.OWNER_A,
    attemptsUsed: 0,
    issuedAt: new Date(now),
    expiresAt: new Date(now + 300000),
    claimedAt: new Date(now),
    claim: { challengeRef: null, openedAt: null },
    consumedAt: null,
    grantedGrantId: null,
    issuedFromSourceHash: null,
    deviceSessionId: null,
    ...overrides,
  };
  const docs = await ctx.models.PairingSession.create([doc], { writeConcern: env.WRITE_CONCERN });
  return docs[0];
}

async function seedChallenge(ctx, overrides = {}) {
  const now = ctx.clock.now();
  const doc = {
    challengeHash: `t0a-challenge-hash-${Math.random().toString(16).slice(2)}`,
    purpose: 'registration',
    deviceId: null,
    deviceKeyId: null,
    tenantId: env.w3a.TENANT,
    boundPairingSessionId: null,
    boundOwnerId: null,
    boundGrantId: null,
    issuedAt: new Date(now),
    expiresAt: new Date(now + 120000),
    consumedAt: null,
    ...overrides,
  };
  const docs = await ctx.models.Challenge.create([doc], { writeConcern: env.WRITE_CONCERN });
  return docs[0];
}

module.exports = {
  withFixture,
  compositionBlocked,
  seedAuthority,
  seedPairingSession,
  seedChallenge,
  fence,
  env,
  results,
};