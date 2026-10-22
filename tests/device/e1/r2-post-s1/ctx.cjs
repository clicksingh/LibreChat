'use strict';

/**
 * W3-B R2-T0 per-fixture context (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Every fixture gets:
 *   - its own fenced database `cbhr_rdc_phase1_r2_t0_<unique>` (fence runs before any client);
 *   - a real Mongo connection (guarded) and the real Mongoose connection;
 *   - the real `createModels(mongoose)` registry, whose members are genuine Model constructors;
 *   - the real `AuditEvent` model as the ONLY audit sink;
 *   - a DB read-back and a teardown that drops only its own database.
 */

const path = require('node:path');

const fence = require('./fence.cjs');
const env = require('./env.cjs');
const results = require('./results.cjs');

const EVIDENCE_DIR = path.resolve(
  __dirname,
  '..',
  '..',
  '_phase1_evidence',
  'w3b-r2',
  'post-s1',
  'artifacts',
);

async function withFixture(tag, body, { syncIndexes = true, dropOnTeardown = true, clock = null } = {}) {
  const dbName = fence.createDbName(tag);
  const fenceDecision = { dbName, problems: fence.checkDbName(dbName), checkedBeforeClient: true };
  if (fenceDecision.problems.length > 0) {
    throw new fence.R2FenceViolation(fenceDecision.problems, { dbName, phase: 'fixture-pre-connect' });
  }
  const { client, topology } = await fence.connectGuarded({ dbName, appName: `cbhr-r2-t0-${tag}` });
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
    TE: null,
  };
  try {
    const loaded = env.loadRegistry();
    context.registry = loaded.registry;
    context.shape = loaded.shape;
    context.models = {
      DeviceAuthority: loaded.registry.DeviceAuthority,
      PairingSession: loaded.registry.PairingSession,
      Challenge: loaded.registry.Challenge,
      AuditEvent: loaded.registry.AuditEvent,
    };
    await env.connectMongoose({ uri: fence.FROZEN_URI, dbName, appName: `cbhr-r2-t0-${tag}` }).catch(() => null);
    context.audit = env.makeRealAuditSink(context.models, context.clock);
    context.syncReport = syncIndexes ? await env.syncDeclaredIndexes(context.models) : null;

    /** Composes the three frozen factories with the RAW registry; no facade, no retry. */
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
    return { outcome, dbReadBack, dbName };
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
 * Shared shape for a composition-gated E1/E2 row: the first truthful failure is factory
 * construction, so the row is EXPECTED_RED / FACTORY_COMPOSITION_FAIL and the downstream frozen
 * oracle is preserved as `pendingOracle` (pending-after-first-fix).
 */
function compositionBlocked(ctx, { pendingOracle, extraActual = {}, sourceAnchors = [], components = [] }) {
  const composition = ctx.compose();
  const view = env.compositionFailView(composition, pendingOracle, extraActual);
  const rejected = composition.filter((c) => c.accepted === false);
  return {
    status: results.STATUS.EXPECTED_RED,
    actual: view,
    components,
    sourceAnchors: [...new Set([...sourceAnchors, ...rejected.map((c) => c.guardAnchor)])],
  };
}

/**
 * Fixture definition: `build(ctx)` returns the row fields (status/actual/components/...).
 * The runner hashes the whole payload into the artifact directory and stamps `artifactSha256`.
 */
async function runFixture(def) {
  const { outcome, dbReadBack, dbName } = await withFixture(def.id, def.build, def.options ?? {});
  return results.makeRow({
    id: def.id,
    hostileRows: def.hostileRows ?? [],
    tier: def.tier,
    executedTier: outcome.executedTier ?? def.executedTier ?? def.tier,
    status: outcome.status,
    expectedOracle: def.expectedOracle,
    actual: outcome.actual,
    components: outcome.components ?? [],
    sourceAnchors: outcome.sourceAnchors ?? [],
    pids: outcome.pids ?? null,
    attempts: outcome.attempts ?? null,
    notes: outcome.notes ?? def.notes ?? null,
    productClaim: outcome.productClaim ?? false,
    dbReadBack,
    dbName,
    artifactPayload: { id: def.id, hostileRows: def.hostileRows ?? [], expectedOracle: def.expectedOracle, actual: outcome.actual, components: outcome.components ?? [], sourceAnchors: outcome.sourceAnchors ?? [], dbName, dbReadBack },
    evidenceDir: EVIDENCE_DIR,
  });
}

/** Harness setup write through the REAL AuditEvent/DeviceAuthority model, majority+journal. */
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

module.exports = {
  withFixture,
  compositionBlocked,
  runFixture,
  seedAuthority,
  EVIDENCE_DIR,
  fence,
  env,
  results,
  /** Cross-fixture run state (e.g. the G16 pre-suite verification for the before/after control). */
  state: {},
};