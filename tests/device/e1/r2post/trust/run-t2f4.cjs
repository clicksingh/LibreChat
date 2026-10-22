'use strict';

/**
 * W3-B R2 T2-F4 trusted-tenant / ALS runner (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Order of operations (frozen):
 *   1. six-preimage SHA-256 hash gate FIRST — a mismatch BLOCKS the run with no row executed;
 *   2. pre-run baseline (governance inventory, pinned runtime versions, prior-evidence manifest,
 *      fence-ordering probe, server database set);
 *   3. T2F4-01 … T2F4-09, in the authorization's exact order, one row per fenced
 *      `cbhr_rdc_phase1_r2_t2f4_*` database, real AsyncLocalStorage + genuine Mongoose/Mongo;
 *   4. owned-database cleanup + server-wide before/after namespace audit;
 *   5. post-run integrity (preimages re-hashed, prior evidence re-hashed);
 *   6. machine-readable nine-row ledger + manifest, all artifacts under this runner's own
 *      `run-<id>` directory inside the authorized `tests/device/e1/r2post/trust/**` scope;
 *   7. exit 0 ONLY when every row reaches exactly its authorized current state and all
 *      cleanup/integrity checks are green.
 *
 * PM executes this file exactly once. The writer never executed it.
 */

const path = require('node:path');

const expected = require('./expected.cjs');
const preimages = require('./preimages.cjs');
const harness = require('./harness.cjs');
const { ROWS } = require('./rows.cjs');

const WORKTREE = harness.WORKTREE;
const fence = harness.fence;
const TRUST_DIR = __dirname;

const RUN_ID = `run-w3b-r2-t2f4-${new Date()
  .toISOString()
  .replace(/[-:.TZ]/g, '')
  .slice(0, 14)}-${require('node:crypto').randomBytes(3).toString('hex')}`;

const REPORTS = Object.freeze({
  writerReport: 'tests/device/_phase1_evidence/w3b-r2/t2-f4-trust/T2-F4-TRUST-WRITER.md',
  pmGateManifest: 'tests/device/_phase1_evidence/w3b-r2/t2-f4-trust/GATE-MANIFEST.json',
  pmTerminal: 'tests/device/_phase1_evidence/w3b-r2/t2-f4-trust/PM-T2-F4-TERMINAL.json',
  authorization:
    'cbhr-rdc/docs/GOVERNOR-W3B-R2-T2-F4-TRUST-TEST-AUTHORIZATION-20261015.md',
  recovery: 'cbhr-rdc/docs/GOVERNOR-W3B-R2-T2-F4R-RECOVERY-20261015.md',
});

function classifyRunError(err) {
  const name = (err && err.name) || 'Error';
  const message = (err && err.message) || String(err);
  if (
    name === 'T2F4FenceViolation' ||
    name === 'FenceViolation' ||
    /DRIVER_VERSION_DRIFT/.test(message)
  ) {
    return expected.STATUS.ENV_BLOCKED;
  }
  if (
    /MongoNetworkError|MongoServerSelectionError|MongoNotConnectedError|MongoTopologyClosedError|ECONNREFUSED|ETIMEDOUT/i.test(
      `${name} ${message}`,
    )
  ) {
    return expected.STATUS.ENV_BLOCKED;
  }
  return expected.STATUS.HARNESS_FAIL;
}

function compactRowProjection(row) {
  return {
    id: row.id,
    order: row.order,
    tier: row.tier,
    title: row.title,
    status: row.status,
    authorizedStatus: row.authorizedStatus,
    matchesAuthorizedState: row.matchesAuthorizedState,
    productMethodInvoked: row.productMethodInvoked,
    componentsMet: row.components.filter((component) => component.met === true).length,
    componentsTotal: row.components.length,
    dbName: row.dbName,
    dbDropped: row.dbDropped && row.dbDropped.dropped === true,
  };
}

/** The nine-row table the PM can diff directly against the authorization. */
function buildExpectedStateTable() {
  return expected.EXPECTED_ROWS.map((row) => ({
    id: row.id,
    order: row.order,
    tier: row.tier,
    title: row.title,
    authorizedStatus: row.authorizedStatus,
    requiredBehavior: row.requiredBehavior,
    assertionIds: row.assertionIds,
    expectedCurrentObservation: row.expectedCurrentObservation,
    tierNote: expected.TIER_NOTES[row.id],
  }));
}

function checkRowDefinitionDrift() {
  const problems = [];
  if (ROWS.length !== expected.EXPECTED_ROWS.length) {
    problems.push(`runner defines ${ROWS.length} rows, authorization defines ${expected.EXPECTED_ROWS.length}`);
  }
  for (let index = 0; index < expected.EXPECTED_ROWS.length; index += 1) {
    const defined = ROWS[index];
    const authorized = expected.EXPECTED_ROWS[index];
    if (defined === undefined) {
      problems.push(`runner is missing row at order ${index + 1} (${authorized.id})`);
      continue;
    }
    if (defined.id !== authorized.id) {
      problems.push(`order ${index + 1}: runner has ${defined.id}, authorization has ${authorized.id}`);
    }
    if (defined.tier !== authorized.tier) {
      problems.push(`${defined.id}: tier ${defined.tier} != ${authorized.tier}`);
    }
    if (defined.title !== authorized.title) {
      problems.push(`${defined.id}: title ${defined.title} != ${authorized.title}`);
    }
    if (defined.authorizedStatus !== authorized.authorizedStatus) {
      problems.push(
        `${defined.id}: authorizedStatus ${defined.authorizedStatus} != ${authorized.authorizedStatus}`,
      );
    }
  }
  return problems;
}

async function main() {
  const runDir = path.join(TRUST_DIR, RUN_ID);
  const writer = new expected.RunWriter({ runDir });
  writer.log(`[t2f4] RUN_ID ${RUN_ID}`);
  writer.log(`[t2f4] run directory ${path.relative(WORKTREE, runDir).replace(/\\/g, '/')}`);

  writer.log('[t2f4] STEP 0 — nine-row definition drift check');
  const driftProblems = checkRowDefinitionDrift();
  if (driftProblems.length > 0) {
    writer.writeArtifact('T2F4-DEFINITION-DRIFT.json', { problems: driftProblems });
    writer.log(`[t2f4] BLOCKED: row definition drift: ${driftProblems.join(' | ')}`);
    writer.writeLedger({
      commission: 'PHASE1-LOCAL-AUTHORITY-001/W3B-R2-T2-F4R',
      runner: 'tests/device/e1/r2post/trust/run-t2f4.cjs',
      runId: RUN_ID,
      blocked: true,
      blockedReason: `row definition drift: ${driftProblems.join(' | ')}`,
      rows: [],
      exit: { code: 2, reasons: driftProblems },
      generatedAt: new Date().toISOString(),
    });
    writer.flushLog();
    process.exitCode = 2;
    return;
  }
  writer.log('[t2f4] row definitions match the authorization (id/order/tier/title/authorizedStatus)');

  writer.log('[t2f4] STEP 1 — six controlling-preimage SHA-256 gate');
  const gate = preimages.runHashGate(WORKTREE);
  writer.writeArtifact('T2F4-PREIMAGES.json', {
    verdict: gate.ok ? 'PASS' : 'BLOCKED',
    algorithm: gate.algorithm,
    source: gate.source,
    entries: gate.entries.map((entry) => ({
      id: entry.id,
      path: entry.path,
      expected: entry.expected,
      observed: entry.observed,
      match: entry.match,
      error: entry.error,
    })),
    hashes: gate.hashes,
    problems: gate.problems,
  });
  if (!gate.ok) {
    writer.log(`[t2f4] BLOCKED by preimage gate: ${gate.problems.join(' | ')}`);
    writer.writeLedger({
      commission: 'PHASE1-LOCAL-AUTHORITY-001/W3B-R2-T2-F4R',
      workstream: 'W3-B / R2 / T2-F4 (TRUSTED TENANT / ALS TEST-FIRST, RECOVERY)',
      authorization: REPORTS.authorization,
      runner: 'tests/device/e1/r2post/trust/run-t2f4.cjs',
      runId: RUN_ID,
      blocked: true,
      blockedReason: `six-preimage hash gate FAILED: ${gate.problems.join(' | ')}`,
      preImageGate: { ok: false, hashes: gate.hashes, problems: gate.problems },
      rows: [],
      authorizedRowStates: expected.AUTHORIZED_STATES,
      expectedStateTable: buildExpectedStateTable(),
      exit: { code: 2, reasons: gate.problems },
      generatedAt: new Date().toISOString(),
    });
    writer.flushLog();
    process.exitCode = 2;
    return;
  }
  writer.log(`[t2f4] preimage gate PASS (${gate.entries.length}/6 matched)`);

  writer.log('[t2f4] STEP 2 — pre-run baseline');
  const priorEvidenceFiles = preimages.listPriorEvidenceFiles(WORKTREE);
  const priorEvidenceBefore = preimages.hashManifest(WORKTREE, priorEvidenceFiles);
  const fenceProbe = fence.probeFenceOrdering();
  writer.writeArtifact('T2F4-FENCE-PROBE.json', fenceProbe);
  writer.log(
    `[t2f4] fence probe: ${fenceProbe.probed} names, all refused before client construction=${fenceProbe.allRefusedBeforeClientConstruction}`,
  );

  const namespaceBefore = await fence.listDatabaseNames();
  writer.writeArtifact('T2F4-PRE-RUN-BASELINE.json', {
    generatedAt: new Date().toISOString(),
    runId: RUN_ID,
    nodeVersion: process.version,
    preImageHashes: gate.hashes,
    governanceDocuments: preimages.governanceInventory(),
    scopedRuntimeVersions: preimages.runtimeVersions(WORKTREE),
    priorEvidence: { files: priorEvidenceBefore.count, hashes: priorEvidenceBefore.files },
    namespaceBefore,
    tenantIsolationEnvironment: {
      TENANT_ISOLATION_STRICT: process.env.TENANT_ISOLATION_STRICT ?? null,
      strictModeActive: process.env.TENANT_ISOLATION_STRICT === 'true',
      note:
        'the runner never mutates process env; with TENANT_ISOLATION_STRICT=true the frozen plugin fails closed inside its own pre-hooks for ALS-absent operations, which is a substrate condition, not a T2-F4 finding',
    },
    fenceProbe: {
      gateOrder: fenceProbe.gateOrder,
      probed: fenceProbe.probed,
      allRefusedBeforeClientConstruction: fenceProbe.allRefusedBeforeClientConstruction,
    },
    mongo: {
      uri: fence.FROZEN_URI,
      requiredReplicaSet: fence.REQUIRED_REPLICA_SET,
      requiredServerVersion: fence.REQUIRED_SERVER_VERSION,
      pinnedDriverVersion: fence.PINNED_DRIVER_VERSION,
    },
  });

  writer.log('[t2f4] STEP 3 — rows T2F4-01 … T2F4-09 (authorization order)');
  const rows = [];
  const plannedDbNames = [];

  for (const def of ROWS) {
    let row;
    try {
      // eslint-disable-next-line no-await-in-loop
      const result = await harness.withRowDb(def.tag, def.run);
      plannedDbNames.push(result.dbName);
      const outcome = result.outcome;
      row = expected.makeRow({
        id: def.id,
        order: def.order,
        tier: def.tier,
        title: def.title,
        status: outcome.status,
        expectedOracle: def.expectedOracle ?? expected.EXPECTED_ROWS[def.order - 1].requiredBehavior,
        assertionIds: expected.EXPECTED_ROWS[def.order - 1].assertionIds,
        productMethodInvoked: outcome.productMethodInvoked,
        actual: {
          ...outcome.actual,
          fenceDecision: result.fenceDecision,
          counterRestoredBeforeReadBack: result.dbReadBack
            ? result.dbReadBack.counterRestored
            : null,
        },
        components: outcome.components,
        dbName: result.dbName,
        dbDropped: result.dropped,
        dbReadBack: result.dbReadBack,
        sourceHashes: gate.hashes,
      });
    } catch (err) {
      const status =
        err instanceof harness.HarnessFail ? expected.STATUS.HARNESS_FAIL : classifyRunError(err);
      row = expected.makeRow({
        id: def.id,
        order: def.order,
        tier: def.tier,
        title: def.title,
        status,
        expectedOracle: expected.EXPECTED_ROWS[def.order - 1].requiredBehavior,
        assertionIds: expected.EXPECTED_ROWS[def.order - 1].assertionIds,
        productMethodInvoked: false,
        actual: {
          scenario: `row ${def.id} did not produce a product observation`,
          classification: status,
          error: expected.rawError(err),
          harnessFailDetail: err instanceof harness.HarnessFail ? err.detail : null,
        },
        components: [],
        dbName: null,
        dbDropped: null,
        dbReadBack: null,
        sourceHashes: gate.hashes,
      });
    }
    rows.push(row);
    writer.writeArtifact(`${row.id}-row.json`, row);
    writer.log(
      `[t2f4] ${row.id} ${row.status} (authorized=${row.authorizedStatus} invoked=${row.productMethodInvoked} components=${row.components.filter((c) => c.met === true).length}/${row.components.length})`,
    );
  }

  writer.log('[t2f4] STEP 4 — owned-database cleanup + server-wide namespace audit');
  let namespaceAfter = await fence.listDatabaseNames();
  const leftoverBeforeCleanup = namespaceAfter.filter((name) => fence.isOwnedDb(name));
  const cleanupDrops = [];
  if (leftoverBeforeCleanup.length > 0) {
    const guarded = await fence.connectGuarded({
      dbName: fence.createDbName('cleanup'),
      appName: 'cbhr-r2-t2f4-cleanup',
    });
    try {
      for (const name of leftoverBeforeCleanup) {
        // eslint-disable-next-line no-await-in-loop
        cleanupDrops.push(await fence.dropOwnDatabase(guarded.client, name));
      }
    } finally {
      await guarded.client.close().catch(() => {});
    }
    namespaceAfter = await fence.listDatabaseNames();
  }
  const namespaceAudit = {
    ...fence.auditDatabaseSets(namespaceBefore, namespaceAfter),
    leftoverBeforeCleanup,
    leftoversDropped: cleanupDrops,
    plannedDbNames,
  };
  writer.writeArtifact('T2F4-NAMESPACE-AUDIT.json', namespaceAudit);
  writer.log(
    `[t2f4] namespace ok=${namespaceAudit.ok} identical=${namespaceAudit.identical} created=${JSON.stringify(namespaceAudit.created)} removed=${JSON.stringify(namespaceAudit.removed)} leftovers=${JSON.stringify(namespaceAudit.leftovers)}`,
  );

  writer.log('[t2f4] STEP 5 — post-run integrity re-hash');
  const postRunGate = preimages.runHashGate(WORKTREE);
  const priorEvidenceAfter = preimages.hashManifest(WORKTREE, priorEvidenceFiles);
  const integrity = {
    postRunPreImages: {
      ok: postRunGate.ok,
      hashes: postRunGate.hashes,
      problems: postRunGate.problems,
    },
    preImageStability: {
      before: gate.hashes,
      after: postRunGate.hashes,
      unchanged: JSON.stringify(gate.hashes) === JSON.stringify(postRunGate.hashes),
    },
    priorEvidence: {
      files: priorEvidenceBefore.count,
      comparison: preimages.compareManifests(priorEvidenceBefore, priorEvidenceAfter),
    },
  };
  writer.writeArtifact('T2F4-INTEGRITY.json', integrity);

  const summary = expected.summarise(rows);

  const exitReasons = [];
  if (rows.length !== expected.EXPECTED_ROWS.length) {
    exitReasons.push(`row count ${rows.length} != ${expected.EXPECTED_ROWS.length}`);
  }
  if (!summary.orderMatchesAuthorization) {
    exitReasons.push(
      `row order ${summary.rowOrder.join(',')} != authorization ${summary.expectedOrder.join(',')}`,
    );
  }
  if (!summary.allRowsMatchAuthorizedState) {
    exitReasons.push(`rows not in authorized current state: ${summary.unauthorizedStateRows.join(',')}`);
  }
  if (summary.fixtureDefectRows.length > 0) {
    exitReasons.push(
      `${summary.fixtureDefectRows.length} harness failure(s): ${summary.fixtureDefectRows.join(',')}`,
    );
  }
  if (!namespaceAudit.ok) {
    exitReasons.push('namespace audit not clean');
  }
  if (!cleanupDrops.every((entry) => entry.dropped === true)) {
    exitReasons.push('owned-database cleanup drop failed');
  }
  if (fenceProbe.allRefusedBeforeClientConstruction !== true) {
    exitReasons.push('fence ordering probe failed');
  }
  if (!postRunGate.ok) {
    exitReasons.push('post-run preimage hash mismatch');
  }
  if (integrity.preImageStability.unchanged !== true) {
    exitReasons.push('preimage hashes changed during the run');
  }
  if (integrity.priorEvidence.comparison.unchanged !== true) {
    exitReasons.push('prior-lane T2-F4 evidence changed during the run');
  }

  const exitCode = exitReasons.length === 0 ? 0 : 1;

  const ledgerValue = {
    commission: 'PHASE1-LOCAL-AUTHORITY-001/W3B-R2-T2-F4R',
    workstream: 'W3-B / R2 / T2-F4 (TRUSTED TENANT / ALS TEST-FIRST, RECOVERY)',
    authorization: REPORTS.authorization,
    recoveryAuthorization: REPORTS.recovery,
    writerReport: REPORTS.writerReport,
    runner: 'tests/device/e1/r2post/trust/run-t2f4.cjs',
    runId: RUN_ID,
    generatedAt: new Date().toISOString(),
    nodeVersion: process.version,
    runnerPid: process.pid,
    substrate: {
      realAsyncLocalStorage: {
        module: 'packages/data-schemas/src/config/tenantContext.ts',
        loadedThrough: 'pinned I10 bridge (require.extensions[".ts"], ts.transpileModule, CommonJS)',
        storageIsNativeAsyncLocalStorage: harness.als.storageIsNativeAsyncLocalStorage,
        moduleKind: harness.als.moduleKind,
        systemTenantId: harness.als.SYSTEM_TENANT_ID,
      },
      genuineMongooseMongo: {
        modelRegistry: 'packages/data-schemas/src/models/index.ts createModels(mongoose)',
        dbObjectHandedToFactories: 'raw registry directly (no facade, no proxy)',
        mongodbUri: fence.FROZEN_URI,
        requiredReplicaSet: fence.REQUIRED_REPLICA_SET,
        requiredServerVersion: fence.REQUIRED_SERVER_VERSION,
        pinnedDriverVersion: fence.PINNED_DRIVER_VERSION,
      },
      instrumentation: {
        kind: 'genuine model statics wrapped only to count invocations, restored before read-back',
        countedModels: harness.COUNTED_MODELS,
        patchedStatics: 'recorded per row in dbReadBack.counterPatchedStatics',
        noPlainObjectModelFacade: true,
      },
      auditSink: 'genuine product api/server/services/Device/auditSink.js adapter over the genuine AuditEvent model',
    },
    dbPrefix: fence.DB_PREFIX,
    preImageGate: {
      ok: gate.ok,
      algorithm: gate.algorithm,
      entries: gate.entries.map((entry) => ({
        id: entry.id,
        path: entry.path,
        expected: entry.expected,
        observed: entry.observed,
        match: entry.match,
      })),
      problems: gate.problems,
    },
    preImageHashesAfterRun: postRunGate.hashes,
    expectedStateTable: buildExpectedStateTable(),
    authorizedRowStates: expected.AUTHORIZED_STATES,
    rows,
    rowProjection: rows.map(compactRowProjection),
    summary,
    namespaceAudit,
    integrity,
    fenceProbe: {
      gateOrder: fenceProbe.gateOrder,
      probed: fenceProbe.probed,
      allRefusedBeforeClientConstruction: fenceProbe.allRefusedBeforeClientConstruction,
      refusedBeforeClientConstruction: fenceProbe.results
        .filter((entry) => entry.refusedBeforeClientConstruction)
        .map((entry) => entry.dbName),
    },
    cleanupDrops,
    exit: { code: exitCode, reasons: exitReasons },
  };
  writer.writeLedger(ledgerValue);

  const manifestFile = writer.writeArtifact('T2F4-MANIFEST.json', {
    generatedAt: ledgerValue.generatedAt,
    runId: RUN_ID,
    runner: ledgerValue.runner,
    writerReport: REPORTS.writerReport,
    pmOwned: {
      gateManifest: REPORTS.pmGateManifest,
      terminal: REPORTS.pmTerminal,
    },
    preImageGateVerdict: gate.ok ? 'PASS' : 'BLOCKED',
    postRunPreImageVerdict: postRunGate.ok ? 'PASS' : 'BLOCKED',
    rowCounts: summary,
    rows: rows.map(compactRowProjection),
    expectedStateTable: buildExpectedStateTable(),
    namespaceAudit: {
      ok: namespaceAudit.ok,
      identical: namespaceAudit.identical,
      created: namespaceAudit.created,
      removed: namespaceAudit.removed,
      leftovers: namespaceAudit.leftovers,
      plannedDbNames,
      cleanupDrops,
    },
    exitCode,
    exitReasons,
    artifacts: writer.artifacts,
  });

  writer.log(`[t2f4] rows=${summary.rows} ${JSON.stringify(summary.byStatus)}`);
  writer.log(`[t2f4] authorized-state match=${summary.allRowsMatchAuthorizedState}`);
  writer.log(`[t2f4] row order matches authorization=${summary.orderMatchesAuthorization}`);
  writer.log(`[t2f4] preimage hashes unchanged during run=${integrity.preImageStability.unchanged}`);
  writer.log(`[t2f4] manifest=${path.relative(WORKTREE, manifestFile).replace(/\\/g, '/')}`);
  writer.log(
    `[t2f4] LEDGER ${JSON.stringify(
      rows.reduce((accumulator, row) => {
        accumulator[row.id] = row.status;
        return accumulator;
      }, {}),
    )}`,
  );
  writer.log(`[t2f4] EXIT ${exitCode}${exitReasons.length > 0 ? ` reasons=${JSON.stringify(exitReasons)}` : ''}`);
  writer.flushLog();

  process.exitCode = exitCode;
}

main().catch((err) => {
  process.stderr.write(`[t2f4] FATAL ${err && err.stack ? err.stack : err}\n`);
  process.exitCode = 1;
});