'use strict';

/**
 * W3-B R2 S4T create-path durability runner (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Order of operations (frozen):
 *   1. six-source SHA-256 hash gate FIRST — a mismatch BLOCKS the run with no row executed;
 *   2. pre-run integrity baseline (dependency surface, prior-lane evidence, server database set,
 *      fence-ordering probe);
 *   3. S4T-01 … S4T-07 executed one row per fenced `cbhr_rdc_phase1_r2_s4t_*` database;
 *   4. owned-database cleanup + server-wide before/after namespace audit;
 *   5. S4T-08 namespace/integrity row derived from the observed facts;
 *   6. machine-readable 8-row ledger + small deterministic artifacts;
 *   7. exit 0 ONLY when every row reaches exactly its authorized pre-repair state and all
 *      cleanup/integrity checks are green.
 */

const fs = require('node:fs');
const path = require('node:path');

const { HarnessFail, fence, ledger, withRowDb } = require('./harness.cjs');
const preflightModule = require('./preflight.cjs');
const { ROWS, runS4T08 } = require('./rows.cjs');

const PRIOR_LANE_PHASES = Object.freeze([
  's1',
  's1r',
  's1r2',
  's2i',
  's2ir',
  's2t',
  's3-audit',
  's3b-r',
  't0',
  't0a',
  't1-audit',
  't1r-audit',
  'post-s1',
  'post-s1-clean1',
  'post-s1a-clean1',
]);

const EVIDENCE_ROOT = path.join(preflightModule.WORKTREE, 'tests', 'device', '_phase1_evidence', 'w3b-r2');

function listPriorLaneEvidenceFiles() {
  const files = [];
  for (const phase of PRIOR_LANE_PHASES) {
    const dir = path.join(EVIDENCE_ROOT, phase);
    if (!fs.existsSync(dir)) {
      continue;
    }
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (!entry.isFile()) {
        continue;
      }
      if (!/\.(md|json)$/i.test(entry.name)) {
        continue;
      }
      files.push(
        path.relative(preflightModule.WORKTREE, path.join(dir, entry.name)).replace(/\\/g, '/'),
      );
    }
  }
  return files.sort();
}

function classifyRunError(err) {
  const name = (err && err.name) || 'Error';
  const message = (err && err.message) || String(err);
  if (name === 'S4TFenceViolation' || name === 'FenceViolation' || /DRIVER_VERSION_DRIFT/.test(message)) {
    return ledger.STATUS.ENV_BLOCKED;
  }
  if (
    /MongoNetworkError|MongoServerSelectionError|MongoNotConnectedError|MongoTopologyClosedError|ECONNREFUSED|ETIMEDOUT/i.test(
      `${name} ${message}`,
    )
  ) {
    return ledger.STATUS.ENV_BLOCKED;
  }
  return ledger.STATUS.HARNESS_FAIL;
}

function compactRowProjection(row) {
  return {
    id: row.id,
    tier: row.tier,
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

async function main() {
  const writer = new ledger.LedgerWriter();
  writer.log('[r2-s4t] STEP 1 — frozen-input SHA-256 hash gate');

  const preflight = preflightModule.runPreflight();
  writer.writeArtifact('S4T-PREFLIGHT.json', {
    verdict: preflight.ok ? 'PASS' : 'BLOCKED',
    entries: preflight.entries.map((entry) => ({
      path: entry.path,
      observed: entry.observed,
      authorized: entry.authorized,
      match: entry.match,
      error: entry.error,
    })),
    problems: preflight.problems,
  });

  if (!preflight.ok) {
    const ledgerValue = {
      commission: 'PHASE1-LOCAL-AUTHORITY-001/W3B-R2-S4T',
      runner: 'tests/device/e1/r2post/durability/run-s4t.cjs',
      blocked: true,
      blockedReason: `frozen-input hash gate FAILED: ${preflight.problems.join(' | ')}`,
      rows: [],
      authorizedRowStates: ledger.AUTHORIZED_STATES,
      generatedAt: new Date().toISOString(),
    };
    writer.writeLedger(ledgerValue);
    writer.flushLog();
    writer.log(`[r2-s4t] BLOCKED by frozen-input hash gate: ${preflight.problems.join(' | ')}`);
    process.exitCode = 2;
    return;
  }
  writer.log(`[r2-s4t] hash gate PASS (${preflight.entries.length} sources matched)`);

  writer.log('[r2-s4t] STEP 2 — pre-run integrity baseline');
  const dependencyBefore = preflightModule.hashManifest(preflightModule.DEPENDENCY_SURFACE);
  const priorLaneFiles = listPriorLaneEvidenceFiles();
  const priorLaneBefore = preflightModule.hashManifest(priorLaneFiles);
  const fenceProbe = fence.probeFenceOrdering();
  writer.writeArtifact('S4T-FENCE-PROBE.json', fenceProbe);
  writer.log(
    `[r2-s4t] fence probe: ${fenceProbe.probed} names, all refused before client construction=${fenceProbe.allRefusedBeforeClientConstruction}`,
  );

  const namespaceBefore = await fence.listDatabaseNames();
  writer.writeArtifact('S4T-PRE-RUN-BASELINE.json', {
    generatedAt: new Date().toISOString(),
    frozenSourceHashes: preflight.hashes,
    dependencySurface: dependencyBefore,
    priorLaneEvidence: { files: priorLaneBefore.count, hashes: priorLaneBefore.files },
    namespaceBefore,
    fenceProbe: {
      gateOrder: fenceProbe.gateOrder,
      probed: fenceProbe.probed,
      allRefusedBeforeClientConstruction: fenceProbe.allRefusedBeforeClientConstruction,
    },
  });

  writer.log('[r2-s4t] STEP 3 — rows S4T-01 … S4T-07');
  const rowsById = new Map();
  const plannedDbNames = [];

  const pushRow = (row) => {
    rowsById.set(row.id, row);
    writer.writeArtifact(`${row.id}-row.json`, row);
    writer.log(
      `[r2-s4t] ${row.id} ${row.status} (authorized=${row.authorizedStatus} invoked=${row.productMethodInvoked} components=${row.components.filter((c) => c.met === true).length}/${row.components.length})`,
    );
  };

  for (const def of ROWS) {
    try {
      // eslint-disable-next-line no-await-in-loop
      const result = await withRowDb(def.tag, def.run);
      plannedDbNames.push(result.dbName);
      const outcome = result.outcome;
      pushRow(
        ledger.makeRow({
          id: def.id,
          tier: def.tier,
          status: outcome.status,
          expectedOracle: def.expectedOracle,
          repairPredicate: def.repairPredicate,
          productMethodInvoked: outcome.productMethodInvoked,
          actual: {
            ...outcome.actual,
            fenceDecision: result.fenceDecision,
            captureRecordsRestored: result.dbReadBack
              ? result.dbReadBack.captureRestored
              : null,
          },
          components: outcome.components,
          dbName: result.dbName,
          dbDropped: result.dropped,
          dbReadBack: result.dbReadBack,
          sourceHashes: preflight.hashes,
        }),
      );
    } catch (err) {
      const status = err instanceof HarnessFail ? ledger.STATUS.HARNESS_FAIL : classifyRunError(err);
      pushRow(
        ledger.makeRow({
          id: def.id,
          tier: def.tier,
          status,
          expectedOracle: def.expectedOracle,
          repairPredicate: def.repairPredicate,
          productMethodInvoked: false,
          actual: {
            scenario: `row ${def.id} did not produce a product observation`,
            classification: status,
            error: ledger.rawError(err),
            harnessFailDetail: err instanceof HarnessFail ? err.detail : null,
          },
          components: [],
          dbName: null,
          dbDropped: null,
          dbReadBack: null,
          sourceHashes: preflight.hashes,
        }),
      );
    }
  }

  writer.log('[r2-s4t] STEP 4 — owned-database cleanup + namespace audit');
  let namespaceAfter = await fence.listDatabaseNames();
  const leftoverBeforeCleanup = namespaceAfter.filter((name) => fence.isOwnedDb(name));
  const cleanupDrops = [];
  if (leftoverBeforeCleanup.length > 0) {
    const guarded = await fence.connectGuarded({
      dbName: fence.createDbName('cleanup'),
      appName: 'cbhr-r2-s4t-cleanup',
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
  writer.writeArtifact('S4T-NAMESPACE-AUDIT.json', namespaceAudit);
  writer.log(
    `[r2-s4t] namespace ok=${namespaceAudit.ok} identical=${namespaceAudit.identical} created=${JSON.stringify(namespaceAudit.created)} removed=${JSON.stringify(namespaceAudit.removed)} leftovers=${JSON.stringify(namespaceAudit.leftovers)}`,
  );

  writer.log('[r2-s4t] STEP 5 — post-run integrity + S4T-08');
  const postRunHashes = preflightModule.runPreflight();
  const dependencyAfter = preflightModule.hashManifest(preflightModule.DEPENDENCY_SURFACE);
  const priorLaneAfter = preflightModule.hashManifest(priorLaneFiles);
  const integrity = {
    postRunHashes: {
      ok: postRunHashes.ok,
      hashes: postRunHashes.hashes,
      problems: postRunHashes.problems,
    },
    dependencySurface: {
      files: dependencyBefore.count,
      comparison: preflightModule.compareManifests(dependencyBefore, dependencyAfter),
    },
    priorLaneEvidence: {
      files: priorLaneBefore.count,
      comparison: preflightModule.compareManifests(priorLaneBefore, priorLaneAfter),
    },
  };
  writer.writeArtifact('S4T-INTEGRITY.json', integrity);

  const s4t08 = runS4T08({
    preflight,
    postRunHashes,
    dependencySurface: { before: dependencyBefore, after: dependencyAfter, comparison: integrity.dependencySurface.comparison },
    priorLaneEvidence: { before: priorLaneBefore, after: priorLaneAfter, comparison: integrity.priorLaneEvidence.comparison },
    namespaceAudit,
    fenceOrderingProbe: fenceProbe,
    cleanupDrops,
  });
  const s4t08Def = {
    id: 'S4T-08',
    tier: 'E0',
    expectedOracle:
      'PASS iff all binding source hashes remain exact, accepted S1/S2/S3/T0/T0A/T1/T1R evidence is untouched, all owned databases are dropped and no foreign database changed',
    repairPredicate: null,
  };
  pushRow(
    ledger.makeRow({
      id: s4t08Def.id,
      tier: s4t08Def.tier,
      status: s4t08.status,
      expectedOracle: s4t08Def.expectedOracle,
      repairPredicate: s4t08Def.repairPredicate,
      productMethodInvoked: s4t08.productMethodInvoked,
      actual: s4t08.actual,
      components: s4t08.components,
      dbName: null,
      dbDropped: null,
      dbReadBack: null,
      sourceHashes: postRunHashes.hashes,
    }),
  );

  const rows = Array.from(rowsById.values()).sort((a, b) => a.id.localeCompare(b.id));
  const summary = ledger.summarise(rows);

  const blockers = rows
    .filter((row) => row.actual !== null && typeof row.actual === 'object' && row.actual.blocker)
    .map((row) => ({
      row: row.id,
      authorizedStatus: row.authorizedStatus,
      observedStatus: row.status,
      blocker: row.actual.blocker,
    }));
  if (blockers.length > 0) {
    writer.writeArtifact('S4T-BLOCKER.json', {
      generatedAt: new Date().toISOString(),
      blockers,
      note:
        'Each blocker is a frozen-substrate defect that prevents the authorized EXPECTED_RED state, because the authorization makes that state conditional on proven durable row read-back. The failed rows are NOT red findings and are NOT fixture defects.',
    });
  }

  const exitReasons = [];
  if (rows.length !== Object.keys(ledger.AUTHORIZED_STATES).length) {
    exitReasons.push(`row count ${rows.length} != ${Object.keys(ledger.AUTHORIZED_STATES).length}`);
  }
  if (!summary.allRowsMatchAuthorizedState) {
    exitReasons.push(`rows not in authorized pre-repair state: ${summary.unauthorizedStateRows.join(',')}`);
  }
  if (summary.fixtureDefectRows.length > 0) {
    exitReasons.push(
      `${summary.fixtureDefectRows.length} fixture-defect harness failure(s): ${summary.fixtureDefectRows.join(',')}`,
    );
  }
  for (const blocker of blockers) {
    exitReasons.push(
      `${blocker.row} BLOCKED (${blocker.blocker.kind}): ${blocker.blocker.observedCreateError ? blocker.blocker.observedCreateError.message : 'see S4T-BLOCKER.json'}`,
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
  if (!postRunHashes.ok) {
    exitReasons.push('post-run binding-source hash mismatch');
  }
  if (integrity.dependencySurface.comparison.unchanged !== true) {
    exitReasons.push('dependency surface changed during the run');
  }
  if (integrity.priorLaneEvidence.comparison.unchanged !== true) {
    exitReasons.push('prior-lane evidence changed during the run');
  }

  const exitCode = exitReasons.length === 0 ? 0 : 1;

  const frozenHashRecheck = postRunHashes.entries.map((entry) => ({
    path: entry.path,
    observed: entry.observed,
    authorized: entry.authorized,
    match: entry.match,
  }));

  const ledgerValue = {
    commission: 'PHASE1-LOCAL-AUTHORITY-001/W3B-R2-S4T',
    workstream: 'W3-B / R2 / S4T (CREATE-PATH DURABILITY TEST-FIRST)',
    authorization: 'cbhr-rdc/docs/GOVERNOR-W3B-R2-S4T-DURABILITY-TEST-AUTHORIZATION-20261015.md',
    frozenHead: 'a3fb9754bce5a940cb0f78161985b93c20d74727',
    runner: 'tests/device/e1/r2post/durability/run-s4t.cjs',
    generatedAt: new Date().toISOString(),
    nodeVersion: process.version,
    runnerPid: process.pid,
    mongo: {
      uri: fence.FROZEN_URI,
      requiredReplicaSet: fence.REQUIRED_REPLICA_SET,
      requiredServerVersion: fence.REQUIRED_SERVER_VERSION,
      pinnedDriverVersion: fence.PINNED_DRIVER_VERSION,
    },
    dbPrefix: fence.DB_PREFIX,
    frozenSourceHashes: preflight.hashes,
    frozenSourceHashesAfterRun: postRunHashes.hashes,
    frozenHashRecheck,
    repairPredicateLaw:
      "a create row is pinned only when the captured Model.create call includes an options object with writeConcern.w==='majority' and writeConcern.j===true; a connection/server default does not satisfy F8",
    authorizedRowStates: ledger.AUTHORIZED_STATES,
    rows,
    rowProjection: rows.map(compactRowProjection),
    summary,
    blockers,
    namespaceAudit,
    integrity,
    fenceProbe: {
      gateOrder: fenceProbe.gateOrder,
      probed: fenceProbe.probed,
      allRefusedBeforeClientConstruction: fenceProbe.allRefusedBeforeClientConstruction,
      refusedBeforeClientConstruction: fenceProbe.results
        .filter((entry) => entry.refusedBeforeClientConstruction)
        .map((entry) => entry.dbName),
      artifact: 'tests/device/e1/r2post/durability/artifacts/S4T-FENCE-PROBE.json',
    },
    cleanupDrops,
    exit: { code: exitCode, reasons: exitReasons },
  };
  writer.writeLedger(ledgerValue);

  const manifestFile = writer.writeArtifact('S4T-MANIFEST.json', {
    generatedAt: ledgerValue.generatedAt,
    runner: ledgerValue.runner,
    report: 'tests/device/_phase1_evidence/w3b-r2/s4t/S4T-DURABILITY-TEST.md',
    ledger: 'tests/device/e1/r2post/durability/artifacts/S4T-LEDGER.json',
    frozenSourceHashes: preflight.hashes,
    frozenSourceHashesAfterRun: postRunHashes.hashes,
    hashGateVerdict: preflight.ok ? 'PASS' : 'BLOCKED',
    postRunHashVerdict: postRunHashes.ok ? 'PASS' : 'BLOCKED',
    rowCounts: summary,
    rows: rows.map(compactRowProjection),
    blockers: blockers.map((entry) => ({
      row: entry.row,
      authorizedStatus: entry.authorizedStatus,
      observedStatus: entry.observedStatus,
      kind: entry.blocker.kind,
      observedCreateError: entry.blocker.observedCreateError,
      independenceProbe: entry.blocker.independenceProbe,
    })),
    namespaceAudit: {
      ok: namespaceAudit.ok,
      identical: namespaceAudit.identical,
      created: namespaceAudit.created,
      removed: namespaceAudit.removed,
      leftovers: namespaceAudit.leftovers,
      plannedDbNames,
      cleanupDrops,
    },
    fenceProbe: {
      probed: fenceProbe.probed,
      allRefusedBeforeClientConstruction: fenceProbe.allRefusedBeforeClientConstruction,
    },
    exitCode,
    exitReasons,
    artifacts: writer.artifacts,
  });

  writer.log(`[r2-s4t] rows=${summary.rows} ${JSON.stringify(summary.byStatus)}`);
  writer.log(`[r2-s4t] authorized-state match=${summary.allRowsMatchAuthorizedState}`);
  writer.log(`[r2-s4t] frozen hashes after run ok=${postRunHashes.ok}`);
  writer.log(`[r2-s4t] manifest=${path.relative(preflightModule.WORKTREE, manifestFile).replace(/\\/g, '/')}`);
  writer.log(
    `[r2-s4t] LEDGER ${JSON.stringify(
      rows.reduce((accumulator, row) => {
        accumulator[row.id] = row.status;
        return accumulator;
      }, {}),
    )}`,
  );
  writer.log(`[r2-s4t] EXIT ${exitCode}${exitReasons.length > 0 ? ` reasons=${JSON.stringify(exitReasons)}` : ''}`);
  writer.flushLog();

  process.exitCode = exitCode;
}

main().catch((err) => {
  process.stderr.write(`[r2-s4t] FATAL ${err && err.stack ? err.stack : err}\n`);
  process.exitCode = 1;
});
