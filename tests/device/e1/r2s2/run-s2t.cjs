'use strict';

/**
 * W3-B R2 S2-T runner (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Runs the eight authorized S2-T rows, refreshes S2T-RESULTS.json and S2T-TEST-REPORT.md after every
 * row, captures raw per-row artifacts, and finishes with a before/after namespace audit.
 *
 * Order of operations (frozen): frozen-input hash preflight FIRST; if it fails, the run is BLOCKED,
 * no row executes, and the report/results record the observed hashes.
 */

const fs = require('node:fs');
const path = require('node:path');

const { HarnessFail, env, fence, ledger, w3a, withRowDb } = require('./harness.cjs');
const preflightModule = require('./preflight.cjs');
const { ROWS } = require('./fixtures-e1.cjs');
const { runS2T03 } = require('./fixtures-e2.cjs');

const S2T03_SPEC = {
  id: 'S2T-03',
  tier: 'E2',
  expectedOracle:
    'PASS iff same-generation competing operations at one frozen expectedEpoch g produce at most exactly one successful generation transition per the fixture budget (row X: exactly one, the generation-changing revoke; row Y: exactly one claim), every loser 0-match/fail-closed, and a row-generation delta of exactly +1 per fixture row',
};

function harnessInfo(preflight) {
  return {
    commission: 'PHASE1-LOCAL-AUTHORITY-001',
    workstream: 'W3-B R2 S2-T',
    agent: 'S2T-TEST (depth one, single child of PM)',
    frozenHead: 'a3fb9754bce5a940cb0f78161985b93c20d74727',
    authorization: 'cbhr-rdc/docs/GOVERNOR-W3B-R2-S2T-AUTHORIZATION-20261015.md',
    registrySource:
      'genuine createModels(mongoose) from packages/data-schemas/src/models/index.ts via the disclosed I10 TS bridge; raw registry handed to product factories directly (no plain-object facade)',
    compositionPrecondition: 'all three frozen factories accepted the raw genuine registry before every row',
    auditSink: 'real AuditEvent Mongoose model (no raw-driver audit downgrade)',
    compositionShortcutUsed: false,
    mongo: {
      uri: fence.FROZEN_URI,
      replicaSet: fence.REQUIRED_REPLICA_SET,
      requiredServerVersion: fence.REQUIRED_SERVER_VERSION,
      pinnedDriverVersion: fence.PINNED_DRIVER_VERSION,
    },
    dbPrefix: fence.DB_PREFIX,
    evidenceDir: path.relative(env.WORKTREE, ledger.ARTIFACT_DIR).replace(/\\/g, '/'),
    nodeVersion: process.version,
    runnerPid: process.pid,
    driverVersion: fence.PINNED_DRIVER_VERSION,
    statusVocabulary: Object.values(ledger.STATUS),
    frozenInputCount: preflight.entries.length,
  };
}

function emptyNamespaceAudit() {
  return {
    before: [],
    after: [],
    created: [],
    removed: [],
    foreignCreated: [],
    foreignRemoved: [],
    leftovers: [],
    leftoverOwned: [],
    identical: false,
    ok: false,
  };
}

function classifyRunError(err) {
  const name = err && err.name ? err.name : 'Error';
  const message = err && err.message ? err.message : String(err);
  if (name === 'S2TFenceViolation' || name === 'FenceViolation' || /DRIVER_VERSION_DRIFT/.test(message)) {
    return 'ENV_BLOCKED';
  }
  if (
    /MongoNetworkError|MongoServerSelectionError|MongoNotConnectedError|MongoTopologyClosedError|ECONNREFUSED|ETIMEDOUT/i.test(
      `${name} ${message}`,
    )
  ) {
    return 'ENV_BLOCKED';
  }
  return 'HARNESS_FAIL';
}

function rawError(err) {
  return {
    name: err && err.name ? err.name : 'Error',
    code: err && err.code ? err.code : null,
    message: err && err.message ? err.message : String(err),
    stack: err && err.stack ? err.stack : null,
    problems: err && Array.isArray(err.problems) ? err.problems : null,
    clientCreated: err && typeof err.clientCreated === 'boolean' ? err.clientCreated : null,
  };
}

async function main() {
  const preflight = preflightModule.runPreflight();
  const harness = harnessInfo(preflight);

  if (!preflight.ok) {
    ledger.writeOutputs({
      rows: [],
      preflight,
      namespaceAudit: emptyNamespaceAudit(),
      harness,
      blockedReason: `STEP 2 frozen-input hash preflight FAILED: ${preflight.problems.join(' | ')}`,
    });
    process.stdout.write(
      `[r2-s2t] BLOCKED by frozen-input preflight: ${preflight.problems.join(' | ')}\n`,
    );
    process.exitCode = 2;
    return;
  }

  const namespaceBefore = await fence.listDatabaseNames();
  const rows = [];
  const artifacts = [];

  const refresh = () =>
    ledger.writeOutputs({
      rows,
      preflight,
      namespaceAudit: {
        ...fence.auditDatabaseSets(namespaceBefore, namespaceBefore),
        pending: true,
        ok: false,
        identical: false,
        note: 'interim refresh; the authoritative before/after namespace audit is written after the final row',
      },
      harness,
    });

  const pushRow = (row) => {
    rows.push(row);
    const artifactFile = path.join(ledger.ARTIFACT_DIR, `${row.id}-row.json`);
    ledger.writeJson(artifactFile, row);
    artifacts.push({
      id: row.id,
      file: path.relative(env.WORKTREE, artifactFile).replace(/\\/g, '/'),
      bytes: fs.statSync(artifactFile).size,
    });
    refresh();
    process.stdout.write(`[r2-s2t] ${row.id} ${row.status} (productMethodInvoked=${row.productMethodInvoked})\n`);
  };

  // S2T-01, S2T-02, S2T-04, S2T-05, S2T-06, S2T-07, S2T-08 (E1/E0 rows), then S2T-03 (E2).
  for (const def of ROWS) {
    try {
      // eslint-disable-next-line no-await-in-loop
      const result = await withRowDb(def.tag, def.run);
      const outcome = result.outcome;
      const actual = outcome.notes ? { ...outcome.actual, notes: outcome.notes } : outcome.actual;
      pushRow(
        ledger.makeRow({
          id: def.id,
          tier: def.tier,
          status: outcome.status,
          productMethodInvoked: outcome.productMethodInvoked,
          expectedOracle: def.expectedOracle,
          actual,
          components: outcome.components ?? [],
          pids: null,
          attempts: null,
          dbName: result.dbName,
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
          productMethodInvoked: false,
          expectedOracle: def.expectedOracle,
          actual: {
            scenario: `row ${def.id} did not produce a product observation`,
            error: rawError(err),
            classification: status,
            harnessFailDetail: err instanceof HarnessFail ? err.detail : null,
          },
          components: [],
          pids: null,
          attempts: null,
          dbName: null,
          dbReadBack: null,
          sourceHashes: preflight.hashes,
        }),
      );
    }
  }

  try {
    const result = await runS2T03();
    pushRow(
      ledger.makeRow({
        id: S2T03_SPEC.id,
        tier: S2T03_SPEC.tier,
        status: result.status,
        productMethodInvoked: true,
        expectedOracle: S2T03_SPEC.expectedOracle,
        actual: result.actual,
        components: result.components,
        pids: result.pids,
        attempts: result.attempts,
        dbName: result.dbName,
        dbReadBack: result.dbReadBack,
        sourceHashes: preflight.hashes,
      }),
    );
  } catch (err) {
    const status = classifyRunError(err);
    pushRow(
      ledger.makeRow({
        id: S2T03_SPEC.id,
        tier: S2T03_SPEC.tier,
        status,
        productMethodInvoked: false,
        expectedOracle: S2T03_SPEC.expectedOracle,
        actual: {
          scenario: 'S2T-03 did not produce a product observation',
          error: rawError(err),
          classification: status,
        },
        components: [],
        pids: null,
        attempts: null,
        dbName: null,
        dbReadBack: null,
        sourceHashes: preflight.hashes,
      }),
    );
  }

  // STEP 5 — namespace hygiene: drop every owned leftover, then re-inventory.
  let namespaceAfter = await fence.listDatabaseNames();
  const leftoverBeforeCleanup = namespaceAfter.filter((name) => fence.isOwnedDb(name));
  const leftoversDropped = [];
  if (leftoverBeforeCleanup.length > 0) {
    const { client } = await fence.connectGuarded({
      dbName: fence.createDbName('cleanup'),
      appName: 'cbhr-r2-s2t-cleanup',
    });
    try {
      for (const name of leftoverBeforeCleanup) {
        // eslint-disable-next-line no-await-in-loop
        leftoversDropped.push(await fence.dropOwnDatabase(client, name));
      }
    } finally {
      await client.close().catch(() => {});
    }
    namespaceAfter = await fence.listDatabaseNames();
  }

  const namespaceAudit = {
    ...fence.auditDatabaseSets(namespaceBefore, namespaceAfter),
    leftoverBeforeCleanup,
    leftoversDropped,
  };

  ledger.writeOutputs({ rows, preflight, namespaceAudit, harness });

  const manifestFile = path.join(ledger.ARTIFACT_DIR, 'S2T-MANIFEST.json');
  ledger.writeJson(manifestFile, {
    generatedAt: new Date().toISOString(),
    frozenInputHashes: preflight.hashes,
    preflightOk: preflight.ok,
    harness,
    rowCounts: ledger.summarise(rows),
    namespaceAudit,
    artifacts,
    reportPath: path.relative(env.WORKTREE, ledger.REPORT_PATH).replace(/\\/g, '/'),
    resultsPath: path.relative(env.WORKTREE, ledger.RESULTS_PATH).replace(/\\/g, '/'),
  });

  const summary = ledger.summarise(rows);
  process.stdout.write(`[r2-s2t] rows=${summary.rows} ${JSON.stringify(summary.byStatus)}\n`);
  process.stdout.write(
    `[r2-s2t] namespace ok=${namespaceAudit.ok} identical=${namespaceAudit.identical} leftovers=${JSON.stringify(
      namespaceAudit.leftovers,
    )}\n`,
  );

  const blocking = rows.filter(
    (row) => row.status === ledger.STATUS.HARNESS_FAIL || row.status === ledger.STATUS.ENV_BLOCKED,
  );
  if (!namespaceAudit.ok || blocking.length > 0) {
    process.exitCode = 1;
  }
}

main().catch((err) => {
  process.stderr.write(`[r2-s2t] FATAL ${err && err.stack ? err.stack : err}\n`);
  process.exitCode = 1;
});