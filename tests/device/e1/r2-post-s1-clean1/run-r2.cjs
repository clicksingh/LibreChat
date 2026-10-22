'use strict';

/**
 * W3-B R2-T0 runner (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 *   node tests/device/e1/r2-post-s1-clean1/run-r2.cjs
 *
 * Order of operations:
 *   1. G16 pre-write gate — recompute all 51 ledger preimages + the R1 final-freeze SHA-256.
 *      On any mismatch it writes NOTHING and exits BLOCKED_NEEDS_GM.
 *   2. Server-wide namespace audit BEFORE.
 *   3. The four required named groups (R2-FENCE-EPOCH, R2-TRUST-PAIRING, R2-AUDIT-DURABILITY,
 *      R2-COMPOSITION-ERRORS), the two extra required items (F10 rejoin budget, G16 control) and
 *      the E2 two-process rows.
 *   4. Namespace audit AFTER; the run fails closed if any foreign database changed or any owned
 *      database was left behind.
 *   5. Durable results ledger + incremental baseline update.
 */

const fs = require('node:fs');
const path = require('node:path');

const fence = require('./fence.cjs');
const env = require('./env.cjs');
const results = require('./results.cjs');
const preflight = require('./preflight.cjs');
const ctx = require('./ctx.cjs');

const ctxState = ctx.state;

const GROUP_MODULES = [
  require('./fixtures-fence-epoch.cjs'),
  require('./fixtures-trust-pairing.cjs'),
  require('./fixtures-audit-durability.cjs'),
  require('./fixtures-composition-errors.cjs'),
];

const T0_DIR = path.resolve(__dirname, '..', '..', '_phase1_evidence', 'w3b-r2', 'post-s1-clean1');
const BASELINE = path.join(T0_DIR, 'R2-POST-S1-CLEAN1-BASELINE.md');
const RUNNER_COMMAND = 'node tests/device/e1/r2-post-s1-clean1/run-r2.cjs';

function sha256FileSafe(file) {
  try {
    return results.sha256File(file);
  } catch {
    return null;
  }
}

function appendBaseline(text) {
  fs.mkdirSync(T0_DIR, { recursive: true });
  fs.appendFileSync(BASELINE, `\n${text}\n`, 'utf8');
}

function groupTable(rows) {
  const lines = ['| id | hostileRows | tier | executedTier | status | expected oracle | actual (headline) |', '|---|---|---|---|---|---|---|'];
  for (const row of rows) {
    const actualHeadline =
      row.actual && row.actual.kind
        ? `${row.actual.kind}${row.actual.firstRejectedFactory ? ` @ ${row.actual.firstRejectedFactory}` : ''}`
        : (row.actual && row.actual.scenario) || 'see JSON artifact';
    lines.push(
      `| ${row.id} | ${row.hostileRows.join(', ')} | ${row.tier} | ${row.executedTier} | ${row.status} | ${String(row.expectedOracle).replace(/\|/g, '\\|')} | ${String(actualHeadline).replace(/\|/g, '\\|')} |`,
    );
  }
  return lines.join('\n');
}

async function runGroup(module, rows) {
  const groupRows = [];
  for (const def of module.fixtures()) {
    let row;
    try {
      // eslint-disable-next-line no-await-in-loop
      row = await ctx.runFixture(def);
    } catch (err) {
      row = results.makeRow({
        id: def.id,
        hostileRows: def.hostileRows ?? [],
        tier: def.tier,
        executedTier: def.executedTier ?? def.tier,
        status: results.STATUS.HARNESS_FAIL,
        expectedOracle: def.expectedOracle,
        actual: { kind: 'HARNESS_FAIL', error: results.errorView(err), scenario: 'fixture threw before completing' },
        notes: 'A fixture exception is a harness failure, never a product red.',
      });
    }
    groupRows.push(row);
    rows.push(row);
  }
  appendBaseline(
    `### ${module.id} (H rows in this group)\n\n${groupTable(groupRows)}\n`,
  );
  process.stdout.write(`[r2-t0] ${module.id}: ${groupRows.length} fixtures\n`);
  for (const row of groupRows) {
    process.stdout.write(`  ${row.status.padEnd(20)} ${row.id}\n`);
  }
}

async function main() {
  const startedAt = new Date().toISOString();
  const before = preflight.verifyLedger();
  const ledgerRaw = before.ledgerPath && fs.existsSync(before.ledgerPath) ? JSON.parse(fs.readFileSync(before.ledgerPath, 'utf8')) : { items: [] };
  ctxState.g16Before = before;
  ctxState.g16LedgerPaths = ledgerRaw.items.map((item) => ({ key: `${item.root}:${item.path}` }));

  if (!before.ok) {
    process.stdout.write(`${JSON.stringify({ status: 'BLOCKED_NEEDS_GM', detail: before }, null, 2)}\n`);
    process.exitCode = 2;
    return;
  }
  appendBaseline(`\n## 3.1 Pre-write gate re-verified in-runner (${startedAt})\n\n- ledger: \`${before.ledgerPath}\`\n- preimages verified: ${before.verified}/${before.itemCount}\n- final freeze SHA-256: \`${before.freeze.actual}\` (expected \`${before.freeze.expected}\`)\n- gate: PASS\n`);

  const databaseNamesBefore = await fence.listDatabaseNames();
  const rows = [];

  for (const module of GROUP_MODULES) {
    // eslint-disable-next-line no-await-in-loop
    await runGroup(module, rows);
  }

  const extra = require('./fixtures-extra.cjs');
  await runGroup(extra, rows);

  const e2 = require('./fixtures-e2.cjs');
  const e2Rows = [];
  for (const def of e2.fixtureDefs()) {
    let row;
    try {
      // eslint-disable-next-line no-await-in-loop
      const outcome = await e2.runTwoProcessRow(def);
      row = outcome.row;
    } catch (err) {
      row = results.makeRow({
        id: def.id,
        hostileRows: def.hostileRows,
        tier: 'E2',
        executedTier: 'E2',
        status: results.STATUS.HARNESS_FAIL,
        expectedOracle: def.expectedOracle,
        actual: { kind: 'HARNESS_FAIL', error: results.errorView(err), scenario: def.scenario },
        notes: 'An E2 orchestration exception is a harness failure.',
      });
    }
    e2Rows.push(row);
    rows.push(row);
  }
  appendBaseline(`### R2-E2-TWO-PROCESS\n\n${groupTable(e2Rows)}\n`);
  process.stdout.write(`[r2-t0] R2-E2-TWO-PROCESS: ${e2Rows.length} fixtures\n`);
  for (const row of e2Rows) {
    process.stdout.write(`  ${row.status.padEnd(20)} ${row.id}\n`);
  }

  const databaseNamesAfter = await fence.listDatabaseNames();
  const namespaceAudit = fence.auditDatabaseSets(databaseNamesBefore, databaseNamesAfter);

  const summary = results.summarise(rows);
  const finishedAt = new Date().toISOString();

  // Live topology probe: the guarded connection is closed immediately so the run cannot leak a
  // Mongo monitor socket and hang the event loop.
  const topologyProbe = await fence.connectGuarded({ dbName: fence.createDbName('topologyprobe') });
  const liveMongo = topologyProbe.topology;
  await topologyProbe.client.close().catch(() => {});
  await env.w3a.mongoose.disconnect().catch(() => {});
  const blockedAtFirstStep = rows.filter((row) => row.actual && row.actual.kind === 'FACTORY_COMPOSITION_FAIL').length;
  const guardAnchors = Array.from(
    new Set(rows.flatMap((row) => (row.sourceAnchors ?? []).filter((anchor) => typeof anchor === 'string' && anchor.includes('assertDependencies')))),
  );

  const payload = {
    schema: 'cbhr-rdc/r2-t0-baseline/v1',
    wave: 'W3-B R2-T0',
    commission: 'PHASE1-LOCAL-AUTHORITY-001',
    frozenHead: preflight.FROZEN_HEAD,
    runnerCommand: RUNNER_COMMAND,
    startedAt,
    finishedAt,
    node: process.version,
    runtime: {
      mongoose: require(path.join(env.w3a.WORKTREE, 'tests', 'device', '_phase1_evidence', 'w2-runtime', 'node_modules', 'mongoose', 'package.json')).version,
      mongodb: require(path.join(env.w3a.WORKTREE, 'tests', 'device', '_phase1_evidence', 'w2-runtime', 'node_modules', 'mongodb', 'package.json')).version,
    },
    liveMongo,
    preflight: {
      ok: before.ok,
      ledgerPath: before.ledgerPath,
      governanceRoot: before.governanceRoot,
      itemCount: before.itemCount,
      declaredCount: before.declaredCount,
      verified: before.verified,
      mismatches: before.mismatches,
      missing: before.missing,
      freeze: before.freeze,
    },
    namespaceAudit,
    summary,
    blockedAtFactoryComposition: blockedAtFirstStep,
    guardAnchorsObserved: guardAnchors,
    liveMongo,
    rows,
  };

  results.ensureDir(T0_DIR);
  const resultsFile = path.join(T0_DIR, 'R2-POST-S1-CLEAN1-RESULTS.json');
  fs.writeFileSync(resultsFile, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');

  const lines = [];
  lines.push(`\n## 4. T0 suite summary (${finishedAt})\n`);
  lines.push(`- runner: \`${RUNNER_COMMAND}\``);
  lines.push(`- fixtures: ${summary.fixtures}`);
  lines.push(`- by status: ${JSON.stringify(summary.byStatus)}`);
  lines.push(`- by tier: ${JSON.stringify(summary.byTier)}`);
  lines.push(`- rows stopped at factory composition: ${blockedAtFirstStep}`);
  lines.push(`- uncovered hostile rows: ${summary.uncoveredHostileRows.length === 0 ? 'none' : summary.uncoveredHostileRows.join(', ')}`);
  lines.push(`- namespace audit ok: ${namespaceAudit.ok} (created ${namespaceAudit.created.length}, removed ${namespaceAudit.removed.length}, foreign created ${namespaceAudit.foreignCreated.length}, foreign removed ${namespaceAudit.foreignRemoved.length}, leftover owned ${namespaceAudit.leftoverOwned.length})`);
  lines.push(`- machine-readable ledger: \`tests/device/_phase1_evidence/w3b-r2/post-s1-clean1/R2-POST-S1-CLEAN1-RESULTS.json\``);
  lines.push('');
  lines.push(groupTable(rows));
  lines.push('');
  appendBaseline(lines.join('\n'));

  const fileHashes = [
    'tests/device/e1/r2-post-s1-clean1/fence.cjs',
    'tests/device/e1/r2-post-s1-clean1/env.cjs',
    'tests/device/e1/r2-post-s1-clean1/preflight.cjs',
    'tests/device/e1/r2-post-s1-clean1/results.cjs',
    'tests/device/e1/r2-post-s1-clean1/ctx.cjs',
    'tests/device/e1/r2-post-s1-clean1/fixtures-fence-epoch.cjs',
    'tests/device/e1/r2-post-s1-clean1/fixtures-trust-pairing.cjs',
    'tests/device/e1/r2-post-s1-clean1/fixtures-audit-durability.cjs',
    'tests/device/e1/r2-post-s1-clean1/fixtures-composition-errors.cjs',
    'tests/device/e1/r2-post-s1-clean1/fixtures-extra.cjs',
    'tests/device/e1/r2-post-s1-clean1/fixtures-e2.cjs',
    'tests/device/e1/r2-post-s1-clean1/child-e2.cjs',
    'tests/device/e1/r2-post-s1-clean1/run-r2.cjs',
  ].map((relative) => ({
    path: relative,
    sha256: sha256FileSafe(path.join(env.WORKTREE, ...relative.split('/'))),
  }));
  fs.writeFileSync(path.join(T0_DIR, 'R2-POST-S1-CLEAN1-FILE-HASHES.json'), `${JSON.stringify(fileHashes, null, 2)}\n`, 'utf8');

  process.stdout.write(`[r2-t0] fixtures=${summary.fixtures} byStatus=${JSON.stringify(summary.byStatus)} byTier=${JSON.stringify(summary.byTier)}\n`);
  process.stdout.write(`[r2-t0] namespace audit ok=${namespaceAudit.ok}\n`);
  process.stdout.write(`[r2-t0] uncovered hostile rows: ${summary.uncoveredHostileRows.length === 0 ? 'none' : summary.uncoveredHostileRows.join(',')}\n`);
  if (summary.uncoveredHostileRows.length > 0 || !namespaceAudit.ok) {
    process.exitCode = 1;
  }
}

main().catch((err) => {
  process.stdout.write(`${JSON.stringify({ status: 'HARNESS_FAIL', error: results.errorView(err), stack: err.stack }, null, 2)}\n`);
  process.exitCode = 1;
});