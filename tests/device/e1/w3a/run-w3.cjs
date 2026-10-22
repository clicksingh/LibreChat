'use strict';

/**
 * W3-A / I11 top-level runner (PHASE1-LOCAL-AUTHORITY-001).
 *
 *   node tests/device/e1/w3a/run-w3.cjs [--only=E1-ONEPC-GRANT-CAS] [--n=50] [--run-key=<key>]
 *
 * Runs every product fixture and harness control against real frozen product bytes, real
 * Mongoose models and a real MongoDB at 127.0.0.1:27027, one self-owned
 * `cbhr_rdc_phase1_w3_*` database per fixture, drops only its own databases in `finally`, and
 * writes the raw per-fixture results plus an aggregate into
 * tests/device/_phase1_evidence/w3/I11-runs/<run-key>/.
 *
 * Exit codes: 0 all green / 2 blocked / 4 harness failure / 5 product failure.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const fence = require('./fence.cjs');
const env = require('./env.cjs');
const support = require('./support.cjs');

const authorityFixtures = require('./fixture-authority.cjs');
const pairingFixtures = require('./fixture-pairing.cjs');
const twoProcessFixtures = require('./fixture-two-process.cjs');
const naiveFixtures = require('./fixture-naive.cjs');
const crashFixtures = require('./fixture-crash.cjs');
const sweepFixtures = require('./fixture-sweep.cjs');
const fenceControls = require('./fixture-fence.cjs');

const PRODUCT_FIXTURES = [
  ...authorityFixtures.FIXTURES,
  ...pairingFixtures.FIXTURES,
  ...twoProcessFixtures.FIXTURES,
  ...crashFixtures.FIXTURES,
  ...sweepFixtures.FIXTURES,
];

const CONTROLS = [...fenceControls.CONTROLS, ...naiveFixtures.FIXTURES, ...sweepFixtures.CONTROLS];

const ALL = [...PRODUCT_FIXTURES, ...CONTROLS];

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith('--')) {
      continue;
    }
    const [flag, inlineValue] = arg.includes('=') ? arg.split(/=(.*)/s, 2) : [arg, null];
    const value = inlineValue !== null ? inlineValue : argv[index + 1];
    options[flag.slice(2)] = value === undefined ? true : value;
    if (inlineValue === null) {
      index += 1;
    }
  }
  return options;
}

function makeRunKey() {
  const stamp = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 15);
  return `run-${stamp}-${process.pid}`;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const only = options.only ? String(options.only).split(',') : null;
  const n = Number(options.n ?? 50);
  const runKey = options['run-key'] ? String(options['run-key']) : makeRunKey();
  const runDir = support.ensureDir(support.runDir(runKey));
  process.env.CBHR_W3A_RUN_KEY = runKey;

  const selected = only === null ? ALL : ALL.filter((fixture) => only.includes(fixture.id));
  if (selected.length === 0) {
    throw new Error(`no fixture matched --only=${only}`);
  }

  const manifest = {
    check: 'I11-W3A-MONGO-PRODUCT',
    lane: 'I11',
    runKey,
    runnerPid: process.pid,
    nodeVersion: process.version,
    command: process.argv.join(' '),
    n,
    selected: selected.map((fixture) => fixture.id),
    uri: fence.FROZEN_URI,
    dbPrefix: fence.DB_PREFIX,
    sweepKnobEnv: process.env.CBHR_PHASE1_SWEEP ?? 'unset',
    startedAt: new Date().toISOString(),
    productFiles: {},
    frozenHashes: {},
  };

  for (const [name, file] of Object.entries(env.PRODUCT_FILES)) {
    manifest.productFiles[name] = {
      file: path.relative(env.WORKTREE, file).replace(/\\/g, '/'),
      sha256: crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex').toUpperCase(),
    };
  }
  const governorReports = 'C:\\Users\\Aryan\\Desktop\\codellm\\cbhr-rdc\\reports';
  for (const name of [
    'GATE-CLOSURE-002-AUTHORITY-CANDIDATE.md',
    'GATE-CLOSURE-002-PAIRING-BOOTSTRAP.md',
    'GATE-CLOSURE-002-26-TOOLS.md',
    'GATE-CLOSURE-002-TEST-MATRIX.md',
  ]) {
    const file = path.join(governorReports, name);
    manifest.frozenHashes[name] = fs.existsSync(file)
      ? crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex').toUpperCase()
      : 'ABSENT';
  }

  const databasesBefore = await fence.listDatabaseNames();
  manifest.databasesBefore = databasesBefore;

  const results = [];
  for (const fixture of selected) {
    const startedAt = new Date().toISOString();
    const started = process.hrtime.bigint();
    let report;
    try {
      report = await fixture.run(fixture, { n });
    } catch (err) {
      report = {
        id: fixture.id,
        tier: fixture.tier,
        kind: fixture.kind,
        runner: fixture.runner,
        requires: fixture.requires,
        title: fixture.title,
        runnerPid: process.pid,
        productClaim: fixture.kind === 'product',
        status: 'HARNESS_FAIL',
        error: { name: err.name, message: err.message, stack: err.stack },
      };
    }
    const durationMs = Number(process.hrtime.bigint() - started) / 1e6;
    const artifact = path.join(runDir, `${fixture.id}.json`);
    const enriched = {
      ...report,
      tier: fixture.tier,
      kind: fixture.kind,
      runner: fixture.runner,
      requires: fixture.requires,
      title: fixture.title,
      runKey,
      startedAt,
      durationMs: Number(durationMs.toFixed(3)),
      rawCommand: `${process.execPath} ${process.argv.slice(1).join(' ')} --only=${fixture.id}`,
    };
    support.writeJson(runDir, `${fixture.id}.json`, enriched);
    enriched.artifactPath = artifact;
    enriched.artifactSha256 = support.sha256File(artifact);
    results.push(enriched);
    process.stderr.write(
      `[w3a] ${fixture.id} status=${enriched.status} durationMs=${enriched.durationMs} artifact=${path.basename(artifact)} sha256=${enriched.artifactSha256.slice(0, 16)}\n`,
    );
  }

  const databasesAfter = await fence.listDatabaseNames();
  const databaseAudit = fence.auditDatabaseSets(databasesBefore, databasesAfter);

  const counts = {
    total: results.length,
    product: results.filter((entry) => entry.kind === 'product').length,
    controls: results.filter((entry) => entry.kind !== 'product').length,
    pass: results.filter((entry) => entry.status === 'PASS').length,
    expectedFail: results.filter((entry) => entry.status === 'EXPECTED_FAIL').length,
    productFail: results.filter((entry) => entry.status === 'PRODUCT_FAIL').length,
    envBlocked: results.filter((entry) => entry.status === 'ENV_BLOCKED').length,
    blockedNotWired: results.filter((entry) => entry.status === 'BLOCKED_NOT_WIRED').length,
    harnessFail: results.filter((entry) => entry.status === 'HARNESS_FAIL').length,
    fabricatedPasses: results.filter((entry) => entry.kind === 'product' && entry.productClaim !== true && entry.status === 'PASS').length,
  };

  const aggregate = {
    ...manifest,
    finishedAt: new Date().toISOString(),
    counts,
    databaseAudit,
    fixtures: results.map((entry) => ({
      id: entry.id,
      tier: entry.tier,
      kind: entry.kind,
      runner: entry.runner,
      requires: entry.requires,
      status: entry.status,
      productClaim: entry.productClaim,
      runnerPid: entry.runnerPid,
      childPids: entry.childPids ?? null,
      dbName: entry.dbName ?? null,
      attempts: entry.attempts ?? null,
      durationMs: entry.durationMs,
      artifactSha256: entry.artifactSha256,
      failedCount: entry.failedCount ?? (entry.failedAssertions ? entry.failedAssertions.length : 0),
      realReturns: entry.realReturns ?? null,
      counterexample: entry.counterexample ?? null,
    })),
  };

  let status = 'COMPLETE';
  let exitCode = 0;
  if (counts.harnessFail > 0 || !databaseAudit.ok) {
    status = 'FAILED';
    exitCode = 4;
  } else if (counts.envBlocked > 0) {
    status = 'ENV_BLOCKED';
    exitCode = 2;
  } else if (counts.blockedNotWired > 0) {
    status = 'BLOCKED_NOT_WIRED';
    exitCode = 2;
  } else if (counts.productFail > 0) {
    status = 'PARTIAL';
    exitCode = 5;
  }
  aggregate.status = status;
  aggregate.exitCode = exitCode;

  support.writeJson(runDir, 'aggregate.json', aggregate);
  support.writeJson(runDir, 'run-manifest.json', manifest);

  process.stdout.write(`${JSON.stringify({ runKey, runDir, status, exitCode, counts, databaseAudit }, null, 2)}\n`);
  return exitCode;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    process.stdout.write(
      `${JSON.stringify({ check: 'I11-W3A', status: 'HARNESS_FAIL', error: { name: err.name, message: err.message, stack: err.stack } }, null, 2)}\n`,
    );
    process.exitCode = 4;
  },
);