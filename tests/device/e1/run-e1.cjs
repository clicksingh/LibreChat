'use strict';

/**
 * I9 E1/E2 fixture runner (lane I9, PHASE1-LOCAL-AUTHORITY-001 / W2-B).
 *
 *   node tests/device/e1/run-e1.cjs --fixture=all
 *   node tests/device/e1/run-e1.cjs --fixture=E1-T16-P1-STALE-OWNER-REVOKE
 *   node tests/device/e1/run-e1.cjs --fixture=NC-NAIVE-NOINDEX --n=50
 *
 * Product fixtures resolve to BLOCKED_PENDING_I6_I5 while the I6/I5 services are absent.
 * Control fixtures execute real work against real MongoDB inside self-owned
 * cbhr_rdc_phase1_w2b_* databases only.
 */

const harness = require('./harness.cjs');
const fixtures = require('./fixtures.cjs');
const { runTwoProcess } = require('../two-process-runner.cjs');
const { runBaseline } = require('../naive-baseline/run-baseline.cjs');
const { runCrash } = require('../crash-runner.cjs');
const { runSweep } = require('../sweep-rerun.cjs');

const CONTROL_OK_STATUSES = new Set(['PASS', 'EXPECTED_FAIL']);
const PRODUCT_BLOCKED_STATUSES = new Set(['BLOCKED_PENDING_I6_I5', 'BLOCKED_NOT_WIRED', 'BLOCKED_SERVICE_SHAPE']);

async function runE1Fixture(fixture, options = {}) {
  const n = Number(options.n ?? harness.N_MIN);
  const uri = options.uri ?? harness.DEFAULT_URI;
  const db = options.db && options.fixture !== 'all' ? options.db : undefined;
  const common = { n, uri, db, emit: false };

  switch (fixture.runner) {
    case 'inline':
      return fixture.id === 'NC-DB-FENCE' ? fixtures.runDbFenceControl(fixture) : fixtures.productBlocked(fixture);
    case 'two-process': {
      const report = await runTwoProcess({ fixture: fixture.id, strategy: 'contract', mode: 'default', ...common });
      return { ...report, assertionPlan: fixture.assertionPlan };
    }
    case 'naive-noindex':
      return runBaseline({ mode: 'no-index', ...common });
    case 'naive-index':
      return runBaseline({ mode: 'with-index', ...common });
    case 'crash-product':
      return runCrash({ point: 'c3', db, uri, emit: false });
    case 'crash-selftest':
      return runCrash({ point: 'self-test', db, uri, emit: false });
    case 'sweep-product':
      return runSweep({ mode: 'product', db, uri, emit: false });
    case 'sweep-selftest':
      return runSweep({ mode: 'self-test', emit: false });
    default:
      throw new Error(`unknown fixture runner ${fixture.runner}`);
  }
}

async function finalIsolationAudit() {
  const connected = await harness.connect({ dbName: harness.makeDbName('audit_probe'), appName: 'cbhr-phase1-w2b-audit' });
  try {
    const names = connected.isolation.databases;
    return {
      databases: names,
      foreign: connected.isolation.foreign,
      protectedPresent: harness.PROTECTED_DATABASES.filter((name) => names.includes(name)),
      leftoverW2bDatabases: names.filter((name) => name.startsWith(harness.DB_PREFIX)),
      topology: connected.topology,
    };
  } finally {
    await connected.client.close().catch(() => {});
  }
}

async function runE1(options = {}) {
  const requested = options.fixture ?? 'all';
  const selected =
    requested === 'all' ? fixtures.FIXTURES : fixtures.FIXTURES.filter((fixture) => fixture.id === requested);
  if (selected.length === 0) {
    throw new Error(`unknown fixture ${requested}`);
  }

  const results = [];
  for (const fixture of selected) {
    let report;
    try {
      report = await runE1Fixture(fixture, { ...options, fixture: requested });
    } catch (err) {
      report = {
        id: fixture.id,
        status: 'HARNESS_FAIL',
        exitCode: 4,
        productClaim: false,
        error: `${err.name}: ${err.message}`,
      };
    }
    results.push({
      id: fixture.id,
      tier: fixture.tier,
      kind: fixture.kind,
      runner: fixture.runner,
      requires: fixture.requires,
      status: report.status,
      exitCode: report.exitCode,
      productClaim: report.productClaim === true,
      report,
    });
  }

  const controlFailures = results.filter(
    (entry) => entry.kind !== 'product' && !CONTROL_OK_STATUSES.has(entry.status),
  );
  const productBlocked = results.filter((entry) => entry.kind === 'product' && PRODUCT_BLOCKED_STATUSES.has(entry.status));
  const fabricationRisk = results.filter((entry) => entry.kind === 'product' && entry.status === 'PASS');

  const isolation = await finalIsolationAudit().catch((err) => ({ error: `${err.name}: ${err.message}` }));
  const status =
    controlFailures.length > 0 || fabricationRisk.length > 0
      ? 'HARNESS_FAIL'
      : productBlocked.length > 0
        ? 'BLOCKED_PENDING_I6_I5'
        : 'PASS';

  const aggregate = {
    check: 'I9-E1',
    tier: 'E1/E2',
    lane: 'I9',
    fixtureSelection: requested,
    status,
    exitCode: controlFailures.length > 0 || fabricationRisk.length > 0 ? 4 : productBlocked.length > 0 ? 2 : 0,
    productClaim: false,
    counts: {
      total: results.length,
      productFixtures: results.filter((entry) => entry.kind === 'product').length,
      productBlocked: productBlocked.length,
      controls: results.filter((entry) => entry.kind !== 'product').length,
      controlFailures: controlFailures.length,
      fabricatedProductPasses: fabricationRisk.length,
    },
    productBlockedIds: productBlocked.map((entry) => entry.id),
    controlFailureIds: controlFailures.map((entry) => entry.id),
    isolation,
    results,
    finishedAt: new Date().toISOString(),
  };

  if (options['result-out']) {
    harness.writeJsonFile(options['result-out'], aggregate);
  }
  if (options.emit !== false) {
    harness.emit(aggregate);
  }
  return aggregate;
}

if (require.main === module) {
  const options = harness.parseArgs(process.argv.slice(2));
  runE1(options).then(
    (report) => {
      process.exitCode = report.exitCode ?? 0;
    },
    (err) => {
      process.stdout.write(`${JSON.stringify({ check: 'I9-E1', status: 'HARNESS_FAIL', error: err.message })}\n`);
      process.exitCode = 4;
    },
  );
}

module.exports = { CONTROL_OK_STATUSES, PRODUCT_BLOCKED_STATUSES, runE1Fixture, finalIsolationAudit, runE1 };
