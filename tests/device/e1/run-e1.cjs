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
const productInline = require('./product/inline.cjs');
const productRace = require('./product/race.cjs');
const productCrash = require('./product/crash.cjs');
const productSweep = require('./product/sweep.cjs');
const { runTwoProcess } = require('../two-process-runner.cjs');
const { runBaseline } = require('../naive-baseline/run-baseline.cjs');
const { runCrash } = require('../crash-runner.cjs');
const { runSweep } = require('../sweep-rerun.cjs');

const CONTROL_OK_STATUSES = new Set(['PASS', 'EXPECTED_FAIL']);
const PRODUCT_BLOCKED_STATUSES = new Set([
  'BLOCKED_PENDING_I6_I5',
  'BLOCKED_NOT_WIRED',
  'BLOCKED_SERVICE_SHAPE',
  /**
   * The fixture executed for real but cannot satisfy its frozen assertion plan because the frozen
   * protocol makes the planned condition unreachable. Reported instead of a PASS that the fixture
   * does not earn; requires a Governor ruling (plan amendment or protocol change).
   */
  'BLOCKED_CONTRACT_DEVIATION',
]);
const PRODUCT_FAILED_STATUSES = new Set(['PRODUCT_FAIL', 'HARNESS_FAIL']);

/**
 * A product fixture may report PASS only when it claims product evidence and carries the
 * durable evidence of a real run: its own database name, an executed assertion ledger and the
 * recorded real service returns. Anything else is treated as a fabricated PASS.
 */
function productPassIsBacked(report) {
  if (report === null || typeof report !== 'object') return false;
  if (report.productClaim !== true) return false;
  const dbName = report.dbName ?? (Array.isArray(report.dbNames) ? report.dbNames.join('|') : null);
  if (typeof dbName !== 'string' || dbName.length === 0) return false;
  if (!Array.isArray(report.checks) || report.checks.length === 0) return false;
  return report.checks.every((check) => check && typeof check.ok === 'boolean');
}

async function runE1Fixture(fixture, options = {}) {
  const n = Number(options.n ?? harness.N_MIN);
  const uri = options.uri ?? harness.DEFAULT_URI;
  const db = options.db && options.fixture !== 'all' ? options.db : undefined;
  const common = { n, uri, db, emit: false };
  const report = await dispatchE1Fixture(fixture, common);
  if (report !== null && typeof report === 'object' && report.assertionPlan === undefined) {
    report.assertionPlan = fixture.assertionPlan;
  }
  return report;
}

async function dispatchE1Fixture(fixture, common) {

  switch (fixture.runner) {
    case 'inline': {
      if (fixture.id === 'NC-DB-FENCE') return fixtures.runDbFenceControl(fixture);
      if (fixture.kind === 'product') {
        const runner = productInline.BY_ID.get(fixture.id);
        if (runner === undefined) {
          return {
            ...fixtures.productBlocked(fixture),
            reason: `no product wiring is registered for inline fixture ${fixture.id}`,
          };
        }
        return runner(fixture, common);
      }
      return fixtures.productBlocked(fixture);
    }
    case 'two-process': {
      if (fixture.kind === 'product') {
        return productRace.run(fixture, common);
      }
      const report = await runTwoProcess({ fixture: fixture.id, strategy: 'contract', mode: 'default', ...common });
      return { ...report, assertionPlan: fixture.assertionPlan };
    }
    case 'naive-noindex':
      return runBaseline({ mode: 'no-index', ...common });
    case 'naive-index':
      return runBaseline({ mode: 'with-index', ...common });
    case 'crash-product':
      return fixture.kind === 'product' ? productCrash.run(fixture, common) : runCrash({ point: 'c3', ...common });
    case 'crash-selftest':
      return runCrash({ point: 'self-test', ...common });
    case 'sweep-product':
      return fixture.kind === 'product' ? productSweep.run(fixture, common) : runSweep({ mode: 'product', ...common });
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
      // Every product fixture runs in its own cbhr_rdc_phase1_w3_* database; a leftover there is
      // just as much a fence breach as a leftover w2b one, so the audit covers the whole
      // cbhr_rdc_phase1_ namespace (protected pre-existing databases excluded).
      leftoverOwnDatabases: names.filter(
        (name) => name.startsWith(harness.DDL_PREFIX) && !harness.PROTECTED_DATABASES.includes(name),
      ),
      topology: connected.topology,
    };
  } finally {
    await connected.client.close().catch(() => {});
  }
}

/**
 * before/after namespace comparison; a non-empty diff aborts the run.
 *
 * WHAT IS A REAL BREACH, AND WHAT IS NOT
 * Every fixture is SUPPOSED to create its own `cbhr_rdc_phase1_*` database and drop it in teardown,
 * so an own-namespace name appearing in `created`/`removed` is expected lifecycle, not a fence
 * breach. MongoDB drops databases lazily, so the catalog view behind `listDatabases` can also lag a
 * teardown that already completed — which made the raw `created`/`removed` diff a flaky gate that
 * fired on a clean run. The audit therefore separates the two:
 *
 *   HARD FAILURES (unchanged in substance, and one is added):
 *     - `leftoverOwnDatabases`: a fixture database still present at the END of the run. This is the
 *       actual leak check and is computed from `after` alone, so catalog lag cannot mask it.
 *     - `foreignAfter`: any database outside the `cbhr_rdc_phase1_` namespace.
 *     - `protectedRemoved` (new, explicit): a protected pre-existing database disappeared during the
 *       run. Previously this was only caught incidentally by the blanket `removed` diff.
 *   NOT A FAILURE:
 *     - own-namespace `created`/`removed` churn, which is the fixture lifecycle itself.
 *
 * Nothing that used to be caught is now missed: the blanket diff's only true-positive classes were a
 * protected database being removed and a foreign database appearing, and both are asserted directly.
 */
function auditNamespace(before, after) {
  const isOwnNamespace = (name) =>
    name.startsWith(harness.DDL_PREFIX) && !harness.PROTECTED_DATABASES.includes(name);
  const created = after.databases.filter((name) => !before.databases.includes(name));
  const removed = before.databases.filter((name) => !after.databases.includes(name));
  // Own-namespace churn is expected; anything else created or removed is a real namespace change.
  const unexpectedCreated = created.filter((name) => !isOwnNamespace(name));
  const unexpectedRemoved = removed.filter((name) => !isOwnNamespace(name));
  const protectedRemoved = removed.filter((name) => harness.PROTECTED_DATABASES.includes(name));
  return {
    before: before.databases,
    after: after.databases,
    created,
    removed,
    unexpectedCreated,
    unexpectedRemoved,
    protectedRemoved,
    ownNamespaceChurn: { created: created.filter(isOwnNamespace), removed: removed.filter(isOwnNamespace) },
    leftoverOwnDatabases: after.leftoverOwnDatabases,
    foreignAfter: after.foreign,
    ok:
      unexpectedCreated.length === 0 &&
      unexpectedRemoved.length === 0 &&
      protectedRemoved.length === 0 &&
      after.leftoverOwnDatabases.length === 0 &&
      after.foreign.length === 0,
  };
}

async function runE1(options = {}) {
  const requested = options.fixture ?? 'all';
  const selected =
    requested === 'all' ? fixtures.FIXTURES : fixtures.FIXTURES.filter((fixture) => fixture.id === requested);
  if (selected.length === 0) {
    throw new Error(`unknown fixture ${requested}`);
  }

  const namespaceBefore = await finalIsolationAudit().catch((err) => ({ error: `${err.name}: ${err.message}`, databases: [] }));

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
  const fabricatedProductPasses = results.filter(
    (entry) => entry.kind === 'product' && entry.status === 'PASS' && !productPassIsBacked(entry.report),
  );
  /**
   * A blocked product result must be evidence, not a bare label: productClaim must be false and a
   * truthful reason must be present. This enforces at the gate what suite.test.cjs also asserts,
   * so the new BLOCKED_CONTRACT_DEVIATION status cannot be used to smuggle a failure through when
   * the suite gate is skipped (e.g. a direct --fixture= invocation).
   */
  const unevicencedBlocked = results.filter(
    (entry) =>
      entry.kind === 'product' &&
      PRODUCT_BLOCKED_STATUSES.has(entry.status) &&
      (entry.report?.productClaim !== false ||
        typeof entry.report?.reason !== 'string' ||
        entry.report.reason.length === 0),
  );
  const productFailures = results.filter(
    (entry) => entry.kind === 'product' && PRODUCT_FAILED_STATUSES.has(entry.status),
  );

  const isolation = await finalIsolationAudit().catch((err) => ({ error: `${err.name}: ${err.message}` }));
  const namespaceAudit = auditNamespace(namespaceBefore, isolation);
  let status;
  let exitCode;
  if (
    controlFailures.length > 0 ||
    fabricatedProductPasses.length > 0 ||
    unevicencedBlocked.length > 0 ||
    namespaceAudit.ok !== true
  ) {
    status = 'HARNESS_FAIL';
    exitCode = 4;
  } else if (productFailures.length > 0) {
    status = 'PRODUCT_FAIL';
    exitCode = 5;
  } else if (productBlocked.length > 0) {
    // Distinguish "service absent" from "executed but the frozen plan is unreachable".
    const deviations = productBlocked.filter((entry) => entry.status === 'BLOCKED_CONTRACT_DEVIATION');
    status = deviations.length > 0 ? 'BLOCKED_CONTRACT_DEVIATION' : 'BLOCKED_PENDING_I6_I5';
    exitCode = 2;
  } else {
    status = 'PASS';
    exitCode = 0;
  }

  const aggregate = {
    check: 'I9-E1',
    tier: 'E1/E2',
    lane: 'I9',
    fixtureSelection: requested,
    status,
    exitCode,
    productClaim: false,
    counts: {
      total: results.length,
      productFixtures: results.filter((entry) => entry.kind === 'product').length,
      productBlocked: productBlocked.length,
      controls: results.filter((entry) => entry.kind !== 'product').length,
      controlFailures: controlFailures.length,
      fabricatedProductPasses: fabricatedProductPasses.length,
      unevidencedBlocked: unevicencedBlocked.length,
      productFailures: productFailures.length,
    },
    productBlockedIds: productBlocked.map((entry) => entry.id),
    controlFailureIds: controlFailures.map((entry) => entry.id),
    fabricatedProductPassIds: fabricatedProductPasses.map((entry) => entry.id),
    unevidencedBlockedIds: unevicencedBlocked.map((entry) => entry.id),
    productFailureIds: productFailures.map((entry) => entry.id),
    isolation,
    namespaceAudit,
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
