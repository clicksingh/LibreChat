'use strict';

/**
 * Naive-baseline control runner (lane I9, PHASE1-LOCAL-AUTHORITY-001 / W2-B).
 *
 *   node tests/device/naive-baseline/run-baseline.cjs --n=50 [--mode=no-index|with-index] --db=cbhr_rdc_phase1_w2b_...
 *
 * no-index  : the account-axis partial unique index is absent -> the naive
 *             check-then-insert burst must produce TWO active owner rows and is
 *             reported EXPECTED_FAIL (a control that must be able to fail).
 * with-index: the frozen uq_owner_active index is created first -> the same naive
 *             burst must produce exactly ONE active row with an observed E11000 on
 *             {ownerId:1,tenantId:1}. ENGINE-level control only: it does not prove
 *             that the product schema declares the index.
 */

const harness = require('../e1/harness.cjs');
const { runTwoProcess } = require('../two-process-runner.cjs');

async function runBaseline(options = {}) {
  const mode = options.mode === 'with-index' ? 'with-index' : 'no-index';
  const n = Number(options.n ?? harness.N_MIN);
  const dbName = options.db ?? harness.makeDbName(`naive_${mode.replace('-', '')}`);
  const inner = await runTwoProcess({
    fixture: 'NAIVE-BASELINE',
    n,
    strategy: 'naive',
    mode,
    uri: options.uri ?? harness.DEFAULT_URI,
    db: dbName,
    emit: false,
  });

  const expectedStatus = mode === 'no-index' ? 'EXPECTED_FAIL' : 'PASS';
  const report = {
    check: 'naive-baseline',
    baseline: mode === 'no-index' ? 'NAIVE_CHECK_THEN_INSERT' : 'NAIVE_CHECK_THEN_INSERT_WITH_INDEX',
    mode,
    db: dbName,
    n,
    productClaim: false,
    evidenceGrade: 'ENGINE_ONLY_NOT_SCHEMA_DRIVEN',
    expected: mode === 'no-index' ? { rowsActive: 2, status: 'EXPECTED_FAIL' } : { rowsActive: 1, status: 'PASS' },
    ...inner,
    status: inner.status,
    exitCode: inner.status === expectedStatus ? 0 : inner.exitCode === 4 ? 4 : inner.exitCode ?? 4,
    expectedStatus,
  };
  if (options['result-out']) {
    harness.writeJsonFile(options['result-out'], report);
  }
  if (options.emit !== false) {
    harness.emit(report);
  }
  return report;
}

if (require.main === module) {
  const options = harness.parseArgs(process.argv.slice(2));
  runBaseline(options).then(
    (report) => {
      process.exitCode = report.exitCode ?? 0;
    },
    (err) => {
      process.stdout.write(`${JSON.stringify({ check: 'naive-baseline', status: 'HARNESS_FAIL', error: err.message })}\n`);
      process.exitCode = 4;
    },
  );
}

module.exports = { runBaseline };
