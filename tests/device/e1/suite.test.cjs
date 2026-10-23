'use strict';

/**
 * I9 E1/E2 fixture suite under the built-in Node test runner.
 *
 * In-sandbox command (default isolation spawns per-file children over a pipe, which is
 * EPERM here):
 *
 *   node --test --experimental-test-isolation=none --test-concurrency=1 --test-timeout=900000 tests/device/e1/suite.test.cjs
 *
 * What this suite enforces (task T1):
 *   - every product fixture must either really PASS with durable product evidence, or report an
 *     honest BLOCKED_* status with a truthful reason. A PASS is only accepted when the fixture
 *     carries productClaim true, a real per-fixture database name, and an executed assertion
 *     ledger whose every entry is a boolean;
 *   - every control fixture must produce its real observable.
 *
 * A green suite here is a harness self-check over real product bytes and real MongoDB; it is NOT
 * product acceptance (that is the independent review's job).
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const fixtures = require('./fixtures.cjs');
const { runE1Fixture, PRODUCT_BLOCKED_STATUSES } = require('./run-e1.cjs');

const EXPECTED_CONTROL_STATUS = {
  'NC-DB-FENCE': 'PASS',
  'NC-NAIVE-NOINDEX': 'EXPECTED_FAIL',
  'NC-NAIVE-INDEX': 'PASS',
  'NC-CRASH-HARNESS': 'PASS',
  'NC-SWEEP-KNOB': 'PASS',
};

/** A product PASS is only believable with durable evidence attached. */
function productPassEvidenceProblems(report) {
  const problems = [];
  if (report.productClaim !== true) problems.push('productClaim is not true');
  const dbName = report.dbName ?? (Array.isArray(report.dbNames) ? report.dbNames.join('|') : null);
  if (typeof dbName !== 'string' || dbName.length === 0) problems.push('no per-fixture database recorded');
  if (!Array.isArray(report.checks) || report.checks.length === 0) problems.push('no assertion ledger');
  else if (!report.checks.every((entry) => entry && typeof entry.ok === 'boolean')) problems.push('malformed assertion ledger');
  if (!report.realReturns || Object.keys(report.realReturns).length === 0) problems.push('no recorded real service returns');
  if (!report.provenance || typeof report.provenance !== 'object') problems.push('no provenance block');
  return problems;
}

test('I9 E1/E2 fixture suite (real product writes or honest BLOCKED)', async (t) => {
  const observed = [];
  const n = Number(process.env.CBHR_P1_N ?? 50);

  for (const fixture of fixtures.FIXTURES) {
    await t.test(`${fixture.id} [${fixture.kind}]`, async () => {
      const report = await runE1Fixture(fixture, { n, emit: false });
      observed.push({ id: fixture.id, kind: fixture.kind, status: report.status, report });

      if (fixture.kind === 'product') {
        if (report.status === 'PASS') {
          assert.deepStrictEqual(
            productPassEvidenceProblems(report),
            [],
            `${fixture.id} reported PASS without complete durable evidence`,
          );
          return;
        }
        assert.ok(
          PRODUCT_BLOCKED_STATUSES.has(report.status),
          `${fixture.id} must either really PASS or report an honest BLOCKED_* status, observed ${report.status}: ${JSON.stringify(report.failedAssertions ?? report.error ?? null).slice(0, 600)}`,
        );
        assert.strictEqual(report.productClaim, false, `${fixture.id} must not claim product evidence while blocked`);
        assert.ok(typeof report.reason === 'string' && report.reason.length > 0, `${fixture.id} must state why it is blocked`);
        return;
      }

      assert.strictEqual(
        report.status,
        EXPECTED_CONTROL_STATUS[fixture.id],
        `${fixture.id} control status (observed report: ${JSON.stringify(report).slice(0, 400)})`,
      );
      assert.strictEqual(report.productClaim, false, `${fixture.id} is a control, never product evidence`);
    });
  }

  await t.test('no product fixture reported PASS without durable evidence anywhere in the suite', () => {
    const fabricated = observed
      .filter((entry) => entry.kind === 'product' && entry.status === 'PASS')
      .filter((entry) => productPassEvidenceProblems(entry.report).length > 0);
    assert.deepStrictEqual(fabricated.map((entry) => entry.id), []);
  });

  await t.test('the naive baseline is non-vacuous (2 rows without index, 1 row with index)', () => {
    const noIndex = observed.find((entry) => entry.id === 'NC-NAIVE-NOINDEX');
    const withIndex = observed.find((entry) => entry.id === 'NC-NAIVE-INDEX');
    assert.strictEqual(noIndex.status, 'EXPECTED_FAIL');
    assert.strictEqual(withIndex.status, 'PASS');
  });
});
