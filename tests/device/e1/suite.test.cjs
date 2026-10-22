'use strict';

/**
 * I9 E1/E2 fixture suite under the built-in Node test runner.
 *
 * In-sandbox command (default isolation spawns per-file children over a pipe, which is
 * EPERM here):
 *
 *   node --test --experimental-test-isolation=none --test-concurrency=1 --test-timeout=180000 tests/device/e1/suite.test.cjs
 *
 * The suite is GREEN while it honestly asserts the current authorized state:
 *   - every product fixture must be BLOCKED pending I6/I5 and must never report PASS
 *   - every control fixture must produce its real observable
 * A green suite here is a harness self-check, NOT product acceptance.
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

test('I9 E1/E2 fixture suite (honest BLOCKED state, controls executed)', async (t) => {
  const observed = [];
  const n = Number(process.env.CBHR_P1_N ?? 50);

  for (const fixture of fixtures.FIXTURES) {
    await t.test(`${fixture.id} [${fixture.kind}]`, async () => {
      const report = await runE1Fixture(fixture, { n, emit: false });
      observed.push({ id: fixture.id, kind: fixture.kind, status: report.status });

      if (fixture.kind === 'product') {
        assert.ok(
          PRODUCT_BLOCKED_STATUSES.has(report.status),
          `${fixture.id} must report BLOCKED pending I6/I5, observed ${report.status}`,
        );
        assert.notStrictEqual(report.status, 'PASS', `${fixture.id} must never fabricate a product PASS`);
        assert.strictEqual(report.productClaim, false, `${fixture.id} must not claim product evidence`);
        assert.ok(report.assertionPlan, `${fixture.id} must carry its frozen assertion plan while blocked`);
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

  await t.test('no product fixture reported PASS anywhere in the suite', () => {
    const fabricated = observed.filter((entry) => entry.kind === 'product' && entry.status === 'PASS');
    assert.deepStrictEqual(fabricated, [], 'a product fixture reported PASS while I6/I5 are absent');
  });

  await t.test('the naive baseline is non-vacuous (2 rows without index, 1 row with index)', () => {
    const noIndex = observed.find((entry) => entry.id === 'NC-NAIVE-NOINDEX');
    const withIndex = observed.find((entry) => entry.id === 'NC-NAIVE-INDEX');
    assert.strictEqual(noIndex.status, 'EXPECTED_FAIL');
    assert.strictEqual(withIndex.status, 'PASS');
  });
});
