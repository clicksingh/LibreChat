'use strict';

/**
 * I9 sweep-disabled re-run scaffolding (lane I9, PHASE1-LOCAL-AUTHORITY-001 / W2-B).
 *
 *   node tests/device/sweep-rerun.cjs --mode=product  --db=cbhr_rdc_phase1_w2b_sweep_...
 *   node tests/device/sweep-rerun.cjs --mode=self-test
 *
 * product  : re-runs the T16/T17/V24-T09/T24-T10/V24-T13 decision set with
 *            CBHR_PHASE1_SWEEP=enabled and =disabled and requires an identical decision
 *            vector. It needs the I6/I5 services, so while they are absent it reports
 *            BLOCKED_PENDING_I6_I5 and never PASS.
 * self-test: a pure harness control (no database) proving the knob is read from one env
 *            var, that the assertion body is byte-identical across both runs, and that
 *            the hash comparison is non-vacuous (a deliberately sweep-reliant variant
 *            MUST produce a different vector).
 */

const crypto = require('node:crypto');

const harness = require('./e1/harness.cjs');
const serviceLoader = require('./e1/service-loader.cjs');

const SWEEP_ENV = 'CBHR_PHASE1_SWEEP';
const SWEEP_VALUES = ['enabled', 'disabled'];

const NOW = harness.EPOCH_BASE_MS;
const CONTROL_ROWS = [
  { id: 'r-lapsed-beyond-margin', leaseState: 'active', expiresAt: NOW - 6000 },
  { id: 'r-dead-zone', leaseState: 'active', expiresAt: NOW - 1000 },
  { id: 'r-live', leaseState: 'active', expiresAt: NOW + 1000 },
];

function sweepEffect(rows, sweepEnabled) {
  if (!sweepEnabled) {
    return rows.map((row) => ({ ...row }));
  }
  return rows.map((row) => ({
    ...row,
    leaseState: row.leaseState === 'active' && row.expiresAt + harness.SKEW_MARGIN_MS <= NOW ? 'expired' : row.leaseState,
  }));
}

function decisions(sweepEnabled, variant) {
  const rows = sweepEffect(CONTROL_ROWS, sweepEnabled);
  return rows.map((row) => ({
    id: row.id,
    authorized: variant === 'sweep-reliant' ? row.leaseState === 'active' : row.leaseState === 'active' && NOW < row.expiresAt,
  }));
}

function rowStates(sweepEnabled) {
  return sweepEffect(CONTROL_ROWS, sweepEnabled).map((row) => ({ id: row.id, leaseState: row.leaseState }));
}

function hashVector(vector) {
  return crypto.createHash('sha256').update(JSON.stringify(vector)).digest('hex').toUpperCase();
}

/** Single env knob read; fail closed on any value other than the two frozen literals. */
function resolveSweep(fallback = 'enabled') {
  const raw = process.env[SWEEP_ENV];
  if (raw === undefined || raw === null || raw === '') {
    return fallback;
  }
  if (!SWEEP_VALUES.includes(raw)) {
    throw new Error(`invalid ${SWEEP_ENV}=${JSON.stringify(raw)}; expected ${SWEEP_VALUES.join('|')}`);
  }
  return raw;
}

function selfTest() {
  const contractEnabled = decisions(true, 'contract');
  const contractDisabled = decisions(false, 'contract');
  const reliantEnabled = decisions(true, 'sweep-reliant');
  const reliantDisabled = decisions(false, 'sweep-reliant');

  const contractHashEnabled = hashVector(contractEnabled);
  const contractHashDisabled = hashVector(contractDisabled);
  const reliantHashEnabled = hashVector(reliantEnabled);
  const reliantHashDisabled = hashVector(reliantDisabled);

  const sweepReliantDecisions = contractEnabled.filter(
    (entry, index) => entry.authorized !== contractDisabled[index].authorized,
  ).length;

  const checks = {
    knobValuesAreCanonical: SWEEP_VALUES.length === 2 && SWEEP_ENV === 'CBHR_PHASE1_SWEEP',
    knobEnvRead: resolveSweep('enabled') === (SWEEP_VALUES.includes(process.env[SWEEP_ENV]) ? process.env[SWEEP_ENV] : 'enabled'),
    contractVectorIdenticalAcrossSweep: contractHashEnabled === contractHashDisabled,
    sweepReliantDecisionsZero: sweepReliantDecisions === 0,
    hashComparisonIsNonVacuous: reliantHashEnabled !== reliantHashDisabled,
  };
  const failures = Object.entries(checks)
    .filter(([, passed]) => passed !== true)
    .map(([name]) => name);

  return {
    check: 'sweep-rerun',
    mode: 'self-test',
    kind: 'harness-control',
    productClaim: false,
    evidenceGrade: 'HARNESS_CONTROL',
    sweepEnv: SWEEP_ENV,
    sweepSetting: resolveSweep('enabled'),
    now: NOW,
    contractDecisionVector: { enabled: contractEnabled, disabled: contractDisabled },
    rowStates: { enabled: rowStates(true), disabled: rowStates(false) },
    decisionVectorHash: { enabled: contractHashEnabled, disabled: contractHashDisabled, identical: contractHashEnabled === contractHashDisabled },
    sweepReliantVariant: {
      enabled: reliantEnabled,
      disabled: reliantDisabled,
      hashes: { enabled: reliantHashEnabled, disabled: reliantHashDisabled },
      differs: reliantHashEnabled !== reliantHashDisabled,
      note: 'deliberately sweep-dependent variant; it MUST differ so the control is falsifiable',
    },
    sweepReliantDecisions,
    checks,
    failures,
    status: failures.length === 0 ? 'PASS' : 'HARNESS_FAIL',
    exitCode: failures.length === 0 ? 0 : 4,
    assertionPlan: {
      steps: [
        'run one deterministic decision vector twice with CBHR_PHASE1_SWEEP=enabled and =disabled',
        'sha256(JSON.stringify(decisions)) must be identical across both runs',
      ],
      expected: ['identical: true', 'sweepReliantDecisions: 0', 'non-vacuous: the sweep-reliant variant differs'],
    },
  };
}

async function runSweep(options = {}) {
  const mode = options.mode === 'self-test' ? 'self-test' : 'product';
  const emit = options.emit !== false;
  const finish = (report) => {
    if (options['result-out']) {
      harness.writeJsonFile(options['result-out'], report);
    }
    if (emit) {
      harness.emit(report);
    }
    return report;
  };

  if (mode === 'self-test') {
    return finish(selfTest());
  }

  const probe = serviceLoader.probe();
  return finish({
    check: 'sweep-rerun',
    mode: 'product',
    tier: 'E1',
    kind: 'product',
    db: options.db ?? null,
    productClaim: false,
    status: probe.status === 'AVAILABLE' ? 'BLOCKED_NOT_WIRED' : 'BLOCKED_PENDING_I6_I5',
    exitCode: 2,
    reason:
      probe.status === 'AVAILABLE'
        ? 'I6/I5 exist but sweep-disabled wiring is deferred to the authorized post-I4/I6/I5 integration test round'
        : probe.reason,
    serviceProbe: { status: probe.status, missing: probe.missing, shapeProblems: probe.shapeProblems },
    sweepEnv: SWEEP_ENV,
    sweepSetting: resolveSweep('enabled'),
    fixtureIds: ['T16', 'T17', 'V24-T09', 'V24-T10', 'V24-T13'],
    assertionPlan: {
      steps: [
        'run the fixture set twice, byte-identical assertion body, CBHR_PHASE1_SWEEP=enabled then disabled',
        'record the authority rows and the decision vector for each run',
      ],
      expected: [
        'decision vector hashes identical across both runs',
        'no authorization decision changes when the sweep effect is absent',
        'in the disabled run rows that only the sweep would have flipped are still not expired, yet the decisions are unchanged',
      ],
    },
  });
}

if (require.main === module) {
  const options = harness.parseArgs(process.argv.slice(2));
  runSweep(options).then(
    (report) => {
      process.exitCode = report.exitCode ?? 0;
    },
    (err) => {
      process.stdout.write(`${JSON.stringify({ check: 'sweep-rerun', status: 'HARNESS_FAIL', error: err.message })}\n`);
      process.exitCode = 4;
    },
  );
}

module.exports = { SWEEP_ENV, SWEEP_VALUES, CONTROL_ROWS, NOW, decisions, hashVector, resolveSweep, selfTest, runSweep };
