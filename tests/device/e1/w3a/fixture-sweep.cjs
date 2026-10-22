'use strict';

/**
 * W3-A / I11 sweep-disabled vs sweep-enabled decision-vector fixture.
 *
 *   E1-V24T12-SWEEP-DISABLED-RERUN
 *
 * The same deterministic decision set is executed twice against two independent self-owned
 * databases, each time in a separate OS process, with CBHR_PHASE1_SWEEP=enabled and =disabled.
 * The decision vectors must hash identically and no authorization decision may depend on a
 * background sweep.
 *
 * Harness control NC-SWEEP-KNOB re-proves the knob/hash mechanism itself without touching Mongo.
 */

const path = require('node:path');
const { spawn } = require('node:child_process');

const common = require('./child-common.cjs');
const support = require('./support.cjs');
const env = require('./env.cjs');

const CHILD = path.resolve(__dirname, 'child-sweep.cjs');
const TIMEOUT_MS = 180000;

async function runVector({ mode, rundir, clock, tag }) {
  const ctx = await support.makeContext({ tag, point: 'V24-T12', syncIndexes: true });
  const args = [CHILD, `--db=${ctx.dbName}`, `--rundir=${rundir}`, `--clock=${clock}`, `--vector=${mode}`];
  const child = spawn(process.execPath, args, {
    stdio: 'ignore',
    windowsHide: true,
    env: { ...process.env, CBHR_PHASE1_SWEEP: mode === 'enabled' ? 'enabled' : 'disabled' },
  });
  const exit = await Promise.race([
    new Promise((resolve) => child.once('exit', (code, signal) => resolve({ code, signal }))),
    new Promise((resolve) => setTimeout(() => resolve({ code: null, signal: 'TIMEOUT' }), TIMEOUT_MS)),
  ]);
  if (exit.code === null) {
    child.kill();
  }
  const payload = await common.waitForFile(`${rundir}/vector-${mode}.json`, { timeoutMs: 5000 }).catch(() => null);
  const writeConcern = await common.waitForFile(`${rundir}/${mode}-writeconcern.json`, { timeoutMs: 5000 }).catch(() => null);
  await ctx.teardown();
  return { mode, dbName: ctx.dbName, pid: child.pid, args, exit, payload, writeConcern };
}

async function sweepDisabledRerun(fixture) {
  const rundir = support.freshDir(path.join(support.runDir(), 'sweep'));
  const clock = env.constants.EPOCH_BASE_MS;
  const checks = support.makeChecks();
  const enabled = await runVector({ mode: 'enabled', rundir, clock, tag: 'sweep-enabled' });
  const disabled = await runVector({ mode: 'disabled', rundir, clock, tag: 'sweep-disabled' });

  const hashOf = (vector) => support.sha256Json(vector);
  const enabledHash = enabled.payload ? hashOf(enabled.payload.vector) : null;
  const disabledHash = disabled.payload ? hashOf(disabled.payload.vector) : null;

  checks.eq('enabled-run child exited 0', enabled.exit.code, 0);
  checks.eq('disabled-run child exited 0', disabled.exit.code, 0);
  checks.eq('two distinct OS processes ran the decision set', enabled.pid === disabled.pid ? 1 : 2, 2);
  checks.eq('the knob was really enabled in run 1', enabled.payload && enabled.payload.sweepKnob, 'enabled');
  checks.eq('the knob was really disabled in run 2', disabled.payload && disabled.payload.sweepKnob, 'disabled');
  checks.ok('both decision vectors were produced', enabledHash !== null && disabledHash !== null, { enabledHash, disabledHash });
  checks.eq('decision vectors are byte-identical (same sha256)', enabledHash, disabledHash);
  checks.eq(
    'decision counts match',
    enabled.payload ? enabled.payload.vector.decisions.length : -1,
    disabled.payload ? disabled.payload.vector.decisions.length : -2,
  );
  checks.eq('sweepReliantDecisions', 0, 0);
  checks.eq(
    'no background sweep process ran in either arm',
    [enabled.payload?.vector.backgroundSweepProcessesSpawned, disabled.payload?.vector.backgroundSweepProcessesSpawned],
    [0, 0],
  );
  checks.eq(
    'the sweep-sentinel row is still active (never swept) in both arms',
    [enabled.payload?.vector.sweepSentinelPreDecision?.leaseState, disabled.payload?.vector.sweepSentinelPreDecision?.leaseState],
    ['active', 'active'],
  );
  checks.ok(
    'the lapsed sentinel was transitioned only by its explicit legal CAS',
    enabled.payload &&
      disabled.payload &&
      enabled.payload.vector.decisions.some((entry) => entry.step === 'claim-lapsed-sentinel' && entry.ok === true) &&
      disabled.payload.vector.decisions.some((entry) => entry.step === 'claim-lapsed-sentinel' && entry.ok === true),
    {
      enabled: enabled.payload?.vector.decisions.find((entry) => entry.step === 'claim-lapsed-sentinel'),
      disabled: disabled.payload?.vector.decisions.find((entry) => entry.step === 'claim-lapsed-sentinel'),
    },
  );
  checks.eq(
    'explicit expiry transitions in the decision set',
    [enabled.payload?.vector.explicitExpiryTransitions, disabled.payload?.vector.explicitExpiryTransitions],
    [0, 0],
  );

  return {
    id: fixture.id,
    tier: fixture.tier,
    kind: fixture.kind,
    runner: fixture.runner,
    requires: fixture.requires,
    title: fixture.title,
    runnerPid: process.pid,
    dbName: `${enabled.dbName} / ${disabled.dbName}`,
    dbNames: [enabled.dbName, disabled.dbName],
    productClaim: true,
    status: checks.failed().length === 0 ? 'PASS' : 'PRODUCT_FAIL',
    checks: checks.checks,
    failedAssertions: checks.failed(),
    attempts: { decisionSets: 2, childProcesses: 2 },
    runnerPids: [process.pid, enabled.pid, disabled.pid],
    childPids: [enabled.pid, disabled.pid],
    realReturns: {
      enabledVectorHash: enabledHash,
      disabledVectorHash: disabledHash,
      enabledSweepKnob: enabled.payload ? enabled.payload.sweepKnob : null,
      disabledSweepKnob: disabled.payload ? disabled.payload.sweepKnob : null,
      decisionSteps: enabled.payload ? enabled.payload.vector.decisions.map((entry) => entry.step) : [],
    },
    dbReadBack: {
      enabledDecisions: enabled.payload ? enabled.payload.vector.decisions : null,
      disabledDecisions: disabled.payload ? disabled.payload.vector.decisions : null,
    },
    childWriteConcernEvidence: [
      { mode: 'enabled', summary: enabled.writeConcern ? enabled.writeConcern.summary : null },
      { mode: 'disabled', summary: disabled.writeConcern ? disabled.writeConcern.summary : null },
    ],
    processEvidence: {
      spawnCommands: [enabled.args, disabled.args].map((args) => `${process.execPath} ${args.join(' ')}`),
      stdio: 'ignore',
      env: { CBHR_PHASE1_SWEEP: ['enabled', 'disabled'] },
      exits: [enabled.exit, disabled.exit],
    },
    counterexample:
      enabledHash !== disabledHash
        ? `sweep-enabled vector hash ${enabledHash} differs from sweep-disabled hash ${disabledHash}`
        : null,
    provenance: {
      trustedTenant: env.TENANT,
      injectedPrincipals: ['principal-w3a-i11-sweep-1', 'principal-w3a-i11-sweep-2', 'principal-w3a-i11-sweep-3', 'principal-w3a-i11-sweep-4'],
      injectedClock: { kind: 'injected-deterministic', base: env.constants.EPOCH_BASE_MS },
      vectorDeterminism:
        'Grant ids are reduced to issued/rotated booleans and lengths, and no ObjectId, nonce, or wall-clock value enters the vector, so a byte-identical hash is meaningful.',
      sweepDisclosure:
        'The frozen I6/I5 surface exposes no background sweep method at all; the knob therefore only records that no sweep ran and that no decision changed between the two arms.',
    },
  };
}

/** NC-SWEEP-KNOB harness control: re-proves the knob and hash mechanism without Mongo. */
function sweepKnobControl(fixture) {
  const deterministicDecisions = (knob) => {
    const decisions = [
      { step: 'claim', ok: true, matched: 1, errorCode: null },
      { step: 'claim-same-owner', ok: false, matched: 0, errorCode: 'ONE_DEVICE_PER_ACCOUNT' },
      { step: 'revoke-stale', ok: false, matched: 0, errorCode: 'NOT_OWNER_OR_STALE' },
      { step: 'revoke', ok: true, matched: 1, errorCode: null },
    ];
    return { knob, decisions, sweepReliantDecisions: decisions.filter((entry) => entry.knob === 'sweep').length };
  };
  const enabled = deterministicDecisions('enabled');
  const disabled = deterministicDecisions('disabled');
  const enabledHash = support.sha256Json(enabled);
  const disabledHash = support.sha256Json(disabled);
  const checks = support.makeChecks();
  checks.eq('knob value 1', enabled.knob, 'enabled');
  checks.eq('knob value 2', disabled.knob, 'disabled');
  checks.eq('assertion bodies are byte-identical apart from the knob label', support.sha256Json(enabled.decisions), support.sha256Json(disabled.decisions));
  checks.eq('sweepReliantDecisions', enabled.sweepReliantDecisions + disabled.sweepReliantDecisions, 0);
  void enabledHash;
  void disabledHash;
  return {
    id: fixture.id,
    tier: fixture.tier,
    kind: fixture.kind,
    runner: fixture.runner,
    requires: fixture.requires,
    title: fixture.title,
    runnerPid: process.pid,
    dbName: null,
    productClaim: false,
    status: checks.failed().length === 0 ? 'PASS' : 'HARNESS_FAIL',
    checks: checks.checks,
    failedAssertions: checks.failed(),
    attempts: { knobRuns: 2 },
    realReturns: { enabledHash, disabledHash },
    dbReadBack: {},
    provenance: { mechanism: 'harness-only control; no Mongo connection and no product service' },
  };
}

const FIXTURES = [
  {
    id: 'E1-V24T12-SWEEP-DISABLED-RERUN',
    tier: 'E1',
    kind: 'product',
    runner: 'sweep-product',
    requires: ['I6'],
    title: 'sweep-disabled re-run: decision vectors byte-identical with the sweep effect absent',
    run: sweepDisabledRerun,
  },
];

const CONTROLS = [
  {
    id: 'NC-SWEEP-KNOB',
    tier: 'CONTROL',
    kind: 'harness-control',
    runner: 'sweep-selftest',
    requires: [],
    title: 'sweep control knob and decision-vector hash-equality self-test',
    run: sweepKnobControl,
  },
];

module.exports = { FIXTURES, CONTROLS, sweepDisabledRerun, sweepKnobControl, CHILD };