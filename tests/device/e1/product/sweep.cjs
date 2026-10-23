'use strict';

/**
 * E1-V24T12-SWEEP-DISABLED-RERUN PRODUCT fixture (lane I9 / task T1).
 *
 * The same deterministic decision set runs twice, each in its own OS process against its own
 * real MongoDB database, with CBHR_PHASE1_SWEEP=enabled for the first arm and =disabled for the
 * second. The decision vectors must hash identically, and no authorization decision may depend
 * on a background sweep: the product surface exposes no sweep at all, so a lapsed row that only a
 * sweep would flip must still be exactly as the last product CAS left it.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');

const c = require('./context.cjs');
const support = c.support;
const env = c.env;

const CHILD = path.resolve(__dirname, 'sweep-child.cjs');
const CHILD_TIMEOUT_MS = 240000;

function readJsonFile(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function sha256Json(value) {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex').toUpperCase();
}

/**
 * The vector hash must be meaningful: two arms with the same decisions but a different knob
 * label would otherwise hash differently. The knob capture (checked separately) is stripped
 * before hashing; every remaining byte is product-observable decision evidence.
 */
function stripArmLabel(vector) {
  const { mode, sweepKnob, ...rest } = vector;
  return rest;
}

async function runArm(mode, rundir, clock) {
  const ctx = await support.makeContext({
    tag: `sweep-${mode}`,
    mode: 'raw-registry',
    dropOnTeardown: false,
  });
  ctx.clock.set(clock);
  const args = [CHILD, `--db=${ctx.dbName}`, `--mode=${mode}`, `--rundir=${rundir}`, `--clock=${clock}`];
  const logFd = fs.openSync(`${rundir}/${mode}-stderr.log`, 'a');
  const child = spawn(process.execPath, args, {
    stdio: ['ignore', 'ignore', logFd],
    windowsHide: true,
    env: { ...process.env, CBHR_PHASE1_SWEEP: mode },
  });
  const exit = await new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try {
        child.kill();
      } catch {
        /* best effort */
      }
      resolve({ code: null, signal: 'TIMEOUT' });
    }, CHILD_TIMEOUT_MS);
    child.once('exit', (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code, signal });
    });
    child.once('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code: null, signal: null, error: `${err.name}: ${err.message}` });
    });
  });
  try {
    fs.closeSync(logFd);
  } catch {
    /* best effort */
  }
  const vectorPath = `${rundir}/vector-${mode}.json`;
  const payload = fs.existsSync(vectorPath) ? readJsonFile(vectorPath) : null;
  const stderr = fs.existsSync(`${rundir}/${mode}-stderr.log`) ? fs.readFileSync(`${rundir}/${mode}-stderr.log`, 'utf8').slice(-1500) : '';
  const dropped = await support.fence.dropOwnDatabase(ctx.client, ctx.dbName).catch(() => ({ dropped: false, error: 'drop failed' }));
  await ctx.teardown().catch(() => {});
  // teardown ALSO drops the database; normalize both shapes to the string 'dropped' on success.
  const droppedLabel = dropped && (dropped.dropped === true || dropped === 'dropped') ? 'dropped' : dropped;
  return { mode, dbName: ctx.dbName, pid: child.pid, args, exit, payload, stderr, dropped: droppedLabel };
}

async function run(fixture) {
  const rundir = support.freshDir(path.join(support.runDir(), 'e1-product-sweep'));
  const clock = env.constants.EPOCH_BASE_MS;
  const checks = support.makeChecks();
  try {
    const enabled = await runArm('enabled', rundir, clock);
    const disabled = await runArm('disabled', rundir, clock);

    const enabledHash = enabled.payload ? sha256Json(stripArmLabel(enabled.payload)) : null;
    const disabledHash = disabled.payload ? sha256Json(stripArmLabel(disabled.payload)) : null;

    checks.eq('the enabled arm child exited 0', enabled.exit.code, 0);
    checks.eq('the disabled arm child exited 0', disabled.exit.code, 0);
    checks.eq('two distinct OS processes ran the decision set', enabled.pid === disabled.pid ? 1 : 2, 2);
    checks.eq('the knob was really enabled in arm 1', enabled.payload && enabled.payload.sweepKnob, 'enabled');
    checks.eq('the knob was really disabled in arm 2', disabled.payload && disabled.payload.sweepKnob, 'disabled');
    checks.ok('both decision vectors were produced', enabledHash !== null && disabledHash !== null, { enabledHash, disabledHash, stderr: [enabled.stderr, disabled.stderr] });
    checks.eq('decision vectors are byte-identical (same sha256)', enabledHash, disabledHash);
    checks.eq(
      'decision counts match',
      enabled.payload ? enabled.payload.decisionCount : -1,
      disabled.payload ? disabled.payload.decisionCount : -2,
    );
    checks.eq(
      'no background sweep process ran in either arm',
      [enabled.payload?.backgroundSweepProcessesSpawned, disabled.payload?.backgroundSweepProcessesSpawned],
      [0, 0],
    );
    checks.eq(
      'the lapsed sentinel was still active (never swept) in both arms',
      [enabled.payload?.sweepSentinelPreDecision?.leaseState, disabled.payload?.sweepSentinelPreDecision?.leaseState],
      ['active', 'active'],
    );
    checks.eq(
      'the only expiry transition in the set was the explicit product CAS',
      [enabled.payload?.explicitExpiryTransitions, disabled.payload?.explicitExpiryTransitions],
      [1, 1],
    );
    checks.eq(
      'the final durable state is identical across arms',
      enabled.payload?.finalState,
      disabled.payload?.finalState,
    );
    checks.ok(
      'the decision set contains real product decisions (not a vacuous vector)',
      enabled.payload && enabled.payload.decisions.filter((entry) => entry.ok === true).length >= 4,
      enabled.payload ? enabled.payload.decisions.map((entry) => ({ step: entry.step, ok: entry.ok, matched: entry.matched, errorCode: entry.errorCode })) : null,
    );
    checks.eq('both arm databases were dropped (recorded by the arm teardown)', [enabled.dropped, disabled.dropped], ['dropped', 'dropped']);
    checks.eq(
      'the product source contains no background sweep implementation',
      c.productHasNoBackgroundSweep().exposesSweep,
      false,
    );

    const status = support.statusFromChecks(checks.checks);
    return {
      id: fixture.id,
      tier: fixture.tier,
      kind: fixture.kind,
      runner: fixture.runner,
      requires: fixture.requires,
      title: fixture.title,
      runnerPid: process.pid,
      dbName: `${enabled.dbName} | ${disabled.dbName}`,
      dbNames: [enabled.dbName, disabled.dbName],
      productClaim: true,
      ...status,
      checks: checks.checks,
      attempts: { decisionSets: 2, childProcesses: 2 },
      runnerPids: [process.pid, enabled.pid, disabled.pid],
      childPids: [enabled.pid, disabled.pid],
      realReturns: {
        enabledVectorHash: enabledHash,
        disabledVectorHash: disabledHash,
        enabledSweepKnob: enabled.payload ? enabled.payload.sweepKnob : null,
        disabledSweepKnob: disabled.payload ? disabled.payload.sweepKnob : null,
        decisionSteps: enabled.payload ? enabled.payload.decisions.map((entry) => entry.step) : [],
      },
      dbReadBack: {
        enabledDecisions: enabled.payload ? enabled.payload.decisions : null,
        disabledDecisions: disabled.payload ? disabled.payload.decisions : null,
        enabledFinalState: enabled.payload ? enabled.payload.finalState : null,
        disabledFinalState: disabled.payload ? disabled.payload.finalState : null,
      },
      processEvidence: {
        spawnCommands: [enabled.args, disabled.args].map((args) => `${process.execPath} ${args.join(' ')}`),
        stdio: 'ignore + stderr to file',
        env: { CBHR_PHASE1_SWEEP: ['enabled', 'disabled'] },
        exits: [enabled.exit, disabled.exit],
      },
      provenance: support.provenance(ctxForProvenance(), {
        vectorDeterminism:
          'Grant ids are reduced to issued booleans and epoch counters, and no ObjectId, nonce or wall-clock value enters the vector, so a byte-identical hash is meaningful.',
        sweepDisclosure:
          'The frozen I6/I5 surface exposes no background sweep method at all; the knob therefore only records that no sweep ran and that no decision changed between the two arms.',
      }),
    };
  } finally {
    /* per-arm teardown already dropped its own database */
  }
}

/** Provenance needs a context-shaped object; the arms are already closed, so pass a descriptor. */
function ctxForProvenance() {
  return {
    modelInfo: { barrelPath: env.bridge.MODELS_BARREL, keys: [] },
    facadeProvenance: {},
    facadeKind: 'genuine-createModels-registry-no-adapter',
    dbMode: 'raw-registry',
    tenantPolicy: { kind: 'fixed-server-controlled-allowlist', allowed: [env.TENANT] },
    consent: { kind: 'fixed-trusted-local-consent', granted: true },
    clock: { kind: 'injected-deterministic', now: () => env.constants.EPOCH_BASE_MS },
    audit: { kind: 'raw-driver-verbatim-durable-sink' },
  };
}

module.exports = { run, CHILD };