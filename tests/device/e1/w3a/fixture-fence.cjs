'use strict';

/**
 * W3-A / I11 harness controls that touch no product service.
 *
 *   NC-DB-FENCE       fail-closed Mongo fence: refuses every non-w3 database name, refuses
 *                     before constructing a MongoClient, and accepts one well-formed w3 name.
 *   NC-CRASH-HARNESS  crash transport self-test: a child writes a durable marker, exits with
 *                     sentinel 7, and a verifier process re-reads the marker.
 */

const path = require('node:path');
const { spawn } = require('node:child_process');

const common = require('./child-common.cjs');
const support = require('./support.cjs');
const fence = require('./fence.cjs');
const env = require('./env.cjs');

const SENTINEL_CHILD = path.resolve(__dirname, 'child-sentinel.cjs');
const SENTINEL = 7;

function runDbFenceControl(fixture) {
  const refuse = [
    'cbhr_rdc_phase1_preflight_20261010',
    'cbhr_rdc_phase1_governor_nullgrant_probe_20261010',
    'cbhr_rdc_phase1_w2b_e1_onepc_20261012_ab12cd',
    'cbhr_rdc_phase1_w2c_i10_20261012_ab12cd',
    'cbhr_rdc_phase1_w2r_x4_20261012',
    'cbhr_rdc_phase1_w1a_schema',
    'cbhr_rdc_phase1_w0_reverify',
    'devices_prod',
    'deviceauthorities',
    'librechat',
    'production',
    'admin',
    'local',
    'config',
    'cbhr_rdc_phase1_w2_x',
    'cbhr_rdc_phase1_w3',
    'cbhr_rdc_phase1_w3_',
  ].filter(Boolean);
  const accept = ['cbhr_rdc_phase1_w3_e1_onepc_00000000000000_deadbeef'];

  const results = [
    ...refuse.map((name) => {
      const problems = fence.checkDbName(name);
      return { name, expected: 'REFUSED', observed: problems.length > 0 ? 'REFUSED' : 'ACCEPTED', problems };
    }),
    ...accept.map((name) => {
      const problems = fence.checkDbName(name);
      return { name, expected: 'ACCEPTED', observed: problems.length === 0 ? 'ACCEPTED' : 'REFUSED', problems };
    }),
  ];

  const checks = support.makeChecks();
  for (const entry of results) {
    checks.eq(`fence ${entry.expected} ${entry.name}`, entry.observed, entry.expected);
  }
  checks.eq('the frozen URI is accepted', fence.checkUri(fence.FROZEN_URI), []);
  checks.ok('a non-frozen uri is refused', fence.checkUri('mongodb://127.0.0.1:27017/').length > 0, fence.checkUri('mongodb://127.0.0.1:27017/'));
  checks.ok('a credential-bearing uri is refused', fence.checkUri('mongodb://user:pass@127.0.0.1:27027/?replicaSet=cbhrRdcP1').length > 0, fence.checkUri('mongodb://user:pass@127.0.0.1:27027/?replicaSet=cbhrRdcP1'));
  checks.ok('a multi-host uri is refused', fence.checkUri('mongodb://127.0.0.1:27027,127.0.0.1:27028/?replicaSet=cbhrRdcP1').length > 0, fence.checkUri('mongodb://127.0.0.1:27027,127.0.0.1:27028/?replicaSet=cbhrRdcP1'));
  checks.eq('a well-formed w3 name is accepted', fence.checkDbName(accept[0]), []);

  return { checks: checks.checks, results, acceptedNames: accept };
}

async function dbFence(fixture) {
  const staticControl = runDbFenceControl(fixture);
  const checks = support.makeChecks();
  for (const check of staticControl.checks) {
    checks.ok(check.name, check.ok, check.observed);
  }
  // fail-closed refusal really happens BEFORE any client is constructed
  const refusals = [];
  for (const name of [
    'cbhr_rdc_phase1_preflight_20261010',
    'cbhr_rdc_phase1_w2b_e1_onepc_20261012_ab12cd',
    'devices_prod',
  ]) {
    try {
      await fence.connectGuarded({ dbName: name });
      refusals.push({ name, refused: false });
    } catch (err) {
      refusals.push({ name, refused: err.code === 'FENCE_VIOLATION', clientCreated: err.clientCreated, problems: err.problems });
    }
  }
  const uriRefusal = await fence
    .connectGuarded({ dbName: fence.createDbName('fence_uri_probe'), uri: 'mongodb://127.0.0.1:27017/' })
    .then(() => ({ refused: false }), (err) => ({ refused: err.code === 'FENCE_VIOLATION', clientCreated: err.clientCreated }));

  checks.ok('every refused name fails closed before a client exists', refusals.every((entry) => entry.refused === true && entry.clientCreated === false), refusals);
  checks.ok('a non-frozen URI fails closed before a client exists', uriRefusal.refused === true && uriRefusal.clientCreated === false, uriRefusal);

  const failed = checks.failed();
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
    status: failed.length === 0 ? 'PASS' : 'HARNESS_FAIL',
    connectionAttempted: false,
    checks: checks.checks,
    failedAssertions: failed,
    attempts: { fenceEvaluations: staticControl.results.length, liveRefusals: refusals.length + 1 },
    realReturns: { results: staticControl.results, refusals, uriRefusal },
    dbReadBack: {},
    provenance: { mechanism: 'pure fence evaluation plus fail-closed connectGuarded refusals; no connection is opened on refusal' },
  };
}

async function crashHarness(fixture) {
  const ctx = await support.makeContext({ tag: fixture.id, syncIndexes: false });
  const checks = support.makeChecks();
  const rundir = support.freshDir(path.join(support.runDir(), 'crash-selftest'));
  let payload = null;
  let exit = null;
  let pid = null;
  try {
    await ctx.client.db(ctx.dbName).createCollection('deviceauthorityevents').catch(() => {});
    const args = [SENTINEL_CHILD, `--db=${ctx.dbName}`, `--rundir=${rundir}`];
    const child = spawn(process.execPath, args, { stdio: 'ignore', windowsHide: true });
    pid = child.pid;
    exit = await Promise.race([
      new Promise((resolve) => child.once('exit', (code, signal) => resolve({ code, signal }))),
      new Promise((resolve) => setTimeout(() => resolve({ code: null, signal: 'TIMEOUT' }), 60000)),
    ]);
    if (exit.code === null) {
      child.kill();
    }
    payload = await common.waitForFile(`${rundir}/sentinel-witness.json`, { timeoutMs: 5000 }).catch(() => null);
    const marker = await ctx.client.db(ctx.dbName).collection('deviceauthorityevents').findOne({ _id: 'w3a-sentinel-marker' });

    checks.eq('child exited with the sentinel code', exit.code, SENTINEL);
    checks.ok('witness file present', payload !== null, payload);
    checks.eq('child never reached its post-write step', payload && payload.witnessedAfterWrite, false);
    checks.eq('witnessCount is 0', payload && payload.witnessCount, 0);
    checks.eq('witness PID matches the spawned PID', payload && payload.pid, pid);
    checks.ok('the marker is durable after the crash', marker !== null && marker._id === 'w3a-sentinel-marker', marker);
    checks.eq('child reported an acknowledged majority+journal insert', payload && payload.markerInserted, true);

    const failed = checks.failed();
    return {
      id: fixture.id,
      tier: fixture.tier,
      kind: fixture.kind,
      runner: fixture.runner,
      requires: fixture.requires,
      title: fixture.title,
      runnerPid: process.pid,
      dbName: ctx.dbName,
      productClaim: false,
      status: failed.length === 0 ? 'PASS' : 'HARNESS_FAIL',
      checks: checks.checks,
      failedAssertions: failed,
      attempts: { childProcesses: 1 },
      runnerPids: [process.pid, pid],
      childPids: [pid],
      realReturns: { exit, witness: payload },
      dbReadBack: { marker: marker ? { _id: marker._id, kind: marker.kind } : null },
      processEvidence: { spawnCommand: `${process.execPath} ${args.join(' ')}`, stdio: 'ignore', sentinel: SENTINEL, transport: 'durable marker + file witness' },
      provenance: { mechanism: 'harness transport control only; no product service is loaded' },
    };
  } finally {
    await ctx.teardown();
  }
}

const CONTROLS = [
  {
    id: 'NC-DB-FENCE',
    tier: 'CONTROL',
    kind: 'harness-control',
    runner: 'inline',
    requires: [],
    title: 'self-owned w3 database fence rejects every other name and fails closed',
    run: dbFence,
  },
  {
    id: 'NC-CRASH-HARNESS',
    tier: 'CONTROL',
    kind: 'harness-control',
    runner: 'crash-selftest',
    requires: [],
    title: 'crash transport self-test (durable marker then sentinel exit, verifier re-reads)',
    run: crashHarness,
  },
];

module.exports = { CONTROLS, dbFence, crashHarness, runDbFenceControl, SENTINEL_CHILD };