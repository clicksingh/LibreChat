'use strict';

/**
 * W3-A / I11 naive-baseline negative controls (engine level, raw driver only).
 *
 *   NC-NAIVE-NOINDEX  EXPECTED_FAIL: two real OS processes produce TWO active rows for one
 *                     owner in one tenant when uq_owner_active is absent — the product
 *                     invariant R1 is violated, which is what makes the control non-vacuous.
 *   NC-NAIVE-INDEX    PASS: the identical naive burst caught by the frozen unique partial
 *                     index {ownerId:1,tenantId:1} partial {leaseState:'active'} (E11000).
 *
 * This is an ENGINE-level control: it proves the index shape catches the race. It is NOT a
 * schema-driven or product-service proof, and no product service is loaded here.
 */

const path = require('node:path');
const { spawn } = require('node:child_process');

const common = require('./child-common.cjs');
const support = require('./support.cjs');
const env = require('./env.cjs');

const { TENANT } = env;
const CHILD = path.resolve(__dirname, 'child-naive.cjs');
const OWNER = 'principal-w3a-i11-naive';
const TIMEOUT_MS = 180000;

async function runNaive(fixture, { n }) {
  const rounds = Math.max(1, Math.ceil(n / 2));
  const ctx = await support.makeContext({ tag: fixture.id, syncIndexes: false });
  const checks = support.makeChecks();
  const rundir = support.freshDir(path.join(support.runDir(), 'naive', fixture.id));
  const withIndex = fixture.id === 'NC-NAIVE-INDEX';
  let spawned = [];
  try {
    const collection = ctx.client.db(ctx.dbName).collection('deviceauthorities');
    await ctx.client.db(ctx.dbName).createCollection('deviceauthorities').catch(() => {});
    const indexName = withIndex ? 'w3a_naive_uq_owner_active' : null;
    if (withIndex) {
      await collection.createIndex(
        { ownerId: 1, tenantId: 1 },
        { name: indexName, unique: true, partialFilterExpression: { leaseState: 'active' } },
      );
    }
    const liveBefore = (await collection.listIndexes().toArray()).map((row) => row.name);

    spawned = ['A', 'B'].map((shard) => {
      const args = [
        CHILD,
        `--db=${ctx.dbName}`,
        `--shard=${shard}`,
        `--rounds=${rounds}`,
        `--rundir=${rundir}`,
        `--owner=${OWNER}`,
        `--tenant=${TENANT}`,
        `--clock=${ctx.clock.now()}`,
      ];
      const child = spawn(process.execPath, args, { stdio: 'ignore', windowsHide: true });
      const exit = new Promise((resolve) => {
        child.once('exit', (code, signal) => resolve({ code, signal }));
        child.once('error', (err) => resolve({ code: null, error: `${err.name}: ${err.message}` }));
      });
      return { shard, pid: child.pid, args, child, exit };
    });

    const timeline = [];
    for (let round = 0; round < rounds; round += 1) {
      await Promise.all(spawned.map((handle) => common.waitForFile(`${rundir}/naive-read-${round}-${handle.shard}.json`)));
      common.writeJsonFile(`${rundir}/naive-go-${round}.json`, { round });
      const results = await Promise.all(spawned.map((handle) => common.waitForFile(`${rundir}/naive-res-${round}-${handle.shard}.json`)));
      timeline.push({ round, results });
    }

    const exits = await Promise.race([
      Promise.all(spawned.map((handle) => handle.exit)),
      new Promise((resolve) => setTimeout(() => resolve([]), TIMEOUT_MS)),
    ]);

    const activeRows = await collection.find({ ownerId: OWNER, tenantId: TENANT, leaseState: 'active' }).toArray();
    const insertResults = timeline.flatMap((entry) => entry.results);
    const round0 = timeline[0].results;
    const duplicateKeys = insertResults.filter((entry) => entry.code === 11000);
    const pids = spawned.map((handle) => handle.pid);
    const childPids = Array.from(new Set(insertResults.map((entry) => entry.pid)));

    checks.eq('two distinct OS child processes spawned', new Set(pids).size, 2);
    checks.eq('two distinct child PIDs recorded', childPids.length, 2);
    checks.ok('total naive attempts >= N', insertResults.length >= n, { attempts: insertResults.length, n });
    checks.eq('both children exited 0', exits.map((entry) => entry.code), [0, 0]);
    checks.ok('every read preceded every write in round 0 (barrier)', round0.every((entry) => entry.readCount === 0), round0);

    if (withIndex) {
      checks.eq('owner index present before the burst', liveBefore.includes(indexName), true);
      checks.eq('exactly one insert succeeded in round 0', round0.filter((entry) => entry.inserted === true).length, 1);
      checks.ok(
        'the losing insert failed with E11000 on the observed {ownerId,tenantId} keyPattern',
        round0.some((entry) => entry.code === 11000 && entry.keyPattern && entry.keyPattern.ownerId === 1 && entry.keyPattern.tenantId === 1),
        round0,
      );
      checks.eq('active rows for the owner after the burst', activeRows.length, 1);
      checks.ok('at least one E11000 observed across the burst', duplicateKeys.length >= 1, { duplicates: duplicateKeys.length });
      checks.eq('index list (engine-level)', (await collection.listIndexes().toArray()).map((row) => row.name).sort(), ['_id_', indexName].sort());

      return baseResult(fixture, ctx.dbName, {
        status: 'PASS',
        productClaim: false,
        checks: checks.checks,
        failedAssertions: checks.failed(),
        expectedStatus: 'PASS',
        attempts: { totalNaiveInserts: insertResults.length, rounds, shards: 2, n },
        runnerPids: pids,
        childPids,
        realReturns: {
          round0,
          duplicateKeyObservations: duplicateKeys.map((entry) => ({ shard: entry.shard, code: entry.code, keyPattern: entry.keyPattern })),
          errorHistogram: insertResults.reduce((acc, entry) => {
            const key = entry.inserted ? 'INSERTED' : String(entry.code);
            acc[key] = (acc[key] ?? 0) + 1;
            return acc;
          }, {}),
        },
        dbReadBack: {
          activeRowsForOwner: activeRows.length,
          rows: activeRows.map((row) => ({ _id: row._id, ownerId: row.ownerId, leaseState: row.leaseState, epoch: row.epoch, grantId: row.grantId })),
          liveIndexes: (await collection.listIndexes().toArray()).map((row) => ({ name: row.name, key: row.key, unique: row.unique ?? false, partial: row.partialFilterExpression ?? null })),
        },
        processEvidence: {
          spawnCommand: spawned.map((handle) => `${process.execPath} ${handle.args.join(' ')}`),
          stdio: 'ignore',
          transport: 'file-based result files under the run directory',
          exits,
        },
        provenance: support.provenance(ctx, {
          controlDisclosure: 'Engine-level control: raw driver only, no product service and no schema-driven index creation. It proves the frozen index shape catches the naive race; it is not product-service evidence.',
        }),
      });
    }

    checks.eq('only the implicit _id_ index exists before the burst', liveBefore.slice().sort(), ['_id_']);
    checks.eq('round 0: both naive inserts succeeded', round0.filter((entry) => entry.inserted === true).length, 2);
    checks.eq('round 0: both shards read zero active rows before writing', round0.map((entry) => entry.readCount), [0, 0]);
    checks.eq('product invariant R1 violated: TWO active rows for one owner', activeRows.length, 2);
    checks.eq('active rows carry distinct grants', new Set(activeRows.map((row) => row.grantId)).size, 2);
    checks.ok(
      'later rounds observe the violation before writing',
      timeline.slice(1).every((entry) => entry.results.every((result) => result.readCount === 2)),
      timeline.slice(1).map((entry) => entry.results.map((result) => result.readCount)),
    );

    return baseResult(fixture, ctx.dbName, {
      status: activeRows.length === 2 ? 'EXPECTED_FAIL' : 'HARNESS_FAIL',
      productClaim: false,
      productInvariantViolated: activeRows.length === 2,
      checks: checks.checks,
      failedAssertions: checks.failed(),
      expectedStatus: 'EXPECTED_FAIL',
      attempts: { totalNaiveInserts: insertResults.length, rounds, shards: 2, n },
      runnerPids: pids,
      childPids,
      realReturns: {
        round0,
        errorHistogram: insertResults.reduce((acc, entry) => {
          const key = entry.inserted ? 'INSERTED' : String(entry.code);
          acc[key] = (acc[key] ?? 0) + 1;
          return acc;
        }, {}),
      },
      dbReadBack: {
        activeRowsForOwner: activeRows.length,
        rows: activeRows.map((row) => ({ _id: row._id, ownerId: row.ownerId, leaseState: row.leaseState, epoch: row.epoch, grantId: row.grantId })),
        liveIndexes: (await collection.listIndexes().toArray()).map((row) => ({ name: row.name, key: row.key, unique: row.unique ?? false, partial: row.partialFilterExpression ?? null })),
      },
      processEvidence: {
        spawnCommand: spawned.map((handle) => `${process.execPath} ${handle.args.join(' ')}`),
        stdio: 'ignore',
        transport: 'file-based result files under the run directory',
        exits,
      },
      provenance: support.provenance(ctx, {
        controlDisclosure: 'Engine-level EXPECTED_FAIL control: raw driver only, uq_owner_active deliberately absent. Non-vacuous because TWO active rows are actually observed.',
      }),
    });
  } finally {
    for (const handle of spawned) {
      if (handle.child && handle.child.exitCode === null) {
        handle.child.kill();
      }
    }
    await ctx.teardown();
  }
}

function baseResult(fixture, dbName, extras = {}) {
  return {
    id: fixture.id,
    tier: fixture.tier,
    kind: fixture.kind,
    runner: fixture.runner,
    requires: fixture.requires,
    title: fixture.title,
    runnerPid: process.pid,
    dbName,
    ...extras,
  };
}

const FIXTURES = [
  {
    id: 'NC-NAIVE-NOINDEX',
    tier: 'CONTROL',
    kind: 'negative-control',
    runner: 'naive-noindex',
    requires: [],
    title: 'naive check-then-insert without the account-axis index produces two active rows (EXPECTED_FAIL)',
    run: runNaive,
  },
  {
    id: 'NC-NAIVE-INDEX',
    tier: 'CONTROL',
    kind: 'negative-control',
    runner: 'naive-index',
    requires: [],
    title: 'the same naive check-then-insert caught by uq_owner_active (E11000 complement)',
    run: runNaive,
  },
];

module.exports = { FIXTURES, runNaive, CHILD };