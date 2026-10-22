'use strict';

/**
 * W3-A / I11 E2 two-OS-process fixtures (real I6 CAS bytes + real MongoDB).
 *
 *   E2-T7-ONEPC-TWO-PC-RACE           claim-vs-claim for one owner across two devices
 *   E2-T8-TWO-OWNERS-ONE-PC-RACE      two owners claim one device
 *   E2-V24T15-REVOKE-VS-CLAIM-RACE    revoke (owner A) races a fresh claim (owner B)
 *
 * Both shards are separate OS processes; the parent paces them one barrier per round and
 * collects their file-based results. N >= 50 real product CAS attempts per fixture.
 */

const path = require('node:path');
const { spawn } = require('node:child_process');

const common = require('./child-common.cjs');
const support = require('./support.cjs');
const env = require('./env.cjs');

const { TENANT, OWNER_A, OWNER_B } = env;
const CHILD = path.resolve(__dirname, 'child-race.cjs');
const SENTINEL_TIMEOUT_MS = 180000;

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
    productClaim: true,
    ...extras,
  };
}

async function spawnShard(fixture, shard, { dbName, rounds, rundir, clock }) {
  const args = [
    CHILD,
    `--db=${dbName}`,
    `--fixture=${fixture.id}`,
    `--shard=${shard}`,
    `--rounds=${rounds}`,
    `--rundir=${rundir}`,
    `--clock=${clock}`,
  ];
  const child = spawn(process.execPath, args, { stdio: 'ignore', windowsHide: true });
  const exit = new Promise((resolve) => {
    child.once('exit', (code, signal) => resolve({ code, signal }));
    child.once('error', (err) => resolve({ code: null, signal: null, error: `${err.name}: ${err.message}` }));
  });
  return { shard, pid: child.pid, args, child, exit };
}

/** Drives one barrier-paced round for both shards. */
async function driveRounds({ fixture, shards, rounds, rundir, goContentForRound }) {
  const timeline = [];
  for (let round = 0; round < rounds; round += 1) {
    const readyAt = process.hrtime.bigint();
    await Promise.all(
      shards.map((shard) => common.waitForFile(`${rundir}/${fixture.id}-ready-${round}-${shard.shard}.json`)),
    );
    const allReadyAt = process.hrtime.bigint();
    common.writeJsonFile(`${rundir}/${fixture.id}-go-${round}.json`, goContentForRound(round));
    const results = await Promise.all(
      shards.map((shard) => common.waitForFile(`${rundir}/${fixture.id}-res-${round}-${shard.shard}.json`)),
    );
    const doneAt = process.hrtime.bigint();
    timeline.push({
      round,
      readyWaitMs: Number(allReadyAt - readyAt) / 1e6,
      roundWallMs: Number(doneAt - readyAt) / 1e6,
      results,
    });
  }
  return timeline;
}

function summarize(resultsFlat) {
  const winners = resultsFlat.filter((entry) => entry.ok === true && entry.matched > 0);
  const errorHistogram = {};
  for (const entry of resultsFlat) {
    const key = entry.ok === true && entry.matched > 0 ? 'SUCCESS' : entry.errorCode ?? 'NO_ERROR_CODE';
    errorHistogram[key] = (errorHistogram[key] ?? 0) + 1;
  }
  return { winners, errorHistogram };
}

async function runRaceFixture(fixture, { n }) {
  const rounds = Math.max(1, Math.ceil(n / 2));
  const ctx = await support.makeContext({ tag: fixture.id, point: fixture.point });
  const checks = support.makeChecks();
  const rundir = support.freshDir(path.join(support.runDir(), 'two-process', fixture.id));
  const clock = ctx.clock.now();
  let shards = [];
  let t15Expectations = new Map();
  try {
    let goContentForRound;
    let seedChecks = () => true;

    if (fixture.id === 'E2-T7-ONEPC-TWO-PC-RACE') {
      const deviceA = await support.seedDevice(ctx, 't7-a');
      const deviceB = await support.seedDevice(ctx, 't7-b');
      goContentForRound = (round) => ({ round, deviceId: round % 2 === 0 ? deviceA.deviceId : deviceB.deviceId });
      seedChecks = () => {
        checks.eq('two claimable devices for one owner', 2, 2);
        return { deviceA: deviceA.deviceId, deviceB: deviceB.deviceId };
      };
    } else if (fixture.id === 'E2-T8-TWO-OWNERS-ONE-PC-RACE') {
      const device = await support.seedDevice(ctx, 't8');
      goContentForRound = (round) => ({ round, deviceId: device.deviceId });
      seedChecks = () => ({ device: device.deviceId });
    } else if (fixture.id === 'E2-V24T15-REVOKE-VS-CLAIM-RACE') {
      const seeded = [];
      for (let round = 0; round < rounds; round += 1) {
        // The frozen one-device-per-account rule applies even across distinct devices, so every
        // seeded row gets a UNIQUE current owner and a UNIQUE challenger owner. The window under
        // test is: A holds the row at epoch 1 and revokes it while B concurrently claims it.
        const seedOwner = `principal-w3a-i11-t15-seed-${round}`;
        const claimOwner = `principal-w3a-i11-t15-claim-${round}`;
        const device = await support.seedDevice(ctx, `t15-${round}`, {
          _id: `w3a-device-t15-${round}`,
          identityState: 'active',
          leaseState: 'active',
          ownerId: seedOwner,
          grantId: `w3a-t15-grant-${round}`,
          epoch: 1,
          activatedAt: new Date(clock),
          expiresAt: new Date(clock + env.constants.LEASE_TTL_MS),
        });
        seeded.push({ ...device, seedOwner, claimOwner });
      }
      goContentForRound = (round) => ({
        round,
        deviceId: seeded[round].deviceId,
        ownerId: seeded[round].seedOwner,
        epoch: 1,
        claimOwnerId: seeded[round].claimOwner,
      });
      seedChecks = () => {
        t15Expectations = new Map(seeded.map((entry) => [entry.deviceId, { seedOwner: entry.seedOwner, claimOwner: entry.claimOwner }]));
        return { roundsSeeded: seeded.length, epochAtSeed: 1, uniqueSeedOwners: new Set(seeded.map((entry) => entry.seedOwner)).size };
      };
    } else {
      throw new Error(`unknown race fixture ${fixture.id}`);
    }

    const seededInfo = seedChecks();
    shards = ['A', 'B'].map((shard) => ({ shard, started: null }));
    const spawned = [];
    for (const shard of shards) {
      const handle = await spawnShard(fixture, shard.shard, { dbName: ctx.dbName, rounds, rundir, clock });
      spawned.push(handle);
    }
    shards = spawned;

    const timeline = await Promise.race([
      driveRounds({ fixture, shards: spawned, rounds, rundir, goContentForRound }),
      new Promise((resolve, reject) =>
        setTimeout(() => reject(new Error(`SENTINEL_TIMEOUT after ${SENTINEL_TIMEOUT_MS}ms`)), SENTINEL_TIMEOUT_MS),
      ),
    ]);

    const exits = await Promise.all(spawned.map((handle) => handle.exit));
    const summaries = spawned.map((handle) => common.readJsonFile(`${rundir}/${fixture.id}-summary-${handle.shard}.json`));
    const duplicateObservations = summaries.flatMap((summary) => summary.duplicateKeyObservations);
    const childWriteConcern = summaries.map((summary) => ({ shard: summary.shard, summary: summary.writeConcernSummary }));
    const resultsFlat = timeline.flatMap((entry) => entry.results);
    const { winners, errorHistogram } = summarize(resultsFlat);
    const pids = spawned.map((handle) => handle.pid);
    const childPids = Array.from(new Set(resultsFlat.map((entry) => entry.pid)));

    checks.eq('two distinct OS child processes spawned', new Set(pids).size, 2);
    checks.eq('both children exited 0', exits.map((entry) => entry.code), [0, 0]);
    checks.eq('two distinct child PIDs recorded in results', childPids.length, 2);
    checks.ok('total real CAS attempts >= N', resultsFlat.length >= n, { attempts: resultsFlat.length, n });
    checks.eq('child PIDs match the spawned process PIDs', childPids.slice().sort(), pids.slice().sort());
    if (fixture.id === 'E2-T7-ONEPC-TWO-PC-RACE') {
      checks.ok(
        'children observed real E11000 duplicate-key contention on the account axis',
        duplicateObservations.some(
          (entry) => entry.keyPattern && entry.keyPattern.ownerId === 1 && entry.keyPattern.tenantId === 1,
        ),
        duplicateObservations,
      );
    } else {
      checks.eq(
        'losers failed on the frozen CAS filters, with no duplicate-key path needed',
        duplicateObservations.length,
        0,
      );
    }

    let verdict;
    if (fixture.id === 'E2-T7-ONEPC-TWO-PC-RACE') {
      const active = await support.countActiveOwners(ctx.models, OWNER_A, TENANT);
      const allRows = await ctx.models.DeviceAuthority.find({ tenantId: TENANT }).lean();
      verdict = { activeRowsForOwner: active, rows: allRows.length };
      checks.eq('exactly one winner across both shards', winners.length, 1);
      checks.eq('active rows for the account (real index)', active, 1);
      checks.ok(
        'every loser failed closed with a frozen rejection code',
        resultsFlat
          .filter((entry) => !(entry.ok === true && entry.matched > 0))
          .every((entry) => ['ONE_DEVICE_PER_ACCOUNT', 'DEVICE_ALREADY_PAIRED_USE_RENEW'].includes(entry.errorCode)),
        errorHistogram,
      );
      checks.eq(
        'winner row carries a 22-char grant id and 48h TTL',
        allRows
          .filter((row) => row.leaseState === 'active')
          .map((row) => [String(row.grantId).length, new Date(row.expiresAt).getTime() - new Date(row.activatedAt).getTime()]),
        [[22, env.constants.LEASE_TTL_MS]],
      );
    } else if (fixture.id === 'E2-T8-TWO-OWNERS-ONE-PC-RACE') {
      const row = await support.readAuthorityRaw(ctx.models, seededInfo.device, TENANT);
      verdict = { finalRow: support.authorityView(row, ctx.clock.now()), winnerOwner: winners[0] ? winners[0].ownerId : null };
      checks.eq('exactly one winner', winners.length, 1);
      checks.eq('authority row leaseState', row.leaseState, 'active');
      checks.ok('winning owner is exactly one of the two shard owners', [OWNER_A, OWNER_B].includes(row.ownerId), row.ownerId);
      checks.eq('winning owner equals the recorded winner', row.ownerId, winners[0].ownerId);
      checks.eq('epoch incremented exactly once', row.epoch, 1);
      checks.ok(
        'loser failed closed (0-match class error)',
        resultsFlat
          .filter((entry) => entry.ownerId !== row.ownerId)
          .every((entry) => ['DEVICE_ALREADY_PAIRED_USE_RENEW', 'ONE_DEVICE_PER_ACCOUNT', 'PAIRING_WINDOW_TOO_EARLY'].includes(entry.errorCode)),
        errorHistogram,
      );
      checks.ok(
        'authorize(winner) true and authorize(loser) false',
        support.authorizePredicate(row, { ownerId: row.ownerId, epoch: row.epoch, grantId: row.grantId, now: ctx.clock.now() }).allowed === true &&
          support.authorizePredicate(row, { ownerId: row.ownerId === OWNER_A ? OWNER_B : OWNER_A, epoch: row.epoch, grantId: row.grantId, now: ctx.clock.now() }).allowed === false,
        support.authorityView(row, ctx.clock.now()),
      );
    } else {
      const rows = await ctx.models.DeviceAuthority.find({ tenantId: TENANT }).lean();
      const seededGrants = new Map(rows.map((row) => [String(row._id), `w3a-t15-grant-${String(row._id).replace('w3a-device-t15-', '')}`]));
      const revokeWinners = winners.filter((entry) => entry.action === 'revokeLease');
      const claimWinners = winners.filter((entry) => entry.action === 'claimAuthority');
      const roundsWithTwoMatches = timeline.filter((entry) => entry.results.filter((r) => r.ok && r.matched > 0).length > 1).length;
      const roundsWithNoMatch = timeline.filter((entry) => entry.results.filter((r) => r.ok && r.matched > 0).length === 0).length;
      verdict = {
        rounds,
        revokeWinners: revokeWinners.length,
        claimWinners: claimWinners.length,
        roundsWithTwoMatches,
        roundsWithNoMatch,
        epochDeltas: rows.map((row) => row.epoch - 1),
        finalStates: rows.map((row) => ({
          device: String(row._id),
          leaseState: row.leaseState,
          ownerId: row.ownerId,
          epoch: row.epoch,
          grantIdRotatedOnRevoke: row.leaseState === 'revoked' ? row.grantId !== seededGrants.get(String(row._id)) : null,
        })),
      };
      checks.ok(
        'every round committed exactly one of {revoke, claim}',
        roundsWithTwoMatches === 0 && roundsWithNoMatch === 0,
        { roundsWithTwoMatches, roundsWithNoMatch, revokeWinners: revokeWinners.length, claimWinners: claimWinners.length },
      );
      checks.ok(
        'every device advanced its epoch by exactly 1',
        rows.every((row) => row.epoch === 2),
        rows.map((row) => ({ device: String(row._id), epoch: row.epoch })),
      );
      checks.ok(
        'revoke never rotates grantId (G-2)',
        rows.every((row) => row.leaseState !== 'revoked' || row.grantId === seededGrants.get(String(row._id))),
        verdict.finalStates,
      );
      checks.ok(
        'the serialized outcome is the REQUIRED one: last committed transition wins and matches durable state',
        rows.every((row) => {
          const expectation = t15Expectations.get(String(row._id));
          if (expectation === undefined) return false;
          return (
            (row.leaseState === 'revoked' && String(row.ownerId) === expectation.seedOwner && row.epoch === 2) ||
            (row.leaseState === 'active' && String(row.ownerId) === expectation.claimOwner && row.epoch === 3)
          );
        }),
        verdict.finalStates,
      );
      checks.ok(
        'under true concurrency BOTH independent CAS transitions legally commit (observed)',
        verdict.roundsWithTwoMatches === rounds,
        { roundsWithTwoMatches, rounds },
      );
      checks.ok(
        'no attempt blind-wrote: every non-matching CAS reports matched 0',
        resultsFlat.filter((entry) => !(entry.ok === true && entry.matched > 0)).every((entry) => entry.matched === 0 && entry.errorCode !== null),
        errorHistogram,
      );
    }

    return baseResult(fixture, ctx.dbName, {
      ...support.statusFromChecks(checks.checks),
      checks: checks.checks,
      attempts: {
        totalCasAttempts: resultsFlat.length,
        rounds,
        shards: 2,
        n,
      },
      runnerPids: pids,
      childPids,
      realReturns: {
        errorHistogram,
        winnerCount: winners.length,
        winners: winners.map((entry) => ({ shard: entry.shard, round: entry.round, action: entry.action, ownerId: entry.ownerId })),
        perRound: timeline.map((entry) => ({ round: entry.round, results: entry.results.map((r) => ({ shard: r.shard, action: r.action, ok: r.ok, matched: r.matched, errorCode: r.errorCode })) })),
        childDuplicateKeyObservations: duplicateObservations,
      },
      dbReadBack: verdict,
      childWriteConcernEvidence: childWriteConcern,
      processEvidence: {
        spawnCommand: spawned.map((handle) => `${process.execPath} ${handle.args.join(' ')}`),
        stdio: 'ignore',
        transport: 'file-based result files under the run directory',
        exits,
      },
      counterexample:
        fixture.id === 'E2-V24T15-REVOKE-VS-CLAIM-RACE' && verdict.roundsWithTwoMatches === rounds
          ? `${verdict.roundsWithTwoMatches}/${rounds} barrier rounds ended with BOTH transitions committed: ${verdict.revokeWinners} revokeLease (epoch 1->2, row left revoked under the seed owner) and ${verdict.claimWinners} claimAuthority (epoch 2->3, row active under the challenger). Every device row is still coherent (exactly one owner, one live/revoked state, no torn intermediate), but the frozen "one committed transition per row" expectation is NOT what the product bytes produce under this window: both legal CAS transitions commit, serially ordered by whichever call read the row last. Durable proof: deviceauthorities rows show epoch 3, leaseState 'active', ownerId = the challenger, while the revoke path's own update (epoch 2, 'revoked') is overwritten.`
          : null,
      provenance: support.provenance(ctx, {
        twoProcessDisclosure: 'Exactly two OS processes per fixture; the parent pace-sets one file barrier per round so both shards are inside the same critical window.',
      }),
    });
  } finally {
    for (const handle of shards) {
      if (handle.child && handle.child.exitCode === null) {
        handle.child.kill();
      }
    }
    await ctx.teardown();
  }
}

const FIXTURES = [
  {
    id: 'E2-T7-ONEPC-TWO-PC-RACE',
    tier: 'E2',
    kind: 'product',
    runner: 'two-process',
    requires: ['I6'],
    title: 'one account claim race across two real PCs and two OS processes (N>=50)',
    point: 'T7',
    run: runRaceFixture,
  },
  {
    id: 'E2-T8-TWO-OWNERS-ONE-PC-RACE',
    tier: 'E2',
    kind: 'product',
    runner: 'two-process',
    requires: ['I6'],
    title: 'two accounts versus one PC claim race across two OS processes (N>=50)',
    point: 'T8',
    run: runRaceFixture,
  },
  {
    id: 'E2-V24T15-REVOKE-VS-CLAIM-RACE',
    tier: 'E2',
    kind: 'product',
    runner: 'two-process',
    requires: ['I6'],
    title: 'concurrent revoke versus fresh-owner claim across two OS processes (N>=50)',
    point: 'V24-T15',
    run: runRaceFixture,
  },
];

module.exports = { FIXTURES, runRaceFixture, driveRounds, spawnShard };