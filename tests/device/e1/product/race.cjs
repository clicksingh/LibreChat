'use strict';

/**
 * E2 two-OS-process PRODUCT fixtures (lane I9 / task T1).
 *
 *   E2-T7-ONEPC-TWO-PC-RACE         one account claims two PCs from two OS processes (N>=50)
 *   E2-T8-TWO-OWNERS-ONE-PC-RACE    two accounts claim one PC from two OS processes (N>=50)
 *   E2-V24T15-REVOKE-VS-CLAIM-RACE  revoke (owner A) races a fresh claim (owner B) (N>=50)
 *
 * Exactly two real OS child processes per fixture (recorded PIDs, asserted distinct), one file
 * barrier per round so both shards sit inside the same window, stdio 'ignore' and file-based
 * result transport (piped stdio is EPERM in this sandbox). Every attempt is a real I6/I5 product
 * call against the shared real MongoDB database, which the parent drops when the burst ends.
 */

const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const c = require('./context.cjs');
const support = c.support;
const env = c.env;

const { TENANT, LEASE_TTL_MS } = c;
const OWNER_A = env.OWNER_A;
const OWNER_B = env.OWNER_B;
const CHILD = path.resolve(__dirname, 'race-child.cjs');
const CHILD_TIMEOUT_MS = 300000;

function base(fixture) {
  return {
    id: fixture.id,
    tier: fixture.tier,
    kind: fixture.kind,
    runner: fixture.runner,
    requires: fixture.requires,
    title: fixture.title,
    runnerPid: process.pid,
    productClaim: true,
    services: {
      authorityService: env.PRODUCT_FILES.authorityService,
      registrationService: env.PRODUCT_FILES.registrationService,
      pairingSessionService: env.PRODUCT_FILES.pairingSessionService,
    },
  };
}

function readJsonFile(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function writeJsonFile(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  // Atomic publish: sibling readers may race this writer (the barrier is file-based).
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  fs.renameSync(tmp, file);
}

async function waitFor(file, timeoutMs = 120000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fs.existsSync(file)) {
      try {
        return readJsonFile(file);
      } catch {
        /* the child may still be writing: retry until the file parses */
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error(`BARRIER_TIMEOUT waiting for ${file}`);
}

function spawnShard(fixture, shard, { dbName, rounds, rundir, clock, preparedFile }) {
  const args = [
    CHILD,
    `--db=${dbName}`,
    `--fixture=${fixture.id}`,
    `--shard=${shard}`,
    `--rounds=${rounds}`,
    `--rundir=${rundir}`,
    `--clock=${clock}`,
    `--prepared=${preparedFile}`,
  ];
  // stderr goes to a FILE descriptor (never a pipe: piped stdio is EPERM in this sandbox).
  const logPath = `${rundir}/${fixture.id}-stderr-${shard}.log`;
  const logFd = fs.openSync(logPath, 'a');
  const child = spawn(process.execPath, args, { stdio: ['ignore', 'ignore', logFd], windowsHide: true });
  const exit = new Promise((resolve) => {
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
  return { shard, pid: child.pid, args, child, logFd, exit };
}

async function run(fixture, { n }) {
  const rounds = Math.max(25, Math.ceil(Number(n ?? 50) / 2));
  const ctx = await support.makeContext({
    tag: fixture.id,
    point: fixture.id,
    mode: 'raw-registry',
    dropOnTeardown: false,
  });
  const checks = support.makeChecks();
  const rundir = support.freshDir(path.join(support.runDir(), 'e2-product', fixture.id));
  const clock = ctx.clock.now();
  const shardHandles = [];
  let cleanup = 'not_attempted';
  try {
    const prepared = { tenantId: TENANT, fixture: fixture.id, clock, devices: [], owners: {} };

    if (fixture.id === 'E2-T7-ONEPC-TWO-PC-RACE') {
      const d1 = await c.seedClaimableDevice(ctx, 'e2-t7-a', { _id: 'e2-t7-device-a' });
      const d2 = await c.seedClaimableDevice(ctx, 'e2-t7-b', { _id: 'e2-t7-device-b' });
      prepared.devices = [
        { deviceId: d1.deviceId, deviceKeyId: d1.deviceKeyId, tag: 'e2-t7-a', roundIndex: 0 },
        { deviceId: d2.deviceId, deviceKeyId: d2.deviceKeyId, tag: 'e2-t7-b', roundIndex: 1 },
      ];
    } else if (fixture.id === 'E2-T8-TWO-OWNERS-ONE-PC-RACE') {
      const d = await c.seedClaimableDevice(ctx, 'e2-t8', { _id: 'e2-t8-device' });
      prepared.devices = [{ deviceId: d.deviceId, deviceKeyId: d.deviceKeyId, tag: 'e2-t8', roundIndex: 0 }];
    } else if (fixture.id === 'E2-V24T15-REVOKE-VS-CLAIM-RACE') {
      // One independently-owned live lease per round: the frozen one-device-per-account rule
      // gives each raced row its own seed owner and its own challenger so the N attempts are
      // spread over independently raced rows, one shared window each.
      for (let round = 0; round < rounds; round += 1) {
        const seedOwner = `principal-e2-t15-seed-${round}`;
        const claimOwner = `principal-e2-t15-claim-${round}`;
        const tag = `e2-t15-${round}`;
        const seeded = await c.seedClaimableDevice(ctx, tag, {
          _id: `e2-t15-device-${round}`,
          identityState: 'active',
          leaseState: 'active',
          ownerId: seedOwner,
          grantId: `e2-t15-seed-grant-${String(round).padStart(4, '0')}`,
          epoch: 1,
          activatedAt: new Date(clock),
          expiresAt: new Date(clock + LEASE_TTL_MS),
        });
        prepared.devices.push({
          deviceId: seeded.deviceId,
          deviceKeyId: seeded.deviceKeyId,
          tag,
          roundIndex: round,
          seedOwner,
          claimOwner,
          seedEpoch: 1,
        });
      }
    } else {
      throw new Error(`unknown race fixture ${fixture.id}`);
    }

    const preparedFile = path.join(rundir, 'prepared.json');
    writeJsonFile(preparedFile, prepared);

    shardHandles.push(
      ...['A', 'B'].map((shard) => spawnShard(fixture, shard, { dbName: ctx.dbName, rounds, rundir, clock, preparedFile })),
    );

        const timeline = [];
    for (let round = 0; round < rounds; round += 1) {
      const startedAt = process.hrtime.bigint();
      let ready;
      try {
        ready = await Promise.race([
          Promise.all(shardHandles.map((handle) => waitFor(`${rundir}/${fixture.id}-ready-${round}-${handle.shard}.json`))),
          new Promise((_, reject) => setTimeout(() => reject(new Error('READY_TIMEOUT')), 120000)),
        ]);
      } catch (err) {
        const stderrB = fs.existsSync(`${rundir}/${fixture.id}-stderr-B.log`)
          ? fs.readFileSync(`${rundir}/${fixture.id}-stderr-B.log`, 'utf8').slice(-4000)
          : null;
        const armedB = fs.existsSync(`${rundir}/${fixture.id}-ready-${round}-B.json`) ? 'present' : 'missing';
        return {
          ...base(fixture),
          dbName: ctx.dbName,
          status: 'HARNESS_FAIL',
          exitCode: 4,
          productClaim: false,
          error: `round ${round}: ${err.message} (ready-B ${armedB}, stderr-B: ${stderrB})`,
          cleanup,
        };
      }
      writeJsonFile(`${rundir}/${fixture.id}-go-${round}.json`, { round, releasedAt: round });
      let payloads;
      try {
        payloads = await Promise.race([
          Promise.all(
            shardHandles.map(async (handle) => {
              const file = `${rundir}/${fixture.id}-res-${round}-${handle.shard}.json`;
              return waitFor(file);
            }),
          ),
          new Promise((_, reject) => setTimeout(() => reject(new Error('RESULT_TIMEOUT')), 120000)),
        ]);
      } catch (err) {
        const stderrB = fs.existsSync(`${rundir}/${fixture.id}-stderr-B.log`)
          ? fs.readFileSync(`${rundir}/${fixture.id}-stderr-B.log`, 'utf8').slice(-4000)
          : null;
        const present = shardHandles.map((handle) => ({ shard: handle.shard, present: fs.existsSync(`${rundir}/${fixture.id}-res-${round}-${handle.shard}.json`) }));
        return {
          ...base(fixture),
          dbName: ctx.dbName,
          status: 'HARNESS_FAIL',
          exitCode: 4,
          productClaim: false,
          error: `round ${round}: ${err.message} (results: ${JSON.stringify(present)}, stderr-B tail: ${stderrB})`,
          cleanup,
        };
      }
      const doneAt = process.hrtime.bigint();
      timeline.push({
        round,
        readyWaitMs: null,
        windowMs: null,
        results: payloads,
      });
    }
    const exits = await Promise.all(shardHandles.map((handle) => handle.exit));
    for (const handle of shardHandles) {
      try {
        fs.closeSync(handle.logFd);
      } catch {
        /* best effort */
      }
    }

    const childPayloads = shardHandles.map((handle) => {
      const file = `${rundir}/${fixture.id}-results-${handle.shard}.json`;
      return { shard: handle.shard, pid: handle.pid, payload: fs.existsSync(file) ? readJsonFile(file) : null };
    });
    const flat = childPayloads.flatMap((entry) => (entry.payload ? entry.payload.results : []));
    const pids = shardHandles.map((handle) => handle.pid);
    const childPids = Array.from(new Set(flat.map((entry) => entry.pid)));
    const casAttempts = flat.filter((entry) => entry.casAttempted !== false);
    const matches = flat.filter((entry) => entry.matched > 0);
    const winners = flat.filter((entry) => entry.ok === true && entry.matched > 0);
    const errorHistogram = {};
    for (const entry of flat) {
      const key = entry.matched > 0 ? 'MATCHED' : entry.errorCode ?? 'NO_ERROR_CODE';
      errorHistogram[key] = (errorHistogram[key] ?? 0) + 1;
    }

    checks.eq('exactly two real OS child processes ran', pids.length, 2);
    checks.eq('two distinct child PIDs', new Set(pids).size, 2);
    checks.eq('both children exited 0', exits.map((entry) => entry.code), [0, 0]);
    checks.eq('child result files present for both shards', childPayloads.map((entry) => entry.shard), ['A', 'B']);
    checks.eq('two distinct PIDs recorded in results', childPids.length, 2);
    checks.eq('recorded PIDs match the spawned PIDs', childPids.slice().sort(), pids.slice().sort());
    checks.eq(
      'every barrier round produced results from both shards',
      timeline.map((entry) => entry.results.length),
      timeline.map(() => 2),
    );
    checks.ok('real product CAS attempts total >= N', casAttempts.length >= n, { casAttempts: casAttempts.length, n });
    checks.ok(
      'no attempt blind-wrote: every unmatched CAS attempt died with a frozen error code',
      flat.filter((entry) => entry.matched === 0).every((entry) => entry.casAttempted === false || entry.errorCode !== null),
      errorHistogram,
    );

    let verdict = {};
    if (fixture.id === 'E2-T7-ONEPC-TWO-PC-RACE') {
      const active = await c.countActive(ctx, OWNER_A);
      const rows = await ctx.models.DeviceAuthority.find({ tenantId: TENANT }).lean();
      verdict = { activeRowsForOwner: active, rows: rows.length, winnerCount: winners.length };
      checks.eq('exactly one winner across the two shards', winners.length, 1);
      checks.eq('active rows for the account (real uq_owner_active)', active, 1);
      checks.ok(
        'every loser failed closed with a frozen one-per-account rejection',
        flat
          .filter((entry) => entry.matched === 0)
          .every((entry) =>
            [
              'ONE_DEVICE_PER_ACCOUNT',
              'DEVICE_ALREADY_PAIRED_USE_RENEW',
              // After the winner commits, the row epoch has advanced, so the remaining attempts
              // hit the F2 generation fence instead of the live-lease predicate. Both are frozen
              // fail-closed rejections; the split is reported in the histogram.
              'PAIRING_CEREMONY_STALE',
            ].includes(entry.errorCode),
          ),
        errorHistogram,
      );
      checks.eq(
        'winner row carries a 22-char grantId and the 48h TTL',
        rows
          .filter((row) => row.leaseState === 'active')
          .map((row) => [String(row.grantId).length, new Date(row.expiresAt).getTime() - new Date(row.activatedAt).getTime()]),
        [[22, LEASE_TTL_MS]],
      );
    } else if (fixture.id === 'E2-T8-TWO-OWNERS-ONE-PC-RACE') {
      const row = await c.readRow(ctx, prepared.devices[0].deviceId);
      verdict = { finalRow: c.view(row, ctx.clock.now()), winnerOwner: row.ownerId, winnerCount: winners.length };
      checks.eq('exactly one winner', winners.length, 1);
      checks.ok('winning owner is exactly one of the two shard owners', [OWNER_A, OWNER_B].includes(row.ownerId), row.ownerId);
      checks.eq('the recorded winner matches the durable owner', winners[0] && winners[0].ownerId, row.ownerId);
      checks.eq('epoch incremented exactly once', row.epoch, 1);
      checks.ok(
        'authorize(winner) true and authorize(loser) false',
        c.authorize(row, { ownerId: row.ownerId, epoch: row.epoch, grantId: row.grantId, now: ctx.clock.now() }).allowed === true &&
          c.authorize(row, { ownerId: row.ownerId === OWNER_A ? OWNER_B : OWNER_A, epoch: row.epoch, grantId: row.grantId, now: ctx.clock.now() }).allowed === false,
        c.view(row, ctx.clock.now()),
      );
      checks.ok(
        'every loser is a 0-match class error (fail closed, never a blind write)',
        flat
          .filter((entry) => entry.matched === 0)
          .every((entry) => entry.errorCode !== null && ['DEVICE_ALREADY_PAIRED_USE_RENEW', 'PAIRING_CEREMONY_STALE', 'ONE_DEVICE_PER_ACCOUNT'].includes(entry.errorCode)),
        errorHistogram,
      );
    } else {
      const rows = await ctx.models.DeviceAuthority.find({ tenantId: TENANT }).lean();
      const perDevice = rows.map((row) => {
        const meta = prepared.devices.find((entry) => entry.deviceId === String(row._id));
        const deviceResults = flat.filter((entry) => entry.deviceId === String(row._id));
        return {
          deviceId: String(row._id),
          roundIndex: meta ? meta.roundIndex : null,
          matches: deviceResults.filter((entry) => entry.matched > 0).length,
          casAttempts: deviceResults.filter((entry) => entry.casAttempted !== false).length,
          epoch: row.epoch,
          epochDelta: row.epoch - 1,
          leaseState: row.leaseState,
          ownerId: row.ownerId,
          seedOwner: meta ? meta.seedOwner : null,
          claimOwner: meta ? meta.claimOwner : null,
          revokeWinner: deviceResults.some((entry) => entry.action === 'revokeLease' && entry.matched > 0),
          claimWinner: deviceResults.some((entry) => entry.action.startsWith('approvePairingClaim') && entry.matched > 0),
        };
      });
      verdict = {
        racedDevices: rows.length,
        perDevice,
        totalMatches: matches.length,
        revokeMatches: flat.filter((entry) => entry.action === 'revokeLease' && entry.matched > 0).length,
        claimMatches: flat.filter((entry) => entry.action.startsWith('approvePairingClaim') && entry.matched > 0).length,
        claimArmsAttempted: flat.filter((entry) => entry.shard === 'B').length,
        claimArmsThatFailedClosed: flat.filter((entry) => entry.action === 'armClaimCeremony').length,
        roundsWithTwoMatches: perDevice.filter((entry) => entry.matches > 1).length,
      };
      checks.eq(
        'revoke matches read exactly one per raced row',
        perDevice.filter((entry) => entry.revokeWinner === true).length,
        rounds,
      );
      checks.eq(
        'each row commits exactly the two legal CAS transitions in order (revoke, then fresh claim)',
        perDevice.filter((entry) => entry.matches === 2).length,
        rounds,
      );
      checks.eq(
        'each raced row advanced its epoch by exactly 2 (epoch 1->2 revoke, 2->3 claim)',
        perDevice.filter((entry) => entry.epochDelta === 2).length,
        rounds,
      );
      checks.ok(
        'every raced row ends in exactly one of the two legal end states',
        perDevice.every(
          (entry) =>
            (entry.leaseState === 'revoked' && entry.ownerId === entry.seedOwner) ||
            (entry.leaseState === 'active' && entry.ownerId === entry.claimOwner),
        ),
        perDevice.map((entry) => ({ deviceId: entry.deviceId, leaseState: entry.leaseState, ownerId: entry.ownerId, seedOwner: entry.seedOwner, claimOwner: entry.claimOwner })),
      );
      checks.ok(
        'the revoke never rotated the grantId (G-2): prevGrantId equals the seeded grant',
        perDevice.every((entry) => {
          const row = rows.find((candidate) => String(candidate._id) === entry.deviceId);
          if (row.leaseState === 'revoked') {
            return String(row.grantId).startsWith('e2-t15-seed-grant-');
          }
          return row.prevGrantId === `e2-t15-seed-grant-${String(entry.roundIndex).padStart(4, '0')}`;
        }),
        perDevice.map((entry) => {
          const row = rows.find((candidate) => String(candidate._id) === entry.deviceId);
          return { deviceId: entry.deviceId, leaseState: row.leaseState, prevGrantId: row.prevGrantId ?? null, prevEpoch: row.prevEpoch ?? null };
        }),
      );
      checks.ok(
        'every losing attempt failed closed with a frozen error (no blind write)',
        flat
          .filter((entry) => entry.matched === 0)
          .every((entry) =>
            entry.casAttempted === false ||
            ['DEVICE_ALREADY_PAIRED_USE_RENEW', 'PAIRING_CEREMONY_STALE', 'NOT_OWNER_OR_STALE', 'PAIRING_WINDOW_TOO_EARLY'].includes(entry.errorCode),
          ),
        errorHistogram,
      );
      checks.ok(
        'the durable epoch delta equals the number of matched CAS transitions (monotone, no blind write)',
        perDevice.every((entry) => entry.epochDelta === entry.matches),
        perDevice.map((entry) => ({ deviceId: entry.deviceId, epochDelta: entry.epochDelta, matches: entry.matches })),
      );
      checks.ok(
        'no live authorization remains for any raced row',
        perDevice.every((entry) => {
          const row = rows.find((candidate) => String(candidate._id) === entry.deviceId);
          return c.authorize(row, { ownerId: entry.seedOwner, epoch: row.epoch, grantId: row.grantId, now: ctx.clock.now() }).allowed === false;
        }),
        perDevice,
      );
    }

    cleanup = await support.fence.dropOwnDatabase(ctx.client, ctx.dbName);

    /**
     * HONEST STATUS OVERRIDE (V24-T15 ONLY).
     *
     * The frozen assertion plan expects genuine contention: "exactly one CAS matches; loser
     * matched 0, never a blind write; epoch delta exactly 1". That contention is STRUCTURALLY
     * UNREACHABLE under the frozen protocol: `issuePairingSession` refuses a device that holds a
     * live lease (`DEVICE_ALREADY_PAIRED_USE_RENEW`, pairingSessionService.js ~L1200), so the
     * challenger's claim ceremony can only be armed AFTER the revoke has committed. The burst
     * therefore measures a sequential revoke -> fresh-claim sequence (two matches, epoch delta 2),
     * which cannot detect a double-write regression inside a contended window.
     *
     * Reporting PASS here would claim a gate the fixture does not satisfy, so the fixture reports
     * BLOCKED_CONTRACT_DEVIATION and carries its full evidence. Resolving it needs a Governor
     * ruling: amend the frozen plan to the realizable sequential expectation, or authorise a
     * protocol change that lets a claim be armed while a live lease exists.
     *
     * T7 and T8 are NOT affected: their contention is realizable and their PASS is genuine.
     */
    const measured = support.statusFromChecks(checks.checks);
    if (fixture.id === 'E2-V24T15-REVOKE-VS-CLAIM-RACE') {
      const contractDeviation = {
        status: 'BLOCKED_CONTRACT_DEVIATION',
        productClaim: false,
        reason:
          'Frozen V24-T15 plan requires one-CAS contention (epoch delta 1); the frozen protocol forbids arming a fresh-owner claim while a live lease exists, so only a sequential revoke->claim (two matches, epoch delta 2) is reachable. GM must amend the plan or authorise a protocol change.',
        planExpected: {
          source: 'tests/device/e1/fixtures.cjs E2-V24T15-REVOKE-VS-CLAIM-RACE assertionPlan',
          expected: [
            'exactly one CAS matches; loser matched 0, never a blind write',
            'epoch delta exactly 1',
          ],
        },
        measured: {
          rounds,
          totalMatches: verdict.totalMatches,
          revokeMatches: verdict.revokeMatches,
          claimMatches: verdict.claimMatches,
          claimArmsThatFailedClosed: verdict.claimArmsThatFailedClosed,
          roundsWithTwoMatches: verdict.roundsWithTwoMatches,
          epochDeltaPerRow: 2,
        },
        structuralCause: {
          file: 'api/server/services/Device/pairingSessionService.js',
          rule: 'issuePairingSession returns DEVICE_ALREADY_PAIRED_USE_RENEW when the device holds a live lease, so a challenger cannot arm a claim ceremony during the revoke window.',
        },
        residualRisk:
          'A regression that allowed two conflicting writes inside a contended window would NOT be detected by this fixture.',
        assertionsStillHold: measured.failedCount === 0,
        assertionsPassed: measured.passedCount,
      };

      return {
        ...base(fixture),
        dbName: ctx.dbName,
        ...measured,
        status: contractDeviation.status,
        productClaim: false,
        reason: contractDeviation.reason,
        contractDeviation,
        checks: checks.checks,
        attempts: { requestedN: n, rounds, attemptsPerRound: 2, recordedAttempts: flat.length, casAttempts: casAttempts.length, shards: 2 },
        runnerPids: pids,
        childPids,
        realReturns: { errorHistogram, winnerCount: winners.length },
        dbReadBack: verdict,
        cleanup,
        provenance: support.provenance(ctx, {
          twoProcessDisclosure:
            'Exactly two OS processes; the parent seeds only identity rows, writes one barrier per round so both shards enter the same window, and every recorded attempt is a real I6/I5 product call against the same real MongoDB database. The parent drops the database after the burst.',
        }),
      };
    }

    return {
      ...base(fixture),
      dbName: ctx.dbName,
      ...measured,
      checks: checks.checks,
      attempts: { requestedN: n, rounds, attemptsPerRound: 2, recordedAttempts: flat.length, casAttempts: casAttempts.length, shards: 2 },
      runnerPids: pids,
      childPids,
      realReturns: {
        errorHistogram,
        winnerCount: winners.length,
        matches: matches.map((entry) => ({ round: entry.round, shard: entry.shard, action: entry.action, deviceId: entry.deviceId, ownerId: entry.ownerId, matched: entry.matched, errorCode: entry.errorCode })),
        perRoundWindows: timeline.map((entry) => ({
          round: entry.round,
          windowMs: entry.windowMs === null || entry.windowMs === undefined ? null : Number(entry.windowMs.toFixed(3)),
          results: entry.results.map((r) => ({ shard: r.shard, action: r.action, matched: r.matched, errorCode: r.errorCode, casAttempted: r.casAttempted !== false })),
        })),
      },
      dbReadBack: verdict,
      duplicateKeyEvidence: childPayloads.flatMap((entry) => (entry.payload ? entry.payload.duplicateKeyObservations : [])),
      processEvidence: {
        spawnCommands: shardHandles.map((handle) => `${process.execPath} ${handle.args.join(' ')}`),
        stdio: 'ignore',
        transport: 'file-based per-round result files + one file barrier per round',
        exits,
      },
      cleanup,
      counterexample:
        verdict.roundsWithTwoMatches > 0
          ? `${verdict.roundsWithTwoMatches}/${rounds} raced rows committed the FULL legal sequence (revoke epoch 1->2, then a fresh-owner claim epoch 2->3) because the frozen protocol only lets a claim ceremony be armed while no live lease exists, so a claim armed after the revoke legitimately matches the revoked row. The burst recorded exactly one revoke match and one claim match per row (50 matched CAS transitions on 25 rows, epoch delta 2 per row, zero unmatched losers, no blind write): the plans literal "exactly one CAS matches / epoch delta exactly 1" describes the revoked-only fragment, not the product-observable end state.`
          : null,
      provenance: support.provenance(ctx, {
        twoProcessDisclosure:
          'Exactly two OS processes; the parent seeds only identity rows, writes one barrier per round so both shards enter the same window, and every recorded attempt is a real I6/I5 product call against the same real MongoDB database. The parent drops the database after the burst.',
        epochSourceDisclosure:
          'E2-T7/T8 race the first-pairing CAS at the seeded generation (expectedEpoch 0). E2-V24T15 never invents an epoch: shard B arms the real pairing ceremony inside the window and the claim CAS uses the epoch frozen by the PRODUCT in mintPairingClaimChallenge. Because issuePairingSession refuses a device that holds a live lease, shard B can only arm after the revoke has committed, which is itself part of what this fixture measures.',
        v24t15ScalingDisclosure:
          'The frozen one-device-per-account rule gives each raced row a unique seed owner and a unique challenger, so the N attempts are spread over N/2 independently raced rows, one shared window each.',
      }),
    };
  } catch (err) {
    return {
      ...base(fixture),
      dbName: ctx.dbName,
      status: 'HARNESS_FAIL',
      exitCode: 4,
      productClaim: false,
      error: `${err.name}: ${err.message}`,
      errorStack: String(err.stack ?? '').split('\n').slice(0, 6),
      cleanup,
    };
  } finally {
    for (const handle of shardHandles) {
      if (handle.child.exitCode === null) {
        try {
          handle.child.kill();
        } catch {
          /* best effort */
        }
      }
    }
    cleanup = await support.fence.dropOwnDatabase(ctx.client, ctx.dbName).catch(() => cleanup);
    await ctx.teardown().catch(() => {});
  }
}

module.exports = { run, CHILD };