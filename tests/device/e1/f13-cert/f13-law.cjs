'use strict';

/**
 * F13 sessionVersion ABA — two-OS-process LAW evaluation (test-only, NEW FILE).
 *
 *   node tests/device/e1/f13-cert/f13-law.cjs --rounds=25
 *
 * The existing T0A-01 row records that two processes run and that composition is accepted, but
 * its F13 oracle components are hardcoded `met:false` ("not executed"). This fixture actually
 * EVALUATES the same frozen law, with real ceremonies and a real falsification path:
 *
 *   F13: sessionVersion monotonically fences transitions; issuance may supersede a state:open
 *        session only; an approval that observed version v either consumes v exactly once or
 *        0-matches; issuance never flips the same v after approval has observed it.
 *        Two real OS processes, N>=50 attempts.
 *
 * Per round the parent:
 *   1. seeds a claimable device (its own round owner, so `uq_owner_active` is never contended),
 *   2. arms the REAL ceremony through product bytes only until the session is `claim_pending`
 *      at version v = 1 (mint open challenge -> issue -> redeem -> mint claim challenge),
 *   3. releases both children inside one file-barrier window:
 *        role A  `issuePairingSession` for the SAME device (an issuance that, pre-repair, would
 *                have superseded the in-flight `claim_pending` session),
 *        role B  `approvePairingClaim` with the real claim proof armed at v.
 *
 * Falsification path (why this is not vacuous): if issuance ever supersedes or bumps a
 * `claim_pending` session, the armed claim challenge no longer binds `boundSessionVersion: v`,
 * so role B's approval 0-matches and the session ends `superseded` instead of `consumed` — the
 * per-round assertions below fail.
 */

const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const support = require('../w3a/support.cjs');
const env = require('../w3a/env.cjs');

const TENANT = env.TENANT;
const CHILD = path.resolve(__dirname, 'f13-law-child.cjs');
const CHILD_TIMEOUT_MS = 240000;
const ROUND_TIMEOUT_MS = 120000;

function spawnChild({ role, dbName, rundir, rounds, clock, preparedFile }) {
  const args = [
    CHILD,
    `--role=${role}`,
    `--db=${dbName}`,
    `--rundir=${rundir}`,
    `--rounds=${rounds}`,
    `--clock=${clock}`,
    `--prepared=${preparedFile}`,
  ];
  const logFd = fs.openSync(path.join(rundir, `f13law-stderr-${role}.log`), 'a');
  const child = spawn(process.execPath, args, {
    stdio: ['ignore', 'ignore', logFd],
    windowsHide: true,
    cwd: env.WORKTREE,
  });
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
  return { role, pid: child.pid, args, child, logFd, exit };
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  fs.renameSync(tmp, file);
}

async function waitForJson(file, timeoutMs = ROUND_TIMEOUT_MS) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fs.existsSync(file)) {
      try {
        return JSON.parse(fs.readFileSync(file, 'utf8'));
      } catch {
        /* retry until the atomic publish completes */
      }
    }
    // eslint-disable-next-line no-await-in-loop
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error(`ROUND_TIMEOUT waiting for ${file}`);
}

async function run({ rounds = 25 } = {}) {
  const checks = support.makeChecks();
  const rundir = support.freshDir(path.join(support.runDir(), 'f13-law'));
  const ctx = await support.makeContext({
    tag: 'f13law',
    point: 'F13-SESSIONVERSION-ABA',
    mode: 'raw-registry',
    dropOnTeardown: false,
  });
  const clock = ctx.clock.now();
  const pairing = ctx.pairingService();
  const children = [];
  let cleanup = 'not_attempted';

  try {
    /* ---------------------------------------------------------------- arm 25 rounds */
    const plan = { rounds: [], clock, tenantId: TENANT };
    for (let round = 0; round < rounds; round += 1) {
      const deviceTag = `f13law-d${round + 1}`;
      const key = env.makeDeviceKey(deviceTag);
      const ownerId = `principal-f13-owner-${round + 1}`;
      const seeded = await support.seedDevice(ctx, deviceTag, {
        _id: `f13law-device-${round + 1}`,
        identityState: 'pending',
        leaseState: 'never',
        epoch: 0,
        ownerId: null,
        grantId: null,
      });
      const openChallenge = await pairing.mintPairingOpenChallenge({
        tenantId: TENANT,
        deviceId: seeded.deviceId,
        deviceKeyId: seeded.deviceKeyId,
      });
      if (!openChallenge.ok) throw new Error(`round ${round}: mint open challenge failed`);
      const issue = await pairing.issuePairingSession({
        tenantId: TENANT,
        deviceId: seeded.deviceId,
        deviceKeyId: seeded.deviceKeyId,
        domainTag: env.constants.PAIRING_OPEN_DOMAIN,
        requestSource: 'f13-law-arm',
        challengeHash: openChallenge.challengeHash,
        proof: support.pairingOpenProof(ctx, {
          deviceId: seeded.deviceId,
          deviceKeyId: seeded.deviceKeyId,
          key,
          challengeHash: openChallenge.challengeHash,
          issuedAt: openChallenge.issuedAt,
        }),
      });
      if (!issue.ok) throw new Error(`round ${round}: issue failed (${issue.error ? issue.error.code : 'n/a'})`);
      const redeem = await pairing.redeemPairingCode({ code: issue.code, tenantId: TENANT, ownerId });
      if (!redeem.ok) throw new Error(`round ${round}: redeem failed (${redeem.error ? redeem.error.code : 'n/a'})`);
      const sessionId = String(redeem.pairingSession._id);
      const claimChallenge = await pairing.mintPairingClaimChallenge({
        pairingSessionId: sessionId,
        tenantId: TENANT,
        ownerId,
      });
      if (!claimChallenge.ok) throw new Error(`round ${round}: mint claim challenge failed`);
      const armed = await ctx.models.PairingSession.findOne({ _id: sessionId, tenantId: TENANT }).lean();
      if (armed === null || armed.state !== 'claim_pending') {
        throw new Error(`round ${round}: armed session is not claim_pending (${armed ? armed.state : 'absent'})`);
      }
      plan.rounds.push({
        round,
        deviceId: seeded.deviceId,
        deviceTag,
        deviceKeyId: seeded.deviceKeyId,
        ownerId,
        sessionId,
        armedState: armed.state,
        armedVersion: armed.sessionVersion ?? null,
        armedExpectedEpoch: armed.claim ? armed.claim.expectedEpoch ?? null : null,
        claimChallengeHash: claimChallenge.challengeHash,
        claimChallengeIssuedAt: claimChallenge.issuedAt,
      });
    }
    const preparedFile = path.join(rundir, 'f13law-prepared.json');
    writeJson(preparedFile, plan);

    /* ---------------------------------------------------------------- two real OS processes */
    for (const role of ['A', 'B']) {
      children.push(spawnChild({ role, dbName: ctx.dbName, rundir, rounds, clock, preparedFile }));
    }

    const roundRecords = [];
    for (let round = 0; round < rounds; round += 1) {
      const ready = await Promise.all(
        children.map((handle) => waitForJson(path.join(rundir, `f13law-ready-${round}-${handle.role}.json`))),
      );
      writeJson(path.join(rundir, `f13law-go-${round}.json`), { round, releasedBy: process.pid });
      const results = await Promise.all(
        children.map((handle) => waitForJson(path.join(rundir, `f13law-res-${round}-${handle.role}.json`))),
      );
      roundRecords.push({
        round,
        armedVersion: plan.rounds[round].armedVersion,
        observedAtBarrier: ready.map((entry) => ({ role: entry.role, pid: entry.pid, ...entry.observedAtBarrier })),
        byRole: results.map((entry) => ({ action: entry.action, ok: entry.ok, errorCode: entry.errorCode })),
      });
    }

    const exits = await Promise.all(children.map((handle) => handle.exit));
    for (const handle of children) {
      try {
        fs.closeSync(handle.logFd);
      } catch {
        /* best effort */
      }
    }
    const childReports = children.map((handle) => {
      const file = path.join(rundir, `f13law-results-${handle.role}.json`);
      return {
        role: handle.role,
        spawnPid: handle.pid,
        exit: exits[children.indexOf(handle)],
        payload: fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : null,
      };
    });
    const flat = childReports.flatMap((entry) => (entry.payload ? entry.payload.results : []));
    const issuanceRecords = flat.filter((entry) => entry.action === 'issuePairingSession');
    const approvalRecords = flat.filter((entry) => entry.action === 'approvePairingClaim');

    /* ---------------------------------------------------------------- durable read-back */
    const sessionsAfter = [];
    const authoritiesAfter = [];
    for (const planned of plan.rounds) {
      // eslint-disable-next-line no-await-in-loop
      const session = await ctx.models.PairingSession.findOne({ _id: planned.sessionId, tenantId: TENANT }).lean();
      // eslint-disable-next-line no-await-in-loop
      const authority = await ctx.models.DeviceAuthority.findOne({ _id: planned.deviceId, tenantId: TENANT }).lean();
      // eslint-disable-next-line no-await-in-loop
      const allSessions = await ctx.models.PairingSession.find({ deviceId: planned.deviceId, tenantId: TENANT }).lean();
      sessionsAfter.push({
        round: planned.round,
        deviceId: planned.deviceId,
        sessionId: planned.sessionId,
        armedVersion: planned.armedVersion,
        state: session ? session.state : null,
        sessionVersion: session && Number.isInteger(session.sessionVersion) ? session.sessionVersion : null,
        sessionsForDevice: allSessions.map((row) => ({
          _id: String(row._id),
          state: row.state,
          sessionVersion: Number.isInteger(row.sessionVersion) ? row.sessionVersion : null,
        })),
      });
      authoritiesAfter.push({
        round: planned.round,
        deviceId: planned.deviceId,
        ownerId: authority ? authority.ownerId : null,
        leaseState: authority ? authority.leaseState : null,
        identityState: authority ? authority.identityState : null,
        epoch: authority ? authority.epoch : null,
        grantIdIssued: Boolean(authority && typeof authority.grantId === 'string' && authority.grantId.length > 0),
        grantedByPairingSessionId: authority ? authority.grantedByPairingSessionId ?? null : null,
        ttlMs:
          authority && authority.expiresAt && authority.activatedAt
            ? new Date(authority.expiresAt).getTime() - new Date(authority.activatedAt).getTime()
            : null,
      });
    }

    /* ---------------------------------------------------------------- assertions */
    const pids = children.map((handle) => handle.pid);
    const reportedPids = flat.map((entry) => entry.pid);
    checks.eq('exactly two real OS child processes ran', pids.length, 2);
    checks.eq('two distinct child PIDs', new Set(pids).size, 2);
    checks.eq('both children exited 0', exits.map((entry) => entry.code), [0, 0]);
    checks.eq(
      'recorded PIDs match the spawned PIDs',
      Array.from(new Set(reportedPids)).sort(),
      pids.slice().sort(),
    );
    checks.eq('every round produced results from both shards', roundRecords.map((entry) => entry.byRole.length), roundRecords.map(() => 2));
    checks.ok('real product attempts total >= N', flat.length >= rounds * 2, { attempts: flat.length, expected: rounds * 2 });
    checks.eq(
      'every child observed the armed session at the armed version before acting',
      roundRecords.flatMap((entry) => entry.observedAtBarrier).map((entry) => [entry.state, entry.sessionVersion]),
      roundRecords.flatMap((entry) => [
        ['claim_pending', entry.armedVersion],
        ['claim_pending', entry.armedVersion],
      ]),
    );

    /* F13 law: issuance may supersede a state:open session only. */
    const supersededSessions = sessionsAfter.flatMap((entry) =>
      entry.sessionsForDevice.filter((row) => row.state === 'superseded'),
    );
    checks.eq(
      'F13: no round left a superseded session (issuance never superseded a claim_pending session)',
      supersededSessions.length,
      0,
    );

    /* F13 law: an approval that observed version v consumes v exactly once or 0-matches. */
    checks.eq(
      'F13: every armed claim_pending session ends consumed, with the version strictly advanced from the armed value',
      sessionsAfter.map((entry) => [
        entry.state,
        entry.sessionVersion !== null && entry.sessionVersion > entry.armedVersion,
      ]),
      sessionsAfter.map(() => ['consumed', true]),
    );
    checks.eq(
      'F13: the consume/grant path advances the session version by exactly the observed two bumps (no re-consume)',
      sessionsAfter.map((entry) => entry.sessionVersion),
      sessionsAfter.map((entry) => entry.armedVersion + 2),
    );
    checks.eq(
      'F13: the approval leg succeeded in every round (a v-bound approval was never 0-matched by an issuance)',
      approvalRecords.map((entry) => entry.ok),
      approvalRecords.map(() => true),
    );
    checks.eq(
      'the consumed sessions are exactly the 25 armed sessions, once each',
      new Set(sessionsAfter.map((entry) => entry.sessionId)).size,
      rounds,
    );

    /* F13 law: issuance never flips the same v after approval has observed it. */
    checks.eq(
      'F13: the issuance leg never reported a supersede of an in-flight claim (only ok or a live-lease refusal)',
      issuanceRecords.filter((entry) => !(entry.ok === true || entry.errorCode === 'DEVICE_ALREADY_PAIRED_USE_RENEW')).map((entry) => entry.errorCode),
      [],
    );
    checks.ok(
      'the issuance leg really attempted a supersede-capable call in every round',
      issuanceRecords.length === rounds,
      { issuanceAttempts: issuanceRecords.length, rounds },
    );
    checks.eq(
      'every session row for every device carries a non-negative integer sessionVersion',
      sessionsAfter
        .flatMap((entry) => entry.sessionsForDevice)
        .filter((row) => !Number.isInteger(row.sessionVersion) || row.sessionVersion < 0)
        .map((row) => row._id),
      [],
    );

    /* Durable authority outcome: exactly one live lease per round device, bound to that round. */
    checks.eq(
      'every round device holds exactly one active lease owned by its round owner',
      authoritiesAfter.map((entry) => [entry.leaseState, entry.ownerId]),
      authoritiesAfter.map((entry) => ['active', `principal-f13-owner-${entry.round + 1}`]),
    );
    checks.eq(
      'every granted lease is exactly 48 h and epoch 1 (one grant, no re-grant)',
      authoritiesAfter.map((entry) => [entry.ttlMs, entry.epoch, entry.grantIdIssued]),
      authoritiesAfter.map(() => [172800000, 1, true]),
    );
    checks.eq(
      'each grant records the session that granted it',
      authoritiesAfter.map((entry) => entry.grantedByPairingSessionId),
      sessionsAfter.map((entry) => entry.sessionId),
    );

    const measured = support.statusFromChecks(checks.checks);
    cleanup = await support.fence.dropOwnDatabase(ctx.client, ctx.dbName);

    return {
      id: 'F13-LAW-SESSIONVERSION-ABA-TWO-PROCESS',
      contractRef: 'F13/F18-A (law evaluation; supplements T0A-01)',
      tier: 'E2',
      kind: 'product',
      title:
        'F13 sessionVersion ABA fence evaluated with two real OS processes, real ceremonies and N>=50 attempts',
      runnerPid: process.pid,
      productClaim: true,
      ...measured,
      checks: checks.checks,
      attempts: {
        requestedN: rounds * 2,
        rounds,
        attemptsPerRound: 2,
        recordedAttempts: flat.length,
        issuanceAttempts: issuanceRecords.length,
        approvalAttempts: approvalRecords.length,
      },
      runnerPids: pids,
      childPids: pids,
      dbName: ctx.dbName,
      realReturns: {
        issuanceOutcomes: issuanceRecords.map((entry) => ({ round: entry.round, ok: entry.ok, errorCode: entry.errorCode, codeIssued: entry.codeIssued })),
        approvalOutcomes: approvalRecords.map((entry) => ({ round: entry.round, ok: entry.ok, errorCode: entry.errorCode, grantedEpoch: entry.grantedEpoch })),
        supersededSessionCount: supersededSessions.length,
      },
      dbReadBack: { sessionsAfter, authoritiesAfter },
      processEvidence: {
        spawnCommands: children.map((handle) => `${process.execPath} ${handle.args.join(' ')}`),
        stdio: 'ignore + stderr to file',
        transport: 'one file barrier per round + per-round result files',
        exits,
      },
      childReports: childReports.map((entry) => ({
        role: entry.role,
        spawnPid: entry.spawnPid,
        reportedPid: entry.payload ? entry.payload.pid : null,
        attempts: entry.payload ? entry.payload.attempts : null,
        fatal: entry.payload ? entry.payload.fatal : 'no payload',
        exit: entry.exit,
      })),
      cleanup,
      provenance: support.provenance(ctx, {
        lawDisclosure:
          'The armed claim challenge binds boundSessionVersion = the observed version v, so the approval 0-matches if any other writer flips v. The issuance leg is a genuine supersede-capable call on the same device inside the same window.',
        nonVacuityDisclosure:
          'Falsification path: a pre-repair supersede that matched state $in [open, claim_pending] would flip the armed session to superseded and make the v-bound approval 0-match, failing the "every armed session ends consumed" and "no superseded session" assertions.',
        secretsDisclosure:
          'Minted codes are never recorded; only codeIssued / digit counts and signature presence.',
      }),
    };
  } catch (err) {
    return {
      id: 'F13-LAW-SESSIONVERSION-ABA-TWO-PROCESS',
      contractRef: 'F13/F18-A (law evaluation; supplements T0A-01)',
      tier: 'E2',
      kind: 'product',
      runnerPid: process.pid,
      productClaim: false,
      status: 'HARNESS_FAIL',
      exitCode: 4,
      checks: checks.checks,
      error: `${err.name}: ${err.message}`,
      errorStack: String(err.stack ?? '').split('\n').slice(0, 8),
      dbName: ctx.dbName,
      cleanup,
    };
  } finally {
    for (const handle of children) {
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

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith('--')) continue;
    const [flag, inline] = arg.includes('=') ? arg.split(/=(.*)/s, 2) : [arg, null];
    const value = inline !== null ? inline : argv[index + 1];
    options[flag.slice(2)] = value === undefined ? true : value;
    if (inline === null) index += 1;
  }
  return options;
}

if (require.main === module) {
  const options = parseArgs(process.argv.slice(2));
  const rounds = Number(options.rounds ?? 25);
  run({ rounds }).then(
    (report) => {
      process.stdout.write(`${JSON.stringify(report)}\n`);
      process.exitCode = report.exitCode ?? (report.status === 'PASS' ? 0 : 5);
    },
    (err) => {
      process.stdout.write(`${JSON.stringify({ id: 'F13-LAW-SESSIONVERSION-ABA-TWO-PROCESS', status: 'HARNESS_FAIL', error: err.message })}\n`);
      process.exitCode = 4;
    },
  );
}

module.exports = { run, CHILD };