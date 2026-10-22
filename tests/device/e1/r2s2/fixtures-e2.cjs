'use strict';

/**
 * W3-B R2 S2-T E2 row S2T-03 (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * S2T-03 — same-generation competing operations constructed to falsify the generation fence.
 *
 * Fixture specification (one frozen generation g = 0):
 *   - row X starts as a LIVE active lease at g. Its legitimate transition budget is EXACTLY ONE:
 *     the single generation-changing `revokeLease(epoch=g)`.
 *   - row Y starts claimable ('never') at g. Its legitimate transition budget is EXACTLY ONE claim.
 *   - every claim in the fixture carries the same frozen `expectedEpoch = g`; the revoke carries
 *     `epoch = g`. Losers must be 0-match / fail-closed.
 *
 * Two independent OS processes, a four-phase file barrier, and 54 real product invocations total.
 * Raw per-process stdout/stderr is redirected to files (no piped stdio) and gathered by the parent.
 */

const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const { env, fence, ledger, w3a } = require('./harness.cjs');

const { STATUS } = ledger;

const CHILD = path.join(__dirname, 'child-e2.cjs');
const ROW_X = 's2t-03-race-row-x';
const ROW_Y = 's2t-03-race-row-y';
const CLAIMS_PHASE_A = 16;
const CLAIMS_PHASE_C = 9;
const MIN_TOTAL_ATTEMPTS = 50;
const BARRIER_TIMEOUT_MS = 30000;
const CHILD_TIMEOUT_MS = 300000;

function waitForExit(child, timeoutMs) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      child.kill();
      resolve({ timedOut: true, code: null, signal: 'SIGKILL_BY_PARENT_TIMEOUT' });
    }, timeoutMs);
    child.on('exit', (code, signal) => {
      clearTimeout(timer);
      resolve({ timedOut: false, code, signal });
    });
    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({ timedOut: false, spawnError: `${err.name}: ${err.message}` });
    });
  });
}

async function prepareDatabase(dbName, clock) {
  const { client, topology } = await fence.connectGuarded({
    dbName,
    appName: 'cbhr-r2-s2t-e2-prep',
  });
  try {
    const loaded = env.loadRegistry();
    const models = {
      DeviceAuthority: loaded.registry.DeviceAuthority,
      PairingSession: loaded.registry.PairingSession,
      Challenge: loaded.registry.Challenge,
      AuditEvent: loaded.registry.AuditEvent,
    };
    await env.connectMongoose({ uri: fence.FROZEN_URI, dbName, appName: 'cbhr-r2-s2t-e2-prep' });
    const syncReport = await env.syncDeclaredIndexes(models);
    const now = clock.now();
    const rows = [
      {
        _id: ROW_X,
        tenantId: w3a.TENANT,
        deviceKeyId: `key-${ROW_X}`,
        devicePublicKey: w3a.labKey.spkiB64u,
        identityState: 'active',
        leaseState: 'active',
        epoch: 0,
        ownerId: w3a.OWNER_A,
        grantId: 's2t-03-x-grant-0',
        activatedAt: new Date(now - 60000),
        expiresAt: new Date(now + 172800000),
        retiredAt: null,
        retiredBy: null,
        revokedAt: null,
        revokedBy: null,
        renewalCount: 0,
        renewedAt: null,
        grantedByPairingSessionId: null,
        grantProof: null,
        prevOwner: null,
        prevGrantId: null,
        prevEpoch: null,
      },
      {
        _id: ROW_Y,
        tenantId: w3a.TENANT,
        deviceKeyId: `key-${ROW_Y}`,
        devicePublicKey: w3a.labKey.spkiB64u,
        identityState: 'pending',
        leaseState: 'never',
        epoch: 0,
        ownerId: null,
        grantId: null,
        activatedAt: null,
        expiresAt: null,
        retiredAt: null,
        retiredBy: null,
        revokedAt: null,
        revokedBy: null,
        renewalCount: 0,
        renewedAt: null,
        grantedByPairingSessionId: null,
        grantProof: null,
        prevOwner: null,
        prevGrantId: null,
        prevEpoch: null,
      },
    ];
    const created = await models.DeviceAuthority.create(rows, { writeConcern: env.WRITE_CONCERN });
    return {
      topology,
      syncReport,
      seededIds: created.map((doc) => String(doc._id)),
      registryShape: Object.fromEntries(
        Object.entries(loaded.shape).map(([key, value]) => [key, value.typeofModel]),
      ),
    };
  } finally {
    await w3a.mongoose.disconnect().catch(() => {});
    await client.close().catch(() => {});
  }
}

function classifyAttempts(attempts) {
  const byPhase = {};
  let winners = 0;
  let losers = 0;
  let matchedAboveZeroLosers = 0;
  let pairingCeremonyStaleResponses = 0;
  for (const attempt of attempts) {
    const bucket = byPhase[attempt.phase] ?? { attempts: 0, winners: 0, losers: 0 };
    bucket.attempts += 1;
    if (attempt.matched === 1) {
      bucket.winners += 1;
      winners += 1;
    } else {
      bucket.losers += 1;
      losers += 1;
      if (typeof attempt.matched === 'number' && attempt.matched > 1) {
        matchedAboveZeroLosers += 1;
      }
    }
    if (attempt.errorCode === 'PAIRING_CEREMONY_STALE') {
      pairingCeremonyStaleResponses += 1;
    }
    byPhase[attempt.phase] = bucket;
  }
  return { byPhase, winners, losers, matchedAboveZeroLosers, pairingCeremonyStaleResponses };
}

async function runS2T03() {
  const clock = w3a.makeClock();
  const dbName = fence.createDbName('s2t03samegenerationrace');
  const fenceProblems = fence.checkDbName(dbName);
  if (fenceProblems.length > 0) {
    throw new fence.S2TFenceViolation(fenceProblems, { dbName, phase: 'e2-pre-connect' });
  }

  const barrierDir = path.join(ledger.ARTIFACT_DIR, 'S2T-03-barrier');
  fs.rmSync(barrierDir, { recursive: true, force: true });
  fs.mkdirSync(barrierDir, { recursive: true });
  ledger.ensureDir(ledger.ARTIFACT_DIR);

  const prep = await prepareDatabase(dbName, clock);
  const outFiles = {
    A: path.join(barrierDir, 'out-A.json'),
    B: path.join(barrierDir, 'out-B.json'),
  };
  const logFiles = {
    A: {
      stdout: path.join(ledger.ARTIFACT_DIR, 'S2T-03-A.stdout.log'),
      stderr: path.join(ledger.ARTIFACT_DIR, 'S2T-03-A.stderr.log'),
    },
    B: {
      stdout: path.join(ledger.ARTIFACT_DIR, 'S2T-03-B.stdout.log'),
      stderr: path.join(ledger.ARTIFACT_DIR, 'S2T-03-B.stderr.log'),
    },
  };

  const children = [];
  for (const role of ['A', 'B']) {
    const stdoutFd = fs.openSync(logFiles[role].stdout, 'w');
    const stderrFd = fs.openSync(logFiles[role].stderr, 'w');
    const child = spawn(
      process.execPath,
      [
        CHILD,
        '--role',
        role,
        '--db',
        dbName,
        '--barrier',
        barrierDir,
        '--out',
        outFiles[role],
        '--claimsA',
        String(CLAIMS_PHASE_A),
        '--claimsC',
        String(CLAIMS_PHASE_C),
        '--barrierTimeoutMs',
        String(BARRIER_TIMEOUT_MS),
      ],
      { cwd: env.WORKTREE, stdio: ['ignore', stdoutFd, stderrFd], windowsHide: true },
    );
    fs.closeSync(stdoutFd);
    fs.closeSync(stderrFd);
    children.push({ role, child });
  }

  const exits = await Promise.all(children.map(({ child }) => waitForExit(child, CHILD_TIMEOUT_MS)));

  const childReports = children.map(({ role, child }, index) => {
    const outFile = outFiles[role];
    let report = null;
    let readError = null;
    try {
      report = fs.existsSync(outFile) ? JSON.parse(fs.readFileSync(outFile, 'utf8')) : null;
      if (report === null) readError = 'child result file absent';
    } catch (err) {
      readError = `${err.name}: ${err.message}`;
    }
    const stdoutLog = logFiles[role].stdout;
    const stderrLog = logFiles[role].stderr;
    return {
      role,
      spawnPid: child.pid,
      reportedPid: report ? report.pid : null,
      reportedPpid: report ? report.ppid : null,
      exit: exits[index],
      barrierReached: report ? report.barrierReached : null,
      peerReady: report ? report.peerReady : null,
      attempts: report ? report.attempts : [],
      attemptCount: report ? report.attempts.length : 0,
      finalRows: report ? report.finalRows : null,
      compositionPrecondition: report ? report.compositionPrecondition : null,
      registryShape: report ? report.registryShape : null,
      fatal: report ? report.fatal : readError,
      fatalStack: report ? (report.fatalStack ?? null) : null,
      stdoutArtifact: path.relative(env.WORKTREE, stdoutLog).replace(/\\/g, '/'),
      stderrArtifact: path.relative(env.WORKTREE, stderrLog).replace(/\\/g, '/'),
      stdoutBytes: fs.existsSync(stdoutLog) ? fs.statSync(stdoutLog).size : 0,
      stderrBytes: fs.existsSync(stderrLog) ? fs.statSync(stderrLog).size : 0,
    };
  });

  const allAttempts = childReports.flatMap((entry) => entry.attempts);
  const classification = classifyAttempts(allAttempts);
  const spawnPids = childReports.map((entry) => entry.spawnPid).filter((pid) => typeof pid === 'number' && pid > 0);
  const reportedPids = childReports.map((entry) => entry.reportedPid).filter((pid) => typeof pid === 'number' && pid > 0);
  const distinctSpawnPids = new Set(spawnPids);
  const distinctReportedPids = new Set(reportedPids);
  const phases = ['p1', 'p2', 'p3', 'p4'];
  const barrierCredible =
    childReports.length === 2 &&
    childReports.every(
      (entry) =>
        entry.barrierReached !== null &&
        phases.every((phase) => entry.barrierReached[phase] === true && entry.peerReady[phase] === true),
    );

  // Post-race read-back through the raw driver, then drop only this row's database.
  const { client } = await fence.connectGuarded({ dbName, appName: 'cbhr-r2-s2t-e2-readback' });
  let postRace;
  let dropped;
  try {
    const collection = client.db(dbName).collection('deviceauthorities');
    postRace = {
      rowX: await collection.findOne({ _id: ROW_X }),
      rowY: await collection.findOne({ _id: ROW_Y }),
      counts: await env.collectionCounts(client, dbName),
    };
  } finally {
    dropped = await fence.dropOwnDatabase(client, dbName);
    await client.close().catch(() => {});
  }

  const rowXDelta = postRace.rowX ? postRace.rowX.epoch - 0 : null;
  const rowYDelta = postRace.rowY ? postRace.rowY.epoch - 0 : null;
  const staleCeremonyTransitions = classification.byPhase.B2_stale_g_claim_after_revoke
    ? classification.byPhase.B2_stale_g_claim_after_revoke.winners
    : 0;
  const rowXTransitions = classification.byPhase.B1_revoke_at_g
    ? classification.byPhase.B1_revoke_at_g.winners + staleCeremonyTransitions
    : null;
  const rowYTransitions = classification.byPhase.C_pure_same_generation_claim_race
    ? classification.byPhase.C_pure_same_generation_claim_race.winners
    : null;

  const componentX = {
    name: 'row_x_single_generation_transition',
    oracle:
      'row X (live lease at g) takes EXACTLY ONE successful generation transition: the generation-changing revoke at g',
    actual: `row X epoch 0 -> ${postRace.rowX ? postRace.rowX.epoch : null} (delta ${rowXDelta}); matched transitions observed = ${rowXTransitions} (revoke ${classification.byPhase.B1_revoke_at_g ? classification.byPhase.B1_revoke_at_g.winners : 0} + stale g ceremony ${staleCeremonyTransitions})`,
    met: rowXDelta === 1 && rowXTransitions === 1,
    tier: 'E2',
  };
  const componentStale = {
    name: 'stale_g_ceremony_fenced',
    oracle: 'a ceremony pinned to g performs ZERO generation transitions once the row has advanced to g+1',
    actual: `${staleCeremonyTransitions} stale g ceremony transition(s); responses classified PAIRING_CEREMONY_STALE = ${classification.pairingCeremonyStaleResponses}; after the revoke the row read back leaseState=${postRace.rowX ? postRace.rowX.leaseState : null} epoch=${postRace.rowX ? postRace.rowX.epoch : null}`,
    met: staleCeremonyTransitions === 0,
    tier: 'E2',
  };
  const componentY = {
    name: 'row_y_one_winner_per_generation',
    oracle: 'the pure same-generation claim race on row Y produces exactly one winner and a total epoch delta of exactly +1',
    actual: `row Y epoch 0 -> ${postRace.rowY ? postRace.rowY.epoch : null} (delta ${rowYDelta}); winners = ${rowYTransitions}`,
    met: rowYDelta === 1 && rowYTransitions === 1,
    tier: 'E2',
  };
  const componentLosers = {
    name: 'losers_zero_match_fail_closed',
    oracle: 'every non-winning operation is 0-match and fail-closed',
    actual: `${classification.losers} loser operations, all matched=0 (matched>1 losers = ${classification.matchedAboveZeroLosers}); distinct loser error codes = ${JSON.stringify([
      ...new Set(allAttempts.filter((attempt) => attempt.matched !== 1).map((attempt) => attempt.errorCode)),
    ])}`,
    met:
      classification.losers > 0 &&
      classification.matchedAboveZeroLosers === 0 &&
      allAttempts.filter((attempt) => attempt.matched !== 1).every((attempt) => attempt.matched === 0),
    tier: 'E2',
  };
  const componentGate = {
    name: 'e2_gate_credible',
    oracle: `two independent OS processes, a credible four-phase file barrier and at least ${MIN_TOTAL_ATTEMPTS} genuine attempts`,
    actual: `${distinctSpawnPids.size} distinct spawn PIDs (${[...distinctSpawnPids].join(', ')}), ${distinctReportedPids.size} distinct self-reported PIDs (${[...distinctReportedPids].join(', ')}), total attempts ${allAttempts.length}, barrier credible ${barrierCredible}`,
    met:
      distinctSpawnPids.size >= 2 &&
      distinctReportedPids.size >= 2 &&
      allAttempts.length >= MIN_TOTAL_ATTEMPTS &&
      barrierCredible,
    tier: 'E2',
  };

  const components = [componentGate, componentX, componentStale, componentY, componentLosers];
  const gateOk = componentGate.met;
  const oracleMet = componentX.met && componentStale.met && componentY.met && componentLosers.met;
  const childFatal = childReports.some((entry) => entry.fatal !== null);

  let status;
  if (!gateOk || childFatal) {
    status = STATUS.HARNESS_FAIL;
  } else if (oracleMet) {
    status = STATUS.PASS_CURRENT;
  } else {
    status = STATUS.EXPECTED_RED;
  }

  const observedPids = [...new Set([...spawnPids, ...reportedPids])];
  const pidsByRole = childReports.map((entry) => ({
    role: entry.role,
    spawnPid: entry.spawnPid,
    reportedPid: entry.reportedPid,
    reportedPpid: entry.reportedPpid,
  }));

  const actual = {
    scenario:
      'four-phase, two-process same-generation race: 16 live-lease claims + 1 revoke + 1 stale g ceremony on row X, then 9 same-generation claims on row Y; every operation pinned to frozen generation g = 0',
    fixtureGeneration: 0,
    fixtureLegitimateTransitionBudget: { rowX: 1, rowY: 1 },
    dbName,
    fenceProblems,
    barrierKind: 'four-phase file readiness barrier (ready-<role>-p1..p4.json) with a 30 s deadline per phase',
    barrierDir: path.relative(env.WORKTREE, barrierDir).replace(/\\/g, '/'),
    barrierCredible,
    attemptsPerChild: CLAIMS_PHASE_A + 1 + 1 + CLAIMS_PHASE_C,
    minTotalAttemptsRequired: MIN_TOTAL_ATTEMPTS,
    totalAttempts: allAttempts.length,
    distinctSpawnPids: [...distinctSpawnPids],
    distinctReportedPids: [...distinctReportedPids],
    pids: observedPids,
    pidsByRole,
    attemptsByPhase: classification.byPhase,
    winners: classification.winners,
    losers: classification.losers,
    pairingCeremonyStaleResponses: classification.pairingCeremonyStaleResponses,
    rowX: {
      epoch: postRace.rowX ? postRace.rowX.epoch : null,
      epochDelta: rowXDelta,
      leaseState: postRace.rowX ? postRace.rowX.leaseState : null,
      ownerId: postRace.rowX ? postRace.rowX.ownerId : null,
      grantId: postRace.rowX ? postRace.rowX.grantId : null,
      transitions: rowXTransitions,
      staleCeremonyTransitions,
    },
    rowY: {
      epoch: postRace.rowY ? postRace.rowY.epoch : null,
      epochDelta: rowYDelta,
      leaseState: postRace.rowY ? postRace.rowY.leaseState : null,
      ownerId: postRace.rowY ? postRace.rowY.ownerId : null,
      grantId: postRace.rowY ? postRace.rowY.grantId : null,
      transitions: rowYTransitions,
    },
    postRaceCounts: postRace.counts,
    registryShape: prep.registryShape,
    seededIds: prep.seededIds,
    realAuditSinkPerChild: true,
    rawDriverDowngrade: false,
    childReports,
    dropped,
    contractMismatch: oracleMet
      ? null
      : 'the stale g-bound ceremony performed a real generation transition against the g+1 revoked row, so the fixture row budget (exactly one transition on row X) was exceeded',
  };

  const dbReadBack = {
    dbName,
    counts: postRace.counts,
    authorityRows: [postRace.rowX, postRace.rowY].filter(Boolean).map((row) => ({
      _id: row._id,
      tenantId: row.tenantId,
      epoch: row.epoch,
      leaseState: row.leaseState,
      identityState: row.identityState,
      ownerId: row.ownerId,
      grantId: row.grantId,
      prevEpoch: row.prevEpoch ?? null,
      prevGrantId: row.prevGrantId ?? null,
      grantedByPairingSessionId: row.grantedByPairingSessionId ?? null,
    })),
    auditSinkKind: 'real-AuditEvent-model-sink (one per child process)',
    seedReadback: prep.seededIds,
    dropped,
  };

  return { status, actual, components, pids: observedPids, attempts: allAttempts.length, dbReadBack, dbName };
}

module.exports = { runS2T03, ROW_X, ROW_Y, CLAIMS_PHASE_A, CLAIMS_PHASE_C, MIN_TOTAL_ATTEMPTS };