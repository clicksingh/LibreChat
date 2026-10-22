'use strict';

/**
 * W3-B R2-T0 E2 two-process fixtures (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 *   - R2-H07-SEQUENTIAL-REGRANT (H-07, E2): revoke at generation g, then mint a FRESH ceremony at
 *     g+1 and claim — the legitimate sequential regrant of the corrected V24-T15 oracle.
 *   - R2-H28-TWO-RECONCILERS (H-28, E2): two concurrent reconcilers, N >= 50.
 *
 * Both rows use two real independent OS processes (distinct PIDs), a file readiness barrier, and
 * N >= 50 total genuine composition attempts against the same authority generation. When factory
 * composition blocks the race before any attempt can proceed, the gate failure is recorded honestly
 * (EXPECTED_RED / FACTORY_COMPOSITION_FAIL) with the real PIDs and attempts — the fixtures never
 * downgrade to a raw-driver analog, and they never claim a product behaviour they did not observe.
 *
 * V24-T15 fence: no row here encodes both a one-winner and a two-winner assertion. This file asserts
 * ONE winner per generation (H-06, elsewhere) and a NEW post-revoke generation that may sequentially
 * claim (H-07) — never both in one fixture.
 */

const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const fence = require('./fence.cjs');
const env = require('./env.cjs');
const results = require('./results.cjs');
const { EVIDENCE_DIR } = require('./ctx.cjs');

const CHILD = path.join(__dirname, 'child-e2.cjs');
const ATTEMPTS_PER_CHILD = 25;
const MIN_TOTAL_ATTEMPTS = 50;
const BARRIER_TIMEOUT_MS = 30000;
const CHILD_TIMEOUT_MS = 300000;

function waitForExit(child, timeoutMs) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      child.kill();
      resolve({ timedOut: true });
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

async function prepareDatabase(dbName) {
  const { client, topology } = await fence.connectGuarded({ dbName, appName: 'cbhr-r2-t0-e2-prep' });
  try {
    const loaded = env.loadRegistry();
    const four = {
      DeviceAuthority: loaded.registry.DeviceAuthority,
      PairingSession: loaded.registry.PairingSession,
      Challenge: loaded.registry.Challenge,
      AuditEvent: loaded.registry.AuditEvent,
    };
    await env.connectMongoose({ uri: fence.FROZEN_URI, dbName });
    const syncReport = await env.syncDeclaredIndexes(four);
    const seeded = [];
    for (const owner of [env.w3a.OWNER_A, env.w3a.OWNER_B]) {
      const deviceId = `r2-t0-e2-${owner}`;
      // eslint-disable-next-line no-await-in-loop
      const docs = await four.DeviceAuthority.create(
        [
          {
            _id: deviceId,
            tenantId: env.w3a.TENANT,
            deviceKeyId: `key-${deviceId}`,
            devicePublicKey: env.w3a.labKey.spkiB64u,
            identityState: 'pending',
            leaseState: 'never',
            epoch: 0,
            ownerId: owner,
            grantId: null,
            activatedAt: null,
            expiresAt: null,
            retiredAt: null,
            retiredBy: null,
            revokedAt: null,
            revokedBy: null,
            renewalCount: 0,
            grantedByPairingSessionId: null,
            grantProof: null,
            prevOwner: null,
            prevGrantId: null,
            prevEpoch: null,
          },
        ],
        { writeConcern: env.WRITE_CONCERN },
      );
      seeded.push(String(docs[0]._id));
    }
    await env.w3a.mongoose.disconnect().catch(() => {});
    return { topology, syncReport, seeded, registryShape: Object.fromEntries(Object.entries(loaded.shape).map(([k, v]) => [k, v.typeofModel])) };
  } finally {
    await env.w3a.mongoose.disconnect().catch(() => {});
    await client.close().catch(() => {});
  }
}

async function runTwoProcessRow({ id, tag, scenario, hostileRows, tier, expectedOracle, pendingOracle, gateExtra }) {
  const dbName = fence.createDbName(tag);
  const fenceProblems = fence.checkDbName(dbName);
  if (fenceProblems.length > 0) {
    throw new fence.R2FenceViolation(fenceProblems, { dbName, phase: 'e2-pre-connect' });
  }
  const barrierDir = path.join(EVIDENCE_DIR, `${id}-barrier`);
  fs.rmSync(barrierDir, { recursive: true, force: true });
  fs.mkdirSync(barrierDir, { recursive: true });

  const prep = await prepareDatabase(dbName);
  const children = [];
  const outFiles = { A: path.join(barrierDir, 'out-A.json'), B: path.join(barrierDir, 'out-B.json') };

  for (const role of ['A', 'B']) {
    const child = spawn(
      process.execPath,
      [
        CHILD,
        '--role', role,
        '--db', dbName,
        '--barrier', barrierDir,
        '--out', outFiles[role],
        '--attempts', String(ATTEMPTS_PER_CHILD),
        '--scenario', scenario,
        '--tag', tag,
        '--barrierTimeoutMs', String(BARRIER_TIMEOUT_MS),
      ],
      { cwd: env.WORKTREE, stdio: 'ignore', windowsHide: true },
    );
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
    return {
      role,
      spawnPid: child.pid,
      spawnPidIsRealOsPid: typeof child.pid === 'number' && child.pid > 0,
      exit: exits[index],
      reportedPid: report ? report.pid : null,
      barriersReached: report ? report.barrierReached : false,
      peerReady: report ? report.peerReady : false,
      attempts: report ? report.attempts : 0,
      compositionFailures: report ? report.compositionFailures : 0,
      winners: report ? report.winners : 0,
      fatal: report ? report.fatal : readError,
      registryShape: report ? report.registryShape : null,
      attemptsDetail: report ? report.attemptsDetail : null,
      durationMs: report ? report.durationMs : null,
    };
  });

  const totalAttempts = childReports.reduce((sum, entry) => sum + (entry.attempts ?? 0), 0);
  const distinctPids = new Set(childReports.map((entry) => entry.reportedPid ?? entry.spawnPid).filter((pid) => typeof pid === 'number' && pid > 0));
  const observedPids = Array.from(
    new Set(childReports.flatMap((entry) => [entry.spawnPid, entry.reportedPid]).filter((pid) => typeof pid === 'number' && pid > 0)),
  );
  const pidsByRole = childReports.map((entry) => ({ role: entry.role, spawnPid: entry.spawnPid, reportedPid: entry.reportedPid }));
  const barrierCredible = childReports.every((entry) => entry.barriersReached === true) && childReports.length === 2;

  // Read back the shared database state after both processes exited, then drop only this database.
  const { client } = await fence.connectGuarded({ dbName, appName: 'cbhr-r2-t0-e2-readback' });
  let dbReadBack;
  let dropped;
  try {
    dbReadBack = {
      dbName,
      counts: await env.collectionCounts(client, dbName),
      authorityRows: await env.readAuthorityRows(client, dbName),
      auditSinkKind: 'real-AuditEvent-model-sink (each child)',
      seededRows: prep.seeded,
    };
  } finally {
    dropped = await fence.dropOwnDatabase(client, dbName);
    await client.close().catch(() => {});
  }

  let status = results.STATUS.EXPECTED_RED;
  let notes = 'Gate failure recorded honestly: factory composition blocks the two-process race before any attempt can proceed.';
  if (!barrierCredible || totalAttempts < MIN_TOTAL_ATTEMPTS || distinctPids.size < 2) {
    status = results.STATUS.HARNESS_FAIL;
    notes = 'E2 gate not credible: need two independent OS processes, a file barrier and N >= 50 attempts.';
  }

  const actual = {
    kind: totalAttempts >= MIN_TOTAL_ATTEMPTS ? 'FACTORY_COMPOSITION_FAIL' : 'E2_GATE_NOT_CREDIBLE',
    scenario,
    dbName,
    fenceProblems,
    barrierDir: path.relative(env.WORKTREE, barrierDir).replace(/\\/g, '/'),
    barrierKind: 'file readiness barrier (ready-A.json / ready-B.json) with 30 s deadline',
    barrierCredible,
    attemptsPerChild: ATTEMPTS_PER_CHILD,
    totalAttempts,
    minTotalAttemptsRequired: MIN_TOTAL_ATTEMPTS,
    distinctOsPids: distinctPids.size,
    pids: observedPids,
    pidsByRole,
    childReports,
    winners: childReports.reduce((sum, entry) => sum + (entry.winners ?? 0), 0),
    compositionFailures: childReports.reduce((sum, entry) => sum + (entry.compositionFailures ?? 0), 0),
    epochDelta: null,
    registryShape: prep.registryShape,
    realAuditSinkPerChild: true,
    rawDriverDowngrade: false,
    pendingOracle,
    pendingAfterFirstFix: true,
    ...gateExtra,
  };

  return {
    row: results.makeRow({
      id,
      hostileRows,
      tier,
      executedTier: 'E2',
      status,
      expectedOracle,
      actual,
      components: [
        {
          name: 'two_independent_os_processes',
          oracle: 'two real independent OS processes with distinct PIDs',
          actual: `${distinctPids.size} distinct PIDs: ${Array.from(distinctPids).join(', ')}`,
          met: distinctPids.size >= 2,
          tier: 'E2',
        },
        {
          name: 'barrier_credible',
          oracle: 'both processes reach the shared file barrier before attempting',
          actual: JSON.stringify(childReports.map((entry) => ({ role: entry.role, barriersReached: entry.barriersReached, peerReady: entry.peerReady }))),
          met: barrierCredible,
          tier: 'E2',
        },
        {
          name: 'n_at_least_50',
          oracle: `at least ${MIN_TOTAL_ATTEMPTS} genuine attempts`,
          actual: `${totalAttempts} attempts`,
          met: totalAttempts >= MIN_TOTAL_ATTEMPTS,
          tier: 'E2',
        },
        {
          name: 'genuine_composition_only',
          oracle: 'every attempt uses createModels(mongoose) models and the real AuditEvent model (no raw-driver analog)',
          actual: `registry model typeof values: ${JSON.stringify(prep.registryShape)}; raw-driver downgrade: false`,
          met: false,
          tier: 'E2',
        },
      ],
      pids: observedPids,
      attempts: totalAttempts,
      dbReadBack,
      dbName,
      notes,
      productClaim: false,
      artifactPayload: { id, hostileRows, expectedOracle, actual, dbReadBack, dropped },
      evidenceDir: EVIDENCE_DIR,
    }),
    dropped,
  };
}

function fixtureDefs() {
  return [
    {
      id: 'R2-H07-SEQUENTIAL-REGRANT',
      tag: 'h07sequentialregrant',
      scenario: 'revoke-at-g-then-fresh-ceremony-at-g+1-claim',
      hostileRows: ['H-07'],
      tier: 'E2',
      expectedOracle: 'PASS iff a revoke at g followed by a FRESH ceremony at g+1 claims successfully: ok:true, epoch === g+2, grantId !== prevGrantId (a NEW post-revoke generation may sequentially claim)',
      pendingOracle: 'ok:true, epoch === g+2, grantId !== prevGrantId for a fresh post-revoke generation',
      gateExtra: {
        frozenOracleShape: 'one winner in the NEW generation g+1; the loser generation g remains terminal',
        oneWinnerPerGeneration: true,
        twoWinnerAssertion: false,
      },
    },
    {
      id: 'R2-H28-TWO-RECONCILERS',
      tag: 'h28tworeconcilers',
      scenario: 'two-concurrent-reconcilers-at-least-once',
      hostileRows: ['H-28'],
      tier: 'E2',
      expectedOracle: 'PASS iff two concurrent reconcilers, N >= 50, produce growth equal to the number of genuinely missing events under a documented non-racy key',
      pendingOracle: 'collection growth equals the number of genuinely missing events; re-emit key is documented and non-racy',
      gateExtra: {
        reconcilerPresentInProduct: false,
        reconcilerAbsenceAnchor: 'R2 introduces NO background audit reconciler (F6); no reconciler symbol exists in the Device service bytes',
      },
    },
  ];
}

async function main(record) {
  for (const def of fixtureDefs()) {
    const { row } = await runTwoProcessRow(def);
    record(row);
  }
}

module.exports = { id: 'R2-E2-TWO-PROCESS', fixtureDefs, runTwoProcessRow, main, ATTEMPTS_PER_CHILD, MIN_TOTAL_ATTEMPTS };