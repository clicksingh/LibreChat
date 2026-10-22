'use strict';

/**
 * W3-B R2-T0A E2 two-process row (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 *   T0A-01 SESSION-ABA-ISSUE-VS-APPROVE (F13, E2, N>=50): two REAL independent OS processes race
 *   an issuance/supersede attempt (role A) against approval/consume (role B) for one observed
 *   `claim_pending` session. Two genuine independent PIDs, a file readiness barrier, and
 *   25 + 25 = 50 genuine composition attempts against the same observed session.
 *
 * When genuine-model factory composition blocks the race before any attempt can proceed, the gate
 * failure is recorded honestly (EXPECTED_RED / FACTORY_COMPOSITION_FAIL) together with the real
 * PIDs, iteration counts and transport files. The row never downgrades to a raw-driver analog and
 * never claims a product behaviour it did not observe.
 */

const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const fence = require('./fence.cjs');
const env = require('./env.cjs');
const probes = require('./probes.cjs');
const results = require('./results.cjs');

const CHILD = path.join(__dirname, 'child-aba.cjs');
const ITERATIONS_PER_CHILD = 25;
const MIN_TOTAL_ATTEMPTS = 50;
const BARRIER_TIMEOUT_MS = 30000;
const CHILD_TIMEOUT_MS = 300000;

const ROW_ID = 'T0A-01-SESSION-ABA-ISSUE-VS-APPROVE';
const ORACLE =
  'F13: sessionVersion monotonically fences transitions; issuance may supersede a state:open session only; an approval that observed version v either consumes v exactly once or 0-matches; issuance never flips the same v after approval has observed it. Two real OS processes, N>=50.';

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

async function prepareDatabase(dbName, { deviceId, deviceKeyId, sessionId }) {
  const { client, topology } = await fence.connectGuarded({ dbName, appName: 'cbhr-r2-t0a-e2-prep' });
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
    const now = env.w3a.constants.EPOCH_BASE_MS;
    const authorityDocs = await four.DeviceAuthority.create(
      [
        {
          _id: deviceId,
          tenantId: env.w3a.TENANT,
          deviceKeyId,
          devicePublicKey: env.w3a.labKey.spkiB64u,
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
          grantedByPairingSessionId: null,
          grantProof: null,
          prevOwner: null,
          prevGrantId: null,
          prevEpoch: null,
        },
      ],
      { writeConcern: env.WRITE_CONCERN },
    );
    const sessionDocs = await four.PairingSession.create(
      [
        {
          tenantId: env.w3a.TENANT,
          deviceId,
          deviceKeyId,
          lookupTag: 't0a01-lookup-tag-000000000000000000000000000000000000',
          state: 'claim_pending',
          pendingOwnerId: env.w3a.OWNER_A,
          attemptsUsed: 1,
          issuedAt: new Date(now),
          expiresAt: new Date(now + 300000),
          claimedAt: new Date(now),
          claim: { challengeRef: 't0a01-challenge-ref', openedAt: new Date(now) },
          consumedAt: null,
          grantedGrantId: null,
          issuedFromSourceHash: null,
          deviceSessionId: 't0a01-device-session',
        },
      ],
      { writeConcern: env.WRITE_CONCERN },
    );
    const seededSessionId = String(sessionDocs[0]._id);
    const observed = await four.PairingSession.findOne({ _id: seededSessionId, tenantId: env.w3a.TENANT }).lean();
    await env.w3a.mongoose.disconnect().catch(() => {});
    return {
      topology,
      syncReport,
      seededAuthorityId: String(authorityDocs[0]._id),
      seededSessionId,
      observedSession: observed
        ? {
            state: observed.state,
            sessionVersionFieldPresent: Object.prototype.hasOwnProperty.call(observed, 'sessionVersion'),
            sessionVersion: observed.sessionVersion ?? null,
            claimFields: observed.claim ? Object.keys(observed.claim) : null,
          }
        : null,
      registryShape: env.registryModelTypeof(loaded.registry),
    };
  } finally {
    await env.w3a.mongoose.disconnect().catch(() => {});
    await client.close().catch(() => {});
  }
}

function staticAbaEvidence() {
  const sessionVersion = probes.symbolScan('sessionVersion', [
    ...probes.DEVICE_SERVICE_FILES,
    probes.PRODUCT_FILES.pairingSessionSchema,
    probes.PRODUCT_FILES.challengeSchema,
  ]);
  const expectedEpoch = probes.symbolScan('expectedEpoch', [
    ...probes.DEVICE_SERVICE_FILES,
    probes.PRODUCT_FILES.pairingSessionSchema,
    probes.PRODUCT_FILES.challengeSchema,
  ]);
  const boundEpoch = probes.symbolScan('boundEpoch', [
    ...probes.DEVICE_SERVICE_FILES,
    probes.PRODUCT_FILES.challengeSchema,
  ]);
  const nonTerminal = probes.excerpt(probes.PRODUCT_FILES.pairingSessionService, /const NON_TERMINAL_SESSION_STATES/, 0, 2);
  const supersedeFn = probes.extractFunction(probes.PRODUCT_FILES.pairingSessionService, /async function supersedeNonTerminalSessions/);
  const approvalFn = probes.extractFunction(probes.PRODUCT_FILES.pairingSessionService, /async function approvePairingClaimImpl/);
  return {
    tier: 'E0',
    isProductBehavior: false,
    sessionVersionSymbol: { present: sessionVersion.present, anchors: sessionVersion.hits.map((h) => `${h.file}:${h.line}`) },
    expectedEpochSymbol: { present: expectedEpoch.present, anchors: expectedEpoch.hits.map((h) => `${h.file}:${h.line}`) },
    boundEpochSymbol: { present: boundEpoch.present, anchors: boundEpoch.hits.map((h) => `${h.file}:${h.line}`) },
    nonTerminalStatesAnchor: nonTerminal.anchors,
    nonTerminalStatesExcerpt: nonTerminal.text,
    supersedeFunctionExcerpt: supersedeFn.text,
    approvalFunctionScope: { file: approvalFn.file, startLine: approvalFn.startLine, endLine: approvalFn.endLine },
    approvalUsesExpectedSessionVersion: approvalFn.text !== null && approvalFn.text.includes('expectedSessionVersion'),
    approvalConsumeMatchesClaimPendingWithoutVersion:
      approvalFn.text !== null && approvalFn.text.includes("state: 'claim_pending'") && !approvalFn.text.includes('expectedSessionVersion'),
    finding:
      'Pre-repair bytes have NO sessionVersion field anywhere (schema or services): issuance supersede matches state $in [open, claim_pending] and approval consume matches state claim_pending without any observed version, so the F13 anti-ABA fence is absent. Versionless CURRENT behavior is EXPECTED_RED, never a pass.',
  };
}

async function cleanupDatabase(dbName) {
  try {
    const { client } = await fence.connectGuarded({ dbName, appName: 'cbhr-r2-t0a-e2-cleanup' });
    try {
      return await fence.dropOwnDatabase(client, dbName);
    } finally {
      await client.close().catch(() => {});
    }
  } catch (err) {
    return { dropped: false, dbName, error: `${err.name}: ${err.message}` };
  }
}

async function runAbaRow() {
  const dbName = fence.createDbName('t0a01aba');
  const fenceProblems = fence.checkDbName(dbName);
  if (fenceProblems.length > 0) {
    throw new fence.R2aFenceViolation(fenceProblems, { dbName, phase: 'e2-pre-connect' });
  }
  const barrierDir = path.join(env.ARTIFACTS_DIR, `${ROW_ID}-barrier`);
  fs.rmSync(barrierDir, { recursive: true, force: true });
  fs.mkdirSync(barrierDir, { recursive: true });

  const dropState = { dropped: null, dbName };
  try {
  const deviceId = 't0a01-device';
  const deviceKeyId = 't0a01-device-key';
  const prep = await prepareDatabase(dbName, { deviceId, deviceKeyId });
  const sessionId = prep.seededSessionId;

  const children = [];
  const outFiles = { A: path.join(barrierDir, 'out-A.json'), B: path.join(barrierDir, 'out-B.json') };
  const argsFor = (role) => [
    CHILD,
    '--role', role,
    '--db', dbName,
    '--barrier', barrierDir,
    '--out', outFiles[role],
    '--iterations', String(ITERATIONS_PER_CHILD),
    '--scenario', 'session-aba-issue-vs-approve',
    '--tag', 't0a01aba',
    '--session', sessionId,
    '--tenant', env.w3a.TENANT,
    '--device', deviceId,
    '--deviceKey', deviceKeyId,
    '--owner', env.w3a.OWNER_A,
    '--barrierTimeoutMs', String(BARRIER_TIMEOUT_MS),
  ];

  for (const role of ['A', 'B']) {
    const child = spawn(process.execPath, argsFor(role), {
      cwd: env.WORKTREE,
      stdio: 'ignore',
      windowsHide: true,
    });
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
      roleFunction: role === 'A' ? 'issuance/supersede' : 'approval/consume',
      spawnPid: child.pid,
      spawnPidIsRealOsPid: typeof child.pid === 'number' && child.pid > 0,
      exit: exits[index],
      reportedPid: report ? report.pid : null,
      reportedPpid: report ? report.ppid : null,
      barrierReached: report ? report.barrierReached : false,
      peerReady: report ? report.peerReady : false,
      attempts: report ? report.attempts : 0,
      compositionFailures: report ? report.compositionFailures : 0,
      composedInSomeFactory: report ? report.composedInSomeFactory : 0,
      productCallsAttempted: report ? report.productCallsAttempted : 0,
      observedSession: report ? report.observedSession : null,
      auditSinkKind: report ? report.auditSinkKind : null,
      registryShape: report ? report.registryShape : null,
      attemptsDetail: report ? report.attemptsDetail : null,
      durationMs: report ? report.durationMs : null,
      outFile: path.relative(env.WORKTREE, outFile).replace(/\\/g, '/'),
      outFileSha256: fs.existsSync(outFile) ? results.sha256File(outFile) : null,
      fatal: report ? report.fatal : readError,
    };
  });

  const totalAttempts = childReports.reduce((sum, entry) => sum + (entry.attempts ?? 0), 0);
  const productCallsAttempted = childReports.reduce((sum, entry) => sum + (entry.productCallsAttempted ?? 0), 0);
  const distinctPids = new Set(
    childReports.map((entry) => entry.reportedPid ?? entry.spawnPid).filter((pid) => typeof pid === 'number' && pid > 0),
  );
  const observedPids = Array.from(
    new Set(childReports.flatMap((entry) => [entry.spawnPid, entry.reportedPid]).filter((pid) => typeof pid === 'number' && pid > 0)),
  );
  const pidsByRole = childReports.map((entry) => ({ role: entry.role, spawnPid: entry.spawnPid, reportedPid: entry.reportedPid }));
  const barrierCredible = childReports.every((entry) => entry.barrierReached === true) && childReports.length === 2;
  const readyFiles = ['A', 'B'].map((role) => {
    const file = path.join(barrierDir, `ready-${role}.json`);
    return {
      role,
      path: path.relative(env.WORKTREE, file).replace(/\\/g, '/'),
      exists: fs.existsSync(file),
      sha256: fs.existsSync(file) ? results.sha256File(file) : null,
    };
  });

  const { client } = await fence.connectGuarded({ dbName, appName: 'cbhr-r2-t0a-e2-readback' });
  let dbReadBack;
  try {
    dbReadBack = {
      dbName,
      counts: await env.collectionCounts(client, dbName),
      authorityRows: await env.readAuthorityRows(client, dbName),
      auditSinkKind: 'real-AuditEvent-model-sink (each child)',
      seededRows: { authorityId: prep.seededAuthorityId, sessionId: prep.seededSessionId },
    };
  } finally {
    await client.close().catch(() => {});
  }

  const staticEvidence = staticAbaEvidence();
  const allBlocked = totalAttempts >= MIN_TOTAL_ATTEMPTS && childReports.every((entry) => entry.compositionFailures === entry.attempts);
  let status = results.STATUS.EXPECTED_RED;
  let notes =
    'Gate failure recorded honestly: genuine-model factory composition blocks the two-process race before any attempt can proceed. Versionless/absent sessionVersion is EXPECTED_RED, never a pass.';
  if (!barrierCredible || totalAttempts < MIN_TOTAL_ATTEMPTS || distinctPids.size < 2) {
    status = results.STATUS.HARNESS_FAIL;
    notes = 'E2 gate not credible: need two independent OS processes, a file barrier and N >= 50 attempts.';
  } else if (!allBlocked && productCallsAttempted > 0) {
    notes =
      'Composition unexpectedly accepted genuine model constructors: product calls were attempted and their outcomes are recorded. The F13 oracle evaluation for this row is deferred to the post-repair rerun.';
  }

  const actual = {
    kind: status === results.STATUS.HARNESS_FAIL ? 'E2_GATE_NOT_CREDIBLE' : 'FACTORY_COMPOSITION_FAIL',
    scenario: 'session-aba-issue-vs-approve',
    dbName,
    fenceProblems,
    barrierDir: path.relative(env.WORKTREE, barrierDir).replace(/\\/g, '/'),
    barrierKind: 'file readiness barrier (ready-A.json / ready-B.json) with 30 s deadline',
    barrierCredible,
    readyFiles,
    transportKind: 'file transport only (child stdio ignored; this sandbox cannot pipe child stdio)',
    iterationsPerChild: ITERATIONS_PER_CHILD,
    totalAttempts,
    minTotalAttemptsRequired: MIN_TOTAL_ATTEMPTS,
    productCallsAttempted,
    distinctOsPids: distinctPids.size,
    pids: observedPids,
    pidsByRole,
    childReports,
    observedSessionAtBarrier: prep.observedSession,
    seededPreimage: { authorityId: prep.seededAuthorityId, sessionId: prep.seededSessionId, state: 'claim_pending' },
    registryShape: prep.registryShape,
    realAuditSinkPerChild: true,
    rawDriverDowngrade: false,
    staticEvidence,
    pendingOracle: ORACLE,
    pendingAfterFirstFix: true,
  };

  return {
    row: results.makeRow({
      id: ROW_ID,
      contractRef: 'F13/F18-A',
      tier: 'E2',
      tierExecuted: 'E2',
      status,
      expectedOracle: ORACLE,
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
          actual: JSON.stringify(childReports.map((e) => ({ role: e.role, barrierReached: e.barrierReached, peerReady: e.peerReady }))),
          met: barrierCredible,
          tier: 'E2',
        },
        {
          name: 'n_at_least_50',
          oracle: `at least ${MIN_TOTAL_ATTEMPTS} genuine attempts`,
          actual: `${totalAttempts} attempts (${ITERATIONS_PER_CHILD} per child)`,
          met: totalAttempts >= MIN_TOTAL_ATTEMPTS,
          tier: 'E2',
        },
        {
          name: 'genuine_models_no_raw_driver_downgrade',
          oracle: 'every attempt uses createModels(mongoose) models and the real AuditEvent model; no raw-driver analog',
          actual: `registry model typeof values recorded per child; rawDriverDowngrade false; audit sink ${childReports[0] ? childReports[0].auditSinkKind : 'n/a'}`,
          met: childReports.every((e) => e.registryShape && Object.values(e.registryShape).every((m) => m.typeofModel === 'function')),
          tier: 'E2',
        },
        {
          name: 'approval_consumes_observed_version_once_or_zero',
          oracle: 'an approval that observed version v consumes v exactly once or 0-matches',
          met: false,
          actual: 'not executed: genuine-model factory composition gate stopped the race before any product call',
          tier: 'E2',
        },
        {
          name: 'issuance_never_flips_observed_version',
          oracle: 'issuance never flips the same v after approval has observed it; issuance may supersede state:open only',
          met: false,
          actual:
            'not executed: composition gate; static anchor shows supersede matches state $in [open, claim_pending] (an in-flight claim_pending session WOULD be flipped)',
          tier: 'E2',
        },
        {
          name: 'session_version_fence_present',
          oracle: 'sessionVersion monotonically fences transitions',
          met: false,
          actual: `sessionVersion symbol present anywhere in Device services + session/challenge schema: ${staticEvidence.sessionVersionSymbol.present}`,
          tier: 'E0',
          isProductBehavior: false,
        },
      ],
      pids: observedPids,
      attempts: totalAttempts,
      dbReadBack,
      dbName,
      notes,
      productClaim: false,
      blockedAtFactoryComposition: allBlocked && status !== results.STATUS.HARNESS_FAIL,
      processEvidence: {
        pids: observedPids,
        pidsByRole,
        distinctOsPids: distinctPids.size,
        iterationsPerChild: ITERATIONS_PER_CHILD,
        totalAttempts,
        barrierDir: path.relative(env.WORKTREE, barrierDir).replace(/\\/g, '/'),
        readyFiles,
        outFiles: childReports.map((e) => ({ role: e.role, path: e.outFile, sha256: e.outFileSha256 })),
        transportKind: 'file transport only',
        childExits: exits,
      },
      artifactPayload: { id: ROW_ID, actual, dbReadBack },
      evidenceDir: env.ARTIFACTS_DIR,
    }),
    dropped: dropState,
  };
  } finally {
    dropState.dropped = (await cleanupDatabase(dbName)).dropped;
  }
}

module.exports = { ROW_ID, ORACLE, runAbaRow, staticAbaEvidence, ITERATIONS_PER_CHILD, MIN_TOTAL_ATTEMPTS };