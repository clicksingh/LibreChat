'use strict';

/**
 * I9 crash-after-write runner (lane I9, PHASE1-LOCAL-AUTHORITY-001 / W2-B).
 *
 *   node tests/device/crash-runner.cjs --point=c2 --db=cbhr_rdc_phase1_w2b_crash_...
 *   node tests/device/crash-runner.cjs --point=self-test --db=cbhr_rdc_phase1_w2b_crashharness_...
 *
 * Product crash points c1..c6 drive the real I5/I6 product chain: the child performs
 * the real write and then exits with a sentinel before the next step, and a separate
 * verifier process re-reads durable state. While I6/I5 do not exist those points are
 * reported BLOCKED_PENDING_I6_I5 and NO PASS is fabricated.
 *
 * The self-test point is a harness-transport control only: it proves that a write made
 * by a crashing child is durable and that the crash sentinel is observable. It is not a
 * product crash-point result.
 */

const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const harness = require('./e1/harness.cjs');
const serviceLoader = require('./e1/service-loader.cjs');

const CRASH_SENTINEL = 7;

const POINT_PLANS = {
  c1: {
    title: 'crash before the challenge spend',
    expected: ['challenge unspent (consumedAt null)', 'no authority write', 'recovery is a fresh challenge'],
  },
  c2: {
    title: 'crash after the challenge spend, before LP-3 session consume',
    expected: [
      'challenges.consumedAt != null',
      'pairing session still claim_pending',
      'approve fails closed with the uniform INVALID_OR_EXPIRED_CODE',
      'authority row leaseState unchanged',
    ],
  },
  c3: {
    title: 'crash after LP-3 session consume, before LP-4 authority claim',
    expected: [
      'session state consumed with grantedGrantId null',
      'authority row leaseState unchanged and ownerId null',
      'a fresh pairing session recovers',
    ],
  },
  c4: {
    title: 'crash after the LP-4 authority claim',
    expected: [
      'authority row leaseState active with a 22-char CSPRNG grantId',
      'expiresAt === activatedAt + 172800000',
      'session consumed with grantedGrantId equal to the row grantId',
    ],
  },
  c5: {
    title: 'crash after the revoke CAS',
    expected: ['leaseState revoked, epoch+1, prevGrantId/prevEpoch written', 're-pair with a fresh code succeeds'],
  },
  c6: {
    title: 'crash after the retire CAS',
    expected: [
      'identityState retired with retiredAt set',
      'every admission path denies',
      'in-tenant re-registration of the same deviceKeyId is DEVICE_ALREADY_REGISTERED',
      'a fresh key pairs normally',
    ],
  },
};

async function childMain(options) {
  const role = options.role;
  const connected = await harness.connect({
    uri: options.uri,
    dbName: options.db,
    appName: `cbhr-phase1-w2b-crash-${role}`,
  });
  try {
    const collection = connected.db.collection('crash_markers');
    if (role === 'crash') {
      await collection.insertOne({
        _id: `w2b-crash-${options.point}`,
        point: options.point,
        pid: process.pid,
        writtenAt: new Date(harness.EPOCH_BASE_MS),
      });
      // Deliberately die before the next step. The witness file is NEVER written,
      // which is exactly what proves the crash point was reached.
      process.exit(CRASH_SENTINEL);
    }
    if (role === 'verifier') {
      const marker = await collection.findOne({ _id: `w2b-crash-${options.point}` });
      const result = {
        role: 'verifier',
        pid: process.pid,
        point: options.point,
        markerFound: marker !== null,
        marker,
        witnessPresent: options.witness ? fs.existsSync(options.witness) : null,
      };
      if (options.out) {
        harness.writeJsonFile(options.out, result);
      }
      return result;
    }
    throw new Error(`unknown crash role ${role}`);
  } finally {
    await connected.client.close().catch(() => {});
  }
}

async function runCrash(options = {}) {
  const point = String(options.point ?? 'c2');
  const dbName = options.db ?? harness.makeDbName(`crash_${point.replace(/[^A-Za-z0-9]/g, '')}`);
  const uri = options.uri ?? harness.DEFAULT_URI;
  const emit = options.emit !== false;

  const finish = (report) => {
    if (options['result-out']) {
      harness.writeJsonFile(options['result-out'], report);
    }
    if (emit) {
      harness.emit(report);
    }
    return report;
  };

  if (point !== 'self-test') {
    const probe = serviceLoader.probe();
    const plan = POINT_PLANS[point];
    return finish({
      check: 'crash-runner',
      point,
      tier: 'E1',
      kind: 'product',
      db: dbName,
      status: probe.status === 'AVAILABLE' ? 'BLOCKED_NOT_WIRED' : 'BLOCKED_PENDING_I6_I5',
      exitCode: 2,
      productClaim: false,
      reason:
        probe.status === 'AVAILABLE'
          ? 'I6/I5 exist but crash-point wiring is deferred to the authorized post-I4/I6/I5 integration test round'
          : probe.reason,
      serviceProbe: { status: probe.status, missing: probe.missing, shapeProblems: probe.shapeProblems },
      assertionPlan: plan ?? { title: `product crash point ${point}`, expected: [] },
    });
  }

  const workDir = harness.tmpRoot(`crash-self-test-${harness.stamp()}`);
  const witness = path.join(workDir, 'next-step.witness');
  const verifierOut = path.join(workDir, 'verifier.json');
  let client = null;
  let cleanup = 'not_attempted';
  try {
    const connected = await harness.connect({ uri, dbName, appName: 'cbhr-phase1-w2b-crash-parent' });
    client = connected.client;
    const base = {
      check: 'crash-runner',
      point,
      tier: 'CONTROL',
      kind: 'harness-control',
      db: dbName,
      topology: connected.topology,
      isolation: connected.isolation,
      productClaim: false,
      evidenceGrade: 'HARNESS_TRANSPORT_CONTROL',
      crashSentinel: CRASH_SENTINEL,
    };
    if (connected.isolation.foreign.length > 0) {
      return finish({ ...base, status: 'BLOCKED', exitCode: 2, reason: 'foreign databases present' });
    }

    const crashSpawn = spawnSync(
      process.execPath,
      [
        __filename,
        '--role=crash',
        '--point=self-test',
        `--db=${dbName}`,
        `--uri=${uri}`,
        `--witness=${witness}`,
      ],
      { stdio: 'inherit' },
    );

    const verifierSpawn = spawnSync(
      process.execPath,
      [
        __filename,
        '--role=verifier',
        '--point=self-test',
        `--db=${dbName}`,
        `--uri=${uri}`,
        `--witness=${witness}`,
        `--out=${verifierOut}`,
      ],
      { stdio: 'inherit' },
    );

    const verifier = fs.existsSync(verifierOut) ? harness.readJsonFile(verifierOut) : null;
    const checks = {
      crashExitCodeIsSentinel: crashSpawn.status === CRASH_SENTINEL,
      verifierExitCodeZero: verifierSpawn.status === 0,
      markerDurableAfterCrash: verifier !== null && verifier.markerFound === true,
      nextStepNeverReached: fs.existsSync(witness) === false,
      distinctProcesses: verifier !== null && verifier.pid !== connected.topology.pid,
    };
    const failures = Object.entries(checks)
      .filter(([, passed]) => passed !== true)
      .map(([name]) => name);
    const report = {
      ...base,
      crashSpawn: { exitStatus: crashSpawn.status, error: crashSpawn.error ? String(crashSpawn.error.message) : null },
      verifierSpawn: { exitStatus: verifierSpawn.status, error: verifierSpawn.error ? String(verifierSpawn.error.message) : null },
      checks,
      failures,
      verifier,
      status: failures.length === 0 ? 'PASS' : 'HARNESS_FAIL',
      exitCode: failures.length === 0 ? 0 : 4,
      assertionPlan: {
        steps: [
          'child inserts a durable marker then exits with sentinel 7 before any second step',
          'a separate verifier process re-reads the durable marker',
        ],
        expected: ['sentinel exit observed', 'marker durable', 'next-step witness never written', 'distinct verifier process'],
      },
    };
    cleanup = await harness.dropOwnDatabase(connected.db, dbName);
    report.cleanup = cleanup;
    return finish(report);
  } catch (err) {
    return finish({
      check: 'crash-runner',
      point,
      db: dbName,
      status: 'HARNESS_FAIL',
      exitCode: 4,
      productClaim: false,
      reason: `${err.name}: ${err.message}`,
      cleanup,
    });
  } finally {
    if (client !== null) {
      await client.close().catch(() => {});
    }
  }
}

if (require.main === module) {
  const options = harness.parseArgs(process.argv.slice(2));
  if (options.role) {
    childMain(options).then(
      () => {},
      (err) => {
        process.stderr.write(`${err.stack ?? err.message}\n`);
        process.exitCode = 4;
      },
    );
  } else {
    runCrash(options).then(
      (report) => {
        process.exitCode = report.exitCode ?? 0;
      },
      (err) => {
        process.stdout.write(`${JSON.stringify({ check: 'crash-runner', status: 'HARNESS_FAIL', error: err.message })}\n`);
        process.exitCode = 4;
      },
    );
  }
}

module.exports = { CRASH_SENTINEL, POINT_PLANS, childMain, runCrash };
