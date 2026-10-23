'use strict';

/**
 * FRESH F13 TWO-OS-PROCESS CERTIFICATION (test-only, NEW FILE; PHASE1-LOCAL-AUTHORITY-001).
 *
 *   node tests/device/e1/f13-cert/run-f13-cert.cjs
 *
 * What it does, in this order:
 *   1. server-wide Mongo namespace audit BEFORE (raw driver, frozen URI);
 *   2. the EXISTING F13 two-OS-process row `T0A-01-SESSION-ABA-ISSUE-VS-APPROVE`
 *      (tests/device/e1/r2a-post-s1-clean1/fixtures-e2.cjs -> runAbaRow()), unmodified. Its
 *      artifact directory is REDIRECTED to this run's fresh evidence directory so no previously
 *      recorded evidence file is overwritten;
 *   3. the EXISTING E2 two-process product fixtures of the e1 suite
 *      (E2-T7 / E2-T8 / E2-V24T15) through the unmodified `runE1Fixture` dispatcher;
 *   4. namespace audit AFTER, then the fresh certification artifact.
 *
 * Honest reporting rules:
 *   - every fixture's own report is embedded verbatim in `artifacts/<fixture>.json`;
 *   - PID sets, attempt counts and outcomes are MACHINE-EXTRACTED from those reports, never
 *     hand-written;
 *   - the F13 row's own `status` is reported as observed. If its static evidence disagrees with
 *     the current product bytes, that disagreement is recorded as a stale-expectation note rather
 *     than silently rewritten (the fixture itself is NOT edited).
 */

const fs = require('node:fs');
const path = require('node:path');

const WORKTREE = path.resolve(__dirname, '..', '..', '..', '..');
const STAMP = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
const EVIDENCE_DIR = process.env.CBHR_F13_EVIDENCE_DIR
  ? path.resolve(process.env.CBHR_F13_EVIDENCE_DIR)
  : path.join(WORKTREE, 'tests', 'device', '_phase1_evidence', `f13-cert-${STAMP}`);
const RUN_KEY = process.env.CBHR_W3A_RUN_KEY ?? `f13-cert-${STAMP}`;
process.env.CBHR_W3A_RUN_KEY = RUN_KEY;

const fence = require('../w3a/fence.cjs');
const w3a = require('../w3a/support.cjs');
const fixtures = require('../fixtures.cjs');
const { runE1Fixture } = require('../run-e1.cjs');

const F13_ARTIFACTS_DIR = path.join(EVIDENCE_DIR, 'f13-artifacts');
const ARTIFACTS_DIR = path.join(EVIDENCE_DIR, 'artifacts');

const F13_ROW_ID = 'T0A-01-SESSION-ABA-ISSUE-VS-APPROVE';
const F13_CONTRACT_REF = 'F13/F18-A';
const F13_LAW_FIXTURE_ID = 'F13-LAW-SESSIONVERSION-ABA-TWO-PROCESS';
const E1_TWO_PROCESS_IDS = [
  'E2-T7-ONEPC-TWO-PC-RACE',
  'E2-T8-TWO-OWNERS-ONE-PC-RACE',
  'E2-V24T15-REVOKE-VS-CLAIM-RACE',
];

const PRODUCT_SOURCE_FILES = [
  'api/server/services/Device/authorityService.js',
  'api/server/services/Device/pairingSessionService.js',
  'api/server/services/Device/registrationService.js',
  'api/server/services/Device/crypto.js',
  'api/server/services/Device/errors.js',
  'packages/data-schemas/src/schema/deviceAuthority.ts',
  'packages/data-schemas/src/schema/pairingSession.ts',
];

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  return file;
}

function sha256Safe(file) {
  try {
    return w3a.sha256File(file);
  } catch {
    return null;
  }
}

function rel(absolute) {
  return path.relative(WORKTREE, absolute).replace(/\\/g, '/');
}

function gitHead() {
  if (typeof process.env.CBHR_GIT_HEAD === 'string' && /^[0-9a-f]{40}$/.test(process.env.CBHR_GIT_HEAD)) {
    return process.env.CBHR_GIT_HEAD;
  }
  try {
    const dotGit = path.join(WORKTREE, '.git');
    let gitDir = dotGit;
    if (fs.existsSync(dotGit) && fs.statSync(dotGit).isFile()) {
      // Linked worktree: `.git` is a file containing `gitdir: <path>`.
      const pointer = fs.readFileSync(dotGit, 'utf8').trim();
      const match = /^gitdir:\s*(.+)$/.exec(pointer);
      if (match === null) return null;
      gitDir = path.resolve(WORKTREE, match[1]);
    }
    // A linked worktree keeps HEAD locally but the refs (and packed-refs) in the common dir.
    const searchDirs = [gitDir];
    const commondirFile = path.join(gitDir, 'commondir');
    if (fs.existsSync(commondirFile)) {
      searchDirs.push(path.resolve(gitDir, fs.readFileSync(commondirFile, 'utf8').trim()));
    }
    const text = fs.readFileSync(path.join(gitDir, 'HEAD'), 'utf8').trim();
    if (/^[0-9a-f]{40}$/.test(text)) return text;
    const refMatch = /^ref:\s*(.+)$/.exec(text);
    if (refMatch === null) return null;
    const ref = refMatch[1];
    for (const dir of searchDirs) {
      const refPath = path.join(dir, ...ref.split('/'));
      if (fs.existsSync(refPath)) return fs.readFileSync(refPath, 'utf8').trim();
    }
    for (const dir of searchDirs) {
      const packed = path.join(dir, 'packed-refs');
      if (!fs.existsSync(packed)) continue;
      const line = fs
        .readFileSync(packed, 'utf8')
        .split('\n')
        .find((entry) => entry.endsWith(` ${ref}`));
      if (line !== undefined) return line.split(' ')[0];
    }
    return null;
  } catch {
    return null;
  }
}

async function namespaceSnapshot(label) {
  const { client, topology } = await fence.connectGuarded({
    dbName: fence.createDbName(`f13cert_${label}`),
    appName: `cbhr-phase1-f13cert-${label}`,
  });
  try {
    const names = await fence.listDatabaseNames();
    const build = await client.db('admin').command({ buildInfo: 1 });
    return {
      label,
      databases: names,
      foreign: names.filter(
        (name) => !['admin', 'local', 'config'].includes(name) && !name.startsWith('cbhr_rdc_phase1_'),
      ),
      ownedLeftovers: names.filter(
        (name) => name.startsWith('cbhr_rdc_phase1_') && !fence.PROTECTED_DATABASES.includes(name),
      ),
      protectedPresent: fence.PROTECTED_DATABASES.filter((name) => names.includes(name)),
      topology: { ...topology, serverVersion: build.version, mongoUri: fence.FROZEN_URI },
    };
  } finally {
    await client.close().catch(() => {});
  }
}

function auditNamespace(before, after) {
  const created = after.databases.filter((name) => !before.databases.includes(name));
  const removed = before.databases.filter((name) => !after.databases.includes(name));
  return {
    before: before.databases,
    after: after.databases,
    created,
    removed,
    ownedLeftoversAfter: after.ownedLeftovers,
    foreignAfter: after.foreign,
    ok:
      created.length === 0 &&
      removed.length === 0 &&
      after.ownedLeftovers.length === 0 &&
      after.foreign.length === 0,
  };
}

/** Machine-extracted per-fixture certification record for the e1 product two-process fixtures. */
function recordE1Fixture(fixture, report) {
  const childPids = Array.isArray(report.childPids) ? report.childPids : [];
  const spawned = Array.isArray(report.runnerPids) ? report.runnerPids : [];
  const attemptRecord = report.attempts ?? null;
  const processEvidence = report.processEvidence ?? null;
  return {
    fixtureId: fixture.id,
    contractRef: fixture.contractRef ?? null,
    tier: fixture.tier,
    runner: fixture.runner,
    kind: fixture.kind,
    status: report.status,
    exitCode: report.exitCode ?? null,
    productClaim: report.productClaim === true,
    dbName: report.dbName ?? null,
    pids: {
      runnerPid: report.runnerPid ?? null,
      spawnedChildPids: spawned,
      reportedChildPids: childPids,
      distinctChildPids: new Set(childPids.filter((pid) => typeof pid === 'number' && pid > 0)).size,
    },
    attempts: attemptRecord,
    outcome: {
      passedCount: report.passedCount ?? null,
      failedCount: report.failedCount ?? null,
      failedAssertionNames: Array.isArray(report.failedAssertions)
        ? report.failedAssertions.map((entry) => entry.name)
        : [],
      errorHistogram: report.realReturns ? report.realReturns.errorHistogram ?? null : null,
      winnerCount: report.realReturns ? report.realReturns.winnerCount ?? null : null,
      dbReadBack: report.dbReadBack ?? null,
      residualGap: report.residualGap ?? null,
      sequenceNote: report.sequenceNote ?? null,
      notes: report.notes ?? null,
    },
    processEvidence: processEvidence
      ? {
          transport: processEvidence.transport ?? null,
          stdio: processEvidence.stdio ?? null,
          exits: processEvidence.exits ?? null,
        }
      : null,
    cleanup: report.cleanup ?? null,
  };
}

/** Machine-extracted record for the F13 r2a row (different report shape). */
function recordF13Row(row) {
  const actual = row.actual ?? {};
  const childReports = Array.isArray(actual.childReports) ? actual.childReports : [];
  return {
    fixtureId: F13_ROW_ID,
    contractRef: row.contractRef ?? F13_CONTRACT_REF,
    tier: row.tier,
    tierExecuted: row.tierExecuted ?? null,
    runner: 'two-process (r2a-post-s1-clean1/child-aba.cjs)',
    kind: 'product',
    status: row.status,
    productClaim: row.productClaim === true,
    dbName: row.dbName ?? actual.dbName ?? null,
    blockedAtFactoryComposition: row.blockedAtFactoryComposition === true,
    expectedOracle: row.expectedOracle ?? null,
    pids: {
      reportedChildPids: Array.isArray(row.pids) ? row.pids : [],
      spawnedChildPids: childReports.map((entry) => entry.spawnPid),
      distinctOsPids: actual.distinctOsPids ?? null,
      pidsByRole: actual.pidsByRole ?? null,
    },
    attempts: {
      totalAttempts: actual.totalAttempts ?? row.attempts ?? null,
      minTotalAttemptsRequired: actual.minTotalAttemptsRequired ?? null,
      iterationsPerChild: actual.iterationsPerChild ?? null,
      productCallsAttempted: actual.productCallsAttempted ?? null,
      perChild: childReports.map((entry) => ({
        role: entry.role,
        pid: entry.reportedPid,
        spawnPid: entry.spawnPid,
        attempts: entry.attempts,
        compositionFailures: entry.compositionFailures,
        composedInSomeFactory: entry.composedInSomeFactory,
        productCallsAttempted: entry.productCallsAttempted,
        barrierReached: entry.barrierReached,
        peerReady: entry.peerReady,
        exit: entry.exit,
      })),
    },
    barrier: {
      credible: actual.barrierCredible ?? null,
      kind: actual.barrierKind ?? null,
      readyFiles: actual.readyFiles ?? null,
    },
    observedSessionAtBarrier: actual.observedSessionAtBarrier ?? null,
    components: (row.components ?? []).map((entry) => ({
      name: entry.name,
      met: entry.met,
      tier: entry.tier,
      actual: entry.actual,
    })),
    staticEvidence: actual.staticEvidence ?? null,
    registryShapePresent: Boolean(actual.registryShape),
    rawDriverDowngrade: actual.rawDriverDowngrade ?? null,
    artifactPath: row.artifactPath ?? null,
    artifactSha256: row.artifactSha256 ?? null,
  };
}

/** Flags an expectation that no longer matches the current product bytes (reported, never fixed). */
function f13StaleExpectationNotes(record) {
  const notes = [];
  const staticEvidence = record.staticEvidence;
  if (staticEvidence === null || staticEvidence === undefined) {
    notes.push('no static evidence block present in the row');
    return notes;
  }
  if (staticEvidence.sessionVersionSymbol && staticEvidence.sessionVersionSymbol.present === true) {
    notes.push(
      'the row reports sessionVersionSymbol.present = true (the anti-ABA fence symbol IS present in the current product bytes), while the row status/label still reads EXPECTED_RED and its hardcoded finding text describes pre-repair bytes: the fixture narrative is stale relative to HEAD, and the row does not evaluate the F13 oracle (its downstream oracle components are marked met:false, "not executed").',
    );
  }
  if (record.attempts.productCallsAttempted > 0) {
    notes.push(
      `product calls were attempted (${record.attempts.productCallsAttempted}) because genuine-model factory composition is now accepted, so the row is no longer blocked at composition — but it still does not assert the F13 sessionVersion law.`,
    );
  }
  return notes;
}

async function run() {
  fs.mkdirSync(ARTIFACTS_DIR, { recursive: true });
  fs.mkdirSync(F13_ARTIFACTS_DIR, { recursive: true });

  const startedAt = new Date().toISOString();
  const namespaceBefore = await namespaceSnapshot('before');
  const fixtureRecords = [];
  const runErrors = [];

  /* ---------------------------------------------------------------- 2. F13 row */
  let f13Record = null;
  let f13RawRow = null;
  try {
    // eslint-disable-next-line global-require, import/no-dynamic-require
    const r2aEnv = require('../r2a-post-s1-clean1/env.cjs');
    // eslint-disable-next-line global-require, import/no-dynamic-require
    const e2 = require('../r2a-post-s1-clean1/fixtures-e2.cjs');
    // Redirect the row's artifact sink into THIS fresh directory; the fixture bytes are untouched.
    r2aEnv.ARTIFACTS_DIR = F13_ARTIFACTS_DIR;
    const f13Started = Date.now();
    const { row } = await e2.runAbaRow();
    f13RawRow = row;
    f13Record = recordF13Row(row);
    f13Record.durationMs = Date.now() - f13Started;
    f13Record.staleExpectationNotes = f13StaleExpectationNotes(f13Record);
    fixtureRecords.push(f13Record);
    writeJson(path.join(ARTIFACTS_DIR, `${F13_ROW_ID}.json`), row);
  } catch (err) {
    runErrors.push({ stage: 'f13-row', error: `${err.name}: ${err.message}` });
    fixtureRecords.push({
      fixtureId: F13_ROW_ID,
      contractRef: F13_CONTRACT_REF,
      status: 'HARNESS_FAIL',
      error: `${err.name}: ${err.message}`,
      errorStack: String(err.stack ?? '').split('\n').slice(0, 8),
    });
  }

  /* ---------------------------------------------------------------- 3. F13 law evaluation (new) */
  try {
    // eslint-disable-next-line global-require, import/no-dynamic-require
    const f13Law = require('./f13-law.cjs');
    const lawStarted = Date.now();
    const lawReport = await f13Law.run({ rounds: 25 });
    const lawRecord = recordE1Fixture(
      {
        id: F13_LAW_FIXTURE_ID,
        contractRef: 'F13/F18-A (law evaluation; supplements T0A-01)',
        tier: 'E2',
        runner: 'two-process (f13-law.cjs + f13-law-child.cjs)',
        kind: 'product',
      },
      lawReport,
    );
    lawRecord.durationMs = Date.now() - lawStarted;
    lawRecord.supersededSessionCount = lawReport.realReturns ? lawReport.realReturns.supersededSessionCount : null;
    fixtureRecords.push(lawRecord);
    writeJson(path.join(ARTIFACTS_DIR, `${F13_LAW_FIXTURE_ID}.json`), lawReport);
  } catch (err) {
    runErrors.push({ stage: 'f13-law', error: `${err.name}: ${err.message}` });
    fixtureRecords.push({
      fixtureId: F13_LAW_FIXTURE_ID,
      contractRef: 'F13/F18-A (law evaluation; supplements T0A-01)',
      status: 'HARNESS_FAIL',
      error: `${err.name}: ${err.message}`,
    });
  }

  /* ---------------------------------------------------------------- 4. e1 two-process fixtures */
  for (const id of E1_TWO_PROCESS_IDS) {
    const fixture = fixtures.FIXTURES.find((entry) => entry.id === id);
    if (fixture === undefined) {
      runErrors.push({ stage: id, error: 'fixture id not present in fixtures.cjs' });
      continue;
    }
    try {
      // eslint-disable-next-line no-await-in-loop
      const report = await runE1Fixture(fixture, { n: 50, emit: false });
      const record = recordE1Fixture(fixture, report);
      record.durationMs = null;
      fixtureRecords.push(record);
      writeJson(path.join(ARTIFACTS_DIR, `${id}.json`), report);
    } catch (err) {
      runErrors.push({ stage: id, error: `${err.name}: ${err.message}` });
      fixtureRecords.push({
        fixtureId: id,
        contractRef: fixture.contractRef ?? null,
        status: 'HARNESS_FAIL',
        error: `${err.name}: ${err.message}`,
      });
    }
  }

  /* ---------------------------------------------------------------- 4. namespace + artifact */
  const namespaceAfter = await namespaceSnapshot('after');
  const namespaceAudit = auditNamespace(namespaceBefore, namespaceAfter);

  const statuses = fixtureRecords.map((entry) => entry.status);
  const harnessFailures = statuses.filter((status) => status === 'HARNESS_FAIL');
  const productFailures = statuses.filter((status) =>
    ['PRODUCT_FAIL', 'UNEXPECTED_RED'].includes(status),
  );
  /* A fresh certification artifact: every fixture is recorded as observed. `CERTIFIED_AS_OBSERVED`
     means the run itself was sound (no harness failure, namespace unchanged), NOT that every
     fixture was green — the per-fixture statuses carry that. */
  let status;
  let exitCode;
  if (namespaceAudit.ok !== true || harnessFailures.length > 0 || runErrors.length > 0) {
    status = 'HARNESS_FAIL';
    exitCode = 4;
  } else if (productFailures.length > 0) {
    status = 'PRODUCT_FAIL';
    exitCode = 5;
  } else {
    status = 'CERTIFIED_AS_OBSERVED';
    exitCode = 0;
  }

  const summary = {
    check: 'F13-TWO-PROCESS-CERTIFICATION',
    contractRef: F13_CONTRACT_REF,
    certificationOf: F13_ROW_ID,
    runKey: RUN_KEY,
    command: 'node tests/device/e1/f13-cert/run-f13-cert.cjs',
    evidenceDir: rel(EVIDENCE_DIR),
    status,
    exitCode,
    counts: {
      fixtures: fixtureRecords.length,
      harnessFail: harnessFailures.length,
      productFail: productFailures.length,
      errors: runErrors.length,
    },
    fixtureStatuses: fixtureRecords.map((entry) => ({ fixtureId: entry.fixtureId, status: entry.status })),
    fixtures: fixtureRecords,
    f13: f13Record,
    f13StaleExpectationNotes: f13Record ? f13Record.staleExpectationNotes ?? [] : [],
    runErrors,
    namespaceAudit,
    staticFenceEvidenceAtHead: f13Record ? f13Record.staticEvidence : null,
    startedAt,
    finishedAt: new Date().toISOString(),
    runDir: w3a.runDir(),
  };

  writeJson(path.join(EVIDENCE_DIR, 'F13-CERT-RESULTS.json'), summary);
  writeJson(path.join(EVIDENCE_DIR, 'F13-CERT-NAMESPACE-BEFORE.json'), namespaceBefore);
  writeJson(path.join(EVIDENCE_DIR, 'F13-CERT-NAMESPACE-AFTER.json'), namespaceAfter);
  writeJson(path.join(EVIDENCE_DIR, 'F13-CERT-RUN-META.json'), {
    command: summary.command,
    runKey: RUN_KEY,
    runDir: w3a.runDir(),
    evidenceDir: rel(EVIDENCE_DIR),
    f13ArtifactsDir: rel(F13_ARTIFACTS_DIR),
    runnerPid: process.pid,
    gitHead: gitHead(),
    node: process.version,
    mongo: namespaceBefore.topology,
    productSourceHashes: PRODUCT_SOURCE_FILES.map((relative) => ({
      path: relative,
      sha256: sha256Safe(path.join(WORKTREE, ...relative.split('/'))),
    })),
    fixtureIds: [F13_ROW_ID, F13_LAW_FIXTURE_ID, ...E1_TWO_PROCESS_IDS],
  });

  const written = fixtureRecords
    .map((entry) => path.join(ARTIFACTS_DIR, `${entry.fixtureId}.json`))
    .filter((file) => fs.existsSync(file))
    .map((file) => ({ path: rel(file), sha256: sha256Safe(file) }));
  writeJson(path.join(EVIDENCE_DIR, 'F13-CERT-FILE-HASHES.json'), {
    artifacts: written,
    results: sha256Safe(path.join(EVIDENCE_DIR, 'F13-CERT-RESULTS.json')),
    namespaceBefore: sha256Safe(path.join(EVIDENCE_DIR, 'F13-CERT-NAMESPACE-BEFORE.json')),
    namespaceAfter: sha256Safe(path.join(EVIDENCE_DIR, 'F13-CERT-NAMESPACE-AFTER.json')),
    runMeta: sha256Safe(path.join(EVIDENCE_DIR, 'F13-CERT-RUN-META.json')),
  });

  return summary;
}

if (require.main === module) {
  run().then(
    (summary) => {
      process.stdout.write(`${JSON.stringify(summary)}\n`);
      process.exitCode = summary.exitCode ?? 0;
    },
    (err) => {
      process.stdout.write(
        `${JSON.stringify({ check: 'F13-TWO-PROCESS-CERTIFICATION', status: 'HARNESS_FAIL', error: err.message })}\n`,
      );
      process.exitCode = 4;
    },
  );
}

module.exports = { run, EVIDENCE_DIR, F13_ROW_ID, E1_TWO_PROCESS_IDS };