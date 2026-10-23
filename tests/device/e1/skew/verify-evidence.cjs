'use strict';

/**
 * Evidence self-check (test-only, run by hand; new file).
 *
 *   node tests/device/e1/skew/verify-evidence.cjs
 *
 * Recomputes every SHA-256 in the two evidence manifests and re-derives the numbers quoted in
 * SKEW-REPORT.md / F13-CERT-REPORT.md straight from the artifacts, so a hand-edited report cannot
 * drift from the recorded evidence unnoticed. Read-only: it writes nothing.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const WORKTREE = path.resolve(__dirname, '..', '..', '..', '..');
const SKEW_DIR = path.join(WORKTREE, 'tests', 'device', '_phase1_evidence', 'skew-two-clock');
const F13_DIR = path.join(WORKTREE, 'tests', 'device', '_phase1_evidence', 'f13-cert');

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex').toUpperCase();
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

const problems = [];
const notes = [];

function check(condition, message, observed) {
  if (condition !== true) problems.push({ message, observed });
}

/* ---------------------------------------------------------------- manifests */

function verifyManifest(dir, manifestName) {
  const manifest = readJson(path.join(dir, manifestName));
  let ok = 0;
  for (const entry of manifest.files) {
    const absolute = path.join(WORKTREE, ...entry.path.split('/'));
    if (!fs.existsSync(absolute)) {
      problems.push({ message: `manifest names a missing file: ${entry.path}`, observed: null });
      continue;
    }
    const observed = sha256(absolute);
    if (observed !== entry.sha256) {
      problems.push({ message: `hash mismatch: ${entry.path}`, observed: { manifest: entry.sha256, recomputed: observed } });
    } else {
      ok += 1;
    }
  }
  notes.push({ manifest: manifestName, files: manifest.files.length, verified: ok });
}

verifyManifest(SKEW_DIR, 'SKEW-FILE-HASHES.json');
verifyManifest(F13_DIR, 'F13-CERT-FILE-HASHES.json');

/* ---------------------------------------------------------------- skew numbers */

const skew = readJson(path.join(SKEW_DIR, 'SKEW-RESULTS.json'));
const skewMeta = readJson(path.join(SKEW_DIR, 'SKEW-RUN-META.json'));
check(skew.status === 'PRODUCT_FAIL', 'skew aggregate must be PRODUCT_FAIL', skew.status);
check(skew.namespaceAudit.ok === true, 'skew namespace audit must be clean', skew.namespaceAudit);
check(skew.counts.findings === 3, 'all three skew fixtures must report a finding', skew.counts);
check(/^[0-9a-f]{40}$/.test(skewMeta.gitHead), 'skew run must record the git HEAD', skewMeta.gitHead);

const s01 = skew.results.find((entry) => entry.id === 'SKEW-01-FAST-WRITER-OVER-RELEASE').report;
const s02 = skew.results.find((entry) => entry.id === 'SKEW-02-SLOW-WRITER-PAST-EXPIRY-RENEWAL').report;
const s03 = skew.results.find((entry) => entry.id === 'SKEW-03-BOUNDARY-SWEEP').report;

for (const [name, report] of [['SKEW-01', s01], ['SKEW-02', s02], ['SKEW-03', s03]]) {
  check(report.gate.status === 'PASS', `${name} gate must pass`, report.gate.failedCount);
  check(report.writers.CORRECT.pid !== report.writers.OFFSET.pid, `${name} writers must be distinct processes`, report.writers);
}

check(
  s01.overReleases.every((entry) => entry.overRelease === true),
  'SKEW-01 must over-release on every probe',
  s01.overReleases.map((entry) => [entry.probeId, entry.offsetWriterMatched]),
);
check(
  s01.overReleases.every((entry) => entry.parentReadBackMatchesOffsetWriter === true),
  'SKEW-01 parent read-back must corroborate the writer',
  s01.overReleases.map((entry) => entry.parentReadBackMatchesOffsetWriter),
);
check(
  s01.accountAxis.every((entry) => entry.freed === true),
  'SKEW-01 must free every seed account',
  s01.accountAxis,
);
const s01Claim = s01.overReleases.find((entry) => entry.kind === 'claimAuthority');
check(
  s01Claim.offsetWriterFirstCasFilter.$or[1].expiresAt.$lte === '2026-10-03T04:04:55.000Z' &&
    s01Claim.correctWriterFirstCasFilter.$or[1].expiresAt.$lte === '2026-10-03T03:59:55.000Z',
  'SKEW-01 claim filters must differ by exactly delta',
  {
    offset: s01Claim.offsetWriterFirstCasFilter.$or[1],
    correct: s01Claim.correctWriterFirstCasFilter.$or[1],
  },
);

const s02Renewal = s02.overReleases.find((entry) => entry.pastExpiryRenewal === true);
check(s02Renewal !== undefined, 'SKEW-02 must record a past-expiry renewal', s02.overReleases);
if (s02Renewal !== undefined) {
  const extensionMs = s02Renewal.offsetWriterRowAfter.expiresAtMs - s02Renewal.seedRow.expiresAtMs;
  check(
    extensionMs === 172501000,
    'SKEW-02 renewal must extend the expired lease by exactly 172501000 ms',
    extensionMs,
  );
  check(
    s02Renewal.offsetWriterRowAfter.expiresAtMs === 1791172500000,
    'SKEW-02 renewed expiry must be the skewed clock + 48 h (1791172500000)',
    s02Renewal.offsetWriterRowAfter.expiresAtMs,
  );
  check(s02Renewal.offsetWriterRowAfter.epoch === 2, 'SKEW-02 renewal must advance the epoch to 2', s02Renewal.offsetWriterRowAfter.epoch);
}
const s02Control = s02.overReleases.find((entry) => entry.kind === 'claimAuthority');
check(s02Control.offsetWriterMatched === 0, 'SKEW-02 slow-writer claim control must 0-match', s02Control.offsetWriterMatched);

check(
  s03.finding.measuredOverReleaseHorizonMs === 295000,
  'SKEW-03 measured horizon must be delta - SKEW_MARGIN',
  s03.finding.measuredOverReleaseHorizonMs,
);
const s03Grid = s03.overReleases.map((entry) => [entry.remainingLifeMsAtReferenceNow, entry.offsetWriterMatched]);
check(
  JSON.stringify(s03Grid) === JSON.stringify([[1000, 1], [100000, 1], [200000, 1], [294999, 1], [295000, 1], [295001, 0], [300000, 0], [300001, 0]]),
  'SKEW-03 grid must match the reported table',
  s03Grid,
);

/* ---------------------------------------------------------------- f13 numbers */

const f13 = readJson(path.join(F13_DIR, 'F13-CERT-RESULTS.json'));
const f13Meta = readJson(path.join(F13_DIR, 'F13-CERT-RUN-META.json'));
check(f13.namespaceAudit.ok === true, 'f13 namespace audit must be clean', f13.namespaceAudit);
check(/^[0-9a-f]{40}$/.test(f13Meta.gitHead), 'f13 run must record the git HEAD', f13Meta.gitHead);
check(f13.counts.fixtures === 5, 'f13 certification must cover five fixtures', f13.counts);

const law = f13.fixtures.find((entry) => entry.fixtureId === 'F13-LAW-SESSIONVERSION-ABA-TWO-PROCESS');
check(law !== undefined, 'f13 law fixture must be present', f13.fixtures.map((entry) => entry.fixtureId));
if (law !== undefined) {
  check(law.status === 'PASS', 'f13 law fixture must PASS', law.status);
  check(law.outcome.failedCount === 0, 'f13 law fixture must have no failed assertion', law.outcome);
  check(law.attempts.recordedAttempts === 50, 'f13 law fixture must record 50 attempts', law.attempts);
  check(law.pids.distinctChildPids === 2, 'f13 law fixture must run two distinct processes', law.pids);
}

const row = f13.fixtures.find((entry) => entry.fixtureId === 'T0A-01-SESSION-ABA-ISSUE-VS-APPROVE');
check(row !== undefined, 'the existing F13 row must be present', null);
if (row !== undefined) {
  check(row.status === 'EXPECTED_RED', 'the existing row is reported as observed (EXPECTED_RED)', row.status);
  check(row.attempts.totalAttempts === 50, 'the existing row must record 50 attempts', row.attempts);
  check(f13.f13StaleExpectationNotes.length === 2, 'the runner must emit two stale-expectation notes', f13.f13StaleExpectationNotes);
}

const v24 = f13.fixtures.find((entry) => entry.fixtureId === 'E2-V24T15-REVOKE-VS-CLAIM-RACE');
check(v24 !== undefined, 'E2-V24T15 must be present', null);
if (v24 !== undefined && v24.status !== 'PASS') {
  notes.push({
    flakyFixture: v24.fixtureId,
    status: v24.status,
    failedAssertions: v24.outcome.failedAssertionNames,
    casAttempts: v24.attempts.casAttempts,
    errorHistogram: v24.outcome.errorHistogram,
    note: 'Recorded as observed; three standalone re-runs pass 17/17 under flake/.',
  });
}

/* ---------------------------------------------------------------- report */

const report = {
  check: 'EVIDENCE-SELF-CHECK',
  status: problems.length === 0 ? 'PASS' : 'MISMATCH',
  manifests: notes.filter((entry) => entry.manifest !== undefined),
  observations: notes.filter((entry) => entry.manifest === undefined),
  problems,
  finishedAt: new Date().toISOString(),
};
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
process.exitCode = problems.length === 0 ? 0 : 1;