'use strict';

/**
 * Evidence self-check (test-only, run by hand; PHASE1-LOCAL-AUTHORITY-001).
 *
 *   node tests/device/e1/skew/verify-evidence.cjs [--dir=tests/device/_phase1_evidence/skew-rebased]
 *
 * Recomputes every SHA-256 in the skew evidence manifests and re-derives the numbers quoted in
 * SKEW-RESULTS.json / SKEW-RUN-META.json straight from the artifacts, so a hand-edited report
 * cannot drift from the recorded evidence unnoticed. Read-only: it writes nothing.
 *
 * What this check pins for GM-69 (the re-basing):
 *   - all three fixtures PASS with zero violations (no over-release, no margin violation,
 *     no past-expiry renewal) and a green CONTROL arm;
 *   - the run proved no anchor seam (`predicateAnchorMode === 'database'` everywhere, and no
 *     writer reports an injected anchor);
 *   - the reference timeline is a database-clock instant (one shared referenceNowMs per fixture,
 *     reached by both writers, with the writer clocks carrying exactly their injected offsets and
 *     failing the anti-vacuity gate otherwise);
 *   - namespace before == after with zero leftover fixture databases.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const WORKTREE = path.resolve(__dirname, '..', '..', '..', '..');

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

const options = parseArgs(process.argv.slice(2));
const SKEW_DIR = path.isAbsolute(options.dir ?? '')
  ? options.dir
  : path.join(WORKTREE, options.dir ?? 'tests/device/_phase1_evidence/skew-two-clock');

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex').toUpperCase();
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

const problems = [];
const notes = [];

function check(condition, message, observed) {
  if (condition !== true) problems.push({ message, observed: observed === undefined ? null : observed });
}

/* ---------------------------------------------------------------- manifests */

const skew = readJson(path.join(SKEW_DIR, 'SKEW-RESULTS.json'));
const skewMeta = readJson(path.join(SKEW_DIR, 'SKEW-RUN-META.json'));

const manifest = readJson(path.join(SKEW_DIR, 'SKEW-FILE-HASHES.json'));
let manifestVerified = 0;
for (const entry of manifest.artifacts) {
  const absolute = path.join(WORKTREE, ...entry.path.split('/'));
  if (!fs.existsSync(absolute)) {
    problems.push({ message: `manifest names a missing file: ${entry.path}` });
    continue;
  }
  if (sha256(absolute) !== entry.sha256) {
    problems.push({ message: `hash mismatch: ${entry.path}` });
  } else {
    manifestVerified += 1;
  }
}
notes.push({ manifest: manifest.artifacts.length, verified: manifestVerified });

/* ---------------------------------------------------------------- aggregate */

check(skew.status === 'PASS', 'skew aggregate must be PASS in database mode', skew.status);
check(skew.exitCode === 0, 'skew aggregate must exit 0', skew.exitCode);
check(
  skew.counts.total === 3 && skew.counts.pass === 3 && skew.counts.findings === 0,
  'all three fixtures must PASS with zero findings',
  skew.counts,
);
check(skewMeta.predicateAnchorMode === 'database', 'run meta must pin database mode', skewMeta.predicateAnchorMode);
check(skewMeta.voidAsSkewEvidence === false, 'a database-mode run must not be marked VOID', skewMeta.voidAsSkewEvidence);
check(/^[0-9a-f]{40}$/.test(skewMeta.gitHead), 'skew run must record the git HEAD', skewMeta.gitHead);
check(skew.namespaceAudit.ok === true, 'skew namespace audit must be clean', skew.namespaceAudit);
check(
  Array.isArray(skew.namespaceAudit.before) &&
    Array.isArray(skew.namespaceAudit.after) &&
    skew.namespaceAudit.before.length === skew.namespaceAudit.after.length,
  'namespace before must equal namespace after',
  { before: skew.namespaceAudit.before, after: skew.namespaceAudit.after },
);
check(
  Array.isArray(skewMeta.oracleSourceHashes) && skewMeta.oracleSourceHashes.length === 4,
  'run meta must bind the oracle source hashes',
  skewMeta.oracleSourceHashes,
);
for (const entry of skewMeta.oracleSourceHashes ?? []) {
  const absolute = path.join(WORKTREE, ...entry.path.split('/'));
  if (!fs.existsSync(absolute)) {
    problems.push({ message: `oracle manifest names a missing file: ${entry.path}` });
    continue;
  }
  if (sha256(absolute) !== entry.sha256) {
    problems.push({
      message: `oracle source drifted since this evidence run: ${entry.path}`,
      observed: { recorded: entry.sha256, current: sha256(absolute) },
    });
  }
}
check(
  Array.isArray(skewMeta.referenceTimeline) &&
    skewMeta.referenceTimeline.length === 3 &&
    skewMeta.referenceTimeline.every(
      (entry) =>
        typeof entry.referenceNowMs === 'number' &&
        entry.correctWriterAnchorMode === 'database' &&
        entry.offsetWriterAnchorMode === 'database' &&
        entry.correctWriterAnchorSeamSupplied === false &&
        entry.offsetWriterAnchorSeamSupplied === false,
    ),
  'every fixture must record a database-clock reference instant reached by both writers with no anchor seam',
  skewMeta.referenceTimeline,
);

for (const entry of skew.results) {
  const report = entry.report;
  check(entry.status === 'PASS', `${entry.id} must PASS`, entry.status);
  check(report.gate.status === 'PASS', `${entry.id} gate must PASS`, report.gate);
  check(report.desiredLaw.status === 'PASS', `${entry.id} law must PASS`, report.desiredLaw);
  check(
    report.writers.CORRECT.pid !== report.writers.OFFSET.pid,
    `${entry.id} writers must be distinct processes`,
    [report.writers.CORRECT.pid, report.writers.OFFSET.pid],
  );
  check(
    report.writers.CORRECT.anchorSeamSupplied === false && report.writers.OFFSET.anchorSeamSupplied === false,
    `${entry.id} writers must run without an injected anchor`,
    [report.writers.CORRECT.predicateAnchorMode, report.writers.OFFSET.predicateAnchorMode],
  );
  check(
    typeof report.plan.referenceNowMs === 'number',
    `${entry.id} must report its database-clock reference instant`,
    report.plan.referenceNowMs,
  );
  check(
    report.finding.counterexampleReproduced === false &&
      report.finding.overReleases.length === 0 &&
      report.finding.marginViolations.length === 0 &&
      report.finding.pastExpiryRenewals.length === 0,
    `${entry.id} must record zero violations`,
    {
      reproduced: report.finding.counterexampleReproduced,
      overReleases: report.finding.overReleases.length,
      marginViolations: report.finding.marginViolations.length,
      pastExpiryRenewals: report.finding.pastExpiryRenewals.length,
    },
  );
  check(
    Array.isArray(report.overReleases) && report.overReleases.every((probe) => probe.overRelease !== true),
    `${entry.id} must show no over-release in the treatment grid`,
    report.overReleases.map((probe) => [probe.probeId, probe.overRelease]),
  );
  check(
    report.finding.measuredOverReleaseHorizonMs === null,
    `${entry.id} measured horizon must be empty in database mode`,
    report.finding.measuredOverReleaseHorizonMs,
  );
}

const s03 = skew.results.find((entry) => entry.id === 'SKEW-03-BOUNDARY-SWEEP');
if (s03 === undefined) {
  problems.push({ message: 'SKEW-03 is missing from the results' });
} else {
  const grid = s03.report.overReleases.map((entry) => [
    entry.remainingLifeMsAtReferenceNow,
    entry.offsetWriterMatched,
  ]);
  check(
    JSON.stringify(grid) ===
      JSON.stringify([
        [1000, 0],
        [100000, 0],
        [200000, 0],
        [294999, 0],
        [295000, 0],
        [295001, 0],
        [300000, 0],
        [300001, 0],
        [-1000, 0],
        [-5000, 1],
        [-5001, 1],
        [-300001, 1],
      ]),
    'SKEW-03 grid must refuse every live/inside-margin row and transition every row lapsed past the margin',
    grid,
  );
}

const s02 = skew.results.find((entry) => entry.id === 'SKEW-02-SLOW-WRITER-PAST-EXPIRY-RENEWAL');
if (s02 === undefined) {
  problems.push({ message: 'SKEW-02 is missing from the results' });
} else {
  check(
    s02.report.finding.pastExpiryRenewals.length === 0,
    'SKEW-02 must accept no renewal past true expiry',
    s02.report.finding.pastExpiryRenewals,
  );
}

/* ---------------------------------------------------------------- report */

const report = {
  check: 'EVIDENCE-SELF-CHECK',
  dir: path.relative(WORKTREE, SKEW_DIR).replace(/\\/g, '/'),
  status: problems.length === 0 ? 'PASS' : 'MISMATCH',
  manifests: notes,
  problems,
  finishedAt: new Date().toISOString(),
};
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
process.exitCode = problems.length === 0 ? 0 : 1;
