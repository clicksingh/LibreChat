'use strict';

/**
 * Standalone two-clock skew runner (test-only, new file; PHASE1-LOCAL-AUTHORITY-001).
 *
 *   node tests/device/e1/skew/run-skew.cjs --fixture=all --evidence-dir=tests/device/_phase1_evidence/<dir>
 *   node tests/device/e1/skew/run-skew.cjs --fixture=SKEW-01-FAST-WRITER-OVER-RELEASE
 *
 * Each fixture runs in its own self-owned `cbhr_rdc_phase1_w3_*` database, dropped in `finally`
 * (fixture-skew.cjs). The runner audits the server namespace before and after and refuses to
 * report success when the namespace changed.
 *
 * Honest reporting: the treatment arm asserts the DESIRED LAW (a lease live on the reference
 * timeline must not be transitioned by a skewed writer), so a reproduced counterexample surfaces
 * as PRODUCT_FAIL / exit 5 with the exact trace — never as a weakened pass.
 */

const fs = require('node:fs');
const path = require('node:path');

const fixtures = require('./fixture-skew.cjs');
const support = require('../w3a/support.cjs');
const env = require('../w3a/env.cjs');

const WORKTREE = path.resolve(__dirname, '..', '..', '..', '..');

/** Every artifact this runner writes lives under tests/device/_phase1_evidence/**. */
const RUN_KEY =
  process.env.CBHR_W3A_RUN_KEY ?? `skew-${new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 15)}`;
process.env.CBHR_W3A_RUN_KEY = RUN_KEY;

const PRODUCT_SOURCE_FILES = [
  'api/server/services/Device/authorityService.js',
  'api/server/services/Device/pairingSessionService.js',
  'api/server/services/Device/registrationService.js',
  'api/server/services/Device/crypto.js',
  'api/server/services/Device/errors.js',
  'packages/data-schemas/src/schema/deviceAuthority.ts',
  'packages/data-schemas/src/schema/pairingSession.ts',
];

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

function hashProductFiles() {
  return PRODUCT_SOURCE_FILES.map((relative) => {
    const absolute = path.join(WORKTREE, ...relative.split('/'));
    let sha256 = null;
    try {
      sha256 = support.sha256File(absolute);
    } catch {
      sha256 = null;
    }
    return { path: relative, sha256 };
  });
}

async function topology() {
  const { client, topology: observed } = await support.fence.connectGuarded({
    dbName: support.fence.createDbName('skew_meta_probe'),
    appName: 'cbhr-phase1-skew-meta',
  });
  try {
    const build = await client.db('admin').command({ buildInfo: 1 });
    return { ...observed, serverVersion: build.version, mongoUri: support.fence.FROZEN_URI };
  } finally {
    await client.close().catch(() => {});
  }
}

async function isolationAudit() {
  const { client } = await support.fence.connectGuarded({
    dbName: support.fence.createDbName('skew_audit_probe'),
    appName: 'cbhr-phase1-skew-audit',
  });
  try {
    const names = await support.fence.listDatabaseNames();
    return {
      databases: names,
      foreign: names.filter((name) => !['admin', 'local', 'config'].includes(name) && !name.startsWith('cbhr_rdc_phase1_')),
      leftoverOwnDatabases: names.filter(
        (name) => name.startsWith('cbhr_rdc_phase1_') && !support.fence.PROTECTED_DATABASES.includes(name),
      ),
      protectedPresent: support.fence.PROTECTED_DATABASES.filter((name) => names.includes(name)),
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
    leftoverOwnDatabases: after.leftoverOwnDatabases,
    foreignAfter: after.foreign,
    ok:
      created.length === 0 &&
      removed.length === 0 &&
      after.leftoverOwnDatabases.length === 0 &&
      after.foreign.length === 0,
  };
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  return file;
}

/* ------------------------------------------------------------------ run */

async function runSkew(options = {}) {
  const requested = options.fixture ?? 'all';
  const selected =
    requested === 'all' ? fixtures.FIXTURES : fixtures.FIXTURES.filter((entry) => entry.id === requested);
  if (selected.length === 0) {
    throw new Error(`unknown skew fixture ${requested}`);
  }

  const namespaceBefore = await isolationAudit().catch((err) => ({
    error: `${err.name}: ${err.message}`,
    databases: [],
  }));

  const results = [];
  for (const fixture of selected) {
    let report;
    try {
      // eslint-disable-next-line no-await-in-loop
      report = await fixtures.run(fixture);
    } catch (err) {
      report = {
        id: fixture.id,
        status: 'HARNESS_FAIL',
        exitCode: 4,
        productClaim: false,
        error: `${err.name}: ${err.message}`,
      };
    }
    results.push({
      id: fixture.id,
      tier: 'E2',
      kind: 'skew',
      status: report.status,
      exitCode: report.exitCode,
      productClaim: report.productClaim === true,
      findingRecorded: report.findingRecorded === true,
      counterexampleReproduced: report.finding ? report.finding.counterexampleReproduced ?? null : null,
      report,
    });
  }

  const isolation = await isolationAudit().catch((err) => ({ error: `${err.name}: ${err.message}` }));
  const namespaceAudit = auditNamespace(namespaceBefore, isolation);
  let status;
  let exitCode;
  if (namespaceAudit.ok !== true || results.some((entry) => entry.status === 'HARNESS_FAIL')) {
    status = 'HARNESS_FAIL';
    exitCode = 4;
  } else if (results.some((entry) => entry.status === 'PRODUCT_FAIL')) {
    status = 'PRODUCT_FAIL';
    exitCode = 5;
  } else if (results.every((entry) => entry.status === 'PASS')) {
    status = 'PASS';
    exitCode = 0;
  } else {
    status = 'UNEXPECTED_STATUS';
    exitCode = 4;
  }

  const aggregate = {
    check: 'SKEW-TWO-CLOCK',
    tier: 'E2',
    fixtureSelection: requested,
    runKey: RUN_KEY,
    runDir: support.runDir(),
    command:
      'node tests/device/e1/skew/run-skew.cjs ' +
      (requested === 'all' ? '--fixture=all' : `--fixture=${requested}`),
    status,
    exitCode,
    productClaim: false,
    counts: {
      total: results.length,
      productFail: results.filter((entry) => entry.status === 'PRODUCT_FAIL').length,
      harnessFail: results.filter((entry) => entry.status === 'HARNESS_FAIL').length,
      pass: results.filter((entry) => entry.status === 'PASS').length,
      findings: results.filter((entry) => entry.counterexampleReproduced === true).length,
    },
    findingIds: results.filter((entry) => entry.counterexampleReproduced === true).map((entry) => entry.id),
    failureIds: results.filter((entry) => entry.status !== 'PASS').map((entry) => entry.id),
    isolation,
    namespaceAudit,
    results,
    finishedAt: new Date().toISOString(),
  };

  if (options['evidence-dir']) {
    const dir = path.isAbsolute(options['evidence-dir'])
      ? options['evidence-dir']
      : path.join(WORKTREE, options['evidence-dir']);
    const artifacts = path.join(dir, 'artifacts');
    fs.mkdirSync(artifacts, { recursive: true });
    writeJson(path.join(dir, 'SKEW-RESULTS.json'), aggregate);
    writeJson(path.join(dir, 'SKEW-NAMESPACE-BEFORE.json'), namespaceBefore);
    writeJson(path.join(dir, 'SKEW-NAMESPACE-AFTER.json'), isolation);
    writeJson(path.join(dir, 'SKEW-RUN-META.json'), {
      command: aggregate.command,
      runKey: RUN_KEY,
      runDir: support.runDir(),
      evidenceDir: path.relative(WORKTREE, dir).replace(/\\/g, '/'),
      runnerPid: process.pid,
      gitHead: gitHead(),
      node: process.version,
      mongo: await topology().catch((err) => ({ error: `${err.name}: ${err.message}` })),
      productSourceHashes: hashProductFiles(),
      injectedClockBase: env.constants.EPOCH_BASE_MS,
      constants: {
        deltaMs: require('./skew-constants.cjs').DELTA_MS,
        epsilonMs: require('./skew-constants.cjs').EPSILON_MS,
        skewMarginMs: require('./skew-constants.cjs').SKEW_MARGIN_MS,
        leaseTtlMs: require('./skew-constants.cjs').LEASE_TTL_MS,
        sweepGridMs: require('./skew-constants.cjs').SWEEP_GRID_MS,
      },
    });
    const written = [];
    for (const entry of results) {
      const file = writeJson(path.join(artifacts, `${entry.id}.json`), entry.report);
      written.push({ path: path.relative(WORKTREE, file).replace(/\\/g, '/'), sha256: support.sha256File(file) });
    }
    writeJson(path.join(dir, 'SKEW-FILE-HASHES.json'), {
      artifacts: written,
      results: support.sha256File(path.join(dir, 'SKEW-RESULTS.json')),
      namespaceBefore: support.sha256File(path.join(dir, 'SKEW-NAMESPACE-BEFORE.json')),
      namespaceAfter: support.sha256File(path.join(dir, 'SKEW-NAMESPACE-AFTER.json')),
      runMeta: support.sha256File(path.join(dir, 'SKEW-RUN-META.json')),
    });
    aggregate.evidenceDir = path.relative(WORKTREE, dir).replace(/\\/g, '/');
  }

  if (options['result-out']) {
    writeJson(options['result-out'], aggregate);
  }
  if (options.emit !== false) {
    process.stdout.write(`${JSON.stringify(aggregate)}\n`);
  }
  return aggregate;
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
  runSkew(options).then(
    (report) => {
      process.exitCode = report.exitCode ?? 0;
    },
    (err) => {
      process.stdout.write(`${JSON.stringify({ check: 'SKEW-TWO-CLOCK', status: 'HARNESS_FAIL', error: err.message })}\n`);
      process.exitCode = 4;
    },
  );
}

module.exports = { runSkew, RUN_KEY, WORKTREE };