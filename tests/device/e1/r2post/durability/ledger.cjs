'use strict';

/**
 * W3-B R2 S4T result ledger (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Truthfulness rules encoded as code:
 *   - the status vocabulary is exactly PASS_CURRENT / EXPECTED_RED / UNEXPECTED_GREEN /
 *     HARNESS_FAIL / ENV_BLOCKED;
 *   - every row is validated against a fixed key set, and a row's status is derived from its own
 *     observations, never hard-coded;
 *   - EXPECTED_RED requires a non-null `actual` and `productMethodInvoked === true`;
 *   - a setup/substrate failure can only be HARNESS_FAIL, never a red finding;
 *   - an expected PASS_CURRENT row whose assertions fail is HARNESS_FAIL, never a red finding.
 */

const fs = require('node:fs');
const path = require('node:path');

const DURABILITY_DIR = __dirname;
const ARTIFACT_DIR = path.join(DURABILITY_DIR, 'artifacts');

const STATUS = Object.freeze({
  PASS_CURRENT: 'PASS_CURRENT',
  EXPECTED_RED: 'EXPECTED_RED',
  UNEXPECTED_GREEN: 'UNEXPECTED_GREEN',
  HARNESS_FAIL: 'HARNESS_FAIL',
  ENV_BLOCKED: 'ENV_BLOCKED',
});

const ROW_KEYS = Object.freeze([
  'id',
  'tier',
  'status',
  'authorizedStatus',
  'matchesAuthorizedState',
  'productMethodInvoked',
  'expectedOracle',
  'repairPredicate',
  'components',
  'actual',
  'dbName',
  'dbDropped',
  'dbReadBack',
  'sourceHashes',
]);

/** Authorized pre-repair states from GOVERNOR-W3B-R2-S4T-DURABILITY-TEST-AUTHORIZATION-20261015. */
const AUTHORIZED_STATES = Object.freeze({
  'S4T-01': STATUS.EXPECTED_RED,
  'S4T-02': STATUS.EXPECTED_RED,
  'S4T-03': STATUS.EXPECTED_RED,
  'S4T-04': STATUS.PASS_CURRENT,
  'S4T-05': STATUS.PASS_CURRENT,
  'S4T-06': STATUS.PASS_CURRENT,
  'S4T-07': STATUS.PASS_CURRENT,
  'S4T-08': STATUS.PASS_CURRENT,
});

/**
 * Create-row classification (S4T-01/02/03).
 * Setup/substrate failure is HARNESS_FAIL; a still-absent predicate is EXPECTED_RED; a present
 * predicate is UNEXPECTED_GREEN; an authorized PASS_CURRENT create row that is not pinned is
 * HARNESS_FAIL.
 */
function classifyCreateRow({ expected, executed, durableReadBack, explicitMajorityJournal }) {
  if (executed !== true || durableReadBack !== true) {
    return STATUS.HARNESS_FAIL;
  }
  if (expected === STATUS.EXPECTED_RED) {
    return explicitMajorityJournal ? STATUS.UNEXPECTED_GREEN : STATUS.EXPECTED_RED;
  }
  return explicitMajorityJournal ? STATUS.PASS_CURRENT : STATUS.HARNESS_FAIL;
}

/** Control-row classification (S4T-04..08): authorized PASS_CURRENT; any failed assertion is HARNESS_FAIL. */
function classifyControlRow({ expected, executed, components }) {
  if (expected !== STATUS.PASS_CURRENT) {
    return STATUS.HARNESS_FAIL;
  }
  if (executed !== true) {
    return STATUS.HARNESS_FAIL;
  }
  return components.length > 0 && components.every((component) => component.met === true)
    ? STATUS.PASS_CURRENT
    : STATUS.HARNESS_FAIL;
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeJson(file, value) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  return file;
}

function writeText(file, text) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, text, 'utf8');
  return file;
}

function sha256File(absolute) {
  return require('node:crypto').createHash('sha256').update(fs.readFileSync(absolute)).digest('hex');
}

function makeRow({
  id,
  tier,
  status,
  expectedOracle,
  repairPredicate = null,
  productMethodInvoked,
  actual,
  components = [],
  dbName = null,
  dbDropped = null,
  dbReadBack = null,
  sourceHashes,
}) {
  if (!Object.values(STATUS).includes(status)) {
    throw new Error(`row ${id}: unknown status ${status}`);
  }
  if ((status === STATUS.EXPECTED_RED || status === STATUS.UNEXPECTED_GREEN) && (actual === null || actual === undefined)) {
    throw new Error(`row ${id}: ${status} without an observed actual`);
  }
  if (status === STATUS.EXPECTED_RED && productMethodInvoked !== true) {
    throw new Error(`row ${id}: EXPECTED_RED without productMethodInvoked=true`);
  }
  const authorizedStatus = AUTHORIZED_STATES[id] ?? null;
  const row = {
    id,
    tier,
    status,
    authorizedStatus,
    matchesAuthorizedState: authorizedStatus !== null && authorizedStatus === status,
    productMethodInvoked: productMethodInvoked === true,
    expectedOracle: String(expectedOracle),
    repairPredicate,
    components,
    actual,
    dbName,
    dbDropped,
    dbReadBack,
    sourceHashes,
  };
  const keys = Object.keys(row);
  if (keys.length !== ROW_KEYS.length || keys.some((key, index) => key !== ROW_KEYS[index])) {
    throw new Error(`row ${id}: key drift ${keys.join(',')}`);
  }
  return row;
}

function summarise(rows) {
  const byStatus = {};
  for (const row of rows) {
    byStatus[row.status] = (byStatus[row.status] ?? 0) + 1;
  }
  const unauthorized = rows.filter((row) => row.matchesAuthorizedState !== true).map((row) => row.id);
  const substrateBlockedRows = rows
    .filter(
      (row) =>
        row.status === STATUS.HARNESS_FAIL &&
        row.actual !== null &&
        typeof row.actual === 'object' &&
        row.actual.blocker !== undefined &&
        row.actual.blocker !== null,
    )
    .map((row) => row.id);
  const harnessFailureIds = rows
    .filter((row) => row.status === STATUS.HARNESS_FAIL)
    .map((row) => row.id);
  return {
    rows: rows.length,
    byStatus,
    harnessFailures: byStatus[STATUS.HARNESS_FAIL] ?? 0,
    harnessFailureIds,
    substrateBlockedRows,
    fixtureDefectRows: harnessFailureIds.filter((id) => !substrateBlockedRows.includes(id)),
    unauthorizedStateRows: unauthorized,
    allRowsMatchAuthorizedState:
      rows.length === Object.keys(AUTHORIZED_STATES).length && unauthorized.length === 0,
  };
}

function rawError(err) {
  return {
    name: (err && err.name) || 'Error',
    code: (err && err.code) || null,
    message: (err && err.message) || String(err),
    stack: (err && err.stack) || null,
    problems: err && Array.isArray(err.problems) ? err.problems : null,
    clientCreated: err && typeof err.clientCreated === 'boolean' ? err.clientCreated : null,
  };
}

class LedgerWriter {
  constructor({ artifactDir = ARTIFACT_DIR } = {}) {
    this.artifactDir = ensureDir(artifactDir);
    this.artifacts = [];
    this.lines = [];
  }

  log(line) {
    this.lines.push(line);
    process.stdout.write(`${line}\n`);
  }

  writeArtifact(name, value) {
    const file = writeJson(path.join(this.artifactDir, name), value);
    this.artifacts.push({
      file: path.relative(DURABILITY_DIR, file).replace(/\\/g, '/'),
      bytes: fs.statSync(file).size,
    });
    return file;
  }

  writeLedger(ledger) {
    return this.writeArtifact('S4T-LEDGER.json', ledger);
  }

  flushLog(name = 'S4T-RUN-STDOUT.log') {
    return writeText(path.join(this.artifactDir, name), `${this.lines.join('\n')}\n`);
  }
}

module.exports = {
  DURABILITY_DIR,
  ARTIFACT_DIR,
  STATUS,
  ROW_KEYS,
  AUTHORIZED_STATES,
  classifyCreateRow,
  classifyControlRow,
  ensureDir,
  writeJson,
  writeText,
  sha256File,
  makeRow,
  summarise,
  rawError,
  LedgerWriter,
};
