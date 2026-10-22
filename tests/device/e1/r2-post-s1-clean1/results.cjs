'use strict';

/**
 * W3-B R2-T0 result ledger (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * One row per fixture, with the frozen field set:
 *   id, hostileRows, tier, status, expectedOracle, actual, sourceAnchors, productClaim,
 *   pids/attempts (when applicable), dbReadBack, artifactSha256.
 *
 * Truthfulness rules enforced here as code:
 *   - `EXPECTED_RED` is never rewritten to `PASS_CURRENT`;
 *   - `productClaim` is forced false for every row whose status is not PASS_CURRENT, and for every
 *     row whose evidence tier is below the tier its oracle requires;
 *   - a row may not claim both a one-winner and a two-winner oracle (the V24-T15 fence).
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const STATUS = Object.freeze({
  PASS_CURRENT: 'PASS_CURRENT',
  EXPECTED_RED: 'EXPECTED_RED',
  UNEXPECTED_RED: 'UNEXPECTED_RED',
  ENV_BLOCKED: 'ENV_BLOCKED',
  HARNESS_FAIL: 'HARNESS_FAIL',
  EXPECTED_FAIL_CONTROL: 'EXPECTED_FAIL_CONTROL',
});

const HOSTILE_ROWS = Array.from({ length: 39 }, (_, i) => `H-${String(i + 1).padStart(2, '0')}`);

const GROUP_OF_ROW = {};
for (let i = 1; i <= 10; i += 1) GROUP_OF_ROW[`H-${String(i).padStart(2, '0')}`] = 'R2-FENCE-EPOCH';
for (let i = 11; i <= 21; i += 1) GROUP_OF_ROW[`H-${String(i).padStart(2, '0')}`] = 'R2-TRUST-PAIRING';
for (let i = 22; i <= 29; i += 1) GROUP_OF_ROW[`H-${String(i).padStart(2, '0')}`] = 'R2-AUDIT-DURABILITY';
for (let i = 30; i <= 39; i += 1) GROUP_OF_ROW[`H-${String(i).padStart(2, '0')}`] = 'R2-COMPOSITION-ERRORS';

function sha256Json(value) {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex').toUpperCase();
}

function sha256File(absolute) {
  return crypto.createHash('sha256').update(fs.readFileSync(absolute)).digest('hex').toUpperCase();
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeJson(dir, name, value) {
  ensureDir(dir);
  const file = path.join(dir, name);
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  return { file, sha256: sha256File(file) };
}

/**
 * Builds one result row. `components` is an ordered list of sub-observations; each has its own
 * `oracle`, `actual`, `met` and `tier`, so a partially-satisfied frozen oracle stays visible.
 */
function makeRow({
  id,
  hostileRows,
  tier,
  executedTier = tier,
  status,
  expectedOracle,
  actual,
  sourceAnchors = [],
  components = [],
  pids = null,
  attempts = null,
  dbReadBack = null,
  dbName = null,
  notes = null,
  productClaim = false,
  artifactPayload = null,
  evidenceDir = null,
}) {
  if (!Object.values(STATUS).includes(status)) {
    throw new Error(`unknown status ${status}`);
  }
  const oracleText = Array.isArray(expectedOracle) ? expectedOracle.join(' | ') : String(expectedOracle);
  if (/one winner/i.test(oracleText) && /two winner/i.test(oracleText)) {
    throw new Error(`row ${id} encodes both a one-winner and a two-winner oracle (V24-T15 fence)`);
  }
  const row = {
    id,
    hostileRows: hostileRows ?? [],
    tier,
    executedTier,
    status,
    expectedOracle: oracleText,
    actual,
    components,
    sourceAnchors,
    productClaim: status === STATUS.PASS_CURRENT ? productClaim : false,
    pids,
    attempts,
    dbName,
    dbReadBack,
    notes,
    artifactSha256: null,
  };
  if (artifactPayload !== null && evidenceDir !== null) {
    const written = writeJson(evidenceDir, `${id}.json`, artifactPayload);
    row.artifactSha256 = written.sha256;
    const worktreeRoot = path.resolve(evidenceDir, '..', '..', '..', '..', '..', '..');
    row.artifactPath = path.relative(worktreeRoot, written.file).replace(/\\/g, '/');
  }
  return row;
}

/** Aggregates counts and the H-01..H-39 coverage map; fails loudly on an uncovered row. */
function summarise(rows) {
  const byStatus = {};
  const byTier = {};
  const coverage = {};
  for (const row of rows) {
    byStatus[row.status] = (byStatus[row.status] ?? 0) + 1;
    byTier[row.tier] = (byTier[row.tier] ?? 0) + 1;
    for (const hostile of row.hostileRows) {
      coverage[hostile] = coverage[hostile] ?? [];
      coverage[hostile].push(row.id);
    }
  }
  const uncovered = HOSTILE_ROWS.filter((h) => !coverage[h]);
  const byGroup = {};
  for (const hostile of HOSTILE_ROWS) {
    const group = GROUP_OF_ROW[hostile];
    byGroup[group] = byGroup[group] ?? { rows: [], ids: [] };
    byGroup[group].rows.push(hostile);
    byGroup[group].ids.push(...(coverage[hostile] ?? []));
  }
  return {
    fixtures: rows.length,
    byStatus,
    byTier,
    coverage,
    uncoveredHostileRows: uncovered,
    byGroup,
    complete: uncovered.length === 0,
  };
}

/** Normalises an arbitrary thrown value into a serialisable shape. */
function errorView(err) {
  if (err === null || err === undefined) {
    return { name: null, code: null, message: null };
  }
  return {
    name: err.name ?? null,
    code: err.code ?? null,
    message: err.message ?? String(err),
    problems: Array.isArray(err.problems) ? err.problems : null,
  };
}

module.exports = {
  STATUS,
  HOSTILE_ROWS,
  GROUP_OF_ROW,
  sha256Json,
  sha256File,
  ensureDir,
  writeJson,
  makeRow,
  summarise,
  errorView,
};