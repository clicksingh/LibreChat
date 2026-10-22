'use strict';

/**
 * W3-B R2-T0A result ledger (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * One row per supplemental fixture. The field set is the R2-T0A authorization field set:
 *   id, contractRef, tier (intended), tierExecuted, status, expectedOracle, actual, components,
 *   sourceAnchors, productClaim, blockedAtFactoryComposition, processEvidence, dbName, dbReadBack,
 *   sourceHashes, testHashes, noFabricationNote, artifactSha256.
 *
 * Truthfulness rules enforced as code:
 *   - `productClaim` is forced false unless the status is PASS_CURRENT and the caller passed true;
 *   - a row that did not reach its intended tier must say so through `blockedAtFactoryComposition`
 *     or an explicit executed-tier label — it may never be silently promoted;
 *   - EXPECTED_RED is never rewritten to PASS_CURRENT.
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
});

const NO_FABRICATION_NOTE =
  'No fabricated pass: every status is derived from machine-observed evidence in this row. ' +
  'A row stopped at the genuine-model factory composition gate is EXPECTED_RED and its downstream ' +
  'oracle is preserved verbatim as pendingOracle; an exception is HARNESS_FAIL, never product red.';

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

function makeRow({
  id,
  contractRef,
  tier,
  tierExecuted = tier,
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
  blockedAtFactoryComposition = false,
  plannerOnly = null,
  processEvidence = null,
  sourceHashes = null,
  testHashes = null,
  noFabricationNote = NO_FABRICATION_NOTE,
  artifactPayload = null,
  evidenceDir = null,
}) {
  if (!Object.values(STATUS).includes(status)) {
    throw new Error(`unknown status ${status}`);
  }
  const row = {
    id,
    contractRef,
    tier,
    tierExecuted,
    status,
    expectedOracle: Array.isArray(expectedOracle) ? expectedOracle.join(' | ') : String(expectedOracle),
    actual,
    components,
    sourceAnchors,
    productClaim: status === STATUS.PASS_CURRENT ? productClaim === true : false,
    blockedAtFactoryComposition: blockedAtFactoryComposition === true,
    plannerOnly: plannerOnly ?? null,
    pids,
    attempts,
    processEvidence,
    dbName,
    dbReadBack,
    sourceHashes,
    testHashes,
    notes,
    noFabricationNote,
    artifactSha256: null,
    artifactPath: null,
  };
  if (artifactPayload !== null && evidenceDir !== null) {
    const written = writeJson(evidenceDir, `${id}.json`, artifactPayload);
    row.artifactSha256 = written.sha256;
    const worktreeRoot = path.resolve(evidenceDir, '..', '..', '..', '..', '..', '..');
    row.artifactPath = path.relative(worktreeRoot, written.file).replace(/\\/g, '/');
  }
  return row;
}

/** Counts generated strictly from the machine rows. */
function summarise(rows) {
  const byStatus = {};
  const byContract = {};
  const byTierIntended = {};
  const byTierExecuted = {};
  for (const row of rows) {
    byStatus[row.status] = (byStatus[row.status] ?? 0) + 1;
    byContract[row.contractRef] = (byContract[row.contractRef] ?? 0) + 1;
    byTierIntended[row.tier] = (byTierIntended[row.tier] ?? 0) + 1;
    byTierExecuted[row.tierExecuted] = (byTierExecuted[row.tierExecuted] ?? 0) + 1;
  }
  return {
    rows: rows.length,
    byStatus,
    byContract,
    byTierIntended,
    byTierExecuted,
    blockedAtFactoryComposition: rows.filter((r) => r.blockedAtFactoryComposition).length,
    productClaimTrue: rows.filter((r) => r.productClaim === true).length,
  };
}

module.exports = {
  STATUS,
  NO_FABRICATION_NOTE,
  sha256Json,
  sha256File,
  ensureDir,
  writeJson,
  errorView,
  makeRow,
  summarise,
};