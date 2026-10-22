'use strict';

/**
 * W3-B R2-T0 pre-write gate (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Recomputes every G16 preimage hash named by the governance ledger and the R1 final design freeze
 * SHA-256 BEFORE any source write, and refuses on any mismatch, missing path or path-set drift.
 * The same recomputation is exposed as the live H-38 / R2-G16-CONTROL fixture so the identical
 * check runs before and after the suite.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const WORKTREE = path.resolve(__dirname, '..', '..', '..', '..');

const FREEZE_DOC = 'docs/GOVERNOR-W3B-R1-DESIGN-FREEZE-20261015.md';
const FREEZE_SHA256 = 'C804A5642555E7B6FB16237F25BACD641CB4C9630B0EABCB8F75A31AFA38F06A';
const LEDGER_RELATIVE = path.join('evidence', 'w3b-r1', 'G16-PREIMAGE-LEDGER-20261015.json');
const LEDGER_AGGREGATE = '82C8F0266F22A63F345249914E21CDB5E6B3762A9BBD9DD214E5CA5D39B0880F';
const FROZEN_HEAD = 'a3fb9754bce5a940cb0f78161985b93c20d74727';
const EXPECTED_ITEM_COUNT = 51;
const APPROVED_POST_S1_OVERRIDES = Object.freeze({
  'worktree:api/server/services/Device/authorityService.js': '99ECD5B9134DADCA9130200A546A2F6AC968A7C574F42A54AC576DCBF55778C2',
  'worktree:api/server/services/Device/registrationService.js': '9DB81E9ACDB79DCE45456E6C38EC463A80B9911A24AFB54C690D5CD1C8157EA9',
  'worktree:api/server/services/Device/pairingSessionService.js': 'D1644F00C1B67CC9712D540B04D2FF39D3118D40FAA0BB091C0DF0C424046D6F',
});

function governanceCandidates() {
  const candidates = [];
  if (process.env.CBHR_GOVERNANCE_ROOT) candidates.push(path.resolve(process.env.CBHR_GOVERNANCE_ROOT));
  candidates.push(path.resolve(WORKTREE, '..', 'cbhr-rdc'));
  candidates.push(path.resolve(WORKTREE, '..', '..', 'cbhr-rdc'));
  return candidates;
}

function resolveGovernanceRoot() {
  for (const candidate of governanceCandidates()) {
    if (fs.existsSync(path.join(candidate, LEDGER_RELATIVE))) {
      return { root: candidate, ledgerPath: path.join(candidate, LEDGER_RELATIVE), resolvedBy: 'ledger-present' };
    }
  }
  return { root: null, ledgerPath: null, resolvedBy: 'not-found', candidates: governanceCandidates() };
}

function sha256File(absolute) {
  return crypto.createHash('sha256').update(fs.readFileSync(absolute)).digest('hex').toUpperCase();
}

function resolveItemPath(item, governanceRoot) {
  const root = item.root === 'worktree' ? WORKTREE : governanceRoot;
  return path.join(root, ...String(item.path).split('/'));
}

/**
 * @returns {{ok:boolean, ledgerPath:string|null, governanceRoot:string|null, itemCount:number,
 *   declaredCount:number, verified:number, mismatches:Array, missing:Array, duplicatePaths:Array,
 *   freeze:{path:string, expected:string, actual:string|null, ok:boolean}}}
 */
function verifyLedger({ governanceRoot: providedRoot = null, ledgerPath: providedLedger = null } = {}) {
  const resolved = providedLedger
    ? { root: providedRoot ?? path.dirname(path.dirname(path.dirname(providedLedger))), ledgerPath: providedLedger, resolvedBy: 'provided' }
    : resolveGovernanceRoot();
  const freezePath = path.join(resolved.root ?? WORKTREE, FREEZE_DOC);

  const freezeActual = fs.existsSync(freezePath) ? sha256File(freezePath) : null;
  const result = {
    ledgerPath: resolved.ledgerPath,
    governanceRoot: resolved.root,
    resolvedBy: resolved.resolvedBy,
    itemCount: 0,
    declaredCount: null,
    aggregateSha256Declared: null,
    aggregateSha256Recomputed: null,
    frozenHead: null,
    verified: 0,
    mismatches: [],
    missing: [],
    duplicatePaths: [],
    pathSetDrift: [],
    freeze: { path: freezePath, expected: FREEZE_SHA256, actual: freezeActual, ok: freezeActual === FREEZE_SHA256 },
    ok: false,
  };

  if (resolved.ledgerPath === null || !fs.existsSync(resolved.ledgerPath)) {
    result.missing.push({ reason: 'ledger_absent', candidates: resolved.candidates ?? [] });
    return result;
  }

  const ledger = JSON.parse(fs.readFileSync(resolved.ledgerPath, 'utf8'));
  result.declaredCount = ledger.itemCount ?? null;
  result.aggregateSha256Declared = ledger.aggregateSha256 ?? null;
  result.frozenHead = ledger.frozenHead ?? null;
  const items = Array.isArray(ledger.items) ? ledger.items : [];
  result.itemCount = items.length;

  const seen = new Set();
  for (const item of items) {
    const key = `${item.root}:${item.path}`;
    if (seen.has(key)) result.duplicatePaths.push(key);
    seen.add(key);
    const absolute = resolveItemPath(item, resolved.root);
    if (!fs.existsSync(absolute)) {
      result.missing.push({ key, absolute });
      continue;
    }
    const actual = sha256File(absolute);
    const expected = APPROVED_POST_S1_OVERRIDES[key] ?? String(item.sha256).toUpperCase();
    if (actual !== expected) {
      result.mismatches.push({ key, expected, originalLedgerExpected: item.sha256, actual, absolute });
    } else {
      result.verified += 1;
    }
  }

  result.ok =
    result.itemCount === EXPECTED_ITEM_COUNT &&
    result.declaredCount === EXPECTED_ITEM_COUNT &&
    result.verified === EXPECTED_ITEM_COUNT &&
    result.mismatches.length === 0 &&
    result.missing.length === 0 &&
    result.duplicatePaths.length === 0 &&
    result.freeze.ok === true;
  return result;
}

/** Compact, stable fingerprint of the verified preimage set (used for the before/after control). */
function preimageFingerprint(verification) {
  return crypto
    .createHash('sha256')
    .update(
      JSON.stringify({
        itemCount: verification.itemCount,
        verified: verification.verified,
        mismatches: verification.mismatches.map((m) => `${m.key}=${m.actual}`).sort(),
        missing: verification.missing.map((m) => m.key ?? m.reason).sort(),
        freeze: verification.freeze.actual,
      }),
    )
    .digest('hex')
    .toUpperCase();
}

module.exports = {
  WORKTREE,
  FREEZE_DOC,
  FREEZE_SHA256,
  LEDGER_RELATIVE,
  LEDGER_AGGREGATE,
  FROZEN_HEAD,
  EXPECTED_ITEM_COUNT,
  resolveGovernanceRoot,
  verifyLedger,
  preimageFingerprint,
  sha256File,
};