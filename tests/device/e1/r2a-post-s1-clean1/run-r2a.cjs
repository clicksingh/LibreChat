'use strict';

/**
 * W3-B R2-T0A supplemental runner (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 *   node tests/device/e1/r2a-post-s1-clean1/run-r2a.cjs
 *
 * Order of operations:
 *   1. G16 pre-write gate — recompute all 51 ledger preimages + the R1 base design-freeze SHA-256;
 *      also recompute the R1R addendum SHA-256 and hash every immutable r2/** and t0/** byte.
 *      On any mismatch it writes NOTHING and exits BLOCKED_NEEDS_GM.
 *   2. Server-wide namespace audit BEFORE.
 *   3. R2-T0A-TEST-REPORT.md written early, then updated after every row.
 *   4. Rows T0A-01 (E2 two-process) .. T0A-07 (E0 static control).
 *   5. Namespace audit AFTER; the run fails closed if any foreign database changed or any owned
 *      database was left behind.
 *   6. Durable results ledger, final report, file-hash ledger and self-excluding manifest.
 *   7. Post-run protection: G16 + addendum + immutable r2/t0 hashes proven unchanged.
 */

const fs = require('node:fs');
const path = require('node:path');

const fence = require('./fence.cjs');
const env = require('./env.cjs');
const probes = require('./probes.cjs');
const results = require('./results.cjs');
const ctx = require('./ctx.cjs');
const rowsModule = require('./rows.cjs');
const e2 = require('./fixtures-e2.cjs');

// eslint-disable-next-line global-require, import/no-dynamic-require
const r2preflight = require(path.resolve(__dirname, '..', 'r2-post-s1-clean1', 'preflight.cjs'));

const SESSION_ID = process.env.DSH_SESSION_ID ?? null;
const RUN_ID = `w3b-r2-t0a-${new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 17)}`;
const RUNNER_COMMAND = 'node tests/device/e1/r2a-post-s1-clean1/run-r2a.cjs';
const AUTHORIZATION_DOC = 'docs/GOVERNOR-W3B-R2-T0A-SUPPLEMENTAL-TEST-AUTHORIZATION-20261015.md';
const ADDENDUM_DOC = 'docs/GOVERNOR-W3B-R1R-FREEZE-ADDENDUM-20261015.md';

const T0A_DIR = env.T0A_DIR;
const ARTIFACTS_DIR = env.ARTIFACTS_DIR;
const STDOUT_LOG = env.STDOUT_LOG;
const RESULTS_FILE = path.join(T0A_DIR, 'R2-T0A-RESULTS.json');
const REPORT_FILE = path.join(T0A_DIR, 'R2-T0A-TEST-REPORT.md');
const FILE_HASHES_FILE = path.join(T0A_DIR, 'R2-T0A-FILE-HASHES.json');
const MANIFEST_FILE = path.join(T0A_DIR, 'R2-T0A-MANIFEST.json');

const PRODUCT_SOURCE_FILES = [
  'api/server/services/Device/authorityService.js',
  'api/server/services/Device/registrationService.js',
  'api/server/services/Device/pairingSessionService.js',
  'api/server/services/Device/crypto.js',
  'api/server/services/Device/errors.js',
  'packages/data-schemas/src/schema/deviceAuthority.ts',
  'packages/data-schemas/src/schema/challenge.ts',
  'packages/data-schemas/src/schema/pairingSession.ts',
  'packages/data-schemas/src/schema/auditEvent.ts',
  'packages/data-schemas/src/models/index.ts',
];

let sealed = false;
let logStream = null;

function rel(absolute) {
  return path.relative(env.WORKTREE, absolute).replace(/\\/g, '/');
}

function log(line) {
  process.stdout.write(`${line}\n`);
  if (!sealed && logStream !== null) logStream.write(`${line}\n`);
}

function out(line) {
  process.stdout.write(`${line}\n`);
}

function sealLog() {
  return new Promise((resolve) => {
    sealed = true;
    if (logStream === null) {
      resolve();
      return;
    }
    logStream.end(resolve);
  });
}

function sha256FileSafe(absolute) {
  try {
    return results.sha256File(absolute);
  } catch {
    return null;
  }
}

function hashFileSet(worktreeRelatives) {
  return worktreeRelatives.map((relative) => {
    const absolute = path.join(env.WORKTREE, ...relative.split('/'));
    let bytes = null;
    try {
      bytes = fs.statSync(absolute).size;
    } catch {
      bytes = null;
    }
    return { path: relative, bytes, sha256: sha256FileSafe(absolute) };
  });
}

function walkRelative(dir, worktreeRoot) {
  const collected = [];
  const walk = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) walk(full);
      else collected.push(path.relative(worktreeRoot, full).replace(/\\/g, '/'));
    }
  };
  if (fs.existsSync(dir)) walk(dir);
  return collected.sort();
}

function compareHashSets(before, after) {
  const beforeMap = new Map(before.map((e) => [e.path, e.sha256]));
  const afterMap = new Map(after.map((e) => [e.path, e.sha256]));
  const changed = [];
  for (const [file, sha] of beforeMap) {
    if (afterMap.get(file) !== sha) changed.push({ path: file, before: sha, after: afterMap.get(file) ?? null });
  }
  for (const [file, sha] of afterMap) {
    if (!beforeMap.has(file)) changed.push({ path: file, before: null, after: sha });
  }
  const aggregate = (list) => results.sha256Json(list.map((e) => ({ path: e.path, sha256: e.sha256 })));
  return {
    fileCount: before.length,
    changed,
    identical: changed.length === 0,
    aggregateSha256Before: aggregate(before),
    aggregateSha256After: aggregate(after),
  };
}

function governanceFile(governanceRoot, relative) {
  return governanceRoot === null ? null : path.join(governanceRoot, ...relative.split('/'));
}

/* ------------------------------------------------------------------ report */

function rowHeadline(row) {
  if (row.actual && row.actual.kind) {
    return `${row.actual.kind}${row.actual.firstRejectedFactory ? ` @ ${row.actual.firstRejectedFactory}` : ''}`;
  }
  return row.notes ?? 'see artifact';
}

/** Machine-derived evidence digest per row: values only, no hand-counted narrative. */
function evidenceDigest(row) {
  const a = row.actual ?? {};
  const s = a.staticEvidence ?? {};
  if (row.id.startsWith('T0A-01')) {
    const kids = a.childReports ?? [];
    return [
      `barrierCredible=${a.barrierCredible}; barrierDir=${a.barrierDir}`,
      `distinctOsPids=${a.distinctOsPids}; pidsByRole=${JSON.stringify(a.pidsByRole)}`,
      `totalAttempts=${a.totalAttempts} (min ${a.minTotalAttemptsRequired}); productCallsAttempted=${a.productCallsAttempted}`,
      `observedSessionAtBarrier=${JSON.stringify(a.observedSessionAtBarrier)}`,
      `childAttempts=${JSON.stringify(kids.map((k) => ({ role: k.role, attempts: k.attempts, compositionFailures: k.compositionFailures, fatal: k.fatal })))}`,
      `static: sessionVersionSymbolPresent=${s.sessionVersionSymbol ? s.sessionVersionSymbol.present : 'n/a'}; approvalConsumeMatchesClaimPendingWithoutVersion=${s.approvalConsumeMatchesClaimPendingWithoutVersion}`,
    ];
  }
  if (row.id.startsWith('T0A-02')) {
    return [
      `bareTrueAcceptedByCurrentBytes=${s.bareTrueAcceptedByCurrentBytes}; anchors=${JSON.stringify(s.grantedExpressionAnchor)}`,
      `verdictBindingFieldsInConsentVerifier=${JSON.stringify(s.verdictBindingFieldsInConsentVerifier)}`,
      `consentVerifierScope=${JSON.stringify(s.consentVerifierScope)}`,
      `auditSinkControl=${JSON.stringify(a.auditSinkControl)}`,
    ];
  }
  if (row.id.startsWith('T0A-03')) {
    return [
      `mismatchKinds=${JSON.stringify(a.mismatchKinds)}`,
      `verdictBindingFieldsInConsentVerifier=${JSON.stringify(s.verdictBindingFieldsInConsentVerifier)}`,
      `verdictBindingFieldsAbsentFromConsentVerifier=${JSON.stringify(s.verdictBindingFieldsAbsentFromConsentVerifier)}`,
      `consentVerifierScope=${JSON.stringify(s.consentVerifierScope)}`,
    ];
  }
  if (row.id.startsWith('T0A-04')) {
    return [
      `branchA=${JSON.stringify(a.branchA_committedAndAckLost)}`,
      `branchB=${JSON.stringify(a.branchB_absentRow)}`,
      `static: deviceAuthorityReadUsages=${(s.deviceAuthorityReadUsages ?? []).length}; challengeReadUsages=${(s.challengeReadUsages ?? []).length}`,
    ];
  }
  if (row.id.startsWith('T0A-05')) {
    return [
      `lostAckPreimage=${JSON.stringify(a.lostAckPreimage)}`,
      `static: readOrFilterUsesOfGrantedByPairingSessionId=${s.readOrFilterUses}`,
      `static: claimRefusedOnNonOkClaimAnchor=${JSON.stringify(s.claimRefusedOnNonOkClaimAnchor)}`,
    ];
  }
  if (row.id.startsWith('T0A-06')) {
    return [
      `modelRecorder=${JSON.stringify(a.modelRecorder)}`,
      `static: classifyForeignTenantChallengeAnchor=${JSON.stringify(s.classifyForeignTenantChallengeAnchor)}`,
      `static: boundTenantFallbackLines=${JSON.stringify((s.boundTenantFallbackLines ?? []).map((h) => `${h.file}:${h.line}`))}`,
      `static: challengeHashReferences=${s.challengeHashReferences}`,
    ];
  }
  if (row.id.startsWith('T0A-07')) {
    return [
      `requiredComponents=${JSON.stringify(row.components.filter((c) => c.required !== false).map((c) => `${c.name}=${c.met}`))}`,
      `oneActiveDeviceIdentityPerOwnerTenant=${s.oneActiveDeviceIdentityPerOwnerTenant}; productVocabularyClean=${s.productVocabulary ? s.productVocabulary.clean : 'n/a'}`,
      `harnessVocabularyHits=${(s.harnessVocabularyHits ?? []).length}; acceptanceVocabularyPresent=${s.acceptanceVocabularyPresent}`,
      `historicalOnePcOccurrences=${(s.historicalOnePcOccurrences ?? []).length} (immutable W3-A bytes; informational, not violations)`,
    ];
  }
  return [JSON.stringify(a).slice(0, 600)];
}

function renderReport({ phase, rows, preflight, protection, namespaceAudit, summary, startedAt, finishedAt, ownedDbs, dbTeardown, pmOwned }) {
  const lines = [];
  const s = summary;
  lines.push('# R2-T0A SUPPLEMENTAL FAILING-BEFORE TEST REPORT');
  lines.push('');
  lines.push(
    `Commission PHASE1-LOCAL-AUTHORITY-001 · Wave W3-B R2-T0A · child R2-T0A-TEST · session \`${SESSION_ID ?? 'unresolved'}\` · run \`${RUN_ID}\`.`,
  );
  lines.push(
    `Frozen product HEAD \`${r2preflight.FROZEN_HEAD}\`. Authority: TEST/EVIDENCE ONLY; no product source byte was written. Product claim: none (every \`productClaim\` is false).`,
  );
  lines.push(`Runner command: \`${RUNNER_COMMAND}\`. Report phase: **${phase}**.`);
  lines.push('');
  lines.push('## 1. Counts (generated from R2-T0A-RESULTS.json machine rows, never hand-counted)');
  lines.push('');
  lines.push('| status | count | | tier intended | count | | tier executed | count |');
  lines.push('|---|---|---|---|---|---|---|---|');
  const statusKeys = Object.keys(s.byStatus).sort();
  const tierKeys = Object.keys(s.byTierIntended).sort();
  const execKeys = Object.keys(s.byTierExecuted).sort();
  const width = Math.max(statusKeys.length, tierKeys.length, execKeys.length);
  for (let i = 0; i < width; i += 1) {
    lines.push(
      `| ${statusKeys[i] ?? ''} | ${statusKeys[i] ? s.byStatus[statusKeys[i]] : ''} | | ${tierKeys[i] ?? ''} | ${
        tierKeys[i] ? s.byTierIntended[tierKeys[i]] : ''
      } | | ${execKeys[i] ?? ''} | ${execKeys[i] ? s.byTierExecuted[execKeys[i]] : ''} |`,
    );
  }
  lines.push('');
  lines.push(
    `- rows: **${s.rows}**; blockedAtFactoryComposition: **${s.blockedAtFactoryComposition}**; productClaim true: **${s.productClaimTrue}**`,
  );
  lines.push(`- by contract reference: ${JSON.stringify(s.byContract)}`);
  lines.push('');
  lines.push('## 2. Row table');
  lines.push('');
  lines.push('| id | contractRef | tier intended | tier executed | status | blockedAtFactoryComposition | headline |');
  lines.push('|---|---|---|---|---|---|---|');
  for (const row of rows) {
    lines.push(
      `| ${row.id} | ${row.contractRef} | ${row.tier} | ${row.tierExecuted} | ${row.status} | ${row.blockedAtFactoryComposition} | ${String(
        rowHeadline(row),
      ).replace(/\|/g, '\\|')} |`,
    );
  }
  if (rows.length === 0) lines.push('| (no rows executed yet) | | | | | | |');
  lines.push('');

  lines.push('## 3. Per-row detail');
  lines.push('');
  for (const row of rows) {
    lines.push(`### ${row.id} — ${row.status}`);
    lines.push('');
    lines.push(`- contractRef: \`${row.contractRef}\`; tier intended \`${row.tier}\`; tier executed \`${row.tierExecuted}\`; blockedAtFactoryComposition \`${row.blockedAtFactoryComposition}\``);
    lines.push(`- expected oracle (verbatim intended assertion): ${row.expectedOracle}`);
    lines.push(`- actual observed: ${rowHeadline(row)}`);
    if (row.dbName) lines.push(`- database: \`${row.dbName}\``);
    if (row.pids && row.pids.length > 0) lines.push(`- process evidence: PIDs ${row.pids.join(', ')}; attempts ${row.attempts}`);
    if (row.pendingOracle) lines.push(`- preserved pending oracle (post-repair): ${row.pendingOracle}`);
    lines.push('- evidence digest (machine-derived):');
    for (const bullet of evidenceDigest(row)) lines.push(`  - ${bullet}`);
    lines.push(`- no-fabrication note: ${row.noFabricationNote}`);
    lines.push('');
  }

  lines.push('## 4. Pre-write gate and protection (BEFORE)');
  lines.push('');
  if (preflight === null) {
    lines.push('- preflight was not computed.');
  } else {
    lines.push(`- G16 ledger: \`${preflight.g16 ? preflight.g16.ledgerPath : 'n/a'}\` — verified ${preflight.g16 ? preflight.g16.verified : 'n/a'}/${preflight.g16 ? preflight.g16.itemCount : 'n/a'} (declared ${preflight.g16 ? preflight.g16.declaredCount : 'n/a'}); mismatches ${preflight.g16 ? preflight.g16.mismatches.length : 'n/a'}; missing ${preflight.g16 ? preflight.g16.missing.length : 'n/a'}`);
    lines.push(`- base R1 design-freeze SHA-256: expected \`${preflight.g16 ? preflight.g16.freeze.expected : 'n/a'}\`; observed \`${preflight.g16 ? preflight.g16.freeze.actual : 'n/a'}\`; ok ${preflight.g16 ? preflight.g16.freeze.ok : 'n/a'}`);
    lines.push(`- R1R freeze addendum SHA-256 (begin): \`${preflight.addendumSha256}\``);
    lines.push(`- immutable r2/** files hashed: ${preflight.r2SourcesBefore ? preflight.r2SourcesBefore.length : 'n/a'}; immutable t0/** files hashed: ${preflight.t0EvidenceBefore ? preflight.t0EvidenceBefore.length : 'n/a'}`);
  }
  lines.push('');

  if (protection !== null) {
    lines.push('## 5. Post-run protection (AFTER)');
    lines.push('');
    lines.push(`- G16 ledger re-verified: ${protection.g16After.verified}/${protection.g16After.itemCount}; ok ${protection.g16After.ok}; mismatches ${protection.g16After.mismatches.length}`);
    lines.push(`- base R1 design-freeze SHA-256 (end): \`${protection.g16After.freeze.actual}\`; identical to begin: ${protection.g16After.freeze.actual === protection.g16Before.freeze.actual}`);
    lines.push(`- R1R freeze addendum SHA-256 (begin) \`${protection.addendum.sha256Before}\` / (end) \`${protection.addendum.sha256After}\`; byte-identical: ${protection.addendum.identical}`);
    lines.push(`- immutable r2/** unchanged: ${protection.r2Sources.identical} (${protection.r2Sources.changed.length} changed of ${protection.r2Sources.fileCount})`);
    lines.push(`- immutable t0/** evidence unchanged: ${protection.t0Evidence.identical} (${protection.t0Evidence.changed.length} changed of ${protection.t0Evidence.fileCount})`);
    lines.push('');
  }

  lines.push('## 6. Mongo namespace audit');
  lines.push('');
  if (namespaceAudit === null) {
    lines.push('- namespace audit not computed.');
  } else {
    lines.push(`- before: \`${namespaceAudit.before.join(', ')}\``);
    lines.push(`- after: \`${namespaceAudit.after.join(', ')}\``);
    lines.push(
      `- created ${namespaceAudit.created.length}; removed ${namespaceAudit.removed.length}; foreignCreated ${namespaceAudit.foreignCreated.length}; foreignRemoved ${namespaceAudit.foreignRemoved.length}; leftoverOwned ${namespaceAudit.leftoverOwned.length}; protectedChanged ${namespaceAudit.protectedChanged}; ok **${namespaceAudit.ok}**`,
    );
  }
  lines.push(`- owned databases created this wave: ${ownedDbs.length === 0 ? 'none' : ownedDbs.map((d) => `\`${d}\``).join(', ')}`);
  lines.push(`- per-row teardown: ${dbTeardown.length === 0 ? 'n/a' : dbTeardown.map((d) => `${d.dbName}=${d.dropped}`).join(', ')}`);
  lines.push('');

  lines.push('## 7. Scope audit');
  lines.push('');
  lines.push('- written trees: `tests/device/e1/r2a/**` and `tests/device/_phase1_evidence/w3b-r2/t0a/**` (excluding the PM-owned `GATE-MANIFEST.json` lane field and `PM-R2-T0A-TERMINAL.json`).');
  lines.push('- immutable `tests/device/e1/r2/**` and `tests/device/_phase1_evidence/w3b-r2/t0/**` were read only.');
  lines.push('- no product source, schema, model, package/lockfile, governance file, Git ref or production byte was written.');
  lines.push(`- artifacts directory: \`${rel(ARTIFACTS_DIR)}\`; runner stdout log: \`${rel(STDOUT_LOG)}\` (the trailing post-seal digest echo is console-only).`);
  if (pmOwned) {
    lines.push(
      `- PM-owned \`${pmOwned.gateManifest.path}\`: exists ${pmOwned.gateManifest.exists}; sha256 at run time \`${pmOwned.gateManifest.sha256}\` (NOT written by this lane; the PM will fill the lane session field).`,
    );
    lines.push(`- PM-owned \`${pmOwned.pmTerminal.path}\`: exists ${pmOwned.pmTerminal.exists} (NOT written by this lane).`);
  }
  lines.push('');

  lines.push('## 8. Status recommendation');
  lines.push('');
  lines.push(`- ${recommendation(rows, protection, namespaceAudit).verdict}: ${recommendation(rows, protection, namespaceAudit).reason}`);
  lines.push('');
  lines.push(`Generated at ${finishedAt} (report phase ${phase}; run started ${startedAt}).`);
  lines.push('');
  return lines.join('\n');
}

function recommendation(rows, protection, namespaceAudit) {
  const badStatuses = rows.filter((r) => [results.STATUS.UNEXPECTED_RED, results.STATUS.HARNESS_FAIL, results.STATUS.ENV_BLOCKED].includes(r.status));
  if (badStatuses.length > 0) {
    return { verdict: 'INCOMPLETE', reason: `rows with non-red-expected failures: ${badStatuses.map((r) => `${r.id}=${r.status}`).join(', ')}` };
  }
  const notAtTier = rows.filter((r) => !(r.status === results.STATUS.PASS_CURRENT || r.blockedAtFactoryComposition === true));
  if (notAtTier.length > 0) {
    return {
      verdict: 'INCOMPLETE',
      reason: `rows neither at intended tier nor truthfully stopped at the genuine-model composition gate: ${notAtTier.map((r) => r.id).join(', ')}`,
    };
  }
  if (protection !== null && (!protection.r2Sources.identical || !protection.t0Evidence.identical || !protection.addendum.identical || !protection.g16After.ok)) {
    return { verdict: 'INCOMPLETE', reason: 'post-run protection check failed (immutable bytes or freeze/ledger drift)' };
  }
  if (namespaceAudit !== null && !namespaceAudit.ok) {
    return { verdict: 'INCOMPLETE', reason: 'Mongo namespace audit is not clean' };
  }
  return {
    verdict: 'READY_FOR_GOVERNOR_REVIEW',
    reason: `all ${rows.length} rows executed at their intended tier or truthfully stopped at the known genuine-model composition gate; no unexpected red, harness or env failure; scope and DB audits clean`,
  };
}

function writeReport(args) {
  fs.mkdirSync(T0A_DIR, { recursive: true });
  fs.writeFileSync(REPORT_FILE, renderReport(args), 'utf8');
}

/* -------------------------------------------------------------------- main */

async function runRowDefinition(def, sourceHashes, testHashes) {
  const { outcome, dbReadBack, dbName, context } = await ctx.withFixture(def.tag, def.build, {});
  const row = results.makeRow({
    id: def.id,
    contractRef: def.contractRef,
    tier: def.tier,
    tierExecuted: outcome.tierExecuted ?? def.tier,
    status: outcome.status,
    expectedOracle: def.expectedOracle,
    actual: outcome.actual,
    components: outcome.components ?? [],
    sourceAnchors: outcome.sourceAnchors ?? [],
    dbReadBack,
    dbName,
    notes: outcome.notes ?? null,
    productClaim: outcome.productClaim ?? false,
    blockedAtFactoryComposition: outcome.blockedAtFactoryComposition ?? false,
    plannerOnly: outcome.plannerOnly ?? null,
    sourceHashes,
    testHashes,
    artifactPayload: {
      id: def.id,
      contractRef: def.contractRef,
      tierIntended: def.tier,
      tierExecuted: outcome.tierExecuted ?? def.tier,
      expectedOracle: def.expectedOracle,
      pendingOracle: outcome.pendingOracle ?? null,
      actual: outcome.actual,
      components: outcome.components ?? [],
      sourceAnchors: outcome.sourceAnchors ?? [],
      dbName,
      dbReadBack,
    },
    evidenceDir: ARTIFACTS_DIR,
  });
  return { row, dropped: context ? context.dropped : null, outcomeError: null };
}

async function main() {
  fs.mkdirSync(T0A_DIR, { recursive: true });
  fs.mkdirSync(ARTIFACTS_DIR, { recursive: true });
  logStream = fs.createWriteStream(STDOUT_LOG, { flags: 'w' });

  const startedAt = new Date().toISOString();
  log(`[r2-t0a] run=${RUN_ID} session=${SESSION_ID ?? 'unresolved'} startedAt=${startedAt}`);
  log(`[r2-t0a] runner=${RUNNER_COMMAND}`);

  // ---- 1. pre-write gate -------------------------------------------------
  const g16Before = r2preflight.verifyLedger();
  const governanceRoot = g16Before.governanceRoot;
  const addendumPath = governanceFile(governanceRoot, ADDENDUM_DOC);
  const authPath = governanceFile(governanceRoot, AUTHORIZATION_DOC);
  const addendumSha256Before = addendumPath && fs.existsSync(addendumPath) ? sha256FileSafe(addendumPath) : null;
  const r2Files = walkRelative(env.R2_DIR, env.WORKTREE);
  const t0Files = walkRelative(env.T0_DIR, env.WORKTREE);
  const r2SourcesBefore = hashFileSet(r2Files);
  const t0EvidenceBefore = hashFileSet(t0Files);

  const sourceHashes = hashFileSet(PRODUCT_SOURCE_FILES);
  const r2aFiles = walkRelative(env.R2A_DIR, env.WORKTREE);
  const testHashes = hashFileSet([...r2Files, ...r2aFiles]);

  const preflight = {
    g16: g16Before,
    addendumDoc: ADDENDUM_DOC,
    addendumPath,
    addendumSha256: addendumSha256Before,
    authorizationDoc: AUTHORIZATION_DOC,
    authorizationSha256: authPath && fs.existsSync(authPath) ? sha256FileSafe(authPath) : null,
    r2SourcesBefore,
    t0EvidenceBefore,
  };

  log(`[r2-t0a] g16 ok=${g16Before.ok} verified=${g16Before.verified}/${g16Before.itemCount} mismatches=${g16Before.mismatches.length} freezeOk=${g16Before.freeze.ok}`);
  log(`[r2-t0a] addendum sha256=${addendumSha256Before}`);
  log(`[r2-t0a] immutable r2 files=${r2SourcesBefore.length} t0 files=${t0EvidenceBefore.length}`);

  if (!g16Before.ok) {
    const payload = {
      schema: 'cbhr-rdc/r2-t0a-results/v1',
      runId: RUN_ID,
      sessionId: SESSION_ID,
      status: 'BLOCKED_NEEDS_GM',
      detail: 'G16 pre-write gate failed; nothing was written',
      preflight,
    };
    fs.writeFileSync(RESULTS_FILE, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
    log('[r2-t0a] BLOCKED_NEEDS_GM: G16 pre-write gate failed');
    await sealLog();
    process.exitCode = 2;
    return;
  }

  // ---- 2. namespace audit BEFORE ----------------------------------------
  const databaseNamesBefore = await fence.listDatabaseNames();
  log(`[r2-t0a] databases before: ${databaseNamesBefore.join(', ')}`);

  const rows = [];
  const dbTeardown = [];
  const reportArgs = {
    phase: 'preflight complete — no rows executed yet',
    rows,
    preflight,
    protection: null,
    namespaceAudit: null,
    summary: results.summarise(rows),
    startedAt,
    finishedAt: new Date().toISOString(),
    ownedDbs: [],
    dbTeardown,
  };
  writeReport(reportArgs);
  log(`[r2-t0a] early report written: ${rel(REPORT_FILE)}`);

  // ---- 3/4. rows ---------------------------------------------------------
  // T0A-01 (E2 two-process) first, then the E1/E0 rows in contract order.
  let row01;
  try {
    const outcome = await e2.runAbaRow();
    row01 = outcome.row;
    dbTeardown.push({ dbName: outcome.row.dbName, dropped: outcome.dropped ? outcome.dropped.dropped : null });
  } catch (err) {
    row01 = results.makeRow({
      id: e2.ROW_ID,
      contractRef: 'F13/F18-A',
      tier: 'E2',
      tierExecuted: 'E2',
      status: results.STATUS.HARNESS_FAIL,
      expectedOracle: e2.ORACLE,
      actual: { kind: 'HARNESS_FAIL', error: results.errorView(err), scenario: 'two-process ABA orchestration' },
      notes: 'An E2 orchestration exception is a harness failure, never a product red.',
      sourceHashes,
      testHashes,
    });
  }
  row01.sourceHashes = sourceHashes;
  row01.testHashes = testHashes;
  rows.push(row01);
  log(`[r2-t0a] ${row01.status.padEnd(20)} ${row01.id} attempts=${row01.attempts} pids=${(row01.pids ?? []).join(',')}`);
  reportArgs.phase = `T0A-01 executed (${row01.status})`;
  reportArgs.summary = results.summarise(rows);
  reportArgs.ownedDbs = rows.map((r) => r.dbName).filter(Boolean);
  reportArgs.finishedAt = new Date().toISOString();
  writeReport(reportArgs);

  for (const def of rowsModule.ROW_DEFS) {
    let row;
    try {
      // eslint-disable-next-line no-await-in-loop
      const executed = await runRowDefinition(def, sourceHashes, testHashes);
      row = executed.row;
      dbTeardown.push({ dbName: executed.row.dbName, dropped: executed.dropped ? executed.dropped.dropped : null });
    } catch (err) {
      row = results.makeRow({
        id: def.id,
        contractRef: def.contractRef,
        tier: def.tier,
        tierExecuted: def.tier,
        status: results.STATUS.HARNESS_FAIL,
        expectedOracle: def.expectedOracle,
        actual: { kind: 'HARNESS_FAIL', error: results.errorView(err), scenario: 'row threw before completing' },
        notes: 'A row exception is a harness failure, never a product red.',
        sourceHashes,
        testHashes,
      });
    }
    rows.push(row);
    log(`[r2-t0a] ${row.status.padEnd(20)} ${row.id} blockedAtFactoryComposition=${row.blockedAtFactoryComposition}`);
    reportArgs.phase = `${row.id} executed (${row.status}); ${rows.length} of 7 rows complete`;
    reportArgs.summary = results.summarise(rows);
    reportArgs.ownedDbs = rows.map((r) => r.dbName).filter(Boolean);
    reportArgs.finishedAt = new Date().toISOString();
    writeReport(reportArgs);
  }

  // ---- 5. namespace audit AFTER -----------------------------------------
  const databaseNamesAfter = await fence.listDatabaseNames();
  const namespaceAudit = fence.auditDatabaseSets(databaseNamesBefore, databaseNamesAfter);
  log(`[r2-t0a] namespace audit ok=${namespaceAudit.ok} created=${namespaceAudit.created.length} removed=${namespaceAudit.removed.length} leftoverOwned=${namespaceAudit.leftoverOwned.length}`);

  const summary = results.summarise(rows);
  const finishedAt = new Date().toISOString();

  // Live topology probe (guarded connection, closed immediately).
  const topologyProbe = await fence.connectGuarded({ dbName: fence.createDbName('topologyprobe') });
  const liveMongo = topologyProbe.topology;
  await topologyProbe.client.close().catch(() => {});
  await env.w3a.mongoose.disconnect().catch(() => {});

  // ---- 6. results ledger -------------------------------------------------
  const payload = {
    schema: 'cbhr-rdc/r2-t0a-results/v1',
    wave: 'W3-B R2-T0A',
    commission: 'PHASE1-LOCAL-AUTHORITY-001',
    runnerCommand: RUNNER_COMMAND,
    runId: RUN_ID,
    sessionId: SESSION_ID,
    reportPath: rel(REPORT_FILE),
    frozenHead: r2preflight.FROZEN_HEAD,
    startedAt,
    finishedAt,
    node: process.version,
    runtime: env.runtimeVersions(),
    liveMongo,
    preflight: {
      g16: {
        ok: g16Before.ok,
        ledgerPath: g16Before.ledgerPath,
        governanceRoot: g16Before.governanceRoot,
        itemCount: g16Before.itemCount,
        declaredCount: g16Before.declaredCount,
        verified: g16Before.verified,
        mismatches: g16Before.mismatches,
        missing: g16Before.missing,
        aggregateSha256Declared: g16Before.aggregateSha256Declared,
        freeze: g16Before.freeze,
      },
      addendum: { doc: ADDENDUM_DOC, sha256: addendumSha256Before },
      authorization: { doc: AUTHORIZATION_DOC, sha256: preflight.authorizationSha256 },
      immutableR2Files: r2SourcesBefore.length,
      immutableT0Files: t0EvidenceBefore.length,
    },
    sourceHashes,
    testHashes,
    summary,
    namespaceAudit,
    ownedDatabases: rows.map((r) => r.dbName).filter(Boolean),
    dbTeardown,
    rows,
  };
  fs.writeFileSync(RESULTS_FILE, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
  log(`[r2-t0a] results written: ${rel(RESULTS_FILE)}`);

  // ---- 7. post-run protection -------------------------------------------
  const g16After = r2preflight.verifyLedger();
  const addendumSha256After = addendumPath && fs.existsSync(addendumPath) ? sha256FileSafe(addendumPath) : null;
  const r2SourcesAfter = hashFileSet(walkRelative(env.R2_DIR, env.WORKTREE));
  const t0EvidenceAfter = hashFileSet(walkRelative(env.T0_DIR, env.WORKTREE));
  const protection = {
    g16Before,
    g16After,
    addendum: {
      doc: ADDENDUM_DOC,
      path: addendumPath,
      sha256Before: addendumSha256Before,
      sha256After: addendumSha256After,
      identical: addendumSha256Before !== null && addendumSha256Before === addendumSha256After,
    },
    baseFreeze: {
      expected: r2preflight.FREEZE_SHA256,
      before: g16Before.freeze.actual,
      after: g16After.freeze.actual,
      identical: g16Before.freeze.actual === g16After.freeze.actual,
    },
    r2Sources: compareHashSets(r2SourcesBefore, r2SourcesAfter),
    t0Evidence: compareHashSets(t0EvidenceBefore, t0EvidenceAfter),
  };
  log(`[r2-t0a] protection: g16AfterOk=${g16After.ok} addendumIdentical=${protection.addendum.identical} r2Unchanged=${protection.r2Sources.identical} t0Unchanged=${protection.t0Evidence.identical}`);

  // PM-owned files: hashed read-only for the protection record; never written by this lane.
  const gateManifestPath = path.join(T0A_DIR, 'GATE-MANIFEST.json');
  const pmTerminalPath = path.join(T0A_DIR, 'PM-R2-T0A-TERMINAL.json');
  const pmOwned = {
    gateManifest: {
      path: rel(gateManifestPath),
      exists: fs.existsSync(gateManifestPath),
      sha256: fs.existsSync(gateManifestPath) ? sha256FileSafe(gateManifestPath) : null,
      writtenByThisLane: false,
    },
    pmTerminal: {
      path: rel(pmTerminalPath),
      exists: fs.existsSync(pmTerminalPath),
      writtenByThisLane: false,
    },
  };
  log(`[r2-t0a] pm-owned gateManifest exists=${pmOwned.gateManifest.exists} sha256=${pmOwned.gateManifest.sha256}`);

  // final report (full, generated from machine data)
  reportArgs.phase = 'final';
  reportArgs.rows = rows;
  reportArgs.protection = protection;
  reportArgs.namespaceAudit = namespaceAudit;
  reportArgs.summary = summary;
  reportArgs.finishedAt = finishedAt;
  reportArgs.ownedDbs = payload.ownedDatabases;
  reportArgs.pmOwned = pmOwned;
  writeReport(reportArgs);
  log(`[r2-t0a] final report written: ${rel(REPORT_FILE)}`);

  const rec = recommendation(rows, protection, namespaceAudit);
  log(`[r2-t0a] rows=${summary.rows} byStatus=${JSON.stringify(summary.byStatus)} byTierExecuted=${JSON.stringify(summary.byTierExecuted)}`);
  log(`[r2-t0a] blockedAtFactoryComposition=${summary.blockedAtFactoryComposition} productClaimTrue=${summary.productClaimTrue}`);
  log(`[r2-t0a] namespaceAuditOk=${namespaceAudit.ok} r2Unchanged=${protection.r2Sources.identical} t0Unchanged=${protection.t0Evidence.identical} addendumIdentical=${protection.addendum.identical} g16AfterOk=${g16After.ok}`);
  log(`[r2-t0a] VERDICT ${rec.verdict}: ${rec.reason}`);

  // Seal the stdout log before hashing so its digest is stable and final. The trailing digest
  // echo below is console-only by design (it cannot contain its own post-seal digest).
  await sealLog();

  // ---- file-hash ledger (inputs + produced outputs) ----------------------
  const artifactFiles = walkRelative(ARTIFACTS_DIR, env.WORKTREE);
  const producedFiles = [
    rel(RESULTS_FILE),
    rel(REPORT_FILE),
    rel(STDOUT_LOG),
    ...artifactFiles,
  ];
  const fileHashes = {
    schema: 'cbhr-rdc/r2-t0a-file-hashes/v1',
    runId: RUN_ID,
    generatedAtUtc: new Date().toISOString(),
    immutableInputs: {
      r2Sources: r2SourcesBefore,
      t0Evidence: t0EvidenceBefore,
    },
    postRunProtection: protection,
    pmOwnedReadOnlyProtection: pmOwned,
    productSourceHashes: sourceHashes,
    testHashes,
    produced: hashFileSet(producedFiles),
  };
  fs.writeFileSync(FILE_HASHES_FILE, `${JSON.stringify(fileHashes, null, 2)}\n`, 'utf8');

  // ---- manifest (self-excluding) ----------------------------------------
  const manifestFiles = [...new Set([...r2aFiles, ...producedFiles, rel(FILE_HASHES_FILE)])]
    .filter((file) => file !== rel(MANIFEST_FILE))
    .sort();
  const manifestEntries = hashFileSet(manifestFiles);
  const manifest = {
    schema: 'cbhr-rdc/r2-t0a-manifest/v1',
    runId: RUN_ID,
    sessionId: SESSION_ID,
    generatedAtUtc: new Date().toISOString(),
    note: 'Covers every file written by W3-B R2-T0A plus the r2a harness sources, except the manifest itself (self-exclusion). GATE-MANIFEST.json and PM-R2-T0A-TERMINAL.json are PM-owned and excluded.',
    fileCount: manifestEntries.length,
    manifestAggregateSha256: results.sha256Json(manifestEntries),
    files: manifestEntries,
  };
  fs.writeFileSync(MANIFEST_FILE, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');

  out(`[r2-t0a] rows=${summary.rows} byStatus=${JSON.stringify(summary.byStatus)} byTierExecuted=${JSON.stringify(summary.byTierExecuted)}`);
  out(`[r2-t0a] blockedAtFactoryComposition=${summary.blockedAtFactoryComposition} productClaimTrue=${summary.productClaimTrue}`);
  out(`[r2-t0a] namespaceAuditOk=${namespaceAudit.ok} r2Unchanged=${protection.r2Sources.identical} t0Unchanged=${protection.t0Evidence.identical} addendumIdentical=${protection.addendum.identical} g16AfterOk=${g16After.ok}`);
  out(`[r2-t0a] results sha256=${sha256FileSafe(RESULTS_FILE)}`);
  out(`[r2-t0a] report sha256=${sha256FileSafe(REPORT_FILE)}`);
  out(`[r2-t0a] manifest sha256=${sha256FileSafe(MANIFEST_FILE)}`);
  out(`[r2-t0a] VERDICT ${rec.verdict}: ${rec.reason}`);

  const clean =
    rec.verdict === 'READY_FOR_GOVERNOR_REVIEW' &&
    namespaceAudit.ok &&
    protection.r2Sources.identical &&
    protection.t0Evidence.identical &&
    protection.addendum.identical &&
    g16After.ok;
  process.exitCode = clean ? 0 : 1;
}

main().catch(async (err) => {
  try {
    fs.mkdirSync(T0A_DIR, { recursive: true });
    fs.writeFileSync(
      path.join(T0A_DIR, 'R2-T0A-HARNESS-FAIL.json'),
      `${JSON.stringify({ runId: RUN_ID, status: 'HARNESS_FAIL', error: results.errorView(err), stack: err.stack }, null, 2)}\n`,
      'utf8',
    );
  } catch {
    /* nothing else can be done */
  }
  process.stdout.write(`${JSON.stringify({ status: 'HARNESS_FAIL', error: results.errorView(err) }, null, 2)}\n`);
  await sealLog().catch(() => {});
  process.exitCode = 1;
});