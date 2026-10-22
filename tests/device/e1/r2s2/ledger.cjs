'use strict';

/**
 * W3-B R2 S2-T result ledger + report writer (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Truthfulness rules enforced as code:
 *   - status vocabulary is exactly PASS_CURRENT / EXPECTED_RED / UNEXPECTED_RED / HARNESS_FAIL /
 *     ENV_BLOCKED;
 *   - a row's key set is exactly the authorized twelve keys;
 *   - EXPECTED_RED requires a non-null `actual` observation;
 *   - HARNESS_FAIL is reserved for fixture defects (it is the only status a caller passes
 *     explicitly); an EXPECTED_RED row may never carry productMethodInvoked=false.
 */

const fs = require('node:fs');
const path = require('node:path');

const S2T_DIR = path.resolve(__dirname, '..', '..', '_phase1_evidence', 'w3b-r2', 's2t');
const ARTIFACT_DIR = path.join(S2T_DIR, 'artifacts');
const REPORT_PATH = path.join(S2T_DIR, 'S2T-TEST-REPORT.md');
const RESULTS_PATH = path.join(S2T_DIR, 'S2T-RESULTS.json');

const STATUS = Object.freeze({
  PASS_CURRENT: 'PASS_CURRENT',
  EXPECTED_RED: 'EXPECTED_RED',
  UNEXPECTED_RED: 'UNEXPECTED_RED',
  HARNESS_FAIL: 'HARNESS_FAIL',
  ENV_BLOCKED: 'ENV_BLOCKED',
});

const ROW_KEYS = Object.freeze([
  'id',
  'tier',
  'status',
  'productMethodInvoked',
  'expectedOracle',
  'actual',
  'components',
  'pids',
  'attempts',
  'dbName',
  'dbReadBack',
  'sourceHashes',
]);

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeJson(file, value) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  return file;
}

function sha256File(absolute) {
  return require('node:crypto').createHash('sha256').update(fs.readFileSync(absolute)).digest('hex');
}

/** Builds one row with EXACTLY the authorized key set. */
function makeRow({
  id,
  tier,
  status,
  productMethodInvoked,
  expectedOracle,
  actual,
  components = [],
  pids = null,
  attempts = null,
  dbName = null,
  dbReadBack = null,
  sourceHashes,
}) {
  if (!Object.values(STATUS).includes(status)) {
    throw new Error(`unknown status ${status}`);
  }
  if (status === STATUS.EXPECTED_RED && (actual === null || actual === undefined)) {
    throw new Error(`row ${id} is EXPECTED_RED without an observed actual`);
  }
  if (status === STATUS.EXPECTED_RED && productMethodInvoked !== true) {
    throw new Error(`row ${id} is EXPECTED_RED without productMethodInvoked=true`);
  }
  const row = {
    id,
    tier,
    status,
    productMethodInvoked: productMethodInvoked === true,
    expectedOracle: String(expectedOracle),
    actual,
    components,
    pids,
    attempts,
    dbName,
    dbReadBack,
    sourceHashes,
  };
  const keys = Object.keys(row);
  if (keys.length !== ROW_KEYS.length || keys.some((key, index) => key !== ROW_KEYS[index])) {
    throw new Error(`row ${id} key drift: ${keys.join(',')}`);
  }
  return row;
}

function summarise(rows) {
  const byStatus = {};
  for (const row of rows) {
    byStatus[row.status] = (byStatus[row.status] ?? 0) + 1;
  }
  return { rows: rows.length, byStatus };
}

/** Component ledger line: names each sub-oracle with its met verdict. */
function componentLine(component) {
  const met = component.met === true ? 'MET' : 'NOT_MET';
  return `  - [${met}] ${component.name}: oracle=${component.oracle} | actual=${component.actual}`;
}

function renderReport({ rows, preflight, namespaceAudit, harness, generatedAt, blockedReason }) {
  const summary = summarise(rows);
  const lines = [];
  lines.push('# W3-B R2 S2-T — Generation Fence / Error Catalogue Test-First Report');
  lines.push('');
  lines.push('Commission PHASE1-LOCAL-AUTHORITY-001. TEST/EVIDENCE ONLY. Production G0 BLOCKED.');
  lines.push('Owner: child agent S2T-TEST (depth one). Frozen HEAD: a3fb9754bce5a940cb0f78161985b93c20d74727.');
  lines.push('Authorization: cbhr-rdc/docs/GOVERNOR-W3B-R2-S2T-AUTHORIZATION-20261015.md');
  lines.push('Binding design: R1 freeze F2/F9 + R1R freeze addendum + W3-B R2 post-S1 disposition.');
  lines.push('');
  lines.push(`Generated: ${generatedAt}`);
  if (blockedReason) {
    lines.push('');
    lines.push(`**BLOCKED**: ${blockedReason}`);
  }
  lines.push('');
  lines.push('## STEP 2 — Frozen input hash preflight (SHA-256, lowercase hex)');
  lines.push('');
  lines.push(`Preflight verdict: ${preflight.ok ? 'PASS' : 'BLOCKED'}`);
  lines.push('');
  lines.push('| path | observed SHA-256 | authorized | verdict |');
  lines.push('|---|---|---|---|');
  for (const entry of preflight.entries) {
    lines.push(
      `| ${entry.path} | ${entry.observed ?? '(not computed: ' + entry.error + ')'} | ${entry.authorized} | ${
        entry.match ? 'MATCH' : 'MISMATCH'
      } |`,
    );
  }
  lines.push('');
  lines.push('## Harness disclosure');
  lines.push('');
  lines.push(`- registry: ${harness.registrySource}`);
  lines.push(`- composition precondition: ${harness.compositionPrecondition}`);
  lines.push(`- audit sink: ${harness.auditSink}`);
  lines.push(`- mongo: ${JSON.stringify(harness.mongo)}`);
  lines.push(`- db prefix: ${harness.dbPrefix}`);
  lines.push(`- compositionBlocked/compositionFailView used: ${harness.compositionShortcutUsed}`);
  lines.push(
    '- pre-run harness validation: tests/device/e1/r2s2/smoke.cjs composed the genuine registry against a fenced s2t database and confirmed all three frozen factories accepted before the row evidence was built; no row depends on it',
  );
  lines.push(`- evidence dir: ${harness.evidenceDir}`);
  lines.push(`- node: ${harness.nodeVersion}; pids observed by the runner: ${harness.runnerPid}; mongoose/driver: ${harness.driverVersion}`);
  lines.push('');
  const auditInteraction = rows.some((row) =>
    JSON.stringify(row.actual ?? {}).includes('AUDIT_DELIVERY_UNCERTAIN'),
  );
  if (auditInteraction) {
    lines.push('## Cross-cutting truthful observation — after-CAS/audit interaction');
    lines.push('');
    lines.push(
      'The real `AuditEvent` schema marks both `actor` and `reasonCode` as `required: true` ' +
        '(packages/data-schemas/src/schema/auditEvent.ts:57-66), while the product authority emitter ' +
        'passes `reasonCode: null` for grant/renew/revoke (authorityService.js:320-356). With the real ' +
        'sink the event is rejected by a Mongoose ValidationError, so every committed authority CAS in ' +
        'this lane returns `ok:false` with `AUDIT_DELIVERY_UNCERTAIN` (500) AFTER the mutation has ' +
        'committed, and zero audit rows persist. This is reported per row and never worked around with a ' +
        'fake or raw-driver sink; authority mutation is therefore measured from `matched`, the raw-driver ' +
        'read-back and the epoch delta, not from `ok === true`.',
    );
    lines.push('');
  }
  lines.push('## Namespace audit (STEP 5)');
  lines.push('');
  lines.push(`- ok: ${namespaceAudit.ok}`);
  lines.push(`- identical before/after: ${namespaceAudit.identical}`);
  lines.push(`- before (${namespaceAudit.before.length}): ${namespaceAudit.before.join(', ')}`);
  lines.push(`- after (${namespaceAudit.after.length}): ${namespaceAudit.after.join(', ')}`);
  lines.push(`- created: ${JSON.stringify(namespaceAudit.created)}`);
  lines.push(`- removed: ${JSON.stringify(namespaceAudit.removed)}`);
  lines.push(`- foreign created: ${JSON.stringify(namespaceAudit.foreignCreated)}`);
  lines.push(`- foreign removed: ${JSON.stringify(namespaceAudit.foreignRemoved)}`);
  lines.push(`- leftovers: ${JSON.stringify(namespaceAudit.leftovers)}`);
  lines.push('');
  lines.push('## Row ledger');
  lines.push('');
  lines.push('| id | tier | status | productMethodInvoked | attempts/pids |');
  lines.push('|---|---|---|---|---|');
  for (const row of rows) {
    const extra =
      row.attempts === null && row.pids === null
        ? '—'
        : `attempts=${row.attempts ?? '—'} pids=${JSON.stringify(row.pids ?? null)}`;
    lines.push(`| ${row.id} | ${row.tier} | ${row.status} | ${row.productMethodInvoked} | ${extra} |`);
  }
  lines.push('');
  lines.push(
    `Counts by status: ${Object.entries(summary.byStatus)
      .map(([status, count]) => `${status}=${count}`)
      .join(' ')} (total ${summary.rows})`,
  );
  lines.push('');
  for (const row of rows) {
    lines.push(`## ${row.id} — ${row.status} (tier ${row.tier})`);
    lines.push('');
    lines.push(`- expected oracle: ${row.expectedOracle}`);
    lines.push(`- productMethodInvoked: ${row.productMethodInvoked}`);
    lines.push(`- dbName: ${row.dbName ?? '(none)'}`);
    lines.push('');
    lines.push('Components:');
    if (row.components.length === 0) {
      lines.push('  - (none)');
    } else {
      for (const component of row.components) {
        lines.push(componentLine(component));
      }
    }
    lines.push('');
    lines.push('Observed actual:');
    lines.push('');
    lines.push('```json');
    lines.push(JSON.stringify(row.actual, null, 2));
    lines.push('```');
    lines.push('');
    lines.push('DB read-back:');
    lines.push('');
    lines.push('```json');
    lines.push(JSON.stringify(row.dbReadBack, null, 2));
    lines.push('```');
    lines.push('');
    lines.push(`sourceHashes: ${JSON.stringify(row.sourceHashes)}`);
    lines.push('');
  }
  return `${lines.join('\n')}\n`;
}

function writeOutputs({
  rows,
  preflight,
  namespaceAudit,
  harness,
  blockedReason = null,
  generatedAt = new Date().toISOString(),
}) {
  ensureDir(S2T_DIR);
  ensureDir(ARTIFACT_DIR);
  const results = {
    rows,
    namespaceAudit,
    frozenInputHashes: preflight.hashes,
    generatedAt,
    harness,
  };
  writeJson(RESULTS_PATH, results);
  const report = renderReport({ rows, preflight, namespaceAudit, harness, generatedAt, blockedReason });
  fs.writeFileSync(REPORT_PATH, report, 'utf8');
  return { results, report, generatedAt };
}

module.exports = {
  S2T_DIR,
  ARTIFACT_DIR,
  REPORT_PATH,
  RESULTS_PATH,
  STATUS,
  ROW_KEYS,
  ensureDir,
  writeJson,
  sha256File,
  makeRow,
  summarise,
  renderReport,
  writeOutputs,
};