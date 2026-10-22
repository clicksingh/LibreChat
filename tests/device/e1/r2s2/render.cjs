'use strict';

/**
 * W3-B R2 S2-T report/results re-renderer (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Re-renders S2T-TEST-REPORT.md and S2T-RESULTS.json from the ALREADY-CAPTURED row evidence and
 * re-runs only the read-only frozen-input hash preflight. It opens no database connection and
 * executes no product code, so the captured PIDs, attempts and DB read-backs are byte-preserved and
 * the original evidence timestamp is retained.
 */

const fs = require('node:fs');
const path = require('node:path');

const ledger = require('./ledger.cjs');
const { runPreflight } = require('./preflight.cjs');

function main() {
  const stored = JSON.parse(fs.readFileSync(ledger.RESULTS_PATH, 'utf8'));
  const preflight = runPreflight();
  if (!preflight.ok) {
    throw new Error(`frozen-input preflight failed during re-render: ${preflight.problems.join(' | ')}`);
  }
  ledger.writeOutputs({
    rows: stored.rows,
    preflight,
    namespaceAudit: stored.namespaceAudit,
    harness: stored.harness,
    generatedAt: stored.generatedAt,
  });

  const artifacts = fs
    .readdirSync(ledger.ARTIFACT_DIR, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name !== 'S2T-MANIFEST.json')
    .map((entry) => {
      const file = path.join(ledger.ARTIFACT_DIR, entry.name);
      return { id: entry.name, file, bytes: fs.statSync(file).size };
    });
  const manifest = {
    generatedAt: stored.generatedAt,
    reRenderedAt: new Date().toISOString(),
    frozenInputHashes: preflight.hashes,
    preflightOk: preflight.ok,
    harness: stored.harness,
    rowCounts: ledger.summarise(stored.rows),
    namespaceAudit: stored.namespaceAudit,
    artifactFileCount: artifacts.length,
    note: 're-rendered from captured evidence; no row was re-executed',
  };
  ledger.writeJson(path.join(ledger.ARTIFACT_DIR, 'S2T-MANIFEST.json'), manifest);

  process.stdout.write(
    `[r2-s2t] re-rendered report+results for ${stored.rows.length} rows; statuses ${JSON.stringify(
      ledger.summarise(stored.rows).byStatus,
    )}; namespace ok=${stored.namespaceAudit.ok}\n`,
  );
}

main();