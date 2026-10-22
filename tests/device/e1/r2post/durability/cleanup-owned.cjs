'use strict';

/**
 * W3-B R2 S4T lane-owned database cleanup (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 *   node tests/device/e1/r2post/durability/cleanup-owned.cjs [--dry-run]
 *
 * Drops ONLY databases matching `cbhr_rdc_phase1_r2_s4t_*` (this lane's own namespace). Every other
 * database is refused and reported, so a leaked database from an aborted run can be removed without
 * touching accept-lane or production-like names.
 */

const fence = require('./fence.cjs');

async function main() {
  const dryRun = process.argv.includes('--dry-run');
  const dbName = fence.createDbName('cleanup', require('node:crypto'));
  const connector = fence.makeConnector({});
  const guarded = await fence.connectGuarded({
    dbName,
    appName: 'cbhr-phase1-r2-s4t-cleanup',
    connector,
  });
  const out = {
    dryRun,
    gateOrder: 'assertPreConnect -> construct',
    clientConstructions: connector.state.clientConstructions,
    topology: guarded.topology,
    before: [],
    owned: [],
    refused: [],
    drops: [],
    after: [],
    leftover: [],
    ok: false,
  };
  try {
    out.before = await fence.listDatabaseNames();
    for (const name of out.before) {
      if (fence.isOwnedDb(name)) {
        out.owned.push(name);
      } else if (/^cbhr_rdc_phase1_r2_s4t/i.test(name)) {
        out.refused.push({ name, reason: 'matches the s4t prefix but fails isOwnedDb (fence-refused)' });
      }
    }
    if (!dryRun) {
      for (const name of out.owned) {
        // eslint-disable-next-line no-await-in-loop
        out.drops.push(await fence.dropOwnDatabase(guarded.client, name));
      }
    }
    out.after = await fence.listDatabaseNames();
    out.leftover = out.after.filter((name) => fence.isOwnedDb(name));
    out.ok = out.leftover.length === 0 && out.drops.every((entry) => entry.dropped === true);
  } finally {
    await guarded.client.close().catch(() => {});
  }
  process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
  process.exitCode = out.ok ? 0 : 1;
}

main().catch((err) => {
  process.stderr.write(`CLEANUP_FAIL: ${err && err.stack ? err.stack : String(err)}\n`);
  process.exitCode = 1;
});
