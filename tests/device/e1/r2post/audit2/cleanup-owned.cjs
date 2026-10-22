'use strict';

/**
 * Lane-owned database cleanup (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 *   node tests/device/e1/r2post/audit2/cleanup-owned.cjs [--dry-run]
 *
 * Drops ONLY databases matching `cbhr_rdc_phase1_r2_t1r_*` (this lane's own namespace).
 * Every other database is refused and reported. Used to remove a database leaked by an
 * aborted run whose emergency drop raced a still-in-flight Mongoose index build.
 */

const fence = require('./fence.cjs');

async function main() {
  const dryRun = process.argv.includes('--dry-run');
  const dbName = fence.createDbName('cleanup', require('node:crypto'));
  fence.assertDbName(dbName);
  const guarded = await fence.connectGuarded({ dbName, appName: 'cbhr-phase1-r2-t1r-cleanup' });
  const out = { dryRun, topology: guarded.topology, before: [], owned: [], refused: [], drops: [], after: [], leftover: [] };
  try {
    out.before = await fence.listDatabases(guarded.client);
    for (const name of out.before) {
      if (fence.isOwnedDb(name)) {
        out.owned.push(name);
      } else if (/^cbhr_rdc_phase1_r2_t1r/i.test(name)) {
        out.refused.push({ name, reason: 'matches the t1r prefix but fails isOwnedDb (fence-refused)' });
      }
    }
    if (!dryRun) {
      for (const name of out.owned) {
        // eslint-disable-next-line no-await-in-loop
        out.drops.push(await fence.dropOwnDatabase(guarded.client, name));
      }
    }
    out.after = await fence.listDatabases(guarded.client);
    out.leftover = out.after.filter((name) => fence.isOwnedDb(name));
  } finally {
    await guarded.client.close();
  }
  process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
}

main().catch((err) => {
  process.stderr.write(`CLEANUP_FAIL: ${err && err.stack ? err.stack : String(err)}\n`);
  process.exitCode = 1;
});
