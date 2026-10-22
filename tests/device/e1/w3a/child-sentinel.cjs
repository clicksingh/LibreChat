'use strict';

/**
 * W3-A / I11 crash-transport self-test child (harness control, no product service).
 *
 *   node child-sentinel.cjs --db=<w3 db> --rundir=<dir>
 *
 * Inserts one durable marker with majority+journal, writes a witness whose `witnessCount` is 0
 * (proving the child never reached its post-write step) and exits with sentinel code 7.
 */

const common = require('./child-common.cjs');
const fence = require('./fence.cjs');

const SENTINEL = 7;

async function main() {
  const options = common.parseArgs(process.argv.slice(2));
  const dbName = options.db;
  const rundir = options.rundir;
  const { client } = await fence.connectGuarded({ dbName, appName: 'cbhr-phase1-w3a-sentinel' });
  try {
    const result = await client
      .db(dbName)
      .collection('deviceauthorityevents')
      .insertOne(
        { _id: 'w3a-sentinel-marker', kind: 'sentinel', ts: new Date(0), note: 'crash-transport self-test marker' },
        { writeConcern: { w: 'majority', j: true } },
      );
    common.writeJsonFile(`${rundir}/sentinel-witness.json`, {
      pid: process.pid,
      dbName,
      markerInserted: result.acknowledged === true,
      witnessedAfterWrite: false,
      witnessCount: 0,
    });
  } finally {
    await client.close().catch(() => {});
  }
  process.exit(SENTINEL);
}

main().catch((err) => {
  process.stderr.write(`${JSON.stringify({ child: 'sentinel', status: 'HARNESS_FAIL', error: { name: err.name, message: err.message } })}\n`);
  process.exit(4);
});