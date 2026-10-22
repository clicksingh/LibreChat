'use strict';

/**
 * W3-A / I11 naive check-then-insert child (engine-level negative control).
 *
 *   node child-naive.cjs --db=<w3 db> --shard=A --rounds=25 --rundir=<dir> --owner=<id>
 *
 * Per round, in this exact order:
 *   1. read  countDocuments({ownerId,tenantId,leaseState:'active'})   (raw driver)
 *   2. write <rundir>/naive-read-<round>-<shard>.json  { pid, readCount }
 *   3. await <rundir>/naive-go-<round>.json            (parent releases both shards)
 *   4. insertOne one active authority row for the same owner           (raw driver)
 *   5. write <rundir>/naive-res-<round>-<shard>.json
 *
 * The barrier guarantees every read precedes every write, which is exactly the naive
 * check-then-insert race the frozen control requires. No Mongoose model is used here.
 */

const common = require('./child-common.cjs');
const fence = require('./fence.cjs');

async function main() {
  const options = common.parseArgs(process.argv.slice(2));
  const dbName = options.db;
  const shard = options.shard;
  const rounds = Number(options.rounds ?? 25);
  const rundir = options.rundir;
  const ownerId = options.owner;
  const tenantId = options.tenant;
  const clock = Number(options.clock);

  const { client } = await fence.connectGuarded({ dbName, appName: `cbhr-phase1-w3a-naive-${shard}`.slice(0, 60) });
  const collection = client.db(dbName).collection('deviceauthorities');
  const rowId = `w3a-naive-row-${shard}`;
  try {
    for (let round = 0; round < rounds; round += 1) {
      const readCount = await collection.countDocuments({ ownerId, tenantId, leaseState: 'active' });
      common.writeJsonFile(`${rundir}/naive-read-${round}-${shard}.json`, {
        pid: process.pid,
        shard,
        round,
        readCount,
      });
      await common.waitForFile(`${rundir}/naive-go-${round}.json`);
      let outcome;
      try {
        const result = await collection.insertOne(
          {
            _id: rowId,
            tenantId,
            deviceId: `w3a-naive-device-${shard}`,
            deviceKeyId: `w3a-naive-key-${shard}`,
            devicePublicKey: 'naive-control-key',
            identityState: 'active',
            leaseState: 'active',
            epoch: 1,
            ownerId,
            grantId: `w3a-naive-grant-${shard}`,
            activatedAt: new Date(clock),
            expiresAt: new Date(clock + 172800000),
            renewalCount: 0,
          },
          { writeConcern: { w: 'majority', j: true } },
        );
        outcome = { inserted: result.acknowledged === true, code: null, keyPattern: null };
      } catch (err) {
        outcome = { inserted: false, code: err.code ?? null, keyPattern: err.keyPattern ?? null, message: err.message };
      }
      common.writeJsonFile(`${rundir}/naive-res-${round}-${shard}.json`, {
        pid: process.pid,
        shard,
        round,
        readCount,
        ...outcome,
      });
    }
    return 0;
  } finally {
    await client.close().catch(() => {});
  }
}

main().then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(`${JSON.stringify({ child: 'naive', status: 'HARNESS_FAIL', error: { name: err.name, message: err.message } })}\n`);
    process.exit(4);
  },
);