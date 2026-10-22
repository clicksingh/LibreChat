'use strict';

/**
 * W3-A / I11 E2 claim-race child process.
 *
 *   node child-race.cjs --db=<w3 db> --fixture=E2-T7 --shard=A --rounds=25 --rundir=<dir> --clock=<ms>
 *
 * Protocol (file-based only; no piped stdio):
 *   1. write  <rundir>/<fixture>-ready-<round>-<shard>.json  { pid, shard, round }
 *   2. await  <rundir>/<fixture>-go-<round>.json             (written by the parent)
 *   3. run the real product call and write
 *      <rundir>/<fixture>-res-<round>-<shard>.json           { pid, shard, round, action, ok, matched, errorCode }
 *   4. repeat for every round, then disconnect and exit 0.
 */

const common = require('./child-common.cjs');
const env = require('./env.cjs');

const { TENANT } = env;

async function main() {
  const options = common.parseArgs(process.argv.slice(2));
  const dbName = options.db;
  const fixture = options.fixture;
  const shard = options.shard;
  const rounds = Number(options.rounds ?? 25);
  const rundir = options.rundir;
  const clockMs = Number(options.clock);

  const ownerA = env.OWNER_A;
  const ownerB = env.OWNER_B;
  const ctx = await common.buildChildContext({ dbName, clockMs, tag: `${fixture}-${shard}` });
  const authority = ctx.authorityService();

  try {
    for (let round = 0; round < rounds; round += 1) {
      common.writeJsonFile(`${rundir}/${fixture}-ready-${round}-${shard}.json`, {
        pid: process.pid,
        shard,
        round,
        at: ctx.clock.now(),
      });
      const go = await common.waitForFile(`${rundir}/${fixture}-go-${round}.json`);
      const deviceId = go.deviceId;

      let action;
      if (fixture === 'E2-T7-ONEPC-TWO-PC-RACE') {
        action = {
          method: 'claimAuthority',
          args: { deviceId, tenantId: TENANT, ownerId: ownerA, sessionId: `w3a-t7-${shard}-${round}`, grantProof: null },
        };
      } else if (fixture === 'E2-T8-TWO-OWNERS-ONE-PC-RACE') {
        action = {
          method: 'claimAuthority',
          args: { deviceId, tenantId: TENANT, ownerId: shard === 'A' ? ownerA : ownerB, sessionId: `w3a-t8-${shard}-${round}`, grantProof: null },
        };
      } else if (fixture === 'E2-V24T15-REVOKE-VS-CLAIM-RACE') {
        action =
          shard === 'A'
            ? { method: 'revokeLease', args: { deviceId, tenantId: TENANT, ownerId: go.ownerId, epoch: go.epoch } }
            : { method: 'claimAuthority', args: { deviceId, tenantId: TENANT, ownerId: go.claimOwnerId, sessionId: `w3a-t15-${round}`, grantProof: null } };
      } else {
        throw new Error(`unknown race fixture ${fixture}`);
      }

      const started = process.hrtime.bigint();
      const result = await authority[action.method](action.args);
      const durationMs = Number(process.hrtime.bigint() - started) / 1e6;

      common.writeJsonFile(`${rundir}/${fixture}-res-${round}-${shard}.json`, {
        pid: process.pid,
        shard,
        round,
        action: action.method,
        ownerId: action.args.ownerId,
        deviceId,
        ok: result.ok === true,
        matched: result.matched ?? 0,
        errorCode: result.error ? result.error.code : null,
        httpStatus: result.error ? result.error.httpStatus : null,
        durationMs: Number(durationMs.toFixed(3)),
        authorityAfter:
          result.authority === null || result.authority === undefined
            ? null
            : {
                leaseState: result.authority.leaseState,
                identityState: result.authority.identityState,
                epoch: result.authority.epoch,
                ownerId: result.authority.ownerId,
                grantIdIssued: typeof result.authority.grantId === 'string' && result.authority.grantId.length > 0,
              },
      });
    }

    common.writeJsonFile(`${rundir}/${fixture}-summary-${shard}.json`, {
      pid: process.pid,
      shard,
      rounds,
      writeConcernSummary: ctx.recorder.summary(),
      duplicateKeyObservations: ctx.recorder.duplicateErrors(),
      writeCalls: ctx.recorder.entries
        .filter((entry) => ['document', 'update', 'pipeline'].includes(entry.payloadKind))
        .map((entry) => ({ model: entry.model, method: entry.method, options: entry.options, ok: entry.ok, errorCode: entry.error ? entry.error.code : null })),
    });
    return 0;
  } finally {
    await ctx.teardown().catch(() => {});
  }
}

main().then(
  (code) => {
    process.exit(code);
  },
  (err) => {
    process.stderr.write(`${JSON.stringify({ child: 'race', status: 'HARNESS_FAIL', error: { name: err.name, message: err.message } })}\n`);
    process.exit(4);
  },
);