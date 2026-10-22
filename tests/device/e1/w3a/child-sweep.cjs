'use strict';

/**
 * W3-A / I11 sweep child: runs one deterministic decision set through the real product bytes and
 * writes the resulting decision vector.
 *
 *   node child-sweep.cjs --db=<w3 db> --rundir=<dir> --clock=<ms> --vector=<enabled|disabled>
 *
 * `CBHR_PHASE1_SWEEP` is inherited from the parent, so the two runs genuinely differ per OS
 * process. The vector deliberately contains no random value (grant ids are reduced to
 * issued/rotated booleans and lengths), so a byte-identical vector is meaningful.
 */

const common = require('./child-common.cjs');
const support = require('./support.cjs');
const env = require('./env.cjs');

const { TENANT } = env;

function authorityVector(authority) {
  if (!authority) {
    return null;
  }
  return {
    identityState: authority.identityState,
    leaseState: authority.leaseState,
    epoch: authority.epoch,
    ownerId: authority.ownerId,
    grantIdIssued: typeof authority.grantId === 'string' && authority.grantId.length === 22,
    ttlMs: authority.expiresAt && authority.activatedAt ? new Date(authority.expiresAt).getTime() - new Date(authority.activatedAt).getTime() : null,
    renewalCount: authority.renewalCount ?? null,
    prevEpoch: authority.prevEpoch ?? null,
    prevGrantIdIssued: typeof authority.prevGrantId === 'string' && authority.prevGrantId.length === 22,
  };
}

function decision(step, result, authority) {
  return {
    step,
    ok: result.ok === true,
    matched: result.matched ?? 0,
    errorCode: result.error ? result.error.code : null,
    httpStatus: result.error ? result.error.httpStatus : null,
    authority: authorityVector(authority),
  };
}

async function main() {
  const options = common.parseArgs(process.argv.slice(2));
  const dbName = options.db;
  const rundir = options.rundir;
  const clockMs = Number(options.clock);
  const vectorName = options.vector;
  const owner1 = 'principal-w3a-i11-sweep-1';
  const owner2 = 'principal-w3a-i11-sweep-2';
  const owner3 = 'principal-w3a-i11-sweep-3';
  const owner4 = 'principal-w3a-i11-sweep-4';

  const ctx = await common.buildChildContext({ dbName, clockMs, tag: `sweep-${vectorName}` });
  try {
    const T = ctx.clock.now();
    const d1 = await support.seedDevice(ctx, 'sweep-main');
    const sweepSentinel = await support.seedDevice(ctx, 'sweep-sentinel', {
      _id: 'w3a-device-sweep-sentinel',
      identityState: 'active',
      leaseState: 'active',
      ownerId: owner3,
      grantId: 'w3a-sweep-sentinel-grant',
      epoch: 1,
      activatedAt: new Date(T - 2 * env.constants.LEASE_TTL_MS),
      expiresAt: new Date(T - 60000),
    });
    // A second claimable device for the same owner to exercise the account-axis predicate.
    const d2 = await support.seedDevice(ctx, 'sweep-second', { _id: 'w3a-device-sweep-second' });

    const decisions = [];
    const authority = ctx.authorityService();

    const claim1 = await authority.claimAuthority({ deviceId: d1.deviceId, tenantId: TENANT, ownerId: owner1, sessionId: 'w3a-sweep-1', grantProof: null });
    let row = await support.readAuthorityRaw(ctx.models, d1.deviceId, TENANT);
    decisions.push(decision('claim-d1-owner1', claim1, row));
    const grant1 = row.grantId;
    const epoch1 = row.epoch;

    const claim2 = await authority.claimAuthority({ deviceId: d2.deviceId, tenantId: TENANT, ownerId: owner1, sessionId: 'w3a-sweep-2', grantProof: null });
    decisions.push(decision('claim-d2-same-owner', claim2, await support.readAuthorityRaw(ctx.models, d2.deviceId, TENANT)));

    const renewWrongGrant = await ctx
      .authorityService({
        verifyRenewalProof: env.makeRenewalProof({ tenantId: TENANT, ownerId: owner1, deviceId: d1.deviceId, deviceKeyId: d1.deviceKeyId, grantId: 'w3a-sweep-wrong-grant', epoch: epoch1 }),
      })
      .renewAuthority({ deviceId: d1.deviceId, tenantId: TENANT, ownerId: owner1, epoch: epoch1, grantId: grant1, proofInput: { __accept: true } });
    decisions.push(decision('renew-wrong-grant-binding', renewWrongGrant, await support.readAuthorityRaw(ctx.models, d1.deviceId, TENANT)));

    const renewOk = await ctx
      .authorityService({
        verifyRenewalProof: env.makeRenewalProof({ tenantId: TENANT, ownerId: owner1, deviceId: d1.deviceId, deviceKeyId: d1.deviceKeyId, grantId: grant1, epoch: epoch1 }),
      })
      .renewAuthority({ deviceId: d1.deviceId, tenantId: TENANT, ownerId: owner1, epoch: epoch1, grantId: grant1, proofInput: { __accept: true } });
    row = await support.readAuthorityRaw(ctx.models, d1.deviceId, TENANT);
    decisions.push(decision('renew-correct-binding', renewOk, row));

    const revokeStale = await authority.revokeLease({ deviceId: d1.deviceId, tenantId: TENANT, ownerId: owner1, epoch: epoch1 });
    decisions.push(decision('revoke-stale-epoch', revokeStale, await support.readAuthorityRaw(ctx.models, d1.deviceId, TENANT)));

    const revokeOk = await authority.revokeLease({ deviceId: d1.deviceId, tenantId: TENANT, ownerId: owner1, epoch: row.epoch });
    decisions.push(decision('revoke-current-epoch', revokeOk, await support.readAuthorityRaw(ctx.models, d1.deviceId, TENANT)));

    const claimAfterRevoke = await authority.claimAuthority({ deviceId: d1.deviceId, tenantId: TENANT, ownerId: owner2, sessionId: 'w3a-sweep-3', grantProof: null });
    row = await support.readAuthorityRaw(ctx.models, d1.deviceId, TENANT);
    decisions.push(decision('claim-after-revoke', claimAfterRevoke, row));

    const retire = await authority.retireIdentity({ deviceId: d1.deviceId, tenantId: TENANT, actor: owner2, role: 'owner' });
    decisions.push(decision('retire-owner', retire, await support.readAuthorityRaw(ctx.models, d1.deviceId, TENANT)));

    const claimRetired = await authority.claimAuthority({ deviceId: d1.deviceId, tenantId: TENANT, ownerId: owner2, sessionId: 'w3a-sweep-4', grantProof: null });
    decisions.push(decision('claim-retired', claimRetired, await support.readAuthorityRaw(ctx.models, d1.deviceId, TENANT)));

    const adminRetire = await authority.retireIdentity({ deviceId: d1.deviceId, tenantId: TENANT, actor: 'admin-w3a-i11', role: 'admin' });
    decisions.push(decision('retire-already-retired-admin', adminRetire, await support.readAuthorityRaw(ctx.models, d1.deviceId, TENANT)));

    const redeemMiss = await ctx.pairingService().redeemPairingCode({ code: '000001', tenantId: TENANT, ownerId: owner1 });
    decisions.push(decision('redeem-unknown-code', redeemMiss, null));

    const spendMiss = await authority.spendChallenge({ challengeHash: 'w3a-sweep-no-such-challenge', purpose: 'pairing-claim', tenantId: TENANT, bound: {} });
    decisions.push(decision('spend-unknown-challenge', spendMiss, null));

    // A row that only a background sweep could have flipped: it must still be active here.
    const sentinelBefore = await support.readAuthorityRaw(ctx.models, sweepSentinel.deviceId, TENANT);
    const sentinelClaim = await authority.claimAuthority({ deviceId: sweepSentinel.deviceId, tenantId: TENANT, ownerId: owner4, sessionId: 'w3a-sweep-5', grantProof: null });
    const sentinelAfter = await support.readAuthorityRaw(ctx.models, sweepSentinel.deviceId, TENANT);
    decisions.push(decision('claim-lapsed-sentinel', sentinelClaim, sentinelAfter));

    const vector = {
      clockBase: T,
      sweepSentinelPreDecision: authorityVector(sentinelBefore),
      decisions,
      backgroundSweepProcessesSpawned: 0,
      explicitExpiryTransitions: decisions.filter((entry) => entry.authority && entry.authority.leaseState === 'expired').length,
    };

    common.writeJsonFile(`${rundir}/vector-${vectorName}.json`, {
      pid: process.pid,
      vectorName,
      sweepKnob: process.env.CBHR_PHASE1_SWEEP ?? 'unset',
      vector,
    });
    common.writeJsonFile(`${rundir}/${vectorName}-writeconcern.json`, {
      pid: process.pid,
      summary: ctx.recorder.summary(),
    });
    return 0;
  } finally {
    await ctx.teardown().catch(() => {});
  }
}

main().then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(`${JSON.stringify({ child: 'sweep', status: 'HARNESS_FAIL', error: { name: err.name, message: err.message } })}\n`);
    process.exit(4);
  },
);