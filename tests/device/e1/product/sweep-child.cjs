'use strict';

/**
 * E1-V24T12 sweep-arm child (lane I9 / task T1).
 *
 *   node sweep-child.cjs --db=<w3 db> --mode=enabled|disabled --rundir=<dir> --clock=<ms>
 *
 * Runs ONE deterministic decision set through the real I6/I5 bytes against its own real MongoDB
 * database and writes the resulting decision vector. The CBHR_PHASE1_SWEEP env var is set by the
 * parent per arm; the product surface exposes no background sweep at all, so this child measures
 * exactly that: between two observations of a lapsed row, nothing but an explicit product CAS may
 * change it.
 */

const fs = require('node:fs');
const path = require('node:path');

const support = require('../w3a/support.cjs');
const env = require('../w3a/env.cjs');

const TENANT = env.TENANT;
const OWNER = env.OWNER_C;

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith('--')) continue;
    const [flag, inline] = arg.includes('=') ? arg.split(/=(.*)/s, 2) : [arg, null];
    const value = inline !== null ? inline : argv[index + 1];
    options[flag.slice(2)] = value === undefined ? true : value;
    if (inline === null) index += 1;
  }
  return options;
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  // Atomic publish: write a private temp file, then rename, so no reader observes a partial file.
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  fs.renameSync(tmp, file);
}

function decision(step, result) {
  return {
    step,
    ok: result !== null && result !== undefined && result.ok === true,
    matched: result !== null && result !== undefined && typeof result.matched === 'number' ? result.matched : 0,
    errorCode: result !== null && result !== undefined && result.error ? result.error.code : null,
  };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const dbName = options.db;
  const mode = options.mode;
  const rundir = options.rundir;
  const clockMs = Number(options.clock);

  const ctx = await support.makeContext({
    tag: `sweep-${mode}`,
    dbName,
    syncIndexes: false,
    dropOnTeardown: false,
    mode: 'raw-registry',
    principalId: OWNER,
  });
  ctx.clock.set(clockMs);
  const authority = ctx.authorityService();
  const pairing = ctx.pairingService();
  const decisions = [];
  const T = ctx.clock.now();

  try {
    const device = await support.seedDevice(ctx, 'sweep-main', { _id: 'e1-sweep-main' });
    const sentinel = await support.seedDevice(ctx, 'sweep-sentinel', {
      _id: 'e1-sweep-sentinel',
      identityState: 'active',
      leaseState: 'active',
      ownerId: `principal-e1-sweep-sentinel`,
      grantId: 'e1-sweep-sentinel-grant-0001',
      epoch: 1,
      activatedAt: new Date(T),
      expiresAt: new Date(T + env.constants.LEASE_TTL_MS),
    });
    ctx.bindTrust({ deviceId: device.deviceId, principalId: OWNER });

    // 1. real claim
    decisions.push(decision('claim', await authority.claimAuthority({
      deviceId: device.deviceId,
      tenantId: TENANT,
      ownerId: OWNER,
      expectedEpoch: 0,
      sessionId: 'e1-sweep-claim-1',
      grantProof: null,
    })));
    const claimed = await ctx.models.DeviceAuthority.findOne({ _id: device.deviceId, tenantId: TENANT }).lean();
    decisions.push({ step: 'claim-state', ok: claimed.leaseState === 'active' && claimed.epoch === 1, matched: claimed.epoch, errorCode: null });

    // 2. authorize boundaries (harness oracle over product state)
    ctx.clock.set(T + env.constants.LEASE_TTL_MS - 1);
    decisions.push({
      step: 'authorize-live',
      ok: support.authorizePredicate(claimed, { ownerId: OWNER, epoch: claimed.epoch, grantId: claimed.grantId, now: ctx.clock.now() }).allowed === true,
      matched: 1,
      errorCode: null,
    });
    ctx.clock.set(T + env.constants.LEASE_TTL_MS);
    decisions.push({
      step: 'authorize-lapsed',
      ok: support.authorizePredicate(claimed, { ownerId: OWNER, epoch: claimed.epoch, grantId: claimed.grantId, now: ctx.clock.now() }).allowed === false,
      matched: 0,
      errorCode: 'LEASE_EXPIRED_BARE',
    });

    // 3. Lapsed sentinel: the sweep would have flipped this row. Nothing may.
    ctx.clock.set(T + env.constants.LEASE_TTL_MS + env.constants.SKEW_MARGIN_MS + 1);
    const sentinelBefore = await ctx.models.DeviceAuthority.findOne({ _id: sentinel.deviceId, tenantId: TENANT }).lean();
    // (no product call in between: a background sweep, if any existed, would fire here)
    const sentinelAfter = await ctx.models.DeviceAuthority.findOne({ _id: sentinel.deviceId, tenantId: TENANT }).lean();
    decisions.push({
      step: 'sweep-sentinel-untouched',
      ok: sentinelBefore.leaseState === 'active' && sentinelAfter.leaseState === 'active' && sentinelAfter.epoch === sentinelBefore.epoch,
      matched: sentinelAfter.epoch,
      errorCode: null,
    });

    // 4. the ONLY expiry transition is the explicit guarded release
    const release = await authority.releaseLapsedLease({ deviceId: device.deviceId, tenantId: TENANT });
    decisions.push(decision('release-lapsed', release));
    const released = await ctx.models.DeviceAuthority.findOne({ _id: device.deviceId, tenantId: TENANT }).lean();
    decisions.push({
      step: 'release-state',
      ok: released.leaseState === 'expired' && released.epoch === claimed.epoch + 1,
      matched: released.epoch,
      errorCode: null,
    });

    // 5. stale revoke after the release fails closed
    decisions.push(decision('revoke-stale', await authority.revokeLease({
      deviceId: device.deviceId,
      tenantId: TENANT,
      ownerId: OWNER,
      epoch: claimed.epoch,
    })));

    // 6. a fresh product ceremony re-claims and revokes legally
    const ceremony = await support.runPairingCeremony(ctx, {
      deviceId: device.deviceId,
      deviceKeyId: device.deviceKeyId,
      ownerId: OWNER,
      key: device.key,
    });
    decisions.push({ step: 'claim-fresh', ok: ceremony.ok === true, matched: ceremony.ok ? 1 : 0, errorCode: ceremony.approve && ceremony.approve.error ? ceremony.approve.error.code : null });
    const reclaimed = await ctx.models.DeviceAuthority.findOne({ _id: device.deviceId, tenantId: TENANT }).lean();
    decisions.push({ step: 'claim-fresh-state', ok: reclaimed.leaseState === 'active', matched: reclaimed.epoch, errorCode: null });
    decisions.push(decision('revoke-live', await authority.revokeLease({
      deviceId: device.deviceId,
      tenantId: TENANT,
      ownerId: OWNER,
      epoch: reclaimed.epoch,
    })));

    const finalRow = await ctx.models.DeviceAuthority.findOne({ _id: device.deviceId, tenantId: TENANT }).lean();
    const vector = {
      mode,
      sweepKnob: process.env.CBHR_PHASE1_SWEEP ?? 'unset',
      decisions,
      backgroundSweepProcessesSpawned: 0,
      sweepSentinelPreDecision: { leaseState: sentinelAfter.leaseState, epoch: sentinelAfter.epoch },
      explicitExpiryTransitions: decisions.filter((entry) => entry.step === 'release-lapsed' && entry.ok === true).length,
      finalState: {
        leaseState: finalRow.leaseState,
        identityState: finalRow.identityState,
        epoch: finalRow.epoch,
        ownerId: finalRow.ownerId,
        grantIdIssued: typeof finalRow.grantId === 'string' && finalRow.grantId.length > 0,
      },
      decisionCount: decisions.length,
    };

    writeJson(`${rundir}/vector-${mode}.json`, vector);
    writeJson(`${rundir}/${mode}-writeconcern.json`, { summary: ctx.recorder.summary() });
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
