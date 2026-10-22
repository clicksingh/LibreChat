'use strict';

/**
 * W3-A / I11 crash-sentinel child.
 *
 *   node child-crash.cjs --db=<w3 db> --point=c2|c3|c4|c5|c6 --rundir=<dir> --clock=<ms>
 *
 * The child performs the REAL product write for the requested crash point and then calls
 * `process.exit(7)` from inside a test-only wrapper, i.e. before the next product step. A
 * witness file records the durable facts the parent verifier needs. Nothing here reimplements
 * product behaviour: every wrapper delegates to the real product method and only observes its
 * returned envelope.
 */

const common = require('./child-common.cjs');
const support = require('./support.cjs');
const env = require('./env.cjs');

const { TENANT } = env;
const SENTINEL = 7;

async function main() {
  const options = common.parseArgs(process.argv.slice(2));
  const dbName = options.db;
  const point = options.point;
  const rundir = options.rundir;
  const clockMs = Number(options.clock);
  const deviceTag = options.device ?? `crash-${point}`;
  const ownerId = options.owner ?? env.OWNER_A;

  const ctx = await common.buildChildContext({ dbName, clockMs, tag: point });
  let witnessWritten = false;

  function witness(payload) {
    witnessWritten = true;
    common.writeJsonFile(`${rundir}/${point}-witness.json`, {
      point,
      pid: process.pid,
      tenantId: TENANT,
      ownerId,
      clockMs: ctx.clock.now(),
      reachedPostStep: false,
      witnessCount: witnessWritten ? 0 : 1,
      ...payload,
    });
    process.exit(SENTINEL);
  }

  const device = await support.seedDevice(ctx, deviceTag);
  const durable = { deviceId: device.deviceId, deviceKeyId: device.deviceKeyId };

  if (point === 'c2') {
    const baseAuthority = ctx.authorityService();
    const instrumentedAuthority = {
      ...baseAuthority,
      spendChallenge: async (args) => {
        const result = await baseAuthority.spendChallenge(args);
        witness({
          crashPoint: 'c2-after-challenge-spend',
          after: 'authorityService.spendChallenge',
          deviceId: durable.deviceId,
          deviceKeyId: durable.deviceKeyId,
          sessionId: String(session._id),
          claimChallenge: challenge,
          challengeHash: args.challengeHash,
          spendOk: result.ok === true,
          spendMatched: result.matched,
        });
        return result;
      },
    };
    const pairing = ctx.pairingService({ authorityService: instrumentedAuthority });
    const issue = await pairing.issuePairingSession({
      tenantId: TENANT,
      deviceId: durable.deviceId,
      deviceKeyId: durable.deviceKeyId,
      domainTag: env.constants.PAIRING_OPEN_DOMAIN,
      proof: support.pairingOpenProof(ctx, device),
    });
    const redeem = await pairing.redeemPairingCode({ code: issue.code, tenantId: TENANT, ownerId });
    const session = await ctx.models.PairingSession.findOne({ _id: redeem.pairingSession._id, tenantId: TENANT }).lean();
    const challenge = require('node:crypto').randomBytes(32).toString('base64url');
    await support.seedClaimChallenge(ctx, { session, ownerId, challenge });
    const proof = support.pairingClaimProof(ctx, { session, ownerId, challenge, key: device.key });
    const approve = await pairing.approvePairingClaim({
      pairingSessionId: String(session._id),
      tenantId: TENANT,
      ownerId,
      domainTag: env.constants.PAIRING_CLAIM_DOMAIN,
      localConsent: { nonce: 'lab-consent-nonce-0001' },
      proof,
    });
    common.writeJsonFile(`${rundir}/${point}-unexpected.json`, { approveOk: approve.ok, error: approve.error ? approve.error.code : null });
    return 0;
  }

  if (point === 'c3') {
    const original = ctx.db.PairingSession.findOneAndUpdate;
    ctx.db.PairingSession.findOneAndUpdate = async (...args) => {
      const result = await original(...args);
      if (args[0] && args[0].state === 'claim_pending' && result && result.state === 'consumed') {
        witness({
          crashPoint: 'c3-after-session-consume',
          after: 'PairingSession.findOneAndUpdate claim_pending->consumed',
          deviceId: durable.deviceId,
          deviceKeyId: durable.deviceKeyId,
          sessionId: String(result._id),
          grantedGrantIdAfterConsume: result.grantedGrantId ?? null,
        });
      }
      return result;
    };
    const pairing = ctx.pairingService();
    const issue = await pairing.issuePairingSession({
      tenantId: TENANT,
      deviceId: durable.deviceId,
      deviceKeyId: durable.deviceKeyId,
      domainTag: env.constants.PAIRING_OPEN_DOMAIN,
      proof: support.pairingOpenProof(ctx, device),
    });
    const redeem = await pairing.redeemPairingCode({ code: issue.code, tenantId: TENANT, ownerId });
    const session = await ctx.models.PairingSession.findOne({ _id: redeem.pairingSession._id, tenantId: TENANT }).lean();
    const challenge = require('node:crypto').randomBytes(32).toString('base64url');
    await support.seedClaimChallenge(ctx, { session, ownerId, challenge });
    const proof = support.pairingClaimProof(ctx, { session, ownerId, challenge, key: device.key });
    const approve = await pairing.approvePairingClaim({
      pairingSessionId: String(session._id),
      tenantId: TENANT,
      ownerId,
      domainTag: env.constants.PAIRING_CLAIM_DOMAIN,
      localConsent: { nonce: 'lab-consent-nonce-0001' },
      proof,
    });
    common.writeJsonFile(`${rundir}/${point}-unexpected.json`, { approveOk: approve.ok, error: approve.error ? approve.error.code : null });
    return 0;
  }

  if (point === 'c4') {
    const baseAuthority = ctx.authorityService();
    const instrumentedAuthority = {
      ...baseAuthority,
      claimAuthority: async (args) => {
        const result = await baseAuthority.claimAuthority(args);
        witness({
          crashPoint: 'c4-after-authority-claim',
          after: 'authorityService.claimAuthority',
          deviceId: durable.deviceId,
          deviceKeyId: durable.deviceKeyId,
          sessionId: args.sessionId,
          claimOk: result.ok === true,
          claimMatched: result.matched,
          claimEpoch: result.authority ? result.authority.epoch : null,
        });
        return result;
      },
    };
    const pairing = ctx.pairingService({ authorityService: instrumentedAuthority });
    const issue = await pairing.issuePairingSession({
      tenantId: TENANT,
      deviceId: durable.deviceId,
      deviceKeyId: durable.deviceKeyId,
      domainTag: env.constants.PAIRING_OPEN_DOMAIN,
      proof: support.pairingOpenProof(ctx, device),
    });
    const redeem = await pairing.redeemPairingCode({ code: issue.code, tenantId: TENANT, ownerId });
    const session = await ctx.models.PairingSession.findOne({ _id: redeem.pairingSession._id, tenantId: TENANT }).lean();
    const challenge = require('node:crypto').randomBytes(32).toString('base64url');
    await support.seedClaimChallenge(ctx, { session, ownerId, challenge });
    const proof = support.pairingClaimProof(ctx, { session, ownerId, challenge, key: device.key });
    const approve = await pairing.approvePairingClaim({
      pairingSessionId: String(session._id),
      tenantId: TENANT,
      ownerId,
      domainTag: env.constants.PAIRING_CLAIM_DOMAIN,
      localConsent: { nonce: 'lab-consent-nonce-0001' },
      proof,
    });
    common.writeJsonFile(`${rundir}/${point}-unexpected.json`, { approveOk: approve.ok, error: approve.error ? approve.error.code : null });
    return 0;
  }

  // c5 / c6 need a complete, committed ceremony first.
  const ceremony = await support.runPairingCeremony(ctx, {
    deviceId: durable.deviceId,
    deviceKeyId: durable.deviceKeyId,
    ownerId,
    key: device.key,
  });
  if (!ceremony.ok) {
    common.writeJsonFile(`${rundir}/${point}-ceremony-failed.json`, {
      stage: ceremony.stage,
      error: ceremony.error && ceremony.error.toJSON ? ceremony.error.toJSON() : null,
    });
    await ctx.teardown();
    return 4;
  }
  const agendaRow = ceremony.approve.authority;
  const baseAuthority = ctx.authorityService();

  if (point === 'c5') {
    const instrumentedAuthority = {
      ...baseAuthority,
      revokeLease: async (args) => {
        const result = await baseAuthority.revokeLease(args);
        witness({
          crashPoint: 'c5-after-revoke',
          after: 'authorityService.revokeLease',
          deviceId: durable.deviceId,
          deviceKeyId: durable.deviceKeyId,
          sessionId: ceremony.sessionId,
          revokeOk: result.ok === true,
          revokeMatched: result.matched,
          revokeEpoch: result.authority ? result.authority.epoch : null,
          grantBeforeRevokeIssued: agendaRow.grantId !== null,
        });
        return result;
      },
    };
    await instrumentedAuthority.revokeLease({ deviceId: durable.deviceId, tenantId: TENANT, ownerId, epoch: agendaRow.epoch });
    common.writeJsonFile(`${rundir}/${point}-unexpected.json`, { note: 'revoke returned without crashing' });
    return 0;
  }

  if (point === 'c6') {
    const instrumentedAuthority = {
      ...baseAuthority,
      retireIdentity: async (args) => {
        const result = await baseAuthority.retireIdentity(args);
        witness({
          crashPoint: 'c6-after-retire',
          after: 'authorityService.retireIdentity',
          deviceId: durable.deviceId,
          deviceKeyId: durable.deviceKeyId,
          sessionId: ceremony.sessionId,
          retireOk: result.ok === true,
          retireMatched: result.matched,
          retireEpoch: result.authority ? result.authority.epoch : null,
        });
        return result;
      },
    };
    await instrumentedAuthority.retireIdentity({ deviceId: durable.deviceId, tenantId: TENANT, actor: ownerId, role: 'owner' });
    common.writeJsonFile(`${rundir}/${point}-unexpected.json`, { note: 'retire returned without crashing' });
    return 0;
  }

  throw new Error(`unknown crash point ${point}`);
}

main().then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(`${JSON.stringify({ child: 'crash', status: 'HARNESS_FAIL', error: { name: err.name, message: err.message } })}\n`);
    process.exit(4);
  },
);