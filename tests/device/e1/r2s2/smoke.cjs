'use strict';

/** S2-T harness smoke probe (test-only). Not a row: used to validate the harness before rows run. */

const { withRowDb, envelopeView } = require('./harness.cjs');

async function main() {
  const out = await withRowDb('smoke01', async (ctx) => {
    const deviceId = 's2t-smoke-device-1';
    await ctx.seedAuthority({ _id: deviceId, epoch: 0, leaseState: 'never', identityState: 'pending' });
    const authority = ctx.composeAuthority();
    const envelope = await authority.claimAuthority({
      deviceId,
      tenantId: ctx.TENANT,
      ownerId: ctx.OWNER_A,
      sessionId: 's2t-smoke-session-1',
      grantProof: {
        ownerConfirmedAt: new Date(ctx.clock.now()),
        endpointSignatureVerifiedAt: new Date(ctx.clock.now()),
        verifiedKeyId: `key-${deviceId}`,
        localApprovalNonceHash: 'smoke-nonce-hash',
      },
    });
    return {
      registryShape: Object.fromEntries(
        Object.entries(ctx.shape).map(([key, value]) => [key, value.typeofModel]),
      ),
      compositionPrecondition: ctx.compositionPrecondition,
      envelope: envelopeView(envelope),
      rawEnvelopeKeys: Object.keys(envelope),
    };
  });
  process.stdout.write(
    `${JSON.stringify({ dbName: out.dbName, outcome: out.outcome, dbReadBack: out.dbReadBack }, null, 2)}\n`,
  );
}

main().catch((err) => {
  process.stderr.write(`${err.stack ?? err.message}\n`);
  process.exitCode = 1;
});