'use strict';

/**
 * E1 inline PRODUCT fixtures (lane I9 / task T1).
 *
 * Each fixture instantiates the real I6/I5 factories, performs the product writes described by
 * its frozen assertion plan in tests/device/e1/fixtures.cjs, re-reads durable state with the real
 * Mongoose models, and reports PASS only when every assertion really held.
 *
 * Status vocabulary: PASS / PRODUCT_FAIL / HARNESS_FAIL. A fixture never reports PASS on a
 * skipped, stubbed or unexecuted step; an unexecutable step throws and becomes HARNESS_FAIL.
 */

const crypto = require('node:crypto');

const c = require('./context.cjs');
const support = c.support;
const env = c.env;

const { TENANT, LEASE_TTL_MS, SKEW_MARGIN_MS, HOUR_MS } = c;
const OWNER_A = env.OWNER_A;
const OWNER_B = env.OWNER_B;
const OWNER_C = env.OWNER_C;

function base(fixture, dbName, extras = {}) {
  return {
    id: fixture.id,
    tier: fixture.tier,
    kind: fixture.kind,
    runner: fixture.runner,
    requires: fixture.requires,
    title: fixture.title,
    runnerPid: process.pid,
    dbName,
    productClaim: true,
    services: {
      authorityService: env.PRODUCT_FILES.authorityService,
      registrationService: env.PRODUCT_FILES.registrationService,
      pairingSessionService: env.PRODUCT_FILES.pairingSessionService,
      retireTrustAdapter: env.PRODUCT_FILES.retireTrustAdapter,
    },
    ...extras,
  };
}

function finish(fixture, ctx, checks, extras = {}) {
  const status = support.statusFromChecks(checks.checks);
  return base(fixture, ctx.dbName, {
    ...status,
    checks: checks.checks,
    ...extras,
    provenance: support.provenance(ctx, extras.provenanceExtra ?? {}),
  });
}

/* ------------------------------------------------------------------ E1-ONEPC-GRANT-CAS */

async function onepcGrantCas(fixture) {
  const ctx = await c.makeProductContext({ tag: fixture.id, principalId: OWNER_A });
  const checks = support.makeChecks();
  try {
    const now = ctx.clock.now();
    const d1 = await c.seedClaimableDevice(ctx, 'onepc-1', { _id: 'e1-onepc-device-1' });
    const d2 = await c.seedClaimableDevice(ctx, 'onepc-2', { _id: 'e1-onepc-device-2' });

    const first = await c.claim(ctx, {
      deviceId: d1.deviceId,
      ownerId: OWNER_A,
      expectedEpoch: 0,
      sessionId: 'e1-onepc-session-1',
      grantProof: {
        ownerConfirmedAt: new Date(now),
        endpointSignatureVerifiedAt: new Date(now),
        verifiedKeyId: d1.deviceKeyId,
        localApprovalNonceHash: null,
      },
    });
    const row1 = await c.readRow(ctx, d1.deviceId);

    const second = await c.claim(ctx, {
      deviceId: d2.deviceId,
      ownerId: OWNER_A,
      expectedEpoch: 0,
      sessionId: 'e1-onepc-session-2',
      grantProof: null,
    });
    const row2 = await c.readRow(ctx, d2.deviceId);
    const activeCount = await c.countActive(ctx, OWNER_A);

    const revoke = await c.revoke(ctx, { deviceId: d1.deviceId, ownerId: OWNER_A, epoch: row1.epoch });
    const rowRevoked = await c.readRow(ctx, d1.deviceId);
    const regrant = await c.claim(ctx, {
      deviceId: d1.deviceId,
      ownerId: OWNER_A,
      expectedEpoch: rowRevoked.epoch,
      sessionId: 'e1-onepc-session-3',
      grantProof: null,
    });
    const row3 = await c.readRow(ctx, d1.deviceId);

    checks.ok('first claim ok', first.ok === true && first.matched === 1, support.errorView(first.error));
    checks.eq('first claim leaseState', row1.leaseState, 'active');
    checks.eq('first claim identityState', row1.identityState, 'active');
    checks.eq('first claim owner', row1.ownerId, OWNER_A);
    checks.eq('first claim epoch', row1.epoch, 1);
    checks.eq('first claim grantId is 22-char base64url', /^[A-Za-z0-9_-]{22}$/.test(row1.grantId), true);
    checks.eq(
      'first claim TTL is exactly 172800000',
      new Date(row1.expiresAt).getTime() - new Date(row1.activatedAt).getTime(),
      172800000,
    );
    checks.ok('second claim (second PC) rejected', second.ok === false && second.matched === 0, support.errorView(second.error));
    checks.ok(
      'second claim rejection is a frozen one-per-account code',
      second.error !== null && ['ONE_DEVICE_PER_ACCOUNT', 'DEVICE_ALREADY_PAIRED_USE_RENEW'].includes(second.error.code),
      support.errorView(second.error),
    );
    checks.eq(
      'rejected claim left the second row untouched',
      { leaseState: row2.leaseState, ownerId: row2.ownerId, epoch: row2.epoch },
      { leaseState: 'never', ownerId: null, epoch: 0 },
    );
    checks.eq('active rows for the account after the burst', activeCount, 1);
    checks.ok('revoke ok', revoke.ok === true && revoke.matched === 1, support.errorView(revoke.error));
    checks.eq('revoke keeps grantId (G-2)', rowRevoked.grantId, row1.grantId);
    checks.eq('revoke advances epoch', rowRevoked.epoch, 2);
    checks.eq('revoked leaseState', rowRevoked.leaseState, 'revoked');
    checks.ok('re-grant after revoke ok', regrant.ok === true && regrant.matched === 1, support.errorView(regrant.error));
    checks.ok(
      're-grant mints a NEW grantId (never the old one)',
      row3.grantId !== row1.grantId && row3.grantId !== rowRevoked.grantId && row3.grantId.length === 22,
      { newGrantIdLength: row3.grantId.length, differsFromOld: row3.grantId !== row1.grantId },
    );
    checks.eq('re-grant epoch', row3.epoch, 3);
    checks.eq('re-grant leaseState', row3.leaseState, 'active');

    return finish(fixture, ctx, checks, {
      attempts: { claimAuthorityCalls: 3, revokeLeaseCalls: 1 },
      realReturns: {
        firstClaim: { ok: first.ok, matched: first.matched, error: support.errorView(first.error) },
        secondClaim: { ok: second.ok, matched: second.matched, error: support.errorView(second.error) },
        revoke: { ok: revoke.ok, matched: revoke.matched, error: support.errorView(revoke.error) },
        regrant: { ok: regrant.ok, matched: regrant.matched, error: support.errorView(regrant.error) },
      },
      dbReadBack: {
        d1AfterFirstClaim: c.view(row1, now),
        d2AfterRejectedClaim: c.view(row2, now),
        d1AfterRevoke: c.view(rowRevoked, now),
        d1AfterRegrant: c.view(row3, now),
        activeRowsForOwner: activeCount,
      },
    });
  } finally {
    await ctx.teardown();
  }
}

/* ------------------------------------------------- E1-T16-P1-STALE-OWNER-REVOKE */

async function staleOwnerRevoke(fixture) {
  process.env.CBHR_PHASE1_SWEEP = 'disabled';
  const ctx = await c.makeProductContext({ tag: fixture.id, point: 'T16', principalId: OWNER_A });
  const checks = support.makeChecks();
  try {
    const T = ctx.clock.now();
    const device = await c.seedClaimableDevice(ctx, 't16', { _id: 'e1-t16-device' });
    const svc = ctx.authorityService();

    const first = await c.claim(ctx, {
      deviceId: device.deviceId,
      ownerId: OWNER_A,
      expectedEpoch: 0,
      sessionId: 'e1-t16-first',
      service: svc,
    });
    const rowA = await c.readRow(ctx, device.deviceId);
    const grantA = rowA.grantId;
    const epochA = rowA.epoch;

    ctx.clock.set(T + LEASE_TTL_MS + HOUR_MS);
    const second = await c.claim(ctx, {
      deviceId: device.deviceId,
      ownerId: OWNER_B,
      expectedEpoch: epochA,
      sessionId: 'e1-t16-second',
      service: svc,
    });
    const rowB = await c.readRow(ctx, device.deviceId);
    const grantB = rowB.grantId;

    const staleRevoke = await c.revoke(ctx, {
      deviceId: device.deviceId,
      ownerId: OWNER_A,
      epoch: epochA,
      service: svc,
    });
    const rowAfter = await c.readRow(ctx, device.deviceId);

    checks.ok('owner A claims the device at T', first.ok === true && first.matched === 1, support.errorView(first.error));
    checks.ok('owner B claims the device at T+48h+1h', second.ok === true && second.matched === 1, support.errorView(second.error));
    checks.eq('owner after the second claim', rowB.ownerId, OWNER_B);
    checks.eq('epoch after the second claim', rowB.epoch, epochA + 1);
    checks.ok('stale revoke is rejected with matched 0', staleRevoke.ok === false && staleRevoke.matched === 0, support.errorView(staleRevoke.error));
    checks.eq('stale revoke error code', staleRevoke.error && staleRevoke.error.code, 'NOT_OWNER_OR_STALE');
    checks.eq(
      'stale revoke wrote nothing (no field changed)',
      { epoch: rowAfter.epoch, leaseState: rowAfter.leaseState, ownerId: rowAfter.ownerId, grantId: rowAfter.grantId, prevEpoch: rowAfter.prevEpoch ?? null },
      { epoch: rowB.epoch, leaseState: rowB.leaseState, ownerId: rowB.ownerId, grantId: rowB.grantId, prevEpoch: rowB.prevEpoch ?? null },
    );
    checks.ok(
      'owner B remains authorized',
      c.authorize(rowAfter, { ownerId: OWNER_B, epoch: rowB.epoch, grantId: grantB, now: ctx.clock.now() }).allowed === true,
      c.authorize(rowAfter, { ownerId: OWNER_B, epoch: rowB.epoch, grantId: grantB, now: ctx.clock.now() }),
    );
    checks.ok(
      'owner A is NOT authorized with the stale grant/epoch',
      c.authorize(rowAfter, { ownerId: OWNER_A, epoch: epochA, grantId: grantA, now: ctx.clock.now() }).allowed === false,
      c.authorize(rowAfter, { ownerId: OWNER_A, epoch: epochA, grantId: grantA, now: ctx.clock.now() }),
    );
    checks.eq('sweep knob disabled for the whole fixture', process.env.CBHR_PHASE1_SWEEP, 'disabled');
    checks.eq('the product surface exposes no background sweep', c.productHasNoBackgroundSweep().exposesSweep, false);

    return finish(fixture, ctx, checks, {
      attempts: { claimAuthorityCalls: 2, revokeLeaseCalls: 1 },
      realReturns: {
        firstClaim: { ok: first.ok, matched: first.matched, error: support.errorView(first.error) },
        secondClaim: { ok: second.ok, matched: second.matched, error: support.errorView(second.error) },
        staleRevoke: { ok: staleRevoke.ok, matched: staleRevoke.matched, error: support.errorView(staleRevoke.error) },
      },
      dbReadBack: {
        afterFirstClaim: c.view(rowA, T),
        afterSecondClaim: c.view(rowB, ctx.clock.now()),
        afterStaleRevoke: c.view(rowAfter, ctx.clock.now()),
      },
      provenanceExtra: { fixtureClockOffsets: ['T', 'T+48h+1h'] },
    });
  } finally {
    delete process.env.CBHR_PHASE1_SWEEP;
    await ctx.teardown();
  }
}

/* --------------------------------------------- E1-T17-P2-CLAIM-VS-ACTIVE-PC */

async function p2ClaimVsActivePc(fixture) {
  const ctx = await c.makeProductContext({ tag: fixture.id, point: 'T17', principalId: OWNER_A });
  const checks = support.makeChecks();
  try {
    const T = ctx.clock.now();
    const pc1 = await c.seedClaimableDevice(ctx, 't17-pc1', { _id: 'e1-t17-pc1' });
    const pc2 = await c.seedClaimableDevice(ctx, 't17-pc2', { _id: 'e1-t17-pc2' });
    const svc = ctx.authorityService();

    const aClaimPc1 = await c.claim(ctx, { deviceId: pc1.deviceId, ownerId: OWNER_A, expectedEpoch: 0, sessionId: 'e1-t17-a-pc1', service: svc });
    const pc1AfterA = await c.readRow(ctx, pc1.deviceId);
    const grantA = pc1AfterA.grantId;

    ctx.clock.set(T + LEASE_TTL_MS + HOUR_MS);
    const bClaimPc1 = await c.claim(ctx, { deviceId: pc1.deviceId, ownerId: OWNER_B, expectedEpoch: pc1AfterA.epoch, sessionId: 'e1-t17-b-pc1', service: svc });
    const pc1AfterB = await c.readRow(ctx, pc1.deviceId);
    const grantB = pc1AfterB.grantId;

    const aClaimPc2 = await c.claim(ctx, { deviceId: pc2.deviceId, ownerId: OWNER_A, expectedEpoch: 0, sessionId: 'e1-t17-a-pc2', service: svc });
    const pc1AfterPc2 = await c.readRow(ctx, pc1.deviceId);
    const pc2After = await c.readRow(ctx, pc2.deviceId);

    const activeA = await c.countActive(ctx, OWNER_A);
    const activeB = await c.countActive(ctx, OWNER_B);

    checks.ok('owner A claims PC1 at T', aClaimPc1.ok === true && aClaimPc1.matched === 1, support.errorView(aClaimPc1.error));
    checks.ok('owner B claims PC1 at T+48h+1h', bClaimPc1.ok === true && bClaimPc1.matched === 1, support.errorView(bClaimPc1.error));
    checks.eq('PC1.prevOwner after the B claim', pc1AfterB.prevOwner, OWNER_A);
    checks.eq('PC1.prevGrantId after the B claim', pc1AfterB.prevGrantId, grantA);
    checks.eq('PC1.prevEpoch after the B claim', pc1AfterB.prevEpoch, 1);
    checks.ok('owner A then claims a second PC with no revoke of PC1', aClaimPc2.ok === true && aClaimPc2.matched === 1, support.errorView(aClaimPc2.error));
    checks.eq(
      'PC1 prev*/epoch untouched by the PC2 claim (no cross-row write)',
      { prevOwner: pc1AfterPc2.prevOwner, prevGrantId: pc1AfterPc2.prevGrantId, prevEpoch: pc1AfterPc2.prevEpoch, epoch: pc1AfterPc2.epoch, ownerId: pc1AfterPc2.ownerId },
      { prevOwner: pc1AfterB.prevOwner, prevGrantId: pc1AfterB.prevGrantId, prevEpoch: pc1AfterB.prevEpoch, epoch: pc1AfterB.epoch, ownerId: pc1AfterB.ownerId },
    );
    checks.ok(
      'authorize(B, PC1) === true',
      c.authorize(pc1AfterPc2, { ownerId: OWNER_B, epoch: pc1AfterB.epoch, grantId: grantB, now: ctx.clock.now() }).allowed === true,
      c.authorize(pc1AfterPc2, { ownerId: OWNER_B, epoch: pc1AfterB.epoch, grantId: grantB, now: ctx.clock.now() }),
    );
    checks.ok(
      'authorize(A, PC2) === true',
      c.authorize(pc2After, { ownerId: OWNER_A, epoch: pc2After.epoch, grantId: pc2After.grantId, now: ctx.clock.now() }).allowed === true,
      c.authorize(pc2After, { ownerId: OWNER_A, epoch: pc2After.epoch, grantId: pc2After.grantId, now: ctx.clock.now() }),
    );
    checks.ok(
      'authorize(A, PC1) with the stale grant === false',
      c.authorize(pc1AfterPc2, { ownerId: OWNER_A, epoch: 1, grantId: grantA, now: ctx.clock.now() }).allowed === false,
      c.authorize(pc1AfterPc2, { ownerId: OWNER_A, epoch: 1, grantId: grantA, now: ctx.clock.now() }),
    );
    checks.eq('one active row for owner A in the tenant (uq_owner_active)', activeA, 1);
    checks.eq('one active row for owner B in the tenant (uq_owner_active)', activeB, 1);

    return finish(fixture, ctx, checks, {
      attempts: { claimAuthorityCalls: 3 },
      realReturns: {
        aClaimPc1: { ok: aClaimPc1.ok, matched: aClaimPc1.matched, error: support.errorView(aClaimPc1.error) },
        bClaimPc1: { ok: bClaimPc1.ok, matched: bClaimPc1.matched, error: support.errorView(bClaimPc1.error) },
        aClaimPc2: { ok: aClaimPc2.ok, matched: aClaimPc2.matched, error: support.errorView(aClaimPc2.error) },
      },
      dbReadBack: {
        pc1AfterA: c.view(pc1AfterA, T),
        pc1AfterB: c.view(pc1AfterB, ctx.clock.now()),
        pc1AfterPc2Claim: c.view(pc1AfterPc2, ctx.clock.now()),
        pc2AfterClaim: c.view(pc2After, ctx.clock.now()),
        activeRowsOwnerA: activeA,
        activeRowsOwnerB: activeB,
      },
    });
  } finally {
    await ctx.teardown();
  }
}

/* ------------------------------------------- E1-T09-T10-LEASE-48H-MARGIN */

async function lease48hMargin(fixture) {
  const ctx = await c.makeProductContext({ tag: fixture.id, point: 'T09/T10', principalId: OWNER_A });
  const checks = support.makeChecks();
  try {
    const T = ctx.clock.now();
    const tags = ['ttl', 'renew-ok', 'renew-dead', 'deadzone-lo', 'deadzone-hi', 'lazy-release'];
    const seeded = {};
    for (const tag of tags) {
      seeded[tag] = await c.seedClaimableDevice(ctx, `t09-${tag}`, { _id: `e1-t09-${tag}` });
    }
    const owners = Object.fromEntries(tags.map((tag) => [tag, `principal-e1-t09-${tag}`]));
    const svc = ctx.authorityService();
    const grants = {};
    for (const tag of tags) {
      const claim = await c.claim(ctx, {
        deviceId: seeded[tag].deviceId,
        ownerId: owners[tag],
        expectedEpoch: 0,
        sessionId: `e1-t09-${tag}`,
        service: svc,
      });
      const row = await c.readRow(ctx, seeded[tag].deviceId);
      grants[tag] = { claim, row, epoch: row.epoch, grantId: row.grantId };
    }

    // Renewal 1ms inside the margin: now + 5000 < expiresAt -> succeeds.
    ctx.clock.set(T + LEASE_TTL_MS - SKEW_MARGIN_MS - 1);
    const renewOkSvc = ctx.authorityService({
      verifyRenewalProof: env.makeRenewalProof({
        tenantId: TENANT,
        ownerId: owners['renew-ok'],
        deviceId: seeded['renew-ok'].deviceId,
        deviceKeyId: seeded['renew-ok'].deviceKeyId,
        grantId: grants['renew-ok'].grantId,
        epoch: grants['renew-ok'].epoch,
      }),
    });
    const renewOk = await renewOkSvc.renewAuthority({
      deviceId: seeded['renew-ok'].deviceId,
      tenantId: TENANT,
      ownerId: owners['renew-ok'],
      epoch: grants['renew-ok'].epoch,
      grantId: grants['renew-ok'].grantId,
      proofInput: { __accept: true },
    });
    const renewOkRow = await c.readRow(ctx, seeded['renew-ok'].deviceId);

    // Renewal at exactly expiresAt - 5000ms -> LEASE_EXPIRED (fail closed).
    ctx.clock.set(T + LEASE_TTL_MS - SKEW_MARGIN_MS);
    const renewDeadSvc = ctx.authorityService({
      verifyRenewalProof: env.makeRenewalProof({
        tenantId: TENANT,
        ownerId: owners['renew-dead'],
        deviceId: seeded['renew-dead'].deviceId,
        deviceKeyId: seeded['renew-dead'].deviceKeyId,
        grantId: grants['renew-dead'].grantId,
        epoch: grants['renew-dead'].epoch,
      }),
    });
    const renewBoundary = await renewDeadSvc.renewAuthority({
      deviceId: seeded['renew-dead'].deviceId,
      tenantId: TENANT,
      ownerId: owners['renew-dead'],
      epoch: grants['renew-dead'].epoch,
      grantId: grants['renew-dead'].grantId,
      proofInput: { __accept: true },
    });
    const renewBoundaryRow = await c.readRow(ctx, seeded['renew-dead'].deviceId);

    // Dead zone: [expiresAt, expiresAt + 5000) -> claim CAS 0-match -> PAIRING_WINDOW_TOO_EARLY.
    const deadZone = {};
    for (const [tag, offset] of [
      ['deadzone-lo', 0],
      ['deadzone-hi', SKEW_MARGIN_MS - 1],
    ]) {
      ctx.clock.set(T + LEASE_TTL_MS + offset);
      const attempt = await c.claim(ctx, {
        deviceId: seeded[tag].deviceId,
        ownerId: owners[tag],
        expectedEpoch: grants[tag].epoch,
        sessionId: `e1-t09-deadzone-${tag}`,
        service: svc,
      });
      deadZone[tag] = {
        offset,
        ok: attempt.ok,
        matched: attempt.matched,
        error: support.errorView(attempt.error),
      };
    }

    // Guarded lazy release at exactly expiresAt + 5000ms.
    ctx.clock.set(T + LEASE_TTL_MS + SKEW_MARGIN_MS);
    const beforeRelease = await c.readRow(ctx, seeded['lazy-release'].deviceId);
    const release = await ctx.authorityService().releaseLapsedLease({
      deviceId: seeded['lazy-release'].deviceId,
      tenantId: TENANT,
    });
    const afterRelease = await c.readRow(ctx, seeded['lazy-release'].deviceId);

    // authorize boundaries over the untouched TTL row.
    const ttlRow = grants.ttl.row;
    ctx.clock.set(T + LEASE_TTL_MS - 1);
    const allowAtMinus1 = c.authorize(ttlRow, { ownerId: owners.ttl, epoch: ttlRow.epoch, grantId: ttlRow.grantId, now: ctx.clock.now() });
    ctx.clock.set(T + LEASE_TTL_MS);
    const denyAtExpiry = c.authorize(ttlRow, { ownerId: owners.ttl, epoch: ttlRow.epoch, grantId: ttlRow.grantId, now: ctx.clock.now() });

    checks.eq(
      'grant TTL is exactly 172800000',
      new Date(ttlRow.expiresAt).getTime() - new Date(ttlRow.activatedAt).getTime(),
      172800000,
    );
    checks.eq('SKEW_MARGIN constant is exactly 5000', SKEW_MARGIN_MS, 5000);
    checks.ok('authorize ALLOW at T+172799999', allowAtMinus1.allowed === true, allowAtMinus1);
    checks.ok('authorize DENY at T+172800000 (bare now < expiresAt)', denyAtExpiry.allowed === false, denyAtExpiry);
    checks.ok('renewal 1ms inside the margin succeeds', renewOk.ok === true && renewOk.matched === 1, support.errorView(renewOk.error));
    checks.eq('renewal epoch advanced', renewOkRow.epoch, grants['renew-ok'].epoch + 1);
    checks.eq('renewal renewalCount', renewOkRow.renewalCount, 1);
    checks.ok('renewal rotated the grantId', renewOkRow.grantId !== grants['renew-ok'].grantId, { rotated: renewOkRow.grantId !== grants['renew-ok'].grantId });
    checks.eq(
      'renewal advances expiresAt by exactly the lease TTL',
      new Date(renewOkRow.expiresAt).getTime() - new Date(renewOkRow.renewedAt).getTime(),
      172800000,
    );
    checks.ok('renewal at expiresAt-5000 fails closed', renewBoundary.ok === false, support.errorView(renewBoundary.error));
    checks.eq('boundary renewal error code', renewBoundary.error && renewBoundary.error.code, 'LEASE_EXPIRED');
    checks.eq(
      'boundary renewal wrote nothing',
      { epoch: renewBoundaryRow.epoch, grantId: renewBoundaryRow.grantId },
      { epoch: grants['renew-dead'].epoch, grantId: grants['renew-dead'].grantId },
    );
    for (const tag of ['deadzone-lo', 'deadzone-hi']) {
      checks.ok(`dead zone ${tag} (expiresAt+${deadZone[tag].offset}): claim fails closed`, deadZone[tag].ok === false && deadZone[tag].matched === 0, deadZone[tag]);
      checks.eq(`dead zone ${tag}: error code`, deadZone[tag].error && deadZone[tag].error.code, 'PAIRING_WINDOW_TOO_EARLY');
    }
    checks.eq('lazy release precondition leaseState', beforeRelease.leaseState, 'active');
    checks.eq('lazy release precondition epoch', beforeRelease.epoch, grants['lazy-release'].epoch);
    checks.ok('lazy release CAS matched', release.ok === true && release.matched === 1, support.errorView(release.error));
    checks.eq('lazy release leaseState', afterRelease.leaseState, 'expired');
    checks.eq('lazy release advanced epoch by exactly 1', afterRelease.epoch, beforeRelease.epoch + 1);
    checks.eq('lazy release did not rotate the grantId', afterRelease.grantId, beforeRelease.grantId);
    checks.eq('lazy release emitted exactly one expire audit event', ctx.audit.events.filter((event) => event.kind === 'expire').length, 1);

    return finish(fixture, ctx, checks, {
      attempts: { claimAuthorityCalls: tags.length + 2, renewAuthorityCalls: 2, releaseLapsedLeaseCalls: 1 },
      realReturns: {
        renewAtExpiresMinus1: { ok: renewOk.ok, matched: renewOk.matched, error: support.errorView(renewOk.error) },
        renewAtExpiresMinus5000: { ok: renewBoundary.ok, matched: renewBoundary.matched, error: support.errorView(renewBoundary.error) },
        deadZone,
        lazyRelease: { ok: release.ok, matched: release.matched, error: support.errorView(release.error) },
        authorizeProbes: { atExpiresMinus1: allowAtMinus1, atExpires: denyAtExpiry },
      },
      dbReadBack: {
        ttlGrant: c.view(ttlRow, T),
        renewOkAfter: c.view(renewOkRow, ctx.clock.now()),
        renewBoundaryAfter: c.view(renewBoundaryRow, ctx.clock.now()),
        lazyReleaseBefore: c.view(beforeRelease, ctx.clock.now()),
        lazyReleaseAfter: c.view(afterRelease, ctx.clock.now()),
      },
      provenanceExtra: {
        clockOffsetsProbed: ['T', 'T+172794999', 'T+172795000', 'T+172799999', 'T+172800000', 'T+172804999', 'T+172805000'],
      },
    });
  } finally {
    await ctx.teardown();
  }
}

/* --------------------------------------------- E1-T20-AUDIT-UNCERTAINTY */

async function auditUncertainty(fixture) {
  const ctx = await c.makeProductContext({ tag: fixture.id, auditSink: 'durable-raw', principalId: OWNER_A });
  const checks = support.makeChecks();
  try {
    const d1 = await c.seedClaimableDevice(ctx, 'audit-ok', { _id: 'e1-audit-device-1' });
    const d2 = await c.seedClaimableDevice(ctx, 'audit-fail', { _id: 'e1-audit-device-2' });

    const goodSvc = ctx.authorityService();
    const claimOk = await c.claim(ctx, {
      deviceId: d1.deviceId,
      ownerId: OWNER_A,
      expectedEpoch: 0,
      sessionId: 'e1-audit-good',
      service: goodSvc,
    });
    const durableRows = await ctx.models.AuditEvent.find({ tenantId: TENANT }).lean();
    const rawAuditRows = await ctx.client
      .db(ctx.dbName)
      .collection('deviceauthorityevents')
      .find({})
      .toArray();
    const goodEvent = ctx.audit.events.find((event) => event.deviceId === d1.deviceId) ?? null;

    const throwing = support.makeThrowingAuditSink();
    const failingSvc = ctx.authorityService({ audit: throwing.audit });
    const claimFail = await c.claim(ctx, {
      deviceId: d2.deviceId,
      ownerId: OWNER_B,
      expectedEpoch: 0,
      sessionId: 'e1-audit-fail',
      service: failingSvc,
    });
    const d2Row = await c.readRow(ctx, d2.deviceId);
    const auditRowsAfter = await ctx.client.db(ctx.dbName).collection('deviceauthorityevents').countDocuments({});
    const d2AuditRows = await ctx.client.db(ctx.dbName).collection('deviceauthorityevents').countDocuments({ deviceId: d2.deviceId });
    const failingEvent = throwing.events[0] ?? null;

    checks.ok('CAS with a working sink is ok', claimOk.ok === true && claimOk.matched === 1, support.errorView(claimOk.error));
    checks.eq('durable audit rows persisted through the sink', rawAuditRows.length, 1);
    checks.eq('durable audit row kind', rawAuditRows[0] && rawAuditRows[0].kind, 'grant');
    checks.eq('durable audit row epoch equals the post-CAS epoch', rawAuditRows[0] && rawAuditRows[0].epoch, 1);
    checks.eq('durable audit row seq equals the post-CAS epoch', rawAuditRows[0] && rawAuditRows[0].seq, 1);
    checks.ok(
      'sink write acknowledged majority+journal',
      ctx.audit.writes.length === 1 && ctx.audit.writes[0].acknowledged === true,
      ctx.audit.writes,
    );
    checks.ok(
      'required audit fields deviceId/epoch/actor/reasonCode present (G-5)',
      goodEvent !== null &&
        ['tenantId', 'deviceId', 'epoch', 'kind', 'ts', 'actor', 'reasonCode'].every((key) =>
          Object.prototype.hasOwnProperty.call(goodEvent, key),
        ) &&
        goodEvent.actor === OWNER_A,
      goodEvent,
    );
    checks.ok('second CAS surfaces an error rather than a silent pass', claimFail.ok === false, support.errorView(claimFail.error));
    checks.eq('audit failure error code', claimFail.error && claimFail.error.code, 'AUDIT_DELIVERY_UNCERTAIN');
    checks.eq('audit failure http status', claimFail.error && claimFail.error.httpStatus, 500);
    checks.eq('audit failure matched count proves the CAS committed', claimFail.matched, 1);
    checks.eq(
      'committed CAS is NOT rolled back by the audit failure',
      { leaseState: d2Row.leaseState, epoch: d2Row.epoch, ownerId: d2Row.ownerId },
      { leaseState: 'active', epoch: 1, ownerId: OWNER_B },
    );
    checks.ok(
      'committed grantId present after the audit failure',
      typeof d2Row.grantId === 'string' && d2Row.grantId.length === 22,
      { grantIdLength: d2Row.grantId ? d2Row.grantId.length : 0 },
    );
    checks.eq('the missing audit line is detectable', { total: auditRowsAfter, forFailedDevice: d2AuditRows }, { total: 1, forFailedDevice: 0 });
    checks.eq('the failing sink did observe the emitted event', failingEvent && failingEvent.kind, 'grant');
    // AuditEvent is the model over the SAME collection the durable sink writes (deviceauthorityevents):
    // reading it back through the real model proves the verbatim emitted event is model-readable.
    checks.eq('the durable audit row is readable through the real AuditEvent model', durableRows.length, 1);
    checks.eq(
      'the real model reads back the very row the sink wrote',
      durableRows[0] ? String(durableRows[0]._id) : null,
      rawAuditRows[0] ? String(rawAuditRows[0]._id) : null,
    );

    const dump = await support.dumpAllFourCollections(ctx.client, ctx.dbName);
    const leaks = support.findBySerializedValue(dump, env.LAB_PEPPER.toString('utf8'));
    const auditSerialized = dump.deviceauthorityevents.map((row) => JSON.stringify(row));
    const forbiddenAuditKeys = ['lookupTag', 'authorization', 'Authorization', 'Bearer ', 'x-forwarded-for', 'privateKey', 'pepper'];
    checks.eq('no pepper material persisted anywhere', leaks, []);
    checks.eq(
      'no code/lookupTag/private-key/auth-header material in the audit rows',
      forbiddenAuditKeys.filter((needle) => auditSerialized.some((text) => text.includes(needle))),
      [],
    );

    return finish(fixture, ctx, checks, {
      attempts: { claimAuthorityCalls: 2 },
      realReturns: {
        claimWithWorkingSink: { ok: claimOk.ok, matched: claimOk.matched, error: support.errorView(claimOk.error) },
        claimWithThrowingSink: { ok: claimFail.ok, matched: claimFail.matched, error: support.errorView(claimFail.error) },
      },
      dbReadBack: {
        durableAuditRows: rawAuditRows.map((row) => ({ kind: row.kind, epoch: row.epoch, seq: row.seq, actor: row.actor, reasonCode: row.reasonCode, deviceId: row.deviceId })),
        d2AfterAuditFailure: c.view(d2Row, ctx.clock.now()),
        auditRowCounts: { total: auditRowsAfter, forFailedDevice: d2AuditRows },
      },
      provenanceExtra: {
        auditSinkDisclosure:
          'Two injected sinks: a DURABLE raw-driver sink that writes the emitted event verbatim at majority+journal into deviceauthorityevents, and a THROWING sink that records then rejects. The audit sink is an injected seam (freeze §8); neither sink replaces product logic.',
      },
    });
  } finally {
    await ctx.teardown();
  }
}

/* ------------------------------------------------- E1-V24T04-CODE-TTL-300S */

async function codeTtl300s(fixture) {
  const ctx = await c.makeProductContext({ tag: fixture.id, point: 'V24-T04', principalId: OWNER_A });
  const checks = support.makeChecks();
  try {
    const T = ctx.clock.now();
    const pairing = ctx.pairingService();
    const tags = ['ttl-ok', 'ttl-eq', 'ttl-plus'];
    const devices = {};
    for (const tag of tags) {
      devices[tag] = await c.seedClaimableDevice(ctx, `t04-${tag}`, { _id: `e1-t04-${tag}` });
    }
    const issued = {};
    for (const tag of tags) {
      const device = devices[tag];
      const openChallenge = await pairing.mintPairingOpenChallenge({
        tenantId: TENANT,
        deviceId: device.deviceId,
        deviceKeyId: device.deviceKeyId,
      });
      if (!openChallenge.ok) {
        issued[tag] = { ok: false, error: openChallenge.error, stage: 'mint-open-challenge' };
        continue;
      }
      issued[tag] = await pairing.issuePairingSession({
        tenantId: TENANT,
        deviceId: device.deviceId,
        deviceKeyId: device.deviceKeyId,
        domainTag: env.constants.PAIRING_OPEN_DOMAIN,
        requestSource: 'e1-t04',
        challengeHash: openChallenge.challengeHash,
        proof: support.pairingOpenProof(ctx, {
          deviceId: device.deviceId,
          deviceKeyId: device.deviceKeyId,
          key: device.key,
          challengeHash: openChallenge.challengeHash,
          issuedAt: openChallenge.issuedAt,
        }),
      });
    }

    const offsets = { 'ttl-ok': 299999, 'ttl-eq': 300000, 'ttl-plus': 300001 };
    const redeems = {};
    for (const tag of tags) {
      ctx.clock.set(T + offsets[tag]);
      redeems[tag] = {
        offset: offsets[tag],
        result: await pairing.redeemPairingCode({ code: issued[tag].code, tenantId: TENANT, ownerId: `principal-e1-t04-${tag}` }),
      };
    }
    const rows = {};
    for (const tag of tags) {
      rows[tag] = await ctx.models.PairingSession.findOne({ _id: issued[tag].pairingSession._id, tenantId: TENANT }).lean();
    }
    ctx.clock.set(T + 400000);
    const lateRedeem = await pairing.redeemPairingCode({ code: issued['ttl-ok'].code, tenantId: TENANT, ownerId: 'principal-e1-t04-ttl-ok' });
    const lateRow = await ctx.models.PairingSession.findOne({ _id: issued['ttl-ok'].pairingSession._id, tenantId: TENANT }).lean();

    for (const tag of tags) {
      const issue = issued[tag];
      checks.ok(`issue ${tag} ok`, issue.ok === true, support.errorView(issue.error));
      checks.eq(`issue ${tag} code is six digits`, /^\d{6}$/.test(issue.code), true);
      checks.eq(`issue ${tag} lookupTag length`, issue.pairingSession.lookupTag.length, 43);
      checks.eq(
        `issue ${tag} bare 300000ms TTL (no skew margin)`,
        new Date(issue.pairingSession.expiresAt).getTime() - new Date(issue.pairingSession.issuedAt).getTime(),
        300000,
      );
    }
    checks.ok('redeem at T+299999 succeeds', redeems['ttl-ok'].result.ok === true, support.errorView(redeems['ttl-ok'].result.error));
    checks.eq('T+299999 state', rows['ttl-ok'].state, 'claim_pending');
    checks.eq('T+299999 attemptsUsed', rows['ttl-ok'].attemptsUsed, 1);
    checks.eq('T+299999 pendingOwnerId', rows['ttl-ok'].pendingOwnerId, 'principal-e1-t04-ttl-ok');
    checks.ok('redeem at T+300000 fails closed', redeems['ttl-eq'].result.ok === false, support.errorView(redeems['ttl-eq'].result.error));
    checks.eq('T+300000 uniform error code', redeems['ttl-eq'].result.error && redeems['ttl-eq'].result.error.code, 'INVALID_OR_EXPIRED_CODE');
    checks.eq('T+300000 uniform http status', redeems['ttl-eq'].result.error && redeems['ttl-eq'].result.error.httpStatus, 400);
    checks.eq('T+300000 wrote nothing (state stays open)', { state: rows['ttl-eq'].state, attemptsUsed: rows['ttl-eq'].attemptsUsed }, { state: 'open', attemptsUsed: 0 });
    checks.eq('T+300000 pendingOwnerId untouched', rows['ttl-eq'].pendingOwnerId, null);
    checks.ok('redeem at T+300001 fails closed', redeems['ttl-plus'].result.ok === false, support.errorView(redeems['ttl-plus'].result.error));
    checks.eq('T+300001 uniform error code', redeems['ttl-plus'].result.error && redeems['ttl-plus'].result.error.code, 'INVALID_OR_EXPIRED_CODE');
    checks.eq('T+300001 wrote nothing (state stays open)', { state: rows['ttl-plus'].state, attemptsUsed: rows['ttl-plus'].attemptsUsed }, { state: 'open', attemptsUsed: 0 });
    checks.ok('late re-redeem of a claimed session is the uniform miss', lateRedeem.ok === false && lateRedeem.error.code === 'INVALID_OR_EXPIRED_CODE', support.errorView(lateRedeem.error));
    checks.eq('late re-redeem did not increment attemptsUsed', lateRow.attemptsUsed, rows['ttl-ok'].attemptsUsed);

    const dump = await support.dumpAllFourCollections(ctx.client, ctx.dbName);
    const persistedCode = Object.values(issued).some(
      (issue) => issue.code && support.findBySerializedValue(dump, `"${issue.code}"`).length > 0,
    );
    checks.eq('no plaintext six-digit code persisted', persistedCode, false);

    return finish(fixture, ctx, checks, {
      attempts: { mintOpenChallengeCalls: 3, issuePairingSessionCalls: 3, redeemPairingCodeCalls: 4 },
      realReturns: Object.fromEntries(
        Object.entries(redeems).map(([tag, entry]) => [tag, { offset: entry.offset, ok: entry.result.ok, error: support.errorView(entry.result.error) }]),
      ),
      dbReadBack: Object.fromEntries(
        Object.entries(rows).map(([tag, row]) => [tag, { state: row.state, attemptsUsed: row.attemptsUsed, pendingOwnerId: row.pendingOwnerId, issuedAt: row.issuedAt, expiresAt: row.expiresAt }]),
      ),
      provenanceExtra: {
        clockOffsetsProbed: ['T+299999', 'T+300000', 'T+300001', 'T+400000'],
        barePredicateDisclosure:
          'The frozen §10a G rule for pairing-session expiry is the BARE expiresAt > now. A 5000ms margin would make T+300000 succeed, so this fixture discriminates.',
      },
    });
  } finally {
    await ctx.teardown();
  }
}

/* ------------------------------------------------ E1-V24T03-CODE-COLLISION */

async function codeCollision(fixture) {
  const ctx = await c.makeProductContext({ tag: fixture.id, point: 'V24-T03', principalId: OWNER_A });
  const checks = support.makeChecks();
  const FIXED_CODE = '424242';
  const loggerCalls = [];
  const recordingLogger = {
    error: (...args) => loggerCalls.push({ level: 'error', args }),
    warn: (...args) => loggerCalls.push({ level: 'warn', args }),
    info: (...args) => loggerCalls.push({ level: 'info', args }),
    debug: (...args) => loggerCalls.push({ level: 'debug', args }),
    child() {
      return recordingLogger;
    },
  };
  try {
    // Disclosed fault injection: only generatePairingCode is replaced (with a constant) so two
    // issuances in one tenant provably compute the same lookupTag. Every other crypto member is
    // the real implementation, and the tag is independently recomputed with the real
    // computeLookupTag.
    const fixedCrypto = env.makeCrypto({ generatePairingCode: () => FIXED_CODE });
    const pairing = ctx.pairingService({ crypto: fixedCrypto, logger: recordingLogger });
    const first = await c.seedClaimableDevice(ctx, 'collision-1', { _id: 'e1-t03-collision-1' });
    const second = await c.seedClaimableDevice(ctx, 'collision-2', { _id: 'e1-t03-collision-2' });

    const issueOne = async (device) => {
      const openChallenge = await pairing.mintPairingOpenChallenge({
        tenantId: TENANT,
        deviceId: device.deviceId,
        deviceKeyId: device.deviceKeyId,
      });
      if (!openChallenge.ok) {
        return { ok: false, error: openChallenge.error, stage: 'mint-open-challenge' };
      }
      return pairing.issuePairingSession({
        tenantId: TENANT,
        deviceId: device.deviceId,
        deviceKeyId: device.deviceKeyId,
        domainTag: env.constants.PAIRING_OPEN_DOMAIN,
        requestSource: 'e1-t03',
        challengeHash: openChallenge.challengeHash,
        proof: support.pairingOpenProof(ctx, {
          deviceId: device.deviceId,
          deviceKeyId: device.deviceKeyId,
          key: device.key,
          challengeHash: openChallenge.challengeHash,
          issuedAt: openChallenge.issuedAt,
        }),
      });
    };

    const issue1 = await issueOne(first);
    const createCallsBefore = ctx.recorder.entries.filter((entry) => entry.model === 'PairingSession' && entry.method === 'create').length;
    const issue2 = await issueOne(second);
    const createEntries = ctx.recorder.entries.filter((entry) => entry.model === 'PairingSession' && entry.method === 'create');
    const secondIssueCreates = createEntries.slice(createCallsBefore);
    const duplicateEntries = secondIssueCreates.filter((entry) => entry.error && entry.error.code === 11000);

    const lookupTag = issue1.pairingSession.lookupTag;
    const nonTerminalForTag = await ctx.models.PairingSession.countDocuments({
      tenantId: TENANT,
      lookupTag,
      state: { $in: ['open', 'claim_pending'] },
    });
    const allSessions = await ctx.models.PairingSession.find({ tenantId: TENANT }).lean();
    const rowsForTag = allSessions.filter((row) => row.lookupTag === lookupTag).length;
    const recomputedTag = ctx.crypto.computeLookupTag({ code: FIXED_CODE, tenantId: TENANT, pepperLookup: env.LAB_PEPPER });
    const dump = await support.dumpAllFourCollections(ctx.client, ctx.dbName);
    const codeLeaks = support.findBySerializedValue(dump, FIXED_CODE);
    const loggerLeaks = loggerCalls.filter((call) => JSON.stringify(call.args).includes(FIXED_CODE));

    checks.ok('first issuance ok', issue1.ok === true, support.errorView(issue1.error));
    checks.eq('the forced code was used', issue1.code, FIXED_CODE);
    checks.eq('lookupTag length is 43', lookupTag.length, 43);
    checks.eq('lookupTag equals the real tenant-bound HMAC', lookupTag, recomputedTag);
    checks.ok('second issuance fails closed', issue2.ok === false, support.errorView(issue2.error));
    checks.eq('second issuance error code', issue2.error && issue2.error.code, 'CODE_ISSUANCE_EXHAUSTED');
    checks.eq('second issuance http status', issue2.error && issue2.error.httpStatus, 409);
    checks.eq('bounded insert attempts on the second issuance (1 + 3 regenerations)', secondIssueCreates.length, 4);
    checks.eq('regenerations after exhaustion', secondIssueCreates.length - 1, env.constants.MAX_CODE_REGENERATIONS);
    checks.eq('every second-issuance insert observed E11000', duplicateEntries.length, secondIssueCreates.length);
    checks.ok(
      'observed keyPattern is exactly {tenantId:1,lookupTag:1}',
      duplicateEntries.every(
        (entry) =>
          entry.error.keyPattern &&
          entry.error.keyPattern.tenantId === 1 &&
          entry.error.keyPattern.lookupTag === 1 &&
          Object.keys(entry.error.keyPattern).length === 2,
      ),
      duplicateEntries.map((entry) => entry.error.keyPattern),
    );
    checks.eq('exactly one non-terminal session for the colliding tag', nonTerminalForTag, 1);
    checks.eq('no partial write: one persisted row per tag', rowsForTag, 1);
    checks.eq('no plaintext code anywhere in the four collections', codeLeaks, []);
    checks.eq('no plaintext code handed to the injected logger', loggerLeaks, []);

    return finish(fixture, ctx, checks, {
      attempts: {
        issuePairingSessionCalls: 2,
        pairingSessionInsertAttempts: secondIssueCreates.length,
        codeRegenerations: secondIssueCreates.length - 1,
      },
      realReturns: {
        firstIssue: { ok: issue1.ok, codeShape: /^\d{6}$/.test(issue1.code), error: support.errorView(issue1.error) },
        secondIssue: { ok: issue2.ok, error: support.errorView(issue2.error) },
      },
      dbReadBack: {
        sessions: allSessions.map((row) => ({ state: row.state, attemptsUsed: row.attemptsUsed, lookupTagLength: row.lookupTag.length, deviceId: row.deviceId })),
        nonTerminalForTag,
        duplicateKeyPatterns: duplicateEntries.map((entry) => entry.error.keyPattern),
      },
      provenanceExtra: {
        cryptoOverrides: [
          {
            member: 'generatePairingCode',
            replacement: 'test-controlled constant (disclosed)',
            reason:
              'the only way to force two issuances in one tenant to compute the same lookupTag; every other crypto member is the real frozen implementation and the tag is independently recomputed with the real computeLookupTag',
          },
        ],
        loggerOverrides: ['injected recording logger with no product behaviour (both services are constructed with logger: null everywhere else)'],
      },
    });
  } finally {
    await ctx.teardown();
  }
}

const FIXTURES = [
  { id: 'E1-ONEPC-GRANT-CAS', run: onepcGrantCas },
  { id: 'E1-T16-P1-STALE-OWNER-REVOKE', run: staleOwnerRevoke },
  { id: 'E1-T17-P2-CLAIM-VS-ACTIVE-PC', run: p2ClaimVsActivePc },
  { id: 'E1-T09-T10-LEASE-48H-MARGIN', run: lease48hMargin },
  { id: 'E1-T20-AUDIT-UNCERTAINTY', run: auditUncertainty },
  { id: 'E1-V24T04-CODE-TTL-300S', run: codeTtl300s },
  { id: 'E1-V24T03-CODE-COLLISION', run: codeCollision },
];

const BY_ID = new Map(FIXTURES.map((entry) => [entry.id, entry.run]));

module.exports = { FIXTURES, BY_ID, onepcGrantCas, staleOwnerRevoke, p2ClaimVsActivePc, lease48hMargin, auditUncertainty, codeTtl300s, codeCollision };
