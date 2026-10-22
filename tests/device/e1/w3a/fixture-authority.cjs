'use strict';

/**
 * W3-A / I11 E1 authority fixtures (real I6 CAS bytes + real Mongoose models + real MongoDB).
 *
 * Fixtures in this module:
 *   E1-ONEPC-GRANT-CAS        one-account/one-PC claim CAS, E11000 classification, re-grant
 *   E1-T16-P1-STALE-OWNER-REVOKE
 *   E1-T17-P2-CLAIM-VS-ACTIVE-PC
 *   E1-T09-T10-LEASE-48H-MARGIN
 *   E1-T20-AUDIT-UNCERTAINTY
 *   E1-FACTORY-REGISTRY-SHAPE (negative control for the real registry binding)
 *   E1-WRITE-CONCERN-PINNING
 *   E1-AUDIT-MODEL-PERSISTENCE
 *   E1-IDENTITY-PROVENANCE
 */

const crypto = require('node:crypto');

const support = require('./support.cjs');
const env = require('./env.cjs');

const { TENANT, OTHER_TENANT } = env;
const OWNER_A = env.OWNER_A;
const OWNER_B = env.OWNER_B;
const OWNER_C = env.OWNER_C;
const HOUR_MS = 3600000;

function principal(tag) {
  return `principal-w3a-i11-${tag}`;
}

function baseResult(fixture, dbName, extras = {}) {
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
    ...extras,
  };
}

/** E1-ONEPC-GRANT-CAS */
async function onepcGrantCas(fixture) {
  const ctx = await support.makeContext({ tag: fixture.id });
  const checks = support.makeChecks();
  try {
    const now = ctx.clock.now();
    const d1 = 'w3a-device-onepc-1';
    const d2 = 'w3a-device-onepc-2';
    await support.seedAuthority(ctx, { _id: d1, deviceKeyId: `key-${d1}` });
    await support.seedAuthority(ctx, { _id: d2, deviceKeyId: `key-${d2}` });

    const svc = ctx.authorityService();
    const claim1 = await svc.claimAuthority({
      deviceId: d1,
      tenantId: TENANT,
      ownerId: OWNER_A,
      sessionId: 'w3a-session-onepc-1',
      grantProof: { ownerConfirmedAt: new Date(now), endpointSignatureVerifiedAt: new Date(now), verifiedKeyId: `key-${d1}`, localApprovalNonceHash: null },
    });
    const read1 = await support.readAuthorityRaw(ctx.models, d1, TENANT);

    const claim2 = await svc.claimAuthority({
      deviceId: d2,
      tenantId: TENANT,
      ownerId: OWNER_A,
      sessionId: 'w3a-session-onepc-2',
      grantProof: null,
    });
    const read2 = await support.readAuthorityRaw(ctx.models, d2, TENANT);
    const activeCount = await support.countActiveOwners(ctx.models, OWNER_A, TENANT);

    const revoke = await svc.revokeLease({ deviceId: d1, tenantId: TENANT, ownerId: OWNER_A, epoch: read1.epoch });
    const readRevoked = await support.readAuthorityRaw(ctx.models, d1, TENANT);
    const claim3 = await svc.claimAuthority({
      deviceId: d1,
      tenantId: TENANT,
      ownerId: OWNER_A,
      sessionId: 'w3a-session-onepc-3',
      grantProof: null,
    });
    const read3 = await support.readAuthorityRaw(ctx.models, d1, TENANT);

    const duplicateEvidence = ctx.recorder
      .duplicateErrors()
      .filter((entry) => entry.model === 'DeviceAuthority');

    checks.ok('claim1.ok', claim1.ok === true, support.errorView(claim1.error));
    checks.eq('claim1.matched', claim1.matched, 1);
    checks.eq('read1.leaseState', read1.leaseState, 'active');
    checks.eq('read1.identityState', read1.identityState, 'active');
    checks.eq('read1.ownerId', read1.ownerId, OWNER_A);
    checks.eq('read1.epoch', read1.epoch, 1);
    checks.eq('read1.grantId.length', read1.grantId.length, 22);
    checks.eq(
      'read1.ttl=expiresAt-activatedAt',
      new Date(read1.expiresAt).getTime() - new Date(read1.activatedAt).getTime(),
      env.constants.LEASE_TTL_MS,
    );
    checks.ok('claim2 rejected', claim2.ok === false && claim2.matched === 0, support.errorView(claim2.error));
    checks.ok(
      'claim2 error code is a frozen one-per-account rejection',
      claim2.error !== null && ['ONE_DEVICE_PER_ACCOUNT', 'DEVICE_ALREADY_PAIRED_USE_RENEW'].includes(claim2.error.code),
      support.errorView(claim2.error),
    );
    checks.eq('read2 untouched by rejected claim', { leaseState: read2.leaseState, ownerId: read2.ownerId, epoch: read2.epoch }, { leaseState: 'never', ownerId: null, epoch: 0 });
    checks.eq('active rows for owner (real index)', activeCount, 1);
    checks.ok(
      'E11000 observed on {ownerId,tenantId} keyPattern',
      duplicateEvidence.some(
        (entry) => entry.keyPattern && entry.keyPattern.ownerId === 1 && entry.keyPattern.tenantId === 1,
      ),
      duplicateEvidence,
    );
    checks.ok('revoke.ok', revoke.ok === true, support.errorView(revoke.error));
    checks.eq('revoke keeps grantId (G-2)', readRevoked.grantId, read1.grantId);
    checks.eq('revoke epoch advanced', readRevoked.epoch, 2);
    checks.eq('readRevoked.leaseState', readRevoked.leaseState, 'revoked');
    checks.ok('re-grant ok', claim3.ok === true && claim3.matched === 1, support.errorView(claim3.error));
    checks.ok(
      're-grant mints a NEW grantId (never the old one)',
      read3.grantId !== read1.grantId && read3.grantId !== readRevoked.grantId && read3.grantId.length === 22,
      { newLength: read3.grantId.length, differsFromFirst: read3.grantId !== read1.grantId },
    );
    checks.eq('re-grant epoch', read3.epoch, 3);
    checks.eq('re-grant leaseState', read3.leaseState, 'active');

    return baseResult(fixture, ctx.dbName, {
      ...support.statusFromChecks(checks.checks),
      checks: checks.checks,
      attempts: {
        claimAuthorityCalls: 3,
        revokeLeaseCalls: 1,
        insertionAttemptsAtCas: 3,
      },
      realReturns: {
        claim1: { ok: claim1.ok, matched: claim1.matched, error: support.errorView(claim1.error) },
        claim2: { ok: claim2.ok, matched: claim2.matched, error: support.errorView(claim2.error) },
        revoke: { ok: revoke.ok, matched: revoke.matched, error: support.errorView(revoke.error) },
        claim3: { ok: claim3.ok, matched: claim3.matched, error: support.errorView(claim3.error) },
      },
      dbReadBack: {
        d1AfterClaim1: support.authorityView(read1, now),
        d2AfterRejectedClaim: read2,
        d1AfterRevoke: support.authorityView(readRevoked, now),
        d1AfterRegrant: support.authorityView(read3, now),
        activeRowsForOwnerA: activeCount,
      },
      duplicateKeyEvidence: duplicateEvidence,
      provenance: support.provenance(ctx),
    });
  } finally {
    await ctx.teardown();
  }
}

/** E1-T16-P1-STALE-OWNER-REVOKE */
async function staleOwnerRevoke(fixture) {
  const ctx = await support.makeContext({ tag: fixture.id, point: 'T16' });
  const checks = support.makeChecks();
  try {
    const start = ctx.clock.now();
    const device = 'w3a-device-t16';
    await support.seedAuthority(ctx, { _id: device, deviceKeyId: `key-${device}` });
    const svc = ctx.authorityService();

    const first = await svc.claimAuthority({ deviceId: device, tenantId: TENANT, ownerId: OWNER_A, sessionId: 'w3a-t16-first', grantProof: null });
    const rowA = await support.readAuthorityRaw(ctx.models, device, TENANT);
    const grantA = rowA.grantId;
    const epochA = rowA.epoch;

    ctx.clock.set(start + env.constants.LEASE_TTL_MS + HOUR_MS);
    const second = await svc.claimAuthority({ deviceId: device, tenantId: TENANT, ownerId: OWNER_B, sessionId: 'w3a-t16-second', grantProof: null });
    const rowB = await support.readAuthorityRaw(ctx.models, device, TENANT);
    const grantB = rowB.grantId;

    const staleRevoke = await svc.revokeLease({ deviceId: device, tenantId: TENANT, ownerId: OWNER_A, epoch: epochA });
    const rowAfter = await support.readAuthorityRaw(ctx.models, device, TENANT);

    checks.ok('first claim ok', first.ok === true && first.matched === 1, support.errorView(first.error));
    checks.ok('second (new owner) claim ok', second.ok === true && second.matched === 1, support.errorView(second.error));
    checks.eq('owner after second claim', rowB.ownerId, OWNER_B);
    checks.eq('epoch after second claim', rowB.epoch, epochA + 1);
    checks.ok('stale revoke rejected', staleRevoke.ok === false && staleRevoke.matched === 0, support.errorView(staleRevoke.error));
    checks.eq('stale revoke error code', staleRevoke.error && staleRevoke.error.code, 'NOT_OWNER_OR_STALE');
    checks.eq(
      'stale revoke wrote nothing (epoch unchanged)',
      { epoch: rowAfter.epoch, leaseState: rowAfter.leaseState, ownerId: rowAfter.ownerId, grantId: rowAfter.grantId },
      { epoch: rowB.epoch, leaseState: rowB.leaseState, ownerId: rowB.ownerId, grantId: rowB.grantId },
    );
    checks.ok(
      'owner B remains authorized',
      support.authorizePredicate(rowAfter, { ownerId: OWNER_B, epoch: epochA + 1, grantId: grantB, now: ctx.clock.now() }).allowed === true,
      support.authorizePredicate(rowAfter, { ownerId: OWNER_B, epoch: epochA + 1, grantId: grantB, now: ctx.clock.now() }),
    );
    checks.ok(
      'owner A is NOT authorized with the stale grant/epoch',
      support.authorizePredicate(rowAfter, { ownerId: OWNER_A, epoch: epochA, grantId: grantA, now: ctx.clock.now() }).allowed === false,
      support.authorizePredicate(rowAfter, { ownerId: OWNER_A, epoch: epochA, grantId: grantA, now: ctx.clock.now() }),
    );
    checks.eq('sweep knob disabled for this fixture', process.env.CBHR_PHASE1_SWEEP ?? 'unset', 'disabled');

    return baseResult(fixture, ctx.dbName, {
      ...support.statusFromChecks(checks.checks),
      checks: checks.checks,
      attempts: { claimAuthorityCalls: 2, revokeLeaseCalls: 1 },
      realReturns: {
        first: { ok: first.ok, matched: first.matched, error: support.errorView(first.error) },
        second: { ok: second.ok, matched: second.matched, error: support.errorView(second.error) },
        staleRevoke: { ok: staleRevoke.ok, matched: staleRevoke.matched, error: support.errorView(staleRevoke.error) },
      },
      dbReadBack: {
        afterFirstClaim: support.authorityView(rowA, start),
        afterSecondClaim: support.authorityView(rowB, ctx.clock.now()),
        afterStaleRevoke: support.authorityView(rowAfter, ctx.clock.now()),
      },
      provenance: support.provenance(ctx, { fixtureClockOffsets: ['T', 'T+48h+1h'] }),
    });
  } finally {
    await ctx.teardown();
  }
}

/** E1-T17-P2-CLAIM-VS-ACTIVE-PC */
async function p2ClaimVsActivePc(fixture) {
  const ctx = await support.makeContext({ tag: fixture.id, point: 'T17' });
  const checks = support.makeChecks();
  try {
    const start = ctx.clock.now();
    const pc1 = 'w3a-device-t17-pc1';
    const pc2 = 'w3a-device-t17-pc2';
    await support.seedAuthority(ctx, { _id: pc1, deviceKeyId: `key-${pc1}` });
    await support.seedAuthority(ctx, { _id: pc2, deviceKeyId: `key-${pc2}` });
    const svc = ctx.authorityService();

    const aClaimPc1 = await svc.claimAuthority({ deviceId: pc1, tenantId: TENANT, ownerId: OWNER_A, sessionId: 'w3a-t17-a-pc1', grantProof: null });
    const pc1AfterA = await support.readAuthorityRaw(ctx.models, pc1, TENANT);
    const grantA = pc1AfterA.grantId;

    ctx.clock.set(start + env.constants.LEASE_TTL_MS + HOUR_MS);
    const bClaimPc1 = await svc.claimAuthority({ deviceId: pc1, tenantId: TENANT, ownerId: OWNER_B, sessionId: 'w3a-t17-b-pc1', grantProof: null });
    const pc1AfterB = await support.readAuthorityRaw(ctx.models, pc1, TENANT);
    const grantB = pc1AfterB.grantId;

    const aClaimPc2 = await svc.claimAuthority({ deviceId: pc2, tenantId: TENANT, ownerId: OWNER_A, sessionId: 'w3a-t17-a-pc2', grantProof: null });
    const pc1AfterPc2 = await support.readAuthorityRaw(ctx.models, pc1, TENANT);
    const pc2After = await support.readAuthorityRaw(ctx.models, pc2, TENANT);

    const activeA = await support.countActiveOwners(ctx.models, OWNER_A, TENANT);
    const activeB = await support.countActiveOwners(ctx.models, OWNER_B, TENANT);

    checks.ok('A claims PC1', aClaimPc1.ok === true && aClaimPc1.matched === 1, support.errorView(aClaimPc1.error));
    checks.ok('B claims PC1 later', bClaimPc1.ok === true && bClaimPc1.matched === 1, support.errorView(bClaimPc1.error));
    checks.eq('PC1.prevOwner after B claim', pc1AfterB.prevOwner, OWNER_A);
    checks.eq('PC1.prevGrantId after B claim', pc1AfterB.prevGrantId, grantA);
    checks.eq('PC1.prevEpoch after B claim', pc1AfterB.prevEpoch, 1);
    checks.ok('A claims PC2 without revoking PC1', aClaimPc2.ok === true && aClaimPc2.matched === 1, support.errorView(aClaimPc2.error));
    checks.eq(
      'PC1 prev* untouched by the PC2 claim (no cross-row write)',
      { prevOwner: pc1AfterPc2.prevOwner, prevGrantId: pc1AfterPc2.prevGrantId, prevEpoch: pc1AfterPc2.prevEpoch, epoch: pc1AfterPc2.epoch },
      { prevOwner: pc1AfterB.prevOwner, prevGrantId: pc1AfterB.prevGrantId, prevEpoch: pc1AfterB.prevEpoch, epoch: pc1AfterB.epoch },
    );
    checks.ok(
      'B authorized on PC1',
      support.authorizePredicate(pc1AfterPc2, { ownerId: OWNER_B, epoch: pc1AfterB.epoch, grantId: grantB, now: ctx.clock.now() }).allowed === true,
      support.authorizePredicate(pc1AfterPc2, { ownerId: OWNER_B, epoch: pc1AfterB.epoch, grantId: grantB, now: ctx.clock.now() }),
    );
    checks.ok(
      'A authorized on PC2',
      support.authorizePredicate(pc2After, { ownerId: OWNER_A, epoch: pc2After.epoch, grantId: pc2After.grantId, now: ctx.clock.now() }).allowed === true,
      support.authorizePredicate(pc2After, { ownerId: OWNER_A, epoch: pc2After.epoch, grantId: pc2After.grantId, now: ctx.clock.now() }),
    );
    checks.eq('one active row for A in tenant', activeA, 1);
    checks.eq('one active row for B in tenant', activeB, 1);
    checks.ok(
      'A authorized on PC1 with the stale grant',
      support.authorizePredicate(pc1AfterPc2, { ownerId: OWNER_A, epoch: 1, grantId: grantA, now: ctx.clock.now() }).allowed === false,
      support.authorizePredicate(pc1AfterPc2, { ownerId: OWNER_A, epoch: 1, grantId: grantA, now: ctx.clock.now() }),
    );

    return baseResult(fixture, ctx.dbName, {
      ...support.statusFromChecks(checks.checks),
      checks: checks.checks,
      attempts: { claimAuthorityCalls: 3 },
      realReturns: {
        aClaimPc1: { ok: aClaimPc1.ok, matched: aClaimPc1.matched, error: support.errorView(aClaimPc1.error) },
        bClaimPc1: { ok: bClaimPc1.ok, matched: bClaimPc1.matched, error: support.errorView(bClaimPc1.error) },
        aClaimPc2: { ok: aClaimPc2.ok, matched: aClaimPc2.matched, error: support.errorView(aClaimPc2.error) },
      },
      dbReadBack: {
        pc1AfterA: support.authorityView(pc1AfterA, start),
        pc1AfterB: support.authorityView(pc1AfterB, ctx.clock.now()),
        pc1AfterPc2Claim: support.authorityView(pc1AfterPc2, ctx.clock.now()),
        pc2AfterClaim: support.authorityView(pc2After, ctx.clock.now()),
        activeRowsOwnerA: activeA,
        activeRowsOwnerB: activeB,
      },
      provenance: support.provenance(ctx),
    });
  } finally {
    await ctx.teardown();
  }
}

/** E1-T09-T10-LEASE-48H-MARGIN */
async function lease48hMargin(fixture) {
  const ctx = await support.makeContext({ tag: fixture.id, point: 'T09/T10' });
  const checks = support.makeChecks();
  try {
    const T = ctx.clock.now();
    const devices = ['ttl', 'renew-ok', 'renew-dead', 'deadzone-lo', 'deadzone-hi', 'lazy-release'];
    const owners = {};
    const seeded = {};
    for (const tag of devices) {
      owners[tag] = principal(tag);
      seeded[tag] = await support.seedDevice(ctx, tag, { _id: `w3a-device-${tag}` });
    }
    const svc = ctx.authorityService();
    const grants = {};
    for (const tag of devices) {
      const deviceId = `w3a-device-${tag}`;
      const claim = await svc.claimAuthority({ deviceId, tenantId: TENANT, ownerId: owners[tag], sessionId: `w3a-t09-${tag}`, grantProof: null });
      const row = await support.readAuthorityRaw(ctx.models, deviceId, TENANT);
      grants[tag] = { claim, row, epoch: row.epoch, grantId: row.grantId };
    }

    // --- renewal success 1ms before the margin boundary (now + 5000 < expiresAt) ---
    ctx.clock.set(T + env.constants.LEASE_TTL_MS - env.constants.SKEW_MARGIN_MS - 1);
    const renewSvc = ctx.authorityService({
      verifyRenewalProof: env.makeRenewalProof({
        tenantId: TENANT,
        ownerId: owners['renew-ok'],
        deviceId: 'w3a-device-renew-ok',
        deviceKeyId: seeded['renew-ok'].deviceKeyId,
        grantId: grants['renew-ok'].grantId,
        epoch: grants['renew-ok'].epoch,
      }),
    });
    const renewOk = await renewSvc.renewAuthority({
      deviceId: 'w3a-device-renew-ok',
      tenantId: TENANT,
      ownerId: owners['renew-ok'],
      epoch: grants['renew-ok'].epoch,
      grantId: grants['renew-ok'].grantId,
      proofInput: { __accept: true },
    });
    const renewOkRow = await support.readAuthorityRaw(ctx.models, 'w3a-device-renew-ok', TENANT);

    // --- renewal at exactly expiresAt - 5000ms (margin boundary => LEASE_EXPIRED) ---
    ctx.clock.set(T + env.constants.LEASE_TTL_MS - env.constants.SKEW_MARGIN_MS);
    const renewBoundarySvc = ctx.authorityService({
      verifyRenewalProof: env.makeRenewalProof({
        tenantId: TENANT,
        ownerId: owners['renew-dead'],
        deviceId: 'w3a-device-renew-dead',
        deviceKeyId: seeded['renew-dead'].deviceKeyId,
        grantId: grants['renew-dead'].grantId,
        epoch: grants['renew-dead'].epoch,
      }),
    });
    const renewBoundary = await renewBoundarySvc.renewAuthority({
      deviceId: 'w3a-device-renew-dead',
      tenantId: TENANT,
      ownerId: owners['renew-dead'],
      epoch: grants['renew-dead'].epoch,
      grantId: grants['renew-dead'].grantId,
      proofInput: { __accept: true },
    });
    const renewBoundaryRow = await support.readAuthorityRaw(ctx.models, 'w3a-device-renew-dead', TENANT);

    // --- dead zone: issue proceeds, claim CAS 0-matches => PAIRING_WINDOW_TOO_EARLY ---
    const deadZone = {};
    for (const [tag, offset] of [
      ['deadzone-lo', 0],
      ['deadzone-hi', env.constants.SKEW_MARGIN_MS - 1],
    ]) {
      ctx.clock.set(T + env.constants.LEASE_TTL_MS + offset);
      const ceremony = await support.runPairingCeremony(ctx, {
        deviceId: `w3a-device-${tag}`,
        deviceKeyId: seeded[tag].deviceKeyId,
        ownerId: owners[tag],
        key: seeded[tag].key,
      });
      deadZone[tag] = {
        offset,
        issueOk: ceremony.issue ? ceremony.issue.ok === true : false,
        stage: ceremony.stage,
        error: support.errorView(ceremony.approve ? ceremony.approve.error : ceremony.error),
        sessionState: ceremony.sessionId
          ? (await ctx.models.PairingSession.findOne({ _id: ceremony.sessionId, tenantId: TENANT }).lean()).state
          : null,
      };
    }

    // --- lazy release at expiresAt + 5000 ---
    ctx.clock.set(T + env.constants.LEASE_TTL_MS + env.constants.SKEW_MARGIN_MS);
    const beforeRelease = await support.readAuthorityRaw(ctx.models, 'w3a-device-lazy-release', TENANT);
    const lazyIssue = await ctx.pairingService().issuePairingSession({
      tenantId: TENANT,
      deviceId: 'w3a-device-lazy-release',
      deviceKeyId: seeded['lazy-release'].deviceKeyId,
      domainTag: env.constants.PAIRING_OPEN_DOMAIN,
      requestSource: 'w3a-t09',
      proof: support.pairingOpenProof(ctx, {
        deviceId: 'w3a-device-lazy-release',
        deviceKeyId: seeded['lazy-release'].deviceKeyId,
        key: seeded['lazy-release'].key,
      }),
    });
    const afterRelease = await support.readAuthorityRaw(ctx.models, 'w3a-device-lazy-release', TENANT);

    checks.eq(
      'grant TTL is exactly 172800000',
      new Date(grants.ttl.row.expiresAt).getTime() - new Date(grants.ttl.row.activatedAt).getTime(),
      172800000,
    );
    checks.ok('renewal 1ms inside the margin succeeds', renewOk.ok === true && renewOk.matched === 1, support.errorView(renewOk.error));
    checks.eq('renewal epoch advanced', renewOkRow.epoch, 2);
    checks.eq('renewal renewalCount', renewOkRow.renewalCount, 1);
    checks.ok('renewal rotates grantId', renewOkRow.grantId !== grants['renew-ok'].grantId, { rotated: renewOkRow.grantId !== grants['renew-ok'].grantId });
    checks.eq(
      'renewal advances expiresAt by exactly the lease TTL',
      new Date(renewOkRow.expiresAt).getTime() - new Date(renewOkRow.renewedAt).getTime(),
      172800000,
    );
    checks.ok('renewal at expiresAt-5000ms fails closed', renewBoundary.ok === false, support.errorView(renewBoundary.error));
    checks.eq('boundary renewal error code', renewBoundary.error && renewBoundary.error.code, 'LEASE_EXPIRED');
    checks.eq('boundary renewal wrote nothing', { epoch: renewBoundaryRow.epoch, grantId: renewBoundaryRow.grantId }, { epoch: grants['renew-dead'].epoch, grantId: grants['renew-dead'].grantId });

    for (const tag of ['deadzone-lo', 'deadzone-hi']) {
      checks.ok(`dead zone ${tag}: issuance proceeds`, deadZone[tag].issueOk === true, deadZone[tag]);
      checks.eq(`dead zone ${tag}: claim error code`, deadZone[tag].error && deadZone[tag].error.code, 'PAIRING_WINDOW_TOO_EARLY');
      checks.eq(`dead zone ${tag}: session left consumed without grant (fail closed)`, deadZone[tag].sessionState, 'consumed');
    }

    checks.eq('lazy release precondition leaseState', beforeRelease.leaseState, 'active');
    checks.eq('lazy release precondition epoch', beforeRelease.epoch, grants['lazy-release'].epoch);
    checks.eq('lazy release result leaseState', afterRelease.leaseState, 'expired');
    checks.eq('lazy release advanced epoch by exactly 1', afterRelease.epoch, beforeRelease.epoch + 1);
    checks.ok('issuance proceeds after guarded lazy release', lazyIssue.ok === true, support.errorView(lazyIssue.error));
    checks.eq('lazy release event kind emitted', ctx.audit.events.filter((event) => event.kind === 'expire').length, 1);

    return baseResult(fixture, ctx.dbName, {
      ...support.statusFromChecks(checks.checks),
      checks: checks.checks,
      attempts: { claimAuthorityCalls: devices.length, renewAuthorityCalls: 2, issuePairingSessionCalls: 3, approvePairingClaimCalls: 2 },
      realReturns: {
        renewAtExpiresMinus1: { ok: renewOk.ok, matched: renewOk.matched, error: support.errorView(renewOk.error) },
        renewAtExpiresMinus5000: { ok: renewBoundary.ok, matched: renewBoundary.matched, error: support.errorView(renewBoundary.error) },
        lazyReleaseIssue: { ok: lazyIssue.ok, error: support.errorView(lazyIssue.error) },
        deadZone: deadZone,
      },
      dbReadBack: {
        ttlGrant: support.authorityView(grants.ttl.row, T),
        renewOkAfter: support.authorityView(renewOkRow, ctx.clock.now()),
        renewBoundaryAfter: support.authorityView(renewBoundaryRow, ctx.clock.now()),
        lazyReleaseBefore: support.authorityView(beforeRelease, ctx.clock.now()),
        lazyReleaseAfter: support.authorityView(afterRelease, ctx.clock.now()),
      },
      provenance: support.provenance(ctx, {
        clockOffsetsProbed: ['T', 'T+172799999', 'T+172795000', 'T+172800000', 'T+172804999', 'T+172805000'],
      }),
    });
  } finally {
    await ctx.teardown();
  }
}

/** E1-T20-AUDIT-UNCERTAINTY */
async function auditUncertainty(fixture) {
  const ctx = await support.makeContext({ tag: fixture.id, auditSink: 'durable-raw' });
  const checks = support.makeChecks();
  try {
    const d1 = 'w3a-device-audit-ok';
    const d2 = 'w3a-device-audit-fail';
    await support.seedAuthority(ctx, { _id: d1, deviceKeyId: `key-${d1}` });
    await support.seedAuthority(ctx, { _id: d2, deviceKeyId: `key-${d2}` });

    const goodSvc = ctx.authorityService();
    const claimOk = await goodSvc.claimAuthority({ deviceId: d1, tenantId: TENANT, ownerId: OWNER_A, sessionId: 'w3a-t20-good', grantProof: null });
    const durableRows = await ctx.models.AuditEvent.find({ tenantId: TENANT }).lean();
    const goodEvent = ctx.audit.events.find((event) => event.deviceId === d1) ?? null;

    const throwing = support.makeThrowingAuditSink();
    const failingSvc = ctx.authorityService({ audit: throwing.audit });
    const claimFail = await failingSvc.claimAuthority({ deviceId: d2, tenantId: TENANT, ownerId: OWNER_B, sessionId: 'w3a-t20-fail', grantProof: null });
    const d2Row = await support.readAuthorityRaw(ctx.models, d2, TENANT);
    const rowsAfter = await ctx.models.AuditEvent.countDocuments({ tenantId: TENANT });
    const d2AuditRows = await ctx.models.AuditEvent.countDocuments({ tenantId: TENANT, deviceId: d2 });
    const failingEvent = throwing.events[0] ?? null;

    checks.ok('CAS with a working sink is ok', claimOk.ok === true, support.errorView(claimOk.error));
    checks.eq('durable audit row persisted (verbatim sink)', durableRows.length, 1);
    checks.eq('durable audit row kind', durableRows[0] && durableRows[0].kind, 'grant');
    checks.eq('audit row epoch equals post-CAS epoch', durableRows[0] && durableRows[0].epoch, 1);
    checks.eq('audit row seq equals post-CAS epoch', durableRows[0] && durableRows[0].seq, 1);
    checks.ok('durable sink pinned majority+journal',
      ctx.audit.writes.length === 1 && ctx.audit.writes[0].acknowledged === true,
      ctx.audit.writes);
    checks.ok('required audit fields present on the emitted event',
      goodEvent !== null &&
        ['tenantId', 'deviceId', 'epoch', 'kind', 'ts', 'actor', 'reasonCode'].every((key) => Object.prototype.hasOwnProperty.call(goodEvent, key)) &&
        goodEvent.actor === OWNER_A &&
        goodEvent.reasonCode === null,
      goodEvent);
    checks.ok('second CAS surfaces AUDIT_DELIVERY_UNCERTAIN', claimFail.ok === false, support.errorView(claimFail.error));
    checks.eq('audit failure error code', claimFail.error && claimFail.error.code, 'AUDIT_DELIVERY_UNCERTAIN');
    checks.eq('audit failure http status', claimFail.error && claimFail.error.httpStatus, 500);
    checks.eq('audit failure matched count (CAS really committed)', claimFail.matched, 1);
    checks.eq('committed CAS NOT rolled back', { leaseState: d2Row.leaseState, epoch: d2Row.epoch, ownerId: d2Row.ownerId }, { leaseState: 'active', epoch: 1, ownerId: OWNER_B });
    checks.ok('committed grantId present after audit failure', typeof d2Row.grantId === 'string' && d2Row.grantId.length === 22, { length: d2Row.grantId ? d2Row.grantId.length : 0 });
    checks.eq('missing audit line is detectable', { total: rowsAfter, forDevice: d2AuditRows }, { total: 1, forDevice: 0 });
    checks.eq('failing sink did observe the emitted event', failingEvent && failingEvent.kind, 'grant');

    const dump = await support.dumpAllFourCollections(ctx.client, ctx.dbName);
    const forbidden = [
      { label: 'lab pepper', value: env.LAB_PEPPER.toString('utf8') },
      { label: 'raw lookupTag key name in audit', value: 'lookupTag' },
    ];
    const leaks = [];
    for (const entry of forbidden) {
      if (entry.label === 'raw lookupTag key name in audit') {
        const auditRows = dump.deviceauthorityevents.map((row) => JSON.stringify(row));
        if (auditRows.some((text) => text.includes(entry.value))) {
          leaks.push(entry.label);
        }
      } else if (support.findBySerializedValue(dump, entry.value).length > 0) {
        leaks.push(entry.label);
      }
    }
    checks.eq('no pepper/lookupTag persisted anywhere', leaks, []);

    return baseResult(fixture, ctx.dbName, {
      ...support.statusFromChecks(checks.checks),
      checks: checks.checks,
      attempts: { claimAuthorityCalls: 2 },
      realReturns: {
        claimWithWorkingSink: { ok: claimOk.ok, matched: claimOk.matched, error: support.errorView(claimOk.error) },
        claimWithThrowingSink: { ok: claimFail.ok, matched: claimFail.matched, error: support.errorView(claimFail.error) },
      },
      dbReadBack: {
        durableAuditRows: durableRows.map((row) => ({ kind: row.kind, epoch: row.epoch, seq: row.seq, actor: row.actor, reasonCode: row.reasonCode, deviceId: row.deviceId })),
        d2AfterAuditFailure: support.authorityView(d2Row, ctx.clock.now()),
        auditRowCounts: { total: rowsAfter, forFailedDevice: d2AuditRows },
      },
      provenance: support.provenance(ctx, {
        auditSinkDisclosure:
          'Two sinks are used: an injected DURABLE raw-driver sink that writes the emitted event verbatim into the real deviceauthorityevents collection at majority+journal, and an injected THROWING sink that records then rejects. The product sink seam is injected by contract (freeze §8), so neither sink replaces product logic.',
      }),
    });
  } finally {
    await ctx.teardown();
  }
}

/** E1-FACTORY-REGISTRY-SHAPE (real-registry binding control) */
async function factoryRegistryShape(fixture) {
  const ctx = await support.makeContext({ tag: fixture.id });
  const checks = support.makeChecks();
  try {
    const attempts = env.probeFactoryShapeAgainstRawRegistry(ctx.registry, ctx.clock, ctx.crypto);
    for (const attempt of attempts) {
      checks.ok(
        `${attempt.factory} accepts the real createModels(mongoose) registry`,
        attempt.accepted === true,
        attempt.error,
      );
    }
    checks.eq(
      'genuine Mongoose model typeof is function (root cause)',
      ctx.facadeProvenance.DeviceAuthority.realModelTypeof,
      'function',
    );

    return baseResult(fixture, ctx.dbName, {
      ...support.statusFromChecks(checks.checks),
      checks: checks.checks,
      attempts: { factoryConstructionAttempts: attempts.length },
      realReturns: { factoryProbes: attempts },
      dbReadBack: {},
      counterexample:
        'createAuthorityService({ db: createModels(mongoose), clock, crypto, audit, verifyRenewalProof }) throws TypeError: createAuthorityService requires db.DeviceAuthority to be a Mongoose model with findOne/updateOne — because typeof <genuine Mongoose Model> === "function" while assertDependencies requires "object".',
      provenance: support.provenance(ctx, {
        testsOnlyFacadeNote:
          'Every other product fixture reaches the real model methods through the disclosed plain-object facade; this fixture records the raw-registry rejection.',
      }),
    });
  } finally {
    await ctx.teardown();
  }
}

/** E1-WRITE-CONCERN-PINNING */
async function writeConcernPinning(fixture) {
  const ctx = await support.makeContext({ tag: fixture.id });
  const checks = support.makeChecks();
  try {
    const device = await support.seedDevice(ctx, 'wc-issue');
    const svc = ctx.authorityService();
    const issue = await ctx.pairingService().issuePairingSession({
      tenantId: TENANT,
      deviceId: device.deviceId,
      deviceKeyId: device.deviceKeyId,
      domainTag: env.constants.PAIRING_OPEN_DOMAIN,
      proof: support.pairingOpenProof(ctx, device),
    });
    const claim = await svc.claimAuthority({ deviceId: device.deviceId, tenantId: TENANT, ownerId: principal('wc'), sessionId: 'w3a-wc', grantProof: null });
    const registration = await support.registerDevice(ctx, { deviceName: 'w3a-wc-reg', key: env.makeDeviceKey('wc-registered') });

    const writes = ctx.recorder.entries.filter((entry) =>
      ['document', 'update', 'pipeline'].includes(entry.payloadKind),
    );
    const pinned = writes.filter((entry) => entry.options && entry.options.writeConcern && entry.options.writeConcern.w === 'majority' && entry.options.writeConcern.j === true);
    const unpinned = writes.filter((entry) => !(entry.options && entry.options.writeConcern && entry.options.writeConcern.w === 'majority' && entry.options.writeConcern.j === true));

    const casWrites = writes.filter((entry) => entry.method === 'updateOne');
    checks.ok('authority CAS updateOne pins majority+journal', casWrites.length > 0 && casWrites.every((entry) => entry.options && entry.options.writeConcern && entry.options.writeConcern.w === 'majority' && entry.options.writeConcern.j === true), casWrites.map((entry) => ({ model: entry.model, method: entry.method, options: entry.options })));
    checks.ok(
      'every insert path pins majority+journal',
      unpinned.length === 0,
      unpinned.map((entry) => ({ model: entry.model, method: entry.method, options: entry.options })),
    );
    checks.eq(
      'unpinned write calls (the counterexample)',
      unpinned.map((entry) => `${entry.model}.${entry.method}`),
      [],
    );

    return baseResult(fixture, ctx.dbName, {
      ...support.statusFromChecks(checks.checks),
      checks: checks.checks,
      attempts: { claimAuthorityCalls: 1, issuePairingSessionCalls: 1, registrationCeremonies: registration.ok === true ? 1 : 0 },
      realReturns: {
        claim: { ok: claim.ok, matched: claim.matched, error: support.errorView(claim.error) },
        issue: { ok: issue.ok, error: support.errorView(issue.error) },
        registration: { ok: registration.ok, error: support.errorView(registration.error) },
      },
      dbReadBack: { pinnedCallCount: pinned.length, unpinnedCallCount: unpinned.length, allWriteCalls: writes },
      counterexample:
        'Product insert paths call the real Mongoose model without any writeConcern option, e.g. registrationService completeRegistration -> db.DeviceAuthority.create(row) and pairingSessionService issuePairingSession -> db.PairingSession.create(row); the recorded call options are null, so the driver/Mongoose default applies instead of the frozen {w:"majority",j:true}.',
      provenance: support.provenance(ctx, {
        uriWriteConcernParameter: /[?&](w|journal|j)=/.test(support.fence.FROZEN_URI),
        mongooseConnectionWriteConcern: env.mongoose.connection.db.writeConcern ?? null,
      }),
    });
  } finally {
    await ctx.teardown();
  }
}

/** E1-AUDIT-MODEL-PERSISTENCE */
async function auditModelPersistence(fixture) {
  const ctx = await support.makeContext({ tag: fixture.id, auditSink: 'real-model' });
  const checks = support.makeChecks();
  try {
    const registration = await support.registerDevice(ctx, { deviceName: 'w3a-audit-model' });
    const device = 'w3a-device-audit-model';
    await support.seedAuthority(ctx, { _id: device, deviceKeyId: `key-${device}` });
    const claim = await ctx.authorityService().claimAuthority({ deviceId: device, tenantId: TENANT, ownerId: OWNER_C, sessionId: 'w3a-audit-model', grantProof: null });
    const persisted = await ctx.models.AuditEvent.countDocuments({ tenantId: TENANT });
    const outcomes = ctx.audit.outcomes;

    checks.ok(
      'every emitted audit event is persistable through the real AuditEvent model',
      outcomes.length > 0 && outcomes.every((outcome) => outcome.ok === true),
      outcomes,
    );
    checks.eq('audit events durably persisted for this run', persisted, outcomes.length);
    checks.ok('registration surface error is surfaced, not swallowed', registration.ok === false, support.errorView(registration.error));
    checks.ok('claim surface error is surfaced, not swallowed', claim.ok === false, support.errorView(claim.error));

    return baseResult(fixture, ctx.dbName, {
      ...support.statusFromChecks(checks.checks),
      checks: checks.checks,
      attempts: { auditModelWrites: outcomes.length },
      realReturns: {
        registration: { ok: registration.ok, error: support.errorView(registration.error) },
        claim: { ok: claim.ok, matched: claim.matched, error: support.errorView(claim.error) },
      },
      dbReadBack: { persistedAuditRows: persisted, modelSinkOutcomes: outcomes },
      counterexample:
        'Frozen schema/auditEvent.ts declares actor/reasonCode/epoch as required, while the I6/I5 emitters send null for reasonCode (grant/renew/revoke/register/expire/retire/release), null for actor (registration), and null for epoch (pairing claim-refused). Persisting the emitted event through the real model fails with a Mongoose ValidationError.',
      provenance: support.provenance(ctx),
    });
  } finally {
    await ctx.teardown();
  }
}

/** E1-IDENTITY-PROVENANCE */
async function identityProvenance(fixture) {
  const ctx = await support.makeContext({ tag: fixture.id });
  const checks = support.makeChecks();
  const twoTenantPolicy = env.makeTenantPolicy([TENANT, OTHER_TENANT]);
  const attackerBody = {
    tenantId: OTHER_TENANT,
    ownerId: 'attacker-supplied-owner',
    deviceId: 'attacker-supplied-device',
    deviceKeyId: 'attacker-supplied-key',
    epoch: 999,
    grantId: 'attacker-supplied-grant',
  };
  try {
    const before = await support.dumpAllFourCollections(ctx.client, ctx.dbName);
    const beforeCounts = Object.fromEntries(Object.entries(before).map(([key, rows]) => [key, rows.length]));

    const provDevice = await support.seedDevice(ctx, 'provenance');
    const device = provDevice.deviceId;
    const deviceKeyId = provDevice.deviceKeyId;
    await ctx.authorityService().claimAuthority({ deviceId: device, tenantId: TENANT, ownerId: OWNER_A, sessionId: 'w3a-prov', grantProof: null });
    const issue = await ctx.pairingService().issuePairingSession({
      tenantId: TENANT,
      deviceId: device,
      deviceKeyId,
      domainTag: env.constants.PAIRING_OPEN_DOMAIN,
      proof: support.pairingOpenProof(ctx, provDevice),
    });
    const session = issue.ok ? issue.pairingSession : null;
    const challenge = crypto.randomBytes(32).toString('base64url');
    const redeem = session === null ? null : await ctx.pairingService().redeemPairingCode({ code: issue.code, tenantId: TENANT, ownerId: OWNER_A });
    const sessionRow = redeem && redeem.ok ? await ctx.models.PairingSession.findOne({ _id: redeem.pairingSession._id, tenantId: TENANT }).lean() : null;

    const svc = ctx.authorityService();
    const registrationSvc = ctx.registrationService({ tenantPolicy: twoTenantPolicy });
    const pairingSvc = ctx.pairingService();

    const probes = [];
    const containers = ['body', 'query', 'params', 'headers', 'req', 'request', 'res'];
    // Every REQUEST-FACING I5 method carries the frozen request-container rejection.
    const requestFacingSpecs = [
      ['beginRegistration', () => registrationSvc.beginRegistration({ tenantId: TENANT, requestSource: 'w3a', request: attackerBody })],
      ['completeRegistration', () => registrationSvc.completeRegistration({ tenantId: TENANT, devicePublicKey: provDevice.key.spkiB64u, body: attackerBody })],
      ['issuePairingSession', () => pairingSvc.issuePairingSession({ tenantId: TENANT, deviceId: device, deviceKeyId, body: attackerBody })],
      ['redeemPairingCode', () => pairingSvc.redeemPairingCode({ code: issue.code ?? '000000', tenantId: TENANT, ownerId: OWNER_A, res: attackerBody })],
      ['rejoinPendingPairing', () => pairingSvc.rejoinPendingPairing({ code: issue.code ?? '000000', tenantId: TENANT, ownerId: OWNER_A, query: attackerBody })],
      ['approvePairingClaim', () => pairingSvc.approvePairingClaim({ pairingSessionId: session ? String(session._id) : 'x', tenantId: TENANT, ownerId: OWNER_A, req: attackerBody })],
      ['denyPairingSession', () => pairingSvc.denyPairingSession({ pairingSessionId: session ? String(session._id) : 'x', tenantId: TENANT, ownerId: OWNER_A, params: attackerBody })],
    ];
    for (const [name, call] of requestFacingSpecs) {
      const result = await call();
      probes.push({
        method: name,
        ok: result.ok,
        rejected: result.error !== null && result.error !== undefined && result.error.code === 'REQUEST_SUPPLIED_IDENTITY_REJECTED',
        errorCode: support.errorView(result.error) && support.errorView(result.error).code,
        httpStatus: support.errorView(result.error) && support.errorView(result.error).httpStatus,
      });
    }
    // every container variant, on one representative request-facing method
    const containerProbes = [];
    for (const container of containers) {
      const result = await pairingSvc.issuePairingSession({ tenantId: TENANT, deviceId: device, deviceKeyId, [container]: attackerBody });
      containerProbes.push({
        container,
        rejected: result.error !== null && result.error.code === 'REQUEST_SUPPLIED_IDENTITY_REJECTED',
        errorCode: support.errorView(result.error).code,
      });
    }

    /*
     * I6 is an internal CAS surface: it declares no request-container rejection because it never
     * receives one. Injection is therefore proved by INERTNESS — the same trusted call with and
     * without an attacker container must produce byte-identical decision tuples and identical
     * durable state.
     */
    const inertness = [];
    const inertBaselineDevice = await support.seedDevice(ctx, 'provenance-inert-a');
    const inertInjectedDevice = await support.seedDevice(ctx, 'provenance-inert-b');
    const trustedPrincipalForInjected = principal('provenance-inert');
    const baseline = await ctx.authorityService().claimAuthority({ deviceId: inertBaselineDevice.deviceId, tenantId: TENANT, ownerId: OWNER_C, sessionId: 'w3a-inert-base', grantProof: null });
    const baselineRow = await support.readAuthorityRaw(ctx.models, inertBaselineDevice.deviceId, TENANT);
    const injected = await ctx.authorityService().claimAuthority({
      deviceId: inertInjectedDevice.deviceId,
      tenantId: TENANT,
      ownerId: trustedPrincipalForInjected,
      sessionId: 'w3a-inert-injected',
      grantProof: null,
      body: attackerBody,
      query: attackerBody,
      params: attackerBody,
      headers: attackerBody,
      req: attackerBody,
      request: attackerBody,
      res: attackerBody,
    });
    const injectedRow = await support.readAuthorityRaw(ctx.models, inertInjectedDevice.deviceId, TENANT);
    const tuple = (result) => ({ ok: result.ok, matched: result.matched, errorCode: result.error ? result.error.code : null });
    const rowTuple = (row) => ({ identityState: row.identityState, leaseState: row.leaseState, epoch: row.epoch });
    inertness.push({
      method: 'claimAuthority',
      baseline: tuple(baseline),
      injected: tuple(injected),
      identical: JSON.stringify(tuple(baseline)) === JSON.stringify(tuple(injected)),
      baselineRow: rowTuple(baselineRow),
      injectedRow: rowTuple(injectedRow),
      rowIdentical: JSON.stringify(rowTuple(baselineRow)) === JSON.stringify(rowTuple(injectedRow)),
      injectedRowOwnerIsTrustedPrincipal: injectedRow.ownerId === trustedPrincipalForInjected,
      injectedRowOwnerIsAttacker: injectedRow.ownerId === attackerBody.ownerId,
    });
    const inertSpend = await ctx.authorityService().spendChallenge({
      challengeHash: 'w3a-inert-no-such-challenge',
      purpose: 'pairing-claim',
      tenantId: TENANT,
      bound: {},
      body: attackerBody,
      query: attackerBody,
    });
    checks.eq('I6 spendChallenge is inert to injected container keys', tuple(inertSpend), { ok: false, matched: 0, errorCode: null });

    // mid-ceremony tenant switch with a policy that permits both tenants -> TENANT_MISMATCH, zero writes
    const nonce = crypto.randomBytes(16).toString('base64url');
    const issuedAt = String(ctx.clock.now());
    const begin = await registrationSvc.beginRegistration({ tenantId: TENANT, requestSource: 'w3a' });
    const switchMessage = ctx.crypto.canonicalEncode({
      domainTag: env.constants.REGISTRATION_DOMAIN,
      fields: [
        OTHER_TENANT,
        begin.challenge,
        ctx.labKey.spkiB64u,
        ctx.crypto.thumbprintB64u(ctx.labKey.spkiB64u),
        'w3a-switch',
        'win32',
        '0.0.1',
        nonce,
        issuedAt,
      ],
    });
    const challengeCountBefore = await ctx.models.Challenge.countDocuments({ tenantId: TENANT });
    const authorityCountBefore = await ctx.models.DeviceAuthority.countDocuments({ tenantId: OTHER_TENANT });
    const switched = await registrationSvc.completeRegistration({
      tenantId: OTHER_TENANT,
      devicePublicKey: ctx.labKey.spkiB64u,
      deviceName: 'w3a-switch',
      platform: 'win32',
      agentVersion: '0.0.1',
      domainTag: env.constants.REGISTRATION_DOMAIN,
      proof: { challenge: begin.challenge, nonce, issuedAt, signatureB64u: env.sign(ctx.labKey, switchMessage) },
    });
    const authorityCountAfter = await ctx.models.DeviceAuthority.countDocuments({ tenantId: OTHER_TENANT });
    const challengeRowAfter = await ctx.models.Challenge.findOne({ challengeHash: begin.challengeHash, tenantId: TENANT }).lean();

    // cross-tenant redemption of a real code
    const foreignRedeem = await pairingSvc.redeemPairingCode({ code: issue.code, tenantId: OTHER_TENANT, ownerId: OWNER_A });
    const sessionRowAfter = sessionRow ? await ctx.models.PairingSession.findOne({ _id: sessionRow._id, tenantId: TENANT }).lean() : null;

    const staticScan = env.productHasRequestContainersRead();
    const after = await support.dumpAllFourCollections(ctx.client, ctx.dbName);
    const afterCounts = Object.fromEntries(Object.entries(after).map(([key, rows]) => [key, rows.length]));

    checks.ok('all 7 request-facing I5 methods reject a raw request container', probes.length === 7 && probes.every((probe) => probe.rejected === true), probes);
    checks.ok('all 7 container names are rejected', containerProbes.every((probe) => probe.rejected === true), containerProbes);
    checks.ok(
      'I6 internal CAS calls are inert to injected container keys',
      inertness.every((entry) => entry.identical === true && entry.rowIdentical === true && entry.injectedRowOwnerIsTrustedPrincipal === true && entry.injectedRowOwnerIsAttacker === false),
      inertness,
    );
    checks.ok('service files never read a request container', Object.values(staticScan).every((entry) => entry.readsRequestContainer === false), staticScan);
    checks.ok('mid-ceremony tenant switch is TENANT_MISMATCH', switched.error !== null && switched.error.code === 'TENANT_MISMATCH', support.errorView(switched.error));
    checks.eq('mid-ceremony switch wrote no authority row', authorityCountAfter, authorityCountBefore);
    checks.eq('mid-ceremony switch did not spend the challenge', challengeRowAfter && challengeRowAfter.consumedAt, null);
    checks.eq('challenge rows unchanged by the switch', await ctx.models.Challenge.countDocuments({ tenantId: TENANT }), challengeCountBefore);
    checks.ok('cross-tenant redemption is the uniform miss', foreignRedeem.ok === false && foreignRedeem.error.code === 'INVALID_OR_EXPIRED_CODE', support.errorView(foreignRedeem.error));
    checks.eq(
      'cross-tenant redemption left the home-tenant session untouched',
      sessionRowAfter ? { state: sessionRowAfter.state, attemptsUsed: sessionRowAfter.attemptsUsed } : null,
      sessionRow ? { state: sessionRow.state, attemptsUsed: sessionRow.attemptsUsed } : null,
    );
    checks.ok(
      'caller-supplied identity never reached the DB',
      after.deviceauthorities.every((row) => row.ownerId !== 'attacker-supplied-owner') &&
        after.deviceauthorities.every((row) => row._id !== 'attacker-supplied-device') &&
        after.deviceauthorities.every((row) => row.grantId !== 'attacker-supplied-grant'),
      { beforeCounts, afterCounts },
    );

    return baseResult(fixture, ctx.dbName, {
      ...support.statusFromChecks(checks.checks),
      checks: checks.checks,
      attempts: { requestContainerProbes: probes.length, containerVariantProbes: containerProbes.length, inertnessProbes: inertness.length + 1, registrationCeremonies: 1, redemptions: 1 },
      realReturns: { probes, containerProbes, inertness, midCeremonySwitch: support.errorView(switched.error), foreignRedeem: support.errorView(foreignRedeem.error) },
      dbReadBack: { beforeCounts, afterCounts, staticScan },
      provenance: support.provenance(ctx, {
        attackerSuppliedFields: ['tenantId', 'ownerId', 'deviceId', 'deviceKeyId', 'epoch', 'grantId'],
        identitySource:
          'harness-injected fixed tenant + fixed principals only. I5 request-facing methods reject every raw request container; I6 internal CAS methods never read a container and are proved inert by identical baseline/injected decision tuples.',
      }),
    });
  } finally {
    await ctx.teardown();
  }
}

const FIXTURES = [
  {
    id: 'E1-ONEPC-GRANT-CAS',
    tier: 'E1',
    kind: 'product',
    runner: 'inline',
    requires: ['I6'],
    title: 'strict one-PC/account grant CAS through real I6 bytes and real MongoDB',
    run: onepcGrantCas,
  },
  {
    id: 'E1-T16-P1-STALE-OWNER-REVOKE',
    tier: 'E1',
    kind: 'product',
    runner: 'inline',
    requires: ['I6'],
    title: 'P1 stale-owner revoke',
    run: staleOwnerRevoke,
  },
  {
    id: 'E1-T17-P2-CLAIM-VS-ACTIVE-PC',
    tier: 'E1',
    kind: 'product',
    runner: 'inline',
    requires: ['I6'],
    title: 'P2 owner claim versus an active PC',
    run: p2ClaimVsActivePc,
  },
  {
    id: 'E1-T09-T10-LEASE-48H-MARGIN',
    tier: 'E1',
    kind: 'product',
    runner: 'inline',
    requires: ['I6'],
    title: '48h lease TTL and the 5000ms renewal margin boundaries',
    run: lease48hMargin,
  },
  {
    id: 'E1-T20-AUDIT-UNCERTAINTY',
    tier: 'E1',
    kind: 'product',
    runner: 'inline',
    requires: ['I6'],
    title: 'post-CAS audit delivery uncertainty with the commit retained',
    run: auditUncertainty,
  },
  {
    id: 'E1-FACTORY-REGISTRY-SHAPE',
    tier: 'E1',
    kind: 'product',
    runner: 'inline',
    requires: ['I6', 'I5'],
    title: 'frozen factories accept the genuine createModels(mongoose) registry',
    run: factoryRegistryShape,
  },
  {
    id: 'E1-WRITE-CONCERN-PINNING',
    tier: 'E1',
    kind: 'product',
    runner: 'inline',
    requires: ['I6', 'I5'],
    title: 'every product write pins majority+journal',
    run: writeConcernPinning,
  },
  {
    id: 'E1-AUDIT-MODEL-PERSISTENCE',
    tier: 'E1',
    kind: 'product',
    runner: 'inline',
    requires: ['I6', 'I5'],
    title: 'emitted audit events persist through the real AuditEvent model',
    run: auditModelPersistence,
  },
  {
    id: 'E1-IDENTITY-PROVENANCE',
    tier: 'E1',
    kind: 'product',
    runner: 'inline',
    requires: ['I6', 'I5'],
    title: 'no caller-controlled tenant/device/owner identity can be injected',
    run: identityProvenance,
  },
];

module.exports = { FIXTURES, principal };