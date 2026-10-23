'use strict';

/**
 * SERVER-TIME LEASE/TTL ORACLE (new test; PHASE1-LOCAL-AUTHORITY-001, GM-44 / GM-45).
 *
 *   node tests/device/servertime/run-servertime.cjs [--evidence-dir=<dir>]
 *
 * WHAT IT PROVES
 * Every lease-state and TTL predicate is decided by DATABASE time, so a writer whose own clock is
 * offset by +/-300 s cannot over-release a live lease, cannot over-accept a renewal past expiry,
 * cannot accept a dead pairing code, and — the case an adversarial verifier proved was still open
 * under the withdrawn GM-36 ruling — cannot mint a six-digit code for a lease that is live by
 * 4000 ms at the *fully compliant* budget skew of +5000 ms.
 *
 * WHY THE ROWS ARE ANCHORED TO DATABASE TIME
 * The pre-existing fixtures (tests/device/e1/**, api/server/routes/__tests__/devices.spec.js) pin
 * their injected clock to an ABSOLUTE epoch (`EPOCH_BASE_MS`, `BASE_NOW`) that is now in the past.
 * A row minted at that epoch is already dead in database time, so "live on the reference timeline"
 * and "live in the database" stopped meaning the same thing the moment the predicates moved to
 * database time. This oracle therefore takes its reference timeline from the SERVER (`hello`), and
 * applies the writer's offset on top of it — which is the only anchoring under which "live" is a
 * property of the database rather than of a fixture constant.
 *
 * HONESTY RULES
 * - No product byte is stubbed, reimplemented or bypassed: every decision below is a real
 *   `createAuthorityService` / `createPairingSessionService` call over the frozen
 *   `createModels(mongoose)` registry against the real replica set.
 * - The reference timeline is read from the server, never from `Date.now()`.
 * - A failure is reported as a failure with the observed values; nothing is retried into a pass.
 */

const fs = require('node:fs');
const path = require('node:path');

const support = require('../e1/w3a/support.cjs');
const env = require('../e1/w3a/env.cjs');
const { createClockSkewGuard, readDatabaseNowMs } = require('../../../api/server/services/Device/databaseTime');

const TENANT = env.TENANT;
const LEASE_TTL_MS = env.constants.LEASE_TTL_MS;
const SKEW_MARGIN_MS = env.constants.SKEW_MARGIN_MS;

const FAST_MS = 300000;
const SLOW_MS = -300000;

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

/** The reference timeline comes from the SERVER, not from this process. */
async function serverNowMs(client) {
  const hello = await client.db('admin').command({ hello: 1 });
  return new Date(hello.localTime).getTime();
}

function view(row) {
  if (row === null || row === undefined) return null;
  return {
    leaseState: row.leaseState ?? null,
    identityState: row.identityState ?? null,
    epoch: row.epoch ?? null,
    ownerId: row.ownerId ?? null,
    expiresAtMs: row.expiresAt ? new Date(row.expiresAt).getTime() : null,
    renewalCount: row.renewalCount ?? null,
  };
}

/* ------------------------------------------------------------------ cases */

/**
 * Case 1-2 — MARGIN-FREE ADMISSION. A lease that is live by `liveMs` on the database timeline must
 * refuse issuance at ANY writer offset. This is the verifier's PROBE-ADMISSION case: at skew
 * +5000 with 4000 ms of life left, GM-36 minted and consumed a code.
 */
async function caseAdmission(ctx, checks, { label, skewMs, liveMs, expectRefused }) {
  const reference = await serverNowMs(ctx.client);
  const deviceId = `st-adm-${label}`;
  const key = env.makeDeviceKey(`st-adm-${label}`);
  const expiresAt = new Date(reference + liveMs);

  await support.seedDevice(ctx, `st-adm-${label}`, {
    _id: deviceId,
    key,
    identityState: 'active',
    leaseState: 'active',
    epoch: 1,
    ownerId: `principal-st-seed-${label}`,
    grantId: `st-grant-${label}`,
    activatedAt: new Date(expiresAt.getTime() - LEASE_TTL_MS),
    expiresAt,
  });

  // The writer's own clock carries the offset; the lease decision must not read it.
  ctx.clock.set(reference + skewMs);

  const pairing = ctx.pairingService();
  const open = await pairing.mintPairingOpenChallenge({
    tenantId: TENANT,
    deviceId,
    deviceKeyId: ctx.crypto.thumbprintB64u(key.spkiB64u),
  });
  const issue = open.ok
    ? await pairing.issuePairingSession({
        tenantId: TENANT,
        deviceId,
        deviceKeyId: ctx.crypto.thumbprintB64u(key.spkiB64u),
        domainTag: env.constants.PAIRING_OPEN_DOMAIN,
        requestSource: 'servertime-oracle',
        challengeHash: open.challengeHash,
        proof: support.pairingOpenProof(ctx, {
          deviceId,
          deviceKeyId: ctx.crypto.thumbprintB64u(key.spkiB64u),
          key,
          challengeHash: open.challengeHash,
          issuedAt: open.issuedAt,
        }),
      })
    : { ok: false, code: null, error: open.error };

  const codeIssued = typeof issue.code === 'string' && /^[0-9]{6}$/.test(issue.code);
  const sessions = await ctx.models.PairingSession.countDocuments({ tenantId: TENANT, deviceId });
  const row = view(
    await ctx.models.DeviceAuthority.findOne({ _id: deviceId, tenantId: TENANT }).lean(),
  );

  checks.ok(
    `${label}: live by ${liveMs} ms at writer skew ${skewMs} ms ⇒ issuance REFUSED (no code minted)`,
    issue.ok === false && codeIssued === false,
    { issued: issue.ok === true, codeIssued, errorCode: issue.error ? issue.error.code : null },
  );
  checks.eq(
    `${label}: the refusal is the frozen live-lease code`,
    issue.error ? issue.error.code : null,
    expectRefused,
  );
  checks.eq(`${label}: no pairing session row was created`, sessions, 0);
  checks.eq(`${label}: the live lease was not transitioned`, [row.leaseState, row.epoch, row.ownerId], [
    'active',
    1,
    `principal-st-seed-${label}`,
  ]);
}

/** Case 3 — over-release through the claim CAS. */
async function caseClaimOverRelease(ctx, checks, { label, skewMs, liveMs }) {
  const reference = await serverNowMs(ctx.client);
  const deviceId = `st-claim-${label}`;
  const key = env.makeDeviceKey(`st-claim-${label}`);
  const expiresAt = new Date(reference + liveMs);

  await support.seedDevice(ctx, `st-claim-${label}`, {
    _id: deviceId,
    key,
    identityState: 'active',
    leaseState: 'active',
    epoch: 1,
    ownerId: `principal-st-claim-seed-${label}`,
    grantId: `st-claim-grant-${label}`,
    activatedAt: new Date(expiresAt.getTime() - LEASE_TTL_MS),
    expiresAt,
  });

  ctx.clock.set(reference + skewMs);
  const authority = ctx.authorityService();
  const claim = await authority.claimAuthority({
    deviceId,
    tenantId: TENANT,
    ownerId: `principal-st-claim-new-${label}`,
    expectedEpoch: 1,
    sessionId: `st-claim-session-${label}`,
    grantProof: null,
  });
  const row = view(
    await ctx.models.DeviceAuthority.findOne({ _id: deviceId, tenantId: TENANT }).lean(),
  );

  checks.eq(
    `${label}: a live lease (by ${liveMs} ms) is NOT dislodged by a writer fast by ${skewMs} ms`,
    claim.matched,
    0,
  );
  checks.eq(`${label}: the frozen live-lease refusal is returned`, claim.error ? claim.error.code : null, 'DEVICE_ALREADY_PAIRED_USE_RENEW');
  checks.eq(`${label}: owner and epoch are untouched`, [row.ownerId, row.epoch, row.leaseState], [
    `principal-st-claim-seed-${label}`,
    1,
    'active',
  ]);
}

/** Case 4 — over-release through the lazy release CAS. */
async function caseLazyReleaseOverRelease(ctx, checks, { label, skewMs, liveMs }) {
  const reference = await serverNowMs(ctx.client);
  const deviceId = `st-lazy-${label}`;
  const expiresAt = new Date(reference + liveMs);

  await support.seedDevice(ctx, `st-lazy-${label}`, {
    _id: deviceId,
    key: env.makeDeviceKey(`st-lazy-${label}`),
    identityState: 'active',
    leaseState: 'active',
    epoch: 1,
    ownerId: `principal-st-lazy-${label}`,
    grantId: `st-lazy-grant-${label}`,
    activatedAt: new Date(expiresAt.getTime() - LEASE_TTL_MS),
    expiresAt,
  });

  ctx.clock.set(reference + skewMs);
  const authority = ctx.authorityService();
  const release = await authority.releaseLapsedLease({ deviceId, tenantId: TENANT });
  const row = view(
    await ctx.models.DeviceAuthority.findOne({ _id: deviceId, tenantId: TENANT }).lean(),
  );

  checks.eq(
    `${label}: the lazy release 0-matches a lease live by ${liveMs} ms at writer skew ${skewMs} ms`,
    release.matched,
    0,
  );
  checks.eq(`${label}: the lease stays active at the seed epoch`, [row.leaseState, row.epoch], ['active', 1]);
}

/** Case 5 — over-acceptance through the renewal CAS. */
async function caseRenewOverAcceptance(ctx, checks, { label, skewMs, lifeMs }) {
  const reference = await serverNowMs(ctx.client);
  const deviceId = `st-renew-${label}`;
  const key = env.makeDeviceKey(`st-renew-${label}`);
  const expiresAt = new Date(reference + lifeMs);
  const grantId = `st-renew-grant-${label}`;
  const ownerId = `principal-st-renew-${label}`;

  await support.seedDevice(ctx, `st-renew-${label}`, {
    _id: deviceId,
    key,
    identityState: 'active',
    leaseState: 'active',
    epoch: 1,
    ownerId,
    grantId,
    activatedAt: new Date(expiresAt.getTime() - LEASE_TTL_MS),
    expiresAt,
  });

  ctx.clock.set(reference + skewMs);
  const authority = ctx.authorityService({
    verifyRenewalProof: env.makeRenewalProof({
      tenantId: TENANT,
      ownerId,
      deviceId,
      deviceKeyId: ctx.crypto.thumbprintB64u(key.spkiB64u),
      grantId,
      epoch: 1,
    }),
  });
  const renew = await authority.renewAuthority({
    deviceId,
    tenantId: TENANT,
    ownerId,
    epoch: 1,
    grantId,
    proofInput: { __accept: true },
  });
  const row = view(
    await ctx.models.DeviceAuthority.findOne({ _id: deviceId, tenantId: TENANT }).lean(),
  );

  checks.eq(
    `${label}: a lease expired by ${-lifeMs} ms is NOT renewed by a writer slow by ${skewMs} ms`,
    renew.matched,
    0,
  );
  checks.eq(`${label}: the frozen expiry code is returned`, renew.error ? renew.error.code : null, 'LEASE_EXPIRED');
  checks.eq(`${label}: expiresAt, epoch and renewalCount are unchanged`, [row.expiresAtMs, row.epoch, row.renewalCount], [
    expiresAt.getTime(),
    1,
    0,
  ]);
}

/**
 * Case 6 — the pairing-code TTL security consequence: a DEAD one-time code must not be accepted,
 * and therefore not resurrected, by a slow writer.
 */
async function caseDeadCode(ctx, checks, { label, skewMs, deadByMs }) {
  const reference = await serverNowMs(ctx.client);
  const deviceId = `st-code-${label}`;
  const key = env.makeDeviceKey(`st-code-${label}`);

  await support.seedDevice(ctx, `st-code-${label}`, {
    _id: deviceId,
    key,
    identityState: 'active',
    leaseState: 'never',
    epoch: 0,
  });

  ctx.clock.set(reference);
  const pairing = ctx.pairingService();
  const open = await pairing.mintPairingOpenChallenge({
    tenantId: TENANT,
    deviceId,
    deviceKeyId: ctx.crypto.thumbprintB64u(key.spkiB64u),
  });
  const issue = await pairing.issuePairingSession({
    tenantId: TENANT,
    deviceId,
    deviceKeyId: ctx.crypto.thumbprintB64u(key.spkiB64u),
    domainTag: env.constants.PAIRING_OPEN_DOMAIN,
    requestSource: 'servertime-oracle',
    challengeHash: open.challengeHash,
    proof: support.pairingOpenProof(ctx, {
      deviceId,
      deviceKeyId: ctx.crypto.thumbprintB64u(key.spkiB64u),
      key,
      challengeHash: open.challengeHash,
      issuedAt: open.issuedAt,
    }),
  });
  checks.ok(`${label}: a code is minted at skew 0 (precondition)`, issue.ok === true, {
    errorCode: issue.error ? issue.error.code : null,
  });
  if (issue.ok !== true) {
    return;
  }

  // Kill the code on the DATABASE timeline, then attack it with a slow writer.
  await ctx.models.PairingSession.updateOne(
    { tenantId: TENANT, deviceId },
    { $set: { expiresAt: new Date(reference - deadByMs) } },
  );
  ctx.clock.set(reference + skewMs);

  const redeem = await pairing.redeemPairingCode({
    code: issue.code,
    tenantId: TENANT,
    ownerId: `principal-st-code-${label}`,
  });
  const session = await ctx.models.PairingSession.findOne({ tenantId: TENANT, deviceId }).lean();

  checks.ok(
    `${label}: a code dead by ${deadByMs} ms is REFUSED at writer skew ${skewMs} ms`,
    redeem.ok === false,
    { ok: redeem.ok === true, errorCode: redeem.error ? redeem.error.code : null },
  );
  checks.eq(`${label}: the refusal is the uniform miss`, redeem.error ? redeem.error.code : null, 'INVALID_OR_EXPIRED_CODE');
  checks.eq(`${label}: the dead session was not resurrected`, [session.state, session.pendingOwnerId, session.attemptsUsed], [
    'open',
    null,
    0,
  ]);
}

/**
 * Case 7 — `dislodgeOwnLapsedLease`, the fourth clock-driven lease-state write GM-45 records as
 * "previously missed by everyone". A fast writer must not over-release the caller's OWN live lease.
 */
async function caseDislodgeOwnLive(ctx, checks, { label, skewMs, liveMs }) {
  const reference = await serverNowMs(ctx.client);
  const ownerId = `principal-st-dislodge-${label}`;
  const liveDeviceId = `st-dislodge-live-${label}`;
  const newDeviceId = `st-dislodge-new-${label}`;
  const expiresAt = new Date(reference + liveMs);

  await support.seedDevice(ctx, `st-dislodge-live-${label}`, {
    _id: liveDeviceId,
    key: env.makeDeviceKey(`st-dislodge-live-${label}`),
    identityState: 'active',
    leaseState: 'active',
    epoch: 1,
    ownerId,
    grantId: `st-dislodge-grant-${label}`,
    activatedAt: new Date(expiresAt.getTime() - LEASE_TTL_MS),
    expiresAt,
  });
  await support.seedDevice(ctx, `st-dislodge-new-${label}`, {
    _id: newDeviceId,
    key: env.makeDeviceKey(`st-dislodge-new-${label}`),
    identityState: 'active',
    leaseState: 'never',
    epoch: 0,
  });

  ctx.clock.set(reference + skewMs);
  const authority = ctx.authorityService();
  // The second PC claims for the SAME owner: `uq_owner_active` collides, which is what triggers the
  // own-lapsed dislodge. The live lease must survive it.
  const claim = await authority.claimAuthority({
    deviceId: newDeviceId,
    tenantId: TENANT,
    ownerId,
    expectedEpoch: 0,
    sessionId: `st-dislodge-session-${label}`,
    grantProof: null,
  });
  const liveRow = view(
    await ctx.models.DeviceAuthority.findOne({ _id: liveDeviceId, tenantId: TENANT }).lean(),
  );
  const newRow = view(
    await ctx.models.DeviceAuthority.findOne({ _id: newDeviceId, tenantId: TENANT }).lean(),
  );

  checks.eq(
    `${label}: the caller's own live lease is NOT dislodged by a writer fast by ${skewMs} ms`,
    [liveRow.leaseState, liveRow.epoch],
    ['active', 1],
  );
  checks.eq(`${label}: the second device did not take over the account`, newRow.leaseState, 'never');
  checks.eq(`${label}: the frozen one-device-per-account refusal is returned`, claim.error ? claim.error.code : null, 'ONE_DEVICE_PER_ACCOUNT');
}

/**
 * Case 8 — DEFENCE IN DEPTH (GM-44 rule 3). The skew guard refuses a host clock outside the budget
 * and the lease-state write refuses to proceed; correctness does not depend on it (cases 1-7 pass
 * with no guard at all), but a wildly wrong clock must not write lease state.
 */
async function caseSkewGuard(ctx, checks, { label }) {
  const reference = await serverNowMs(ctx.client);
  const deviceId = `st-guard-${label}`;
  const key = env.makeDeviceKey(`st-guard-${label}`);
  const ownerId = `principal-st-guard-${label}`;
  const expiresAt = new Date(reference + 3600000);

  await support.seedDevice(ctx, `st-guard-${label}`, {
    _id: deviceId,
    key,
    identityState: 'active',
    leaseState: 'active',
    epoch: 1,
    ownerId,
    grantId: `st-guard-grant-${label}`,
    activatedAt: new Date(expiresAt.getTime() - LEASE_TTL_MS),
    expiresAt,
  });

  const measured = await readDatabaseNowMs(ctx.db);
  checks.ok(`${label}: database time is readable without touching a document`, Number.isFinite(measured), {
    deltaMs: Number.isFinite(measured) ? Math.abs(measured - reference) : null,
  });

  // Within budget: the guard passes.
  const within = createClockSkewGuard({ db: ctx.db, hostNow: () => reference + 1000, cacheMs: 0 });
  const withinVerdict = await within.check();
  checks.ok(`${label}: a host clock inside the 5000 ms budget passes`, withinVerdict.ok === true, {
    skewMs: withinVerdict.skewMs,
  });

  // Outside budget: the guard fails closed with the frozen code.
  const beyond = createClockSkewGuard({ db: ctx.db, hostNow: () => reference + 6000, cacheMs: 0 });
  const beyondVerdict = await beyond.check();
  checks.ok(`${label}: a host clock outside the budget fails closed`, beyondVerdict.ok === false, {
    skewMs: beyondVerdict.skewMs,
    errorCode: beyondVerdict.error ? beyondVerdict.error.code : null,
  });
  checks.eq(`${label}: the refusal carries CLOCK_SKEW_EXCEEDED`, beyondVerdict.error ? beyondVerdict.error.code : null, 'CLOCK_SKEW_EXCEEDED');

  // WIRED: a lease-state write refuses to proceed when the guard refuses.
  ctx.clock.set(reference);
  const guarded = ctx.authorityService({
    clockSkewGuard: createClockSkewGuard({ db: ctx.db, hostNow: () => reference + 6000, cacheMs: 0 }),
  });
  const refused = await guarded.claimAuthority({
    deviceId,
    tenantId: TENANT,
    ownerId: `principal-st-guard-other-${label}`,
    expectedEpoch: 1,
    sessionId: `st-guard-session-${label}`,
    grantProof: null,
  });
  const row = view(
    await ctx.models.DeviceAuthority.findOne({ _id: deviceId, tenantId: TENANT }).lean(),
  );
  checks.eq(`${label}: the guarded lease-state write refuses with CLOCK_SKEW_EXCEEDED`, refused.error ? refused.error.code : null, 'CLOCK_SKEW_EXCEEDED');
  checks.eq(`${label}: the guarded write touched no row`, [row.ownerId, row.epoch], [ownerId, 1]);
  checks.eq(`${label}: the refusal is a 503-class self-detected inability to serve`, refused.error ? refused.error.httpStatus : null, 503);

  // And the same write SUCCEEDS once the clock is back inside budget (the guard is not a wall).
  const okGuard = ctx.authorityService({
    clockSkewGuard: createClockSkewGuard({ db: ctx.db, hostNow: () => reference + 1000, cacheMs: 0 }),
  });
  const allowed = await okGuard.claimAuthority({
    deviceId,
    tenantId: TENANT,
    ownerId: `principal-st-guard-other-${label}`,
    expectedEpoch: 1,
    sessionId: `st-guard-session-${label}`,
    grantProof: null,
  });
  checks.eq(`${label}: an in-budget writer is not blocked (the guard is not a wall)`, allowed.matched, 0);
  checks.eq(`${label}: …and it is refused for the correct lease reason instead`, allowed.error ? allowed.error.code : null, 'DEVICE_ALREADY_PAIRED_USE_RENEW');
}

/* ------------------------------------------------------------------ runner */

async function run() {
  const checks = support.makeChecks();
  const results = [];
  const specs = [
    {
      id: 'ST-ADMISSION-AT-BUDGET',
      run: (ctx) =>
        caseAdmission(ctx, checks, {
          label: 'ST-ADMISSION-AT-BUDGET',
          skewMs: 5000,
          liveMs: 4000,
          expectRefused: 'DEVICE_ALREADY_PAIRED_USE_RENEW',
        }),
    },
    {
      id: 'ST-ADMISSION-CONTROL',
      run: (ctx) =>
        caseAdmission(ctx, checks, {
          label: 'ST-ADMISSION-CONTROL',
          skewMs: 0,
          liveMs: 4000,
          expectRefused: 'DEVICE_ALREADY_PAIRED_USE_RENEW',
        }),
    },
    {
      id: 'ST-CLAIM-OVER-RELEASE-FAST',
      run: (ctx) => caseClaimOverRelease(ctx, checks, { label: 'ST-CLAIM-OVER-RELEASE-FAST', skewMs: FAST_MS, liveMs: 1000 }),
    },
    {
      id: 'ST-LAZY-RELEASE-FAST',
      run: (ctx) => caseLazyReleaseOverRelease(ctx, checks, { label: 'ST-LAZY-RELEASE-FAST', skewMs: FAST_MS, liveMs: 1000 }),
    },
    {
      id: 'ST-RENEW-OVER-ACCEPT-SLOW',
      run: (ctx) => caseRenewOverAcceptance(ctx, checks, { label: 'ST-RENEW-OVER-ACCEPT-SLOW', skewMs: SLOW_MS, lifeMs: -1000 }),
    },
    {
      id: 'ST-DEAD-CODE-SLOW',
      run: (ctx) => caseDeadCode(ctx, checks, { label: 'ST-DEAD-CODE-SLOW', skewMs: SLOW_MS, deadByMs: 100000 }),
    },
    {
      id: 'ST-DISLODGE-OWN-LIVE-FAST',
      run: (ctx) => caseDislodgeOwnLive(ctx, checks, { label: 'ST-DISLODGE-OWN-LIVE-FAST', skewMs: FAST_MS, liveMs: 1000 }),
    },
    {
      id: 'ST-SKEW-GUARD-DEFENCE-IN-DEPTH',
      run: (ctx) => caseSkewGuard(ctx, checks, { label: 'ST-SKEW-GUARD-DEFENCE-IN-DEPTH' }),
    },
  ];

  for (const spec of specs) {
    const before = checks.checks.length;
    const ctx = await support.makeContext({
      tag: `st-${spec.id.toLowerCase().replace(/[^a-z0-9]+/g, '_')}`,
      point: spec.id,
      mode: 'raw-registry',
      dropOnTeardown: true,
      /**
       * GM-64.5: this oracle exists to prove that lease and TTL decisions do NOT read the
       * writer's clock. `support.makeContext` defaults to `predicateAnchor: 'clock'` (the
       * injected writer clock) so that time-travelling fixtures can place a boundary anywhere on
       * the timeline — but that default would make every case here compare against the very clock
       * under test, silently voiding the result. The oracle must therefore run in DATABASE mode:
       * no anchor seam at all, so the production `$$NOW` / server-clock path is what executes.
       */
      predicateAnchor: 'database',
    });
    let error = null;
    try {
      await spec.run(ctx);
    } catch (err) {
      error = `${err.name}: ${err.message}`;
      checks.fail(`${spec.id}: the case ran to completion`, error);
    } finally {
      await ctx.teardown().catch(() => {});
    }
    const slice = checks.checks.slice(before);
    results.push({
      id: spec.id,
      error,
      passed: slice.filter((entry) => entry.ok).length,
      failed: slice.filter((entry) => !entry.ok).length,
      checks: slice,
    });
  }

  const status = support.statusFromChecks(checks.checks);
  const report = {
    check: 'SERVER-TIME-LEASE-TTL',
    tier: 'E2',
    kind: 'product-oracle',
    runnerPid: process.pid,
    command: 'node tests/device/servertime/run-servertime.cjs',
    status: status.status,
    exitCode: status.status === 'PASS' ? 0 : 5,
    counts: {
      cases: results.length,
      passed: status.passedCount,
      failed: status.failedCount,
    },
    failedAssertions: status.failedAssertions,
    results,
    constants: { LEASE_TTL_MS, SKEW_MARGIN_MS, FAST_MS, SLOW_MS },
    provenance: {
      referenceTimeline: 'MongoDB `hello.localTime` (server), never this process clock',
      productPath:
        'Real createAuthorityService / createPairingSessionService over the frozen createModels(mongoose) registry; no stub, no facade behaviour, no retry.',
      whyDbAnchored:
        'The pre-existing fixtures pin an ABSOLUTE past epoch, which is incompatible with database-time predicates: a row minted at that epoch is already dead in database time.',
      secrets: 'No pairing code, private key, pepper or signature is recorded.',
    },
    finishedAt: new Date().toISOString(),
  };

  const options = parseArgs(process.argv.slice(2));
  if (options['evidence-dir']) {
    const dir = path.isAbsolute(options['evidence-dir'])
      ? options['evidence-dir']
      : path.join(support.WORKTREE ?? path.resolve(__dirname, '..', '..', '..'), options['evidence-dir']);
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, 'SERVER-TIME-RESULTS.json');
    fs.writeFileSync(file, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
    report.evidenceFile = file;
  }
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  return report;
}

run().then(
  (report) => {
    process.exitCode = report.exitCode;
  },
  (err) => {
    process.stdout.write(
      `${JSON.stringify({ check: 'SERVER-TIME-LEASE-TTL', status: 'HARNESS_FAIL', error: `${err.name}: ${err.message}` })}\n`,
    );
    process.exitCode = 4;
  },
);
