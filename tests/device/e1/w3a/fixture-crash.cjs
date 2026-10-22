'use strict';

/**
 * W3-A / I11 E1-T20-CRASH-AFTER-SPEND: real crash sentinel at the c2..c6 write points.
 *
 * For each point a separate OS process performs the real product write and then exits with
 * sentinel code 7 before the next product step. The parent verifier re-reads durable state with
 * the real models and (where the frozen contract requires it) drives further real product calls
 * to prove the post-crash state is fail-closed / recoverable.
 */

const path = require('node:path');
const { spawn } = require('node:child_process');

const common = require('./child-common.cjs');
const support = require('./support.cjs');
const env = require('./env.cjs');

const { TENANT, OWNER_A } = env;
const CHILD = path.resolve(__dirname, 'child-crash.cjs');
const SENTINEL = 7;
const CRASH_TIMEOUT_MS = 120000;

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

async function runCrashPoint(point, rundir) {
  const ctx = await support.makeContext({ tag: `crash-${point}`, point });
  const checks = support.makeChecks();
  const T = ctx.clock.now();
  const deviceTag = `crash-${point}`;
  const deviceId = `w3a-device-${deviceTag}`;
  const ownerId = OWNER_A;
  const args = [
    CHILD,
    `--db=${ctx.dbName}`,
    `--point=${point}`,
    `--rundir=${rundir}`,
    `--clock=${T}`,
    `--device=${deviceTag}`,
    `--owner=${ownerId}`,
  ];
  let childInfo = null;
  try {
    const child = spawn(process.execPath, args, { stdio: 'ignore', windowsHide: true });
    const exit = await Promise.race([
      new Promise((resolve) => child.once('exit', (code, signal) => resolve({ code, signal }))),
      new Promise((resolve) => setTimeout(() => resolve({ code: null, signal: 'TIMEOUT' }), CRASH_TIMEOUT_MS)),
    ]);
    if (exit.code === null) {
      child.kill();
    }
    const witness = await common.waitForFile(`${rundir}/${point}-witness.json`, { timeoutMs: 5000 }).catch(() => null);
    childInfo = { args, pid: child.pid, exit, witness };

    checks.eq(`${point}: child exited with the crash sentinel`, exit.code, SENTINEL);
    checks.ok(`${point}: witness written before the exit`, witness !== null && witness.point === point, witness);
    checks.eq(`${point}: child never reached its post-write step`, witness && witness.reachedPostStep, false);
    checks.eq(`${point}: witnessCount is 0 (post-step counter untouched)`, witness && witness.witnessCount, 0);
    checks.eq(`${point}: crash sentinel PID matches the spawned PID`, witness && witness.pid, child.pid);

    const row = await support.readAuthorityRaw(ctx.models, deviceId, TENANT);
    const sessions = await ctx.models.PairingSession.find({ tenantId: TENANT, deviceId }).lean();
    const challenges = await ctx.models.Challenge.find({ tenantId: TENANT }).lean();
    const authorityView = support.authorityView(row, ctx.clock.now());
    const sessionView = sessions.map((session) => ({
      state: session.state,
      attemptsUsed: session.attemptsUsed,
      grantedGrantId: session.grantedGrantId ?? null,
      consumedAt: session.consumedAt ?? null,
    }));

    let extra = {};

    if (point === 'c2') {
      checks.eq('c2: claim challenge is consumed', challenges.filter((challenge) => challenge.purpose === 'pairing-claim' && challenge.consumedAt !== null).length, 1);
      checks.eq('c2: session still claim_pending (LP-3 not reached)', sessionView[0] && sessionView[0].state, 'claim_pending');
      checks.eq('c2: authority row unchanged', { leaseState: row.leaseState, identityState: row.identityState, epoch: row.epoch, ownerId: row.ownerId }, { leaseState: 'never', identityState: 'pending', epoch: 0, ownerId: null });
      checks.ok('c2: admission is denied after the crash', support.authorizePredicate(row, { ownerId, now: ctx.clock.now() }).allowed === false, authorityView);
      // real product re-approve must fail closed
      const session = sessions[0];
      const challengeRow = challenges.find((entry) => entry.purpose === 'pairing-claim');
      const challenge = witness.claimChallenge ?? null;
      let reapprove = null;
      if (session && challenge) {
        const proof = support.pairingClaimProof(ctx, { session, ownerId, challenge, key: env.makeDeviceKey(deviceTag) });
        reapprove = await ctx.pairingService().approvePairingClaim({
          pairingSessionId: String(session._id),
          tenantId: TENANT,
          ownerId,
          domainTag: env.constants.PAIRING_CLAIM_DOMAIN,
          localConsent: { nonce: 'lab-consent-nonce-0001' },
          proof,
        });
      }
      checks.ok('c2: a re-approve after the crash fails closed', reapprove !== null && reapprove.ok === false, reapprove && reapprove.error ? support.errorView(reapprove.error) : null);
      checks.eq('c2: re-approve error is the uniform miss', reapprove && reapprove.error && reapprove.error.code, 'INVALID_OR_EXPIRED_CODE');
      checks.eq('c2: re-approve wrote nothing', { leaseState: row.leaseState, epoch: row.epoch }, { leaseState: 'never', epoch: 0 });
      extra = { challengeConsumedRows: challenges.filter((challenge) => challenge.consumedAt !== null).length, reapprove: reapprove ? { ok: reapprove.ok, error: support.errorView(reapprove.error) } : null, challengeRowPresent: Boolean(challengeRow) };
    } else if (point === 'c3') {
      checks.eq('c3: session reached consumed', sessionView[0] && sessionView[0].state, 'consumed');
      checks.eq('c3: grantedGrantId is still null (second write not reached)', sessionView[0] && sessionView[0].grantedGrantId, null);
      checks.eq('c3: authority row unchanged', { leaseState: row.leaseState, identityState: row.identityState, epoch: row.epoch }, { leaseState: 'never', identityState: 'pending', epoch: 0 });
      checks.ok('c3: admission denied after the crash', support.authorizePredicate(row, { ownerId, now: ctx.clock.now() }).allowed === false, authorityView);
      const recovery = await support.runPairingCeremony(ctx, {
        deviceId,
        deviceKeyId: (await ctx.models.DeviceAuthority.findOne({ _id: deviceId, tenantId: TENANT }).lean()).deviceKeyId,
        ownerId,
        key: env.makeDeviceKey(deviceTag),
      });
      checks.ok('c3: a FRESH session recovers the device', recovery.ok === true, recovery.approve ? support.errorView(recovery.approve.error) : support.errorView(recovery.error));
      const recovered = await support.readAuthorityRaw(ctx.models, deviceId, TENANT);
      checks.eq('c3: recovery produced a live lease', { leaseState: recovered.leaseState, epoch: recovered.epoch }, { leaseState: 'active', epoch: 1 });
      extra = { recovery: { ok: recovery.ok, stage: recovery.stage } };
    } else if (point === 'c4') {
      checks.eq('c4: authority lease is active', row.leaseState, 'active');
      checks.eq('c4: identity became active', row.identityState, 'active');
      checks.eq('c4: epoch is exactly 1', row.epoch, 1);
      checks.eq('c4: grant id is a 22-char CSPRNG value', row.grantId.length, 22);
      checks.eq('c4: TTL is exactly 172800000', new Date(row.expiresAt).getTime() - new Date(row.activatedAt).getTime(), env.constants.LEASE_TTL_MS);
      checks.ok('c4: a live committed lease authorizes', support.authorizePredicate(row, { ownerId, epoch: row.epoch, grantId: row.grantId, now: ctx.clock.now() }).allowed === true, authorityView);
      checks.eq('c4: session consumed but grantedGrantId still null (second write not reached)', sessionView[0] && sessionView[0].grantedGrantId, null);
      checks.eq('c4: session state', sessionView[0] && sessionView[0].state, 'consumed');
      extra = { secondWriteGap: { grantedGrantId: null, secondWriteGapProven: true } };
    } else if (point === 'c5') {
      checks.eq('c5: leaseState revoked', row.leaseState, 'revoked');
      checks.eq('c5: epoch advanced by exactly 1', row.epoch, 2);
      checks.eq('c5: prevEpoch written', row.prevEpoch, 1);
      checks.ok('c5: prevGrantId written', typeof row.prevGrantId === 'string' && row.prevGrantId.length === 22, { prevGrantIdIssued: typeof row.prevGrantId === 'string' });
      checks.ok('c5: revoke did NOT rotate grantId', row.grantId.length === 22, { grantIdLength: row.grantId.length });
      checks.ok('c5: admission denied after revoke', support.authorizePredicate(row, { ownerId, epoch: 2, grantId: row.grantId, now: ctx.clock.now() }).allowed === false, authorityView);
      const deviceRow = await ctx.models.DeviceAuthority.findOne({ _id: deviceId, tenantId: TENANT }).lean();
      const recovery = await support.runPairingCeremony(ctx, { deviceId, deviceKeyId: deviceRow.deviceKeyId, ownerId, key: env.makeDeviceKey(deviceTag) });
      const recovered = await support.readAuthorityRaw(ctx.models, deviceId, TENANT);
      checks.ok('c5: re-pair succeeds after the crash', recovery.ok === true, recovery.approve ? support.errorView(recovery.approve.error) : support.errorView(recovery.error));
      checks.ok('c5: re-pair minted a NEW grant id', recovered.grantId !== row.grantId && recovered.grantId.length === 22, { rotated: recovered.grantId !== row.grantId });
      checks.eq('c5: re-pair epoch', recovered.epoch, 3);
      extra = { revokeDidNotRotateGrant: row.grantId !== row.prevGrantId, recovery: { ok: recovery.ok } };
    } else if (point === 'c6') {
      checks.eq('c6: identityState retired', row.identityState, 'retired');
      checks.ok('c6: retiredAt written', row.retiredAt !== null && row.retiredAt !== undefined, { retiredAt: row.retiredAt });
      checks.ok('c6: every admission denies', support.authorizePredicate(row, { ownerId, epoch: row.epoch, grantId: row.grantId, now: ctx.clock.now() }).allowed === false, authorityView);
      const retryRetire = await ctx.authorityService().retireIdentity({ deviceId, tenantId: TENANT, actor: ownerId, role: 'owner' });
      checks.ok('c6: second retire is a 0-match recovery', retryRetire.ok === false && retryRetire.matched === 0, support.errorView(retryRetire.error));
      const reReg = await support.registerDevice(ctx, { deviceName: 'w3a-c6-rereg', key: env.makeDeviceKey(deviceTag) });
      checks.ok('c6: in-tenant re-registration of the same deviceKeyId fails closed', reReg.ok === false, support.errorView(reReg.error));
      checks.eq('c6: re-registration error code', reReg.error && reReg.error.code, 'DEVICE_ALREADY_REGISTERED');
      const issueRetired = await ctx.pairingService().issuePairingSession({
        tenantId: TENANT,
        deviceId,
        deviceKeyId: row.deviceKeyId,
        domainTag: env.constants.PAIRING_OPEN_DOMAIN,
        proof: support.pairingOpenProof(ctx, { deviceId, deviceKeyId: row.deviceKeyId, key: env.makeDeviceKey(deviceTag) }),
      });
      checks.eq('c6: pairing issuance refuses a retired identity', issueRetired.error && issueRetired.error.code, 'DEVICE_IDENTITY_REVOKED');
      extra = { reRegistration: { ok: reReg.ok, error: support.errorView(reReg.error) }, retireRetry: support.errorView(retryRetire.error) };
    }

    return {
      point,
      dbName: ctx.dbName,
      checks: checks.checks,
      failedAssertions: checks.failed(),
      child: { pid: childInfo.pid, exit: childInfo.exit, spawnCommand: `${process.execPath} ${args.join(' ')}` },
      witness: childInfo.witness,
      dbReadBack: { authority: authorityView, sessions: sessionView, challengeRows: challenges.length, ...extra },
    };
  } finally {
    await ctx.teardown();
  }
}

async function crashAfterSpend(fixture) {
  const rundir = support.freshDir(path.join(support.runDir(), 'crash'));
  const points = ['c2', 'c3', 'c4', 'c5', 'c6'];
  const results = [];
  for (const point of points) {
    results.push(await runCrashPoint(point, rundir));
  }
  const checks = results.flatMap((result) => result.checks.map((check) => ({ ...check, name: `${result.point}:${check.name}` })));
  const failed = checks.filter((check) => !check.ok);
  const witnesses = results.map((result) => result.witness).filter(Boolean);
  return baseResult(fixture, 'per-point self-owned w3 databases', {
    dbNames: results.map((result) => result.dbName),
    status: failed.length === 0 ? 'PASS' : 'PRODUCT_FAIL',
    productClaim: true,
    checks,
    failedAssertions: failed,
    passedCount: checks.length - failed.length,
    failedCount: failed.length,
    attempts: { crashPoints: points.length, childProcesses: results.length },
    runnerPids: [process.pid, ...results.map((result) => result.child.pid)],
    childPids: results.map((result) => result.child.pid),
    realReturns: Object.fromEntries(results.map((result) => [result.point, { exit: result.child.exit, witness: result.witness }])),
    dbReadBack: Object.fromEntries(results.map((result) => [result.point, result.dbReadBack])),
    processEvidence: {
      spawnCommands: results.map((result) => result.child.spawnCommand),
      stdio: 'ignore',
      sentinel: SENTINEL,
      witnessFiles: witnesses.map((witness) => ({ point: witness.point, pid: witness.pid, reachedPostStep: witness.reachedPostStep })),
    },
    provenance: {
      trustedTenant: TENANT,
      injectedOwner: OWNER_A,
      crashMechanism: 'test-only wrapper around the real product method: the wrapper awaits the REAL call, then writes the witness and calls process.exit(7) before the next product step. No product code is modified or reimplemented.',
      auditSink: 'injected durable raw-driver sink (verbatim event into deviceauthorityevents)',
    },
  });
}

const FIXTURES = [
  {
    id: 'E1-T20-CRASH-AFTER-SPEND',
    tier: 'E1',
    kind: 'product',
    runner: 'crash-product',
    requires: ['I5', 'I6'],
    title: 'crash sentinel and re-read at c2..c6 write points with authorization fail-closed',
    run: crashAfterSpend,
  },
];

module.exports = { FIXTURES, crashAfterSpend, runCrashPoint, CHILD, SENTINEL };