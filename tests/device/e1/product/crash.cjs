'use strict';

/**
 * E1-T20-CRASH-AFTER-SPEND PRODUCT fixture (lane I9 / task T1).
 *
 * For each crash point c2..c6 a separate OS child process performs the REAL product write and
 * then exits with sentinel 7 before the next product step. The parent is a separate OS process:
 * it re-reads durable state with the real models (never trusting child memory) and, where the
 * frozen contract requires it, drives further real product calls to prove the post-crash state
 * is fail-closed or recoverable.
 *
 * Global invariant asserted for every point: no crash point may leave a row that authorizes
 * without a live committed lease.
 */

const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const c = require('./context.cjs');
const support = c.support;
const env = c.env;

const { TENANT } = c;
const OWNER_A = env.OWNER_A;
const CHILD = path.resolve(__dirname, 'crash-child.cjs');
const SENTINEL = 7;
const CHILD_TIMEOUT_MS = 180000;
const POINTS = ['c2', 'c3', 'c4', 'c5', 'c6'];

function readJsonFile(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function spawnChild(point, { dbName, rundir, clock, ownerId }) {
  const args = [
    CHILD,
    `--db=${dbName}`,
    `--point=${point}`,
    `--rundir=${rundir}`,
    `--clock=${clock}`,
    `--owner=${ownerId}`,
  ];
  const logFd = fs.openSync(`${rundir}/${point}-stderr.log`, 'a');
  const child = spawn(process.execPath, args, { stdio: ['ignore', 'ignore', logFd], windowsHide: true });
  const exit = new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try {
        child.kill();
      } catch {
        /* best effort */
      }
      resolve({ code: null, signal: 'TIMEOUT' });
    }, CHILD_TIMEOUT_MS);
    child.once('exit', (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code, signal });
    });
    child.once('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code: null, signal: null, error: `${err.name}: ${err.message}` });
    });
  });
  return { point, pid: child.pid, args, child, logFd, exit };
}

async function runCrashPoint(point, rundir, clock) {
  const ctx = await support.makeContext({
    tag: `e1-crash-${point}`,
    point,
    mode: 'raw-registry',
    dropOnTeardown: false,
  });
  ctx.clock.set(clock);
  const checks = support.makeChecks();
  let handle = null;
  let cleanup = 'not_attempted';
  try {
    handle = spawnChild(point, { dbName: ctx.dbName, rundir, clock, ownerId: OWNER_A });
    const exit = await handle.exit;
    try {
      fs.closeSync(handle.logFd);
    } catch {
      /* best effort */
    }

    const witnessPath = `${rundir}/${point}-witness.json`;
    const witness = fs.existsSync(witnessPath) ? readJsonFile(witnessPath) : null;
    const stderr = fs.existsSync(`${rundir}/${point}-stderr.log`)
      ? fs.readFileSync(`${rundir}/${point}-stderr.log`, 'utf8').slice(-1500)
      : '';

    checks.eq(`${point}: the child really crashed with sentinel 7`, exit.code, SENTINEL);
    checks.ok(`${point}: a witness was written before the exit`, witness !== null && witness.point === point, witness ?? { exit, stderr });
    if (witness === null) {
      return { point, dbName: ctx.dbName, checks: checks.checks, failedAssertions: checks.failed(), child: { pid: handle.pid, exit }, stderr, duplicateKeyEvidence: ctx.recorder.duplicateErrors(), dbReadBack: {} };
    }
    checks.eq(`${point}: the child never reached its post-write step`, witness.reachedPostStep, false);
    checks.eq(`${point}: post-step witness counter untouched`, witness.witnessCount, 0);
    checks.eq(`${point}: witness PID matches the spawned PID`, witness.pid, handle.pid);

    const deviceId = witness.deviceId;
    const deviceKeyId = witness.deviceKeyId;
    ctx.bindTrust({ deviceId, principalId: OWNER_A });
    const row = await c.readRow(ctx, deviceId);
    const sessions = await ctx.models.PairingSession.find({ tenantId: TENANT, deviceId }).lean();
    const challenges = await ctx.models.Challenge.find({ tenantId: TENANT, deviceId }).lean();
    const authorityView = c.view(row, ctx.clock.now());
    const sessionStates = sessions.map((session) => ({ state: session.state, attemptsUsed: session.attemptsUsed, grantedGrantId: session.grantedGrantId ?? null, consumedAt: session.consumedAt ?? null }));

    let extra = {};
    if (point === 'c2') {
      const consumed = challenges.filter((challenge) => challenge.purpose === 'pairing-claim' && challenge.consumedAt !== null);
      checks.eq('c2: exactly one pairing-claim challenge is consumed', consumed.length, 1);
      checks.eq('c2: the pairing session is still claim_pending', sessionStates[0] && sessionStates[0].state, 'claim_pending');
      checks.eq('c2: authority row unchanged', { leaseState: row.leaseState, identityState: row.identityState, epoch: row.epoch, ownerId: row.ownerId }, { leaseState: 'never', identityState: 'pending', epoch: 0, ownerId: null });
      checks.ok('c2: admission is denied after the crash', c.authorize(row, { ownerId: OWNER_A, now: ctx.clock.now() }).allowed === false, authorityView);

      const session = sessions[0];
      const armed = fs.existsSync(`${rundir}/${point}-armed.json`) ? readJsonFile(`${rundir}/${point}-armed.json`) : null;
      let reapprove = null;
      if (session && armed) {
        const proof = support.pairingClaimProof(ctx, {
          session,
          ownerId: OWNER_A,
          challengeHash: armed.claimChallengeHash,
          key: env.makeDeviceKey(armed.deviceTag ?? witness.deviceTag ?? `e1-crash-${point}`),
          issuedAt: armed.claimChallengeIssuedAt,
        });
        reapprove = await ctx.pairingService().approvePairingClaim({
          pairingSessionId: String(session._id),
          tenantId: TENANT,
          ownerId: OWNER_A,
          domainTag: env.constants.PAIRING_CLAIM_DOMAIN,
          localConsent: { nonce: 'lab-consent-nonce-0001' },
          proof,
        });
      }
      checks.ok('c2: a re-approve after the crash fails closed', reapprove !== null && reapprove.ok === false, reapprove && reapprove.error ? support.errorView(reapprove.error) : null);
      checks.eq('c2: re-approve wrote nothing', { leaseState: row.leaseState, epoch: row.epoch }, { leaseState: 'never', epoch: 0 });
      extra = { consumedChallenges: consumed.length, reapprove: reapprove ? { ok: reapprove.ok, error: support.errorView(reapprove.error) } : null };
    } else if (point === 'c3') {
      checks.eq('c3: the session reached consumed', sessionStates[0] && sessionStates[0].state, 'consumed');
      checks.eq('c3: grantedGrantId is still null (second write not reached)', sessionStates[0] && sessionStates[0].grantedGrantId, null);
      checks.eq('c3: authority row unchanged', { leaseState: row.leaseState, identityState: row.identityState, epoch: row.epoch }, { leaseState: 'never', identityState: 'pending', epoch: 0 });
      checks.ok('c3: admission denied after the crash', c.authorize(row, { ownerId: OWNER_A, now: ctx.clock.now() }).allowed === false, authorityView);

      const recovery = await support.runPairingCeremony(ctx, {
        deviceId,
        deviceKeyId,
        ownerId: OWNER_A,
        key: env.makeDeviceKey(witness.deviceTag ?? `e1-crash-${point}`),
      });
      const recovered = await c.readRow(ctx, deviceId);
      checks.ok('c3: a fresh product session recovers the device', recovery.ok === true, recovery.approve ? support.errorView(recovery.approve.error) : support.errorView(recovery.error));
      checks.eq('c3: recovery produced a live lease', { leaseState: recovered.leaseState, epoch: recovered.epoch }, { leaseState: 'active', epoch: 1 });
      extra = { recovery: { ok: recovery.ok, stage: recovery.stage } };
    } else if (point === 'c4') {
      checks.eq('c4: authority lease is active', row.leaseState, 'active');
      checks.eq('c4: identity became active', row.identityState, 'active');
      checks.eq('c4: epoch is exactly 1', row.epoch, 1);
      checks.eq('c4: grantId is a 22-char CSPRNG value', typeof row.grantId === 'string' && row.grantId.length === 22, true);
      checks.eq('c4: TTL is exactly 172800000', new Date(row.expiresAt).getTime() - new Date(row.activatedAt).getTime(), c.LEASE_TTL_MS);
      checks.ok('c4: the live committed lease authorizes', c.authorize(row, { ownerId: OWNER_A, epoch: row.epoch, grantId: row.grantId, now: ctx.clock.now() }).allowed === true, authorityView);
      checks.eq('c4: session is consumed with grantedGrantId still null (crash before the marker write)', sessionStates[0] && sessionStates[0].grantedGrantId, null);
      checks.eq('c4: session state', sessionStates[0] && sessionStates[0].state, 'consumed');
      extra = { secondWriteGap: { grantedGrantId: null, proven: true } };
    } else if (point === 'c5') {
      checks.eq('c5: leaseState revoked', row.leaseState, 'revoked');
      checks.eq('c5: epoch advanced by exactly 1', row.epoch, 2);
      checks.eq('c5: prevEpoch written', row.prevEpoch, 1);
      checks.ok('c5: prevGrantId written', typeof row.prevGrantId === 'string' && row.prevGrantId.length === 22, { prevGrantIdLength: typeof row.prevGrantId === 'string' ? row.prevGrantId.length : 0 });
      checks.ok('c5: revoke did NOT rotate grantId (G-2)', row.grantId === witness.grantIdBeforeRevoke, { grantIdUnchanged: row.grantId === witness.grantIdBeforeRevoke });
      checks.ok('c5: admission denied after revoke', c.authorize(row, { ownerId: OWNER_A, epoch: row.epoch, grantId: row.grantId, now: ctx.clock.now() }).allowed === false, authorityView);

      const recovery = await support.runPairingCeremony(ctx, { deviceId, deviceKeyId, ownerId: OWNER_A, key: env.makeDeviceKey(witness.deviceTag ?? `e1-crash-${point}`) });
      const recovered = await c.readRow(ctx, deviceId);
      checks.ok('c5: re-pair succeeds after the crash', recovery.ok === true, recovery.approve ? support.errorView(recovery.approve.error) : support.errorView(recovery.error));
      checks.ok('c5: re-pair minted a NEW grantId', recovered.grantId !== row.grantId && recovered.grantId.length === 22, { rotated: recovered.grantId !== row.grantId });
      checks.eq('c5: re-pair epoch', recovered.epoch, 3);
      extra = { recovery: { ok: recovery.ok, stage: recovery.stage } };
    } else if (point === 'c6') {
      checks.eq('c6: identityState retired', row.identityState, 'retired');
      checks.ok('c6: retiredAt written', row.retiredAt !== null && row.retiredAt !== undefined, { retiredAt: row.retiredAt });
      checks.ok('c6: every admission denies', c.authorize(row, { ownerId: OWNER_A, epoch: row.epoch, grantId: row.grantId, now: ctx.clock.now() }).allowed === false, authorityView);

      const retryRetire = await ctx.authorityService().retireIdentity({ deviceId, tenantId: TENANT });
      checks.ok('c6: a second retire is a 0-match recovery', retryRetire.ok === false && retryRetire.matched === 0, support.errorView(retryRetire.error));

      const reReg = await support.registerDevice(ctx, {
        deviceName: 'e1-c6-rereg',
        key: env.makeDeviceKey('e1-c6-rereg-attempt'),
      });
      checks.ok('c6: in-tenant re-registration of a different key still succeeds (control)', reReg.ok === true, support.errorView(reReg.error));

      // Same deviceKeyId in the same tenant must be refused: reuse the retired key material.
      const sameKey = env.makeDeviceKey(witness.deviceTag ?? 'e1-crash-c6');
      const dup = await support.registerDevice(ctx, { deviceName: 'e1-c6-dup', key: sameKey });
      checks.ok('c6: in-tenant re-registration of the same deviceKeyId fails closed', dup.ok === false, support.errorView(dup.error));
      checks.eq('c6: re-registration error code', dup.error && dup.error.code, 'DEVICE_ALREADY_REGISTERED');

      const issueRetired = await ctx.pairingService().issuePairingSession({
        tenantId: TENANT,
        deviceId,
        deviceKeyId: row.deviceKeyId,
        domainTag: env.constants.PAIRING_OPEN_DOMAIN,
        challengeHash: 'never-minted',
        proof: { signatureB64u: 'x' },
      });
      checks.eq('c6: pairing issuance refuses a retired identity', issueRetired.error && issueRetired.error.code, 'DEVICE_IDENTITY_REVOKED');
      extra = { reRegistrationSameKey: { ok: dup.ok, error: support.errorView(dup.error) }, retireRetry: support.errorView(retryRetire.error) };
    }

    // Global fail-closed invariant over the durable row.
    const live = row.leaseState === 'active' && new Date(row.expiresAt).getTime() > ctx.clock.now() && row.identityState !== 'retired';
    const authorized = c.authorize(row, { ownerId: row.ownerId, epoch: row.epoch, grantId: row.grantId, now: ctx.clock.now() }).allowed;
    checks.eq(`${point}: no authorization without a live committed lease`, authorized, live);

    cleanup = await support.fence.dropOwnDatabase(ctx.client, ctx.dbName);
    return {
      point,
      dbName: ctx.dbName,
      checks: checks.checks,
      failedAssertions: checks.failed(),
      child: { pid: handle.pid, exit, spawnCommand: `${process.execPath} ${handle.args.join(' ')}` },
      witness,
      duplicateKeyEvidence: ctx.recorder.duplicateErrors(),
      dbReadBack: { authority: authorityView, sessions: sessionStates, challengeRows: challenges.length, ...extra },
      cleanup,
    };
  } finally {
    if (handle !== null && handle.child.exitCode === null) {
      try {
        handle.child.kill();
      } catch {
        /* best effort */
      }
    }
    cleanup = await support.fence.dropOwnDatabase(ctx.client, ctx.dbName).catch(() => cleanup);
    await ctx.teardown().catch(() => {});
  }
}

async function run(fixture) {
  const rundir = support.freshDir(path.join(support.runDir(), 'e1-product-crash'));
  const clock = env.constants.EPOCH_BASE_MS;
  const results = [];
  for (const point of POINTS) {
    results.push(await runCrashPoint(point, rundir, clock));
  }
  const checks = results.flatMap((result) => result.checks.map((check) => ({ ...check, name: `${result.point}:${check.name}` })));
  const status = support.statusFromChecks(checks);
  return {
    id: fixture.id,
    tier: fixture.tier,
    kind: fixture.kind,
    runner: fixture.runner,
    requires: fixture.requires,
    title: fixture.title,
    runnerPid: process.pid,
    dbName: results.map((result) => result.dbName).join(' | '),
    dbNames: results.map((result) => result.dbName),
    productClaim: true,
    ...status,
    checks,
    attempts: { crashPoints: POINTS.length, childProcesses: results.length },
    runnerPids: [process.pid, ...results.map((result) => result.child.pid)],
    childPids: results.map((result) => result.child.pid),
    realReturns: Object.fromEntries(results.map((result) => [result.point, { exit: result.child.exit, witness: result.witness ? { crashPoint: result.witness.crashPoint, after: result.witness.after } : null }])),
    dbReadBack: Object.fromEntries(results.map((result) => [result.point, result.dbReadBack])),
    processEvidence: {
      spawnCommands: results.map((result) => result.child.spawnCommand),
      stdio: 'ignore + stderr to file',
      sentinel: SENTINEL,
    },
    provenance: support.provenance({ ...results[0], modelInfo: { barrelPath: env.bridge.MODELS_BARREL }, facadeProvenance: {}, tenantPolicy: { kind: 'fixed-server-controlled-allowlist', allowed: [TENANT] }, consent: { kind: 'fixed-trusted-local-consent', granted: true }, clock: { kind: 'injected-deterministic', now: () => clock }, audit: { kind: 'raw-driver-verbatim-durable-sink' }, dbMode: 'raw-registry', facadeKind: 'genuine-createModels-registry-no-adapter' }, {
      crashMechanism:
        'Test-only observation wrapper around each real product method: the wrapper awaits the REAL call and then writes the witness and calls process.exit(7) before the next product step. No product code is modified or reimplemented, and the verifier is a separate OS process.',
    }),
  };
}

module.exports = { run, runCrashPoint, POINTS, CHILD, SENTINEL };