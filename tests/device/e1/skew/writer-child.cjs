'use strict';

/**
 * One Mongo-side writer process with an INJECTED CLOCK OFFSET (test-only, new file).
 *
 *   node writer-child.cjs --role=CORRECT --offset=0        --db=<w3 db> --clock=<ms> \
 *        --plan=<plan.json> --barrier=<dir> --out=<file> [--timeoutMs=60000]
 *
 * The process is a real, independent OS process. Its only clock is the injected deterministic
 * clock frozen at `--clock + --offset`; nothing in this file reads the wall clock for a decision
 * (`Date.now()` appears only in barrier/timeout bookkeeping, never in a CAS, a proof or an
 * assertion).
 *
 * Protocol (file transport only; piped child stdio is EPERM in this sandbox):
 *   1. connect, build the REAL product services over the REAL frozen models,
 *   2. publish `ready-<role>.json` (pid + writer-local clock),
 *   3. await `go-<role>.json`,
 *   4. execute every probe in the shared plan through product bytes only,
 *   5. publish `out-<role>.json`.
 *
 * Secrets: a minted pairing code is never written anywhere. Only `codeIssued: boolean` and
 * `codeShape` (a digit-count) are recorded. Signatures are reduced to `{present, issuedAt}`.
 */

const fs = require('node:fs');
const path = require('node:path');

const support = require('../w3a/support.cjs');
const env = require('../w3a/env.cjs');

const TENANT = env.TENANT;

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
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  fs.renameSync(tmp, file);
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

async function waitForFile(file, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fs.existsSync(file)) {
      try {
        return readJson(file);
      } catch {
        /* the peer may still be publishing: retry until it parses */
      }
    }
    // eslint-disable-next-line no-await-in-loop
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`BARRIER_TIMEOUT waiting for ${file}`);
}

/** Public projection of an authority row (no secrets; ISO times plus raw ms). */
function rowView(row) {
  if (row === null || row === undefined) return null;
  const view = support.authorityView(row, null);
  return {
    ...view,
    expiresAtMs: row.expiresAt ? new Date(row.expiresAt).getTime() : null,
    activatedAtMs: row.activatedAt ? new Date(row.activatedAt).getTime() : null,
    identityState: row.identityState ?? null,
  };
}

/** Reduces a probe argument object to a secret-free, JSON-stable record. */
function redactArgs(args) {
  const out = {};
  for (const [key, value] of Object.entries(args ?? {})) {
    if (key === 'proof' || key === 'proofInput' || key === 'localConsent' || key === 'grantProof') {
      out[key] =
        value === null || value === undefined
          ? null
          : {
              present: true,
              issuedAt: value.issuedAt ?? null,
              domainTag: value.domainTag ?? null,
              signaturePresent: typeof value.signatureB64u === 'string',
              noncePresent: typeof value.nonce === 'string',
            };
      continue;
    }
    out[key] = value;
  }
  return out;
}

function envelopeView(result) {
  if (result === null || typeof result !== 'object') return { ok: null, matched: null, errorCode: null };
  return {
    ok: result.ok === true,
    matched: typeof result.matched === 'number' ? result.matched : null,
    errorCode: result.error ? result.error.code : null,
    errorMessage: result.error ? result.error.message : null,
    errorRetryable: result.error ? result.error.retryable ?? null : null,
  };
}

/**
 * Test-only observation wrapper: delegates every call to the real service and records the
 * envelope. It adds no behaviour, no retry and no fallback.
 */
function observeService(service, calls) {
  const wrapped = {};
  for (const name of Object.keys(service)) {
    const fn = service[name];
    if (typeof fn !== 'function') {
      wrapped[name] = fn;
      continue;
    }
    wrapped[name] = async (args) => {
      const result = await fn(args);
      calls.push({
        action: name,
        args: redactArgs(args),
        ...envelopeView(result),
        claimFilter: result && typeof result === 'object' ? result.claimFilter ?? null : null,
      });
      return result;
    };
  }
  return wrapped;
}

/**
 * The deviceauthorities write records one probe actually issued (exact filters + outcomes).
 * Only writes committed while the probe ran are returned; re-reads register no writes.
 */
function authorityWritesSince(recorder, seqStart) {
  return recorder.entries
    .filter((entry) => entry.model === 'DeviceAuthority' && entry.method === 'updateOne' && entry.seq >= seqStart)
    .map((entry) => ({
      seq: entry.seq,
      model: entry.model,
      method: entry.method,
      payloadKind: entry.payloadKind,
      filter: entry.filter,
      writeConcern: entry.options && entry.options.writeConcern ? entry.options.writeConcern : null,
      matchedCount: entry.result ? entry.result.matchedCount : null,
      acknowledged: entry.result ? entry.result.acknowledged : null,
      modifiedCount: entry.result ? entry.result.modifiedCount : null,
      errorCode: entry.error ? entry.error.code : null,
      errorMessage: entry.error ? entry.error.message : null,
    }));
}

/** Full real pairing ceremony (support.runPairingCeremony's exact product path) on `pairing`. */
async function ceremonyProbe(ctx, pairing, probe, key) {
  const steps = [];
  const openChallenge = await pairing.mintPairingOpenChallenge({
    tenantId: TENANT,
    deviceId: probe.deviceId,
    deviceKeyId: probe.deviceKeyId,
  });
  steps.push({ step: 'mintPairingOpenChallenge', ...envelopeView(openChallenge) });
  if (!openChallenge.ok) {
    return { ceremonyStage: 'mint-open-challenge', ceremonyOk: false, steps, codeIssued: false };
  }
  const issue = await pairing.issuePairingSession({
    tenantId: TENANT,
    deviceId: probe.deviceId,
    deviceKeyId: probe.deviceKeyId,
    domainTag: env.constants.PAIRING_OPEN_DOMAIN,
    requestSource: 'skew-harness',
    challengeHash: openChallenge.challengeHash,
    proof: support.pairingOpenProof(ctx, {
      deviceId: probe.deviceId,
      deviceKeyId: probe.deviceKeyId,
      key,
      challengeHash: openChallenge.challengeHash,
      issuedAt: openChallenge.issuedAt,
    }),
  });
  const codeIssued = typeof issue.code === 'string' && /^[0-9]{6}$/.test(issue.code);
  steps.push({
    step: 'issuePairingSession',
    ...envelopeView(issue),
    codeIssued,
    codeDigits: typeof issue.code === 'string' ? issue.code.length : 0,
  });
  if (!issue.ok) {
    return { ceremonyStage: 'issue', ceremonyOk: false, steps, codeIssued };
  }
  const redeem = await pairing.redeemPairingCode({ code: issue.code, tenantId: TENANT, ownerId: probe.claimantOwnerId });
  steps.push({ step: 'redeemPairingCode', ...envelopeView(redeem) });
  if (!redeem.ok) {
    return { ceremonyStage: 'redeem', ceremonyOk: false, steps, codeIssued };
  }
  const session = await ctx.models.PairingSession.findOne({
    _id: redeem.pairingSession._id,
    tenantId: TENANT,
  }).lean();
  const claimChallenge = await pairing.mintPairingClaimChallenge({
    pairingSessionId: String(session._id),
    tenantId: TENANT,
    ownerId: probe.claimantOwnerId,
  });
  steps.push({
    step: 'mintPairingClaimChallenge',
    ...envelopeView(claimChallenge),
    frozenExpectedEpoch: session.claim ? session.claim.expectedEpoch ?? null : null,
  });
  if (!claimChallenge.ok) {
    return { ceremonyStage: 'mint-claim-challenge', ceremonyOk: false, steps, codeIssued };
  }
  const approve = await pairing.approvePairingClaim({
    pairingSessionId: String(session._id),
    tenantId: TENANT,
    ownerId: probe.claimantOwnerId,
    domainTag: env.constants.PAIRING_CLAIM_DOMAIN,
    localConsent: { nonce: 'lab-consent-nonce-0001' },
    proof: support.pairingClaimProof(ctx, {
      session,
      ownerId: probe.claimantOwnerId,
      challengeHash: claimChallenge.challengeHash,
      key,
      issuedAt: claimChallenge.issuedAt,
    }),
  });
  steps.push({ step: 'approvePairingClaim', ...envelopeView(approve), frozenExpectedEpoch: session.claim ? session.claim.expectedEpoch ?? null : null });
  return {
    ceremonyStage: approve.ok ? 'done' : 'approve',
    ceremonyOk: approve.ok === true,
    steps,
    codeIssued,
    frozenExpectedEpoch: session.claim ? session.claim.expectedEpoch ?? null : null,
    sessionId: String(session._id),
  };
}

async function runProbe(ctx, probe) {
  const calls = [];
  const seqStart = ctx.recorder.entries.length;
  const key = env.makeDeviceKey(probe.deviceTag);
  const authority = observeService(
    ctx.authorityService({
      verifyRenewalProof: env.makeRenewalProof({
        tenantId: TENANT,
        ownerId: probe.seedOwnerId,
        deviceId: probe.deviceId,
        deviceKeyId: probe.deviceKeyId,
        grantId: probe.grantId,
        epoch: probe.expectedEpoch,
      }),
    }),
    calls,
  );
  const readRow = async () => {
    const row = await ctx.models.DeviceAuthority.findOne({ _id: probe.deviceId, tenantId: TENANT }).lean();
    return row ?? null;
  };

  const rowBefore = await readRow();
  let detail = {};
  let action = probe.kind;
  if (probe.kind === 'claimAuthority') {
    detail = envelopeView(
      await authority.claimAuthority({
        deviceId: probe.deviceId,
        tenantId: TENANT,
        ownerId: probe.claimantOwnerId,
        expectedEpoch: probe.expectedEpoch,
        sessionId: `skew-${probe.probeId}`,
        grantProof: null,
      }),
    );
  } else if (probe.kind === 'releaseLapsedLease') {
    detail = envelopeView(await authority.releaseLapsedLease({ deviceId: probe.deviceId, tenantId: TENANT }));
  } else if (probe.kind === 'renewAuthority') {
    detail = envelopeView(
      await authority.renewAuthority({
        deviceId: probe.deviceId,
        tenantId: TENANT,
        ownerId: probe.seedOwnerId,
        epoch: probe.expectedEpoch,
        grantId: probe.grantId,
        // Disclosed harness seam: the renewal proof VERIFIER is injected (env.makeRenewalProof,
        // bound to this row's tenant/owner/device/grant/epoch). Only the verdict is substituted.
        proofInput: { __accept: true },
      }),
    );
  } else if (probe.kind === 'admission') {
    /*
     * MARGIN-FREE ADMISSION (GM-45 site 5 `isLiveLease`, site 11 `pairingCompleteHttpHandler
     * .isLiveLease`, site 8 redeem). No margin applies on this axis, so a writer whose clock is
     * offset can accept a lease that is live by only a few milliseconds — unless the decision is
     * made against database time. This is the verifier's PROBE-ADMISSION case, probed here at the
     * fixture's full ±delta.
     */
    const pairing = ctx.pairingService({
      authorityService: authority,
      verifyLocalConsent: ctx.consent.verify.bind(ctx.consent),
    });
    const open = await pairing.mintPairingOpenChallenge({
      tenantId: TENANT,
      deviceId: probe.deviceId,
      deviceKeyId: probe.deviceKeyId,
    });
    const issue = open.ok
      ? await pairing.issuePairingSession({
          tenantId: TENANT,
          deviceId: probe.deviceId,
          deviceKeyId: probe.deviceKeyId,
          domainTag: env.constants.PAIRING_OPEN_DOMAIN,
          requestSource: 'skew-harness-admission',
          challengeHash: open.challengeHash,
          proof: support.pairingOpenProof(ctx, {
            deviceId: probe.deviceId,
            deviceKeyId: probe.deviceKeyId,
            key,
            challengeHash: open.challengeHash,
            issuedAt: open.issuedAt,
          }),
        })
      : { ok: false, code: null, error: open.error };
    const codeIssued = typeof issue.code === 'string' && /^[0-9]{6}$/.test(issue.code);
    const sessions = await ctx.models.PairingSession.countDocuments({
      tenantId: TENANT,
      deviceId: probe.deviceId,
    });
    action = 'admission(mint-open->issue)';
    detail = {
      ok: issue.ok === true,
      matched: null,
      errorCode: issue.error ? issue.error.code : null,
      codeIssued,
      codeDigits: typeof issue.code === 'string' ? issue.code.length : 0,
      pairingSessionRows: sessions,
      openChallengeOk: open.ok === true,
    };
  } else if (probe.kind === 'pairingCeremony') {
    const pairing = ctx.pairingService({
      authorityService: authority,
      verifyLocalConsent: ctx.consent.verify.bind(ctx.consent),
    });
    const ceremony = await ceremonyProbe(ctx, pairing, probe, key);
    action = 'pairingCeremony(issue->claim)';
    detail = {
      ok: ceremony.ceremonyOk,
      matched: calls.filter((entry) => entry.action === 'claimAuthority').map((entry) => entry.matched).pop() ?? null,
      errorCode:
        ceremony.ceremonyOk === true
          ? null
          : (ceremony.steps.find((step) => step.ok === false && step.errorCode) ?? {}).errorCode ?? null,
      ceremonyStage: ceremony.ceremonyStage,
      codeIssued: ceremony.codeIssued,
      frozenExpectedEpoch: ceremony.frozenExpectedEpoch ?? null,
      steps: ceremony.steps,
    };
  } else {
    throw new Error(`unknown probe kind ${probe.kind}`);
  }

  const rowAfter = await readRow();
  return {
    probeId: probe.probeId,
    kind: probe.kind,
    action,
    deviceId: probe.deviceId,
    deviceTag: probe.deviceTag,
    expectedEpoch: probe.expectedEpoch,
    grantId: probe.grantId,
    seedOwnerId: probe.seedOwnerId,
    claimantOwnerId: probe.claimantOwnerId ?? null,
    referenceRemainingLifeMs: probe.remainingLifeMsAtReferenceNow,
    outcome: detail,
    observedCalls: calls,
    rowBefore: rowView(rowBefore),
    rowAfter: rowView(rowAfter),
    authorityWrites: authorityWritesSince(ctx.recorder, seqStart),
  };
}

/**
 * Waits on the DATABASE clock until `targetMs` arrives, then returns the observed database instant.
 * This is a database-clock wait (never a wall-clock assumption): the fixture's reference timeline is
 * a real instant on the server's clock, so a writer must not act before the server reaches it.
 * Returns `null` if the budget expires without reaching the target.
 */
async function waitForDatabaseInstant(ctx, targetMs, budgetMs) {
  const deadline = Date.now() + budgetMs;
  for (;;) {
    // eslint-disable-next-line no-await-in-loop
    const observed = await support.serverNowMs(ctx.client);
    if (observed >= targetMs) return observed;
    if (Date.now() > deadline) return null;
    // eslint-disable-next-line no-await-in-loop
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const role = args.role;
  const offsetMs = Number(args.offset);
  const clockMs = Number(args.clock);
  const timeoutMs = Number(args.timeoutMs ?? 60000);
  // GM-64 rule 5: the skew oracle runs in DATABASE mode unless a caller explicitly says otherwise.
  // `--anchor=clock` would substitute an injected comparison anchor and VOID the result as skew
  // evidence; it exists only so a future fixture can be shown to be running in the wrong mode.
  const anchorMode = args.anchor ?? 'database';
  const plan = readJson(args.plan);
  const barrierDir = args.barrier;
  const outFile = args.out;

  const report = {
    kind: 'skew-writer-child',
    fixtureId: plan.fixtureId,
    role,
    offsetMs,
    clockNowMs: clockMs + offsetMs,
    referenceNowMs: clockMs,
    predicateAnchorMode: anchorMode,
    dbName: args.db,
    pid: process.pid,
    ppid: process.ppid,
    nodeVersion: process.version,
    startedAt: new Date().toISOString(),
    barrierReached: false,
    peerReady: false,
    probes: [],
    probeCount: 0,
    fatal: null,
    fenceProblems: null,
  };

  let ctx = null;
  try {
    report.fenceProblems = support.fence.checkDbName(args.db);
    if (report.fenceProblems.length > 0) {
      throw new support.fence.FenceViolation(report.fenceProblems, { dbName: args.db, phase: 'child-pre-connect' });
    }
    ctx = await support.makeContext({
      tag: `skew-${plan.fixtureId}-${role}`,
      dbName: args.db,
      syncIndexes: false,
      dropOnTeardown: false,
      mode: 'raw-registry',
      // 'database' ⇒ NO injected anchor: every lease/TTL predicate is the production `$$NOW` form.
      predicateAnchor: anchorMode,
    });
    ctx.clock.set(clockMs + offsetMs);
    report.clockKind = ctx.clock.kind;
    report.clockNowMs = ctx.clock.now();

    writeJson(path.join(barrierDir, `ready-${role}.json`), {
      role,
      pid: process.pid,
      offsetMs,
      clockNowMs: ctx.clock.now(),
      referenceNowMs: clockMs,
      dbName: args.db,
      at: new Date().toISOString(),
    });
    report.barrierReached = true;
    await waitForFile(path.join(barrierDir, `go-${role}.json`), timeoutMs);
    report.peerReady = true;

    /*
     * GM-64 rule 5: the fixture's reference timeline is an instant on the DATABASE clock. Wait until
     * the server reaches it before deciding anything, so every probe is evaluated exactly at the
     * declared reference instant (a row live by EPSILON is live by EPSILON when the product decides,
     * and one expired by EPSILON is expired by EPSILON). This is a database-clock wait.
     */
    const reachedAtMs = await waitForDatabaseInstant(ctx, clockMs, timeoutMs);
    report.referenceReached = reachedAtMs !== null;
    report.referenceReachedAtMs = reachedAtMs;
    if (reachedAtMs === null) {
      throw new Error(
        `REFERENCE_INSTANT_NOT_REACHED: database clock did not reach ${clockMs} within ${timeoutMs} ms`,
      );
    }

    const startedAt = process.hrtime.bigint();
    for (const probe of plan.probes) {
      // The instant the product's own `$$NOW` will see, recorded for the liveness cross-check.
      // eslint-disable-next-line no-await-in-loop
      const dbNowAtProbeMs = await support.serverNowMs(ctx.client);
      // eslint-disable-next-line no-await-in-loop
      const result = await runProbe(ctx, probe);
      report.probes.push({
        ...result,
        clockNowMs: ctx.clock.now(),
        dbNowAtProbeMs,
        pid: process.pid,
      });
      report.probeCount += 1;
    }
    report.durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
    report.finishedAt = new Date().toISOString();
  } catch (err) {
    report.fatal = `${err.name}: ${err.message}`;
    report.fatalStack = String(err.stack ?? '').split('\n').slice(0, 8);
  } finally {
    if (ctx !== null) await ctx.teardown().catch(() => {});
    writeJson(outFile, report);
  }
  return report;
}

main().then(
  (report) => {
    process.exitCode = report.fatal === null ? 0 : 4;
  },
  (err) => {
    const args = parseArgs(process.argv.slice(2));
    if (args.out) {
      writeJson(args.out, {
        kind: 'skew-writer-child',
        role: args.role ?? null,
        pid: process.pid,
        fatal: `UNHANDLED: ${err.name}: ${err.message}`,
        stack: String(err.stack ?? '').split('\n').slice(0, 8),
      });
    }
    process.exitCode = 4;
  },
);