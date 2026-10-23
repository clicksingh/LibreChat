'use strict';

/**
 * ONE ARM'S MONGO-SIDE WRITER PROCESS WITH AN INJECTED CLOCK (test-only; new file).
 *
 *   node writer-child.cjs --role=CORRECT|OFFSET --offset=<ms> --anchor=database \
 *        --arm=<arm.json> --barrier=<dir> --out=<file> [--timeoutMs=60000]
 *
 * WHAT ONE ARM IS
 * ---------------
 * An ARM is one (clock, database, preimage) triple:
 *   - its OWN `cbhr_rdc_phase1_w3_*` database, so nothing it does can be observed or disturbed by
 *     the other arm (and so each arm can be anchored to the database clock independently);
 *   - a writer clock frozen at `referenceNowMs + offsetMs`, where `referenceNowMs` is the ONE
 *     database-clock instant the parent publishes to both arms in the go file;
 *   - a preimage seeded by THIS process, immediately BEFORE the declared reference instant, with
 *     `expiresAt = referenceNowMs + remainingLifeMs` for every probe.
 *
 * WHERE THE REFERENCE TIMELINE COMES FROM (GM-69)
 * -----------------------------------------------
 * `referenceNowMs` is not a fixture constant and not a wall-clock read: the parent reads the
 * replica set's own clock (`hello.localTime`, millisecond precision) and publishes
 * `referenceNowMs = thatReading + the published arm lead`. Both writers wait on the DATABASE clock until the
 * server reaches it. Every row is therefore anchored to the same clock the production `$$NOW`
 * predicates use, which is what makes "live on the reference timeline" mean "live in the database".
 *
 * WHY THE ROWS ARE SEEDED BY THE WRITER ITSELF
 * -------------------------------------------
 * Because a boundary probe is only honest if the row is still live (or still expired) at the
 * instant the product decides. Seeding here — a few milliseconds before the wait ends, with the
 * whole `remainingLifeMs` still ahead — removes every cross-process and scheduling delay between
 * "the row is live by epsilon" and "the product decides". The parent re-derives the same rows with
 * its own independent read-back and gates the writer's account of them.
 *
 * TIMING EVIDENCE RECORDED PER PROBE (a genuine failure is never inferred from bad timing)
 *   dbNowAtProbeMs      database clock read immediately before the product call
 *   dbNowAfterProbeMs   database clock read immediately after it (the decision instant is in this
 *                       closed interval, so "was the row really live then?" is answerable)
 *   decisionOffsetMs    dbNowAtProbeMs - referenceNowMs
 *   liveAtDecision      dbNowAtProbeMs < expiresAtMs (bare expiry, the margin-free form)
 *   clockSkewAtDecisionMs  the writer's own clock minus database time at that instant
 *
 * NO PREDICATE ANCHOR IS SUPPLIED in the default `--anchor=database` mode: every lease-state / TTL
 * predicate is the production `$expr` with `$$NOW`. `--anchor=clock` substitutes the injected
 * comparison anchor (GM-64 seam) and exists ONLY to demonstrate that this fixture can still fail —
 * a run in that mode is marked void as skew evidence by the runner.
 *
 * Protocol (file transport only; piped child stdio is EPERM in this sandbox):
 *   1. connect, build the REAL product services over the REAL frozen models,
 *   2. publish `ready-<role>.json`,
 *   3. await `go-<role>.json` (carries the shared database-clock reference instant),
 *   4. freeze this writer's clock at reference+offset, seed the arm's preimage,
 *   5. wait on the DATABASE clock until the reference instant,
 *   6. execute every probe through product bytes only, recording the timing evidence above,
 *   7. publish `out-<role>.json`, then drop this arm's database.
 *
 * Secrets: a minted pairing code is never written anywhere. Only `codeIssued: boolean` and
 * `codeDigits` (a digit count) are recorded. Signatures are reduced to `{present, issuedAt}`.
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

/**
 * The DATABASE clock in epoch milliseconds, at millisecond precision.
 *
 * `hello.localTime` is a real BSON instant from the replica-set primary — the same clock the
 * production `$$NOW` predicates are evaluated against. `new Date(...)` (rather than
 * `Date.parse(...)` on the Date) keeps the millisecond field: `support.serverNowMs` stringifies the
 * Date and therefore floors to whole seconds, which is too coarse to decide a 1000 ms boundary
 * window. Never a wall-clock read of this process.
 */
async function databaseNowMs(client) {
  const hello = await client.db('admin').command({ hello: 1 });
  const localTime = hello.localTime;
  const value = localTime instanceof Date ? localTime.getTime() : Date.parse(String(localTime));
  if (!Number.isFinite(value)) {
    throw new Error('databaseNowMs: hello.localTime is not a parseable instant');
  }
  return value;
}

/**
 * Waits on the DATABASE clock until `targetMs` arrives, then returns the observed instant.
 * Returns `null` if the budget expires without reaching the target.
 */
async function waitForDatabaseInstant(client, targetMs, budgetMs) {
  const deadline = Date.now() + budgetMs;
  for (;;) {
    // eslint-disable-next-line no-await-in-loop
    const observed = await databaseNowMs(client);
    if (observed >= targetMs) return observed;
    if (Date.now() > deadline) return null;
    // eslint-disable-next-line no-await-in-loop
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
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
    renewalCount: row.renewalCount ?? null,
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
 * The deviceauthorities writes one probe actually issued (exact filters + outcomes).
 * Only writes committed while the probe ran are returned; re-reads register no writes.
 */
function authorityWritesSince(recorder, seqStart) {
  return recorder.entries
    .filter((entry) => entry.model === 'DeviceAuthority' && entry.updateOne && entry.seq >= seqStart)
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
  steps.push({
    step: 'approvePairingClaim',
    ...envelopeView(approve),
    frozenExpectedEpoch: session.claim ? session.claim.expectedEpoch ?? null : null,
  });
  return {
    ceremonyStage: approve.ok ? 'done' : 'approve',
    ceremonyOk: approve.ok === true,
    steps,
    codeIssued,
    frozenExpectedEpoch: session.claim ? session.claim.expectedEpoch ?? null : null,
    sessionId: String(session._id),
  };
}

/** Executes ONE probe through product bytes only and returns its full observation record. */
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
        // bound to this row's tenant/owner/device/grant/epoch). Only the verdict is substituted;
        // the expiry predicate under test is untouched.
        proofInput: { __accept: true },
      }),
    );
  } else if (probe.kind === 'admission') {
    /*
     * MARGIN-FREE ADMISSION (GM-45 sites 5/8/11: `isLiveLease` + the guarded release branch). No
     * margin applies on this axis, so a writer whose comparison anchor is its own clock accepts a
     * lease that is live by a few milliseconds. Under database-time predicates it must refuse.
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
    remainingLifeMs: probe.remainingLifeMs,
    outcome: detail,
    observedCalls: calls,
    rowBefore: rowView(rowBefore),
    rowAfter: rowView(rowAfter),
    authorityWrites: authorityWritesSince(ctx.recorder, seqStart),
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const role = args.role;
  const offsetMs = Number(args.offset);
  const timeoutMs = Number(args.timeoutMs ?? 60000);
  // GM-64 rule 5: DATABASE mode unless a caller explicitly says otherwise. `--anchor=clock`
  // substitutes the injected comparison anchor and VOIDS the result as skew evidence; it exists so
  // the fixture can be shown, on the record, to still be able to fail.
  const anchorMode = args.anchor ?? 'database';
  const arm = readJson(args.arm);
  const barrierDir = args.barrier;
  const outFile = args.out;

  const report = {
    kind: 'skew-writer-child',
    fixtureId: arm.fixtureId,
    armId: arm.armId,
    role,
    treatment: arm.treatment === true,
    offsetMs,
    predicateAnchorMode: anchorMode,
    anchorSeamSupplied: anchorMode !== 'database',
    dbName: arm.dbName,
    armHash: support.sha256File(args.arm),
    clockKind: null,
    writerClockMs: null,
    referenceNowMs: null,
    referenceReached: false,
    referenceReachedAtMs: null,
    seedDbNowMs: null,
    seedRows: null,
    seededRowsAtRelease: null,
    pid: process.pid,
    ppid: process.ppid,
    nodeVersion: process.version,
    startedAt: new Date().toISOString(),
    barrierReached: false,
    probes: [],
    probeCount: 0,
    fatal: null,
    fenceProblems: null,
  };

  let ctx = null;
  try {
    report.fenceProblems = support.fence.checkDbName(arm.dbName);
    if (report.fenceProblems.length > 0) {
      throw new support.fence.FenceViolation(report.fenceProblems, {
        dbName: arm.dbName,
        phase: 'child-pre-connect',
      });
    }
    ctx = await support.makeContext({
      tag: arm.armTag,
      dbName: arm.dbName,
      syncIndexes: false,
      dropOnTeardown: false,
      mode: 'raw-registry',
      // 'database' ⇒ NO injected anchor: every lease/TTL predicate is the production `$$NOW` form.
      predicateAnchor: anchorMode,
    });
    report.clockKind = ctx.clock.kind;
    report.predicateAnchorMode = ctx.predicateAnchorMode;

    writeJson(path.join(barrierDir, `ready-${role}.json`), {
      role,
      armId: arm.armId,
      treatment: arm.treatment === true,
      pid: process.pid,
      offsetMs,
      predicateAnchorMode: anchorMode,
      anchorSeamSupplied: anchorMode !== 'database',
      dbName: arm.dbName,
      // The database instant at which this writer became fully armed (context built, models ready).
      // The parent uses it, together with its own reading, to place the reference instant far
      // enough ahead that this writer can still seed and probe before the instant arrives.
      dbNowAtMs: await databaseNowMs(ctx.client),
      at: new Date().toISOString(),
    });
    report.barrierReached = true;

    /* The parent publishes ONE database-clock reference instant for both arms. */
    const go = await waitForFile(path.join(barrierDir, `go-${role}.json`), timeoutMs);
    const referenceNowMs = Number(go.referenceNowMs);
    if (!Number.isFinite(referenceNowMs)) {
      throw new Error('GO_PAYLOAD_INVALID: referenceNowMs is missing from the go file');
    }
    report.referenceNowMs = referenceNowMs;
    report.goPayload = {
      releasedAtMs: Number.isFinite(Number(go.releasedAtMs)) ? Number(go.releasedAtMs) : null,
      writerArmedAtMs: Number.isFinite(Number(go.writerArmedAtMs)) ? Number(go.writerArmedAtMs) : null,
      armLeadMs: Number.isFinite(Number(go.armLeadMs)) ? Number(go.armLeadMs) : null,
      order: go.order ?? null,
      armId: go.armId ?? null,
      referenceNowMs,
    };
    report.writerClockMs = referenceNowMs + offsetMs;
    ctx.clock.set(report.writerClockMs);

    /*
     * Seed this arm's preimage BEFORE the declared reference instant, so that every seeded row is
     * already durable and every probe can decide inside its own declared boundary window.
     */
    const seedRows = [];
    for (const probe of arm.probes) {
      const key = env.makeDeviceKey(probe.deviceTag);
      const expiresAtMs = referenceNowMs + probe.remainingLifeMs;
      const activatedAtMs = expiresAtMs - arm.leaseTtlMs;
      // eslint-disable-next-line no-await-in-loop
      await support.seedAuthority(ctx, {
        _id: probe.deviceId,
        tenantId: TENANT,
        deviceKeyId: probe.deviceKeyId,
        devicePublicKey: probe.devicePublicKey,
        identityState: 'active',
        leaseState: 'active',
        epoch: probe.expectedEpoch,
        ownerId: probe.seedOwnerId,
        grantId: probe.grantId,
        activatedAt: new Date(activatedAtMs),
        expiresAt: new Date(expiresAtMs),
        renewedAt: null,
        renewalCount: 0,
        grantedByPairingSessionId: null,
        registeredAt: new Date(activatedAtMs),
      });
      seedRows.push({
        probeId: probe.probeId,
        kind: probe.kind,
        deviceId: probe.deviceId,
        remainingLifeMs: probe.remainingLifeMs,
        expiresAtMs,
        activatedAtMs,
        ownerId: probe.seedOwnerId,
        grantId: probe.grantId,
        epoch: probe.expectedEpoch,
      });
    }
    report.seedRows = seedRows;
    report.seedDbNowMs = await databaseNowMs(ctx.client);

    /* Immediately-visible proof that every seeded row really exists before this writer acts. */
    const atRelease = [];
    for (const probe of arm.probes) {
      // eslint-disable-next-line no-await-in-loop
      const row = await ctx.models.DeviceAuthority.findOne({ _id: probe.deviceId, tenantId: TENANT }).lean();
      atRelease.push({ probeId: probe.probeId, row: rowView(row ?? null) });
    }
    report.seededRowsAtRelease = atRelease;

    /* Wait on the DATABASE clock until the declared reference instant arrives. */
    const reachedAtMs = await waitForDatabaseInstant(ctx.client, referenceNowMs, timeoutMs);
    report.referenceReached = reachedAtMs !== null;
    report.referenceReachedAtMs = reachedAtMs;
    if (reachedAtMs === null) {
      throw new Error(
        `REFERENCE_INSTANT_NOT_REACHED: database clock did not reach ${referenceNowMs} within ${timeoutMs} ms`,
      );
    }

    const startedAt = process.hrtime.bigint();
    for (const probe of arm.probes) {
      // The instant the product's own comparison anchor will see, read immediately before the call.
      // eslint-disable-next-line no-await-in-loop
      const dbNowAtProbeMs = await databaseNowMs(ctx.client);
      // eslint-disable-next-line no-await-in-loop
      const result = await runProbe(ctx, probe);
      // eslint-disable-next-line no-await-in-loop
      const dbNowAfterProbeMs = await databaseNowMs(ctx.client);
      report.probes.push({
        ...result,
        expiresAtMs: referenceNowMs + probe.remainingLifeMs,
        dbNowAtProbeMs,
        dbNowAfterProbeMs,
        decisionOffsetMs: dbNowAtProbeMs - referenceNowMs,
        liveAtDecision: dbNowAtProbeMs < referenceNowMs + probe.remainingLifeMs,
        clockNowMs: ctx.clock.now(),
        clockSkewAtDecisionMs: ctx.clock.now() - dbNowAtProbeMs,
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
    // The parent owns the arm databases' lifecycle (it drops them after its independent
    // read-back), so crashing children only ever leave durable evidence — but they must not
    // leave OPEN handles behind, so the report is published first and the context is closed.
    if (ctx !== null) {
      try {
        writeJson(outFile, report);
      } catch (err) {
        report.reportWriteFatal = `${err.name}: ${err.message}`;
      }
      await ctx.teardown().catch(() => {});
      try {
        writeJson(outFile, report);
      } catch {
        /* the first write already landed; best effort only */
      }
    } else {
      writeJson(outFile, report);
    }
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