'use strict';

/**
 * TWO-CLOCK SKEW FIXTURE (test-only, new file; PHASE1-LOCAL-AUTHORITY-001).
 *
 * Attempts to reproduce the H01 minimal counterexample (F-H01-4 / F-H01-1) against the REAL
 * product bytes and a REAL MongoDB replica set:
 *
 *   two real OS processes, each a Mongo-side lease-state writer with its own INJECTED clock
 *   offset, act on the SAME database:
 *     CORRECT  offset 0        (the reference timeline)
 *     OFFSET   offset +delta   (S1 fast by delta = 5 min)  for the fast fixtures
 *     OFFSET   offset -delta   (S2 slow by delta = 5 min)  for the renewal fixture
 *
 *   Lease rows are seeded with a known remaining life relative to the reference timeline
 *   (`expiresAt = TRUE_NOW + epsilon`, epsilon = 1000 ms for the boundary rows), so "live" is
 *   decided by construction and never by reading a wall clock.
 *
 * Two assertion ledgers are kept strictly apart:
 *   GATE  (must pass, else HARNESS_FAIL): two distinct real OS PIDs, both armed at the file
 *         barrier, every planned probe executed, no child fatal.
 *   LAW   (allowed to fail: a failure is the FINDING): a lease that is live on the reference
 *         timeline must not be transitioned by a skewed writer, and the CORRECT writer must be
 *         observed refusing the same lease (which proves the preimage really was live).
 *
 * No product byte is changed, no assertion is weakened, and no product behaviour is
 * reimplemented: every state transition is a real I6/I5 product call over the frozen
 * `createModels(mongoose)` registry.
 */

const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const support = require('../w3a/support.cjs');
const env = require('../w3a/env.cjs');
const k = require('./skew-constants.cjs');

const CHILD = path.resolve(__dirname, 'writer-child.cjs');
const TENANT = k.TENANT;

/* ------------------------------------------------------------------ fixtures */

const FIXTURES = [
  {
    id: 'SKEW-01-FAST-WRITER-OVER-RELEASE',
    title:
      'A writer fast by +delta claims / lazily releases / completes a real pairing on a lease that is live on the reference timeline',
    contractRef: 'F-H01-4/F-H01-1 (R9/GM-16)',
    direction: 'fast',
    offsetMs: k.DELTA_MS,
    probes: [
      {
        probeId: 'SKEW-01-P1-CLAIM-AT-BOUNDARY',
        kind: 'claimAuthority',
        remainingLifeMsAtReferenceNow: k.EPSILON_MS,
        claimant: true,
      },
      {
        probeId: 'SKEW-01-P2-LAZY-RELEASE-AT-BOUNDARY',
        kind: 'releaseLapsedLease',
        remainingLifeMsAtReferenceNow: k.EPSILON_MS,
      },
      {
        probeId: 'SKEW-01-P3-CEREMONY-ON-LIVE-LEASE',
        kind: 'pairingCeremony',
        remainingLifeMsAtReferenceNow: k.EPSILON_MS,
        claimant: true,
      },
    ],
  },
  {
    id: 'SKEW-02-SLOW-WRITER-PAST-EXPIRY-RENEWAL',
    title:
      'A writer slow by -delta renews a lease that already expired on the reference timeline (and correctly refuses on the claim axis)',
    contractRef: 'F-H01-4 renewal half (R9/GM-16)',
    direction: 'slow',
    offsetMs: -k.DELTA_MS,
    probes: [
      {
        probeId: 'SKEW-02-P1-RENEW-PAST-TRUE-EXPIRY',
        kind: 'renewAuthority',
        remainingLifeMsAtReferenceNow: -k.EPSILON_MS,
      },
      {
        probeId: 'SKEW-02-P2-SLOW-CLAIM-CONTROL',
        kind: 'claimAuthority',
        remainingLifeMsAtReferenceNow: k.EPSILON_MS,
        claimant: true,
      },
    ],
  },
  {
    id: 'SKEW-03-BOUNDARY-SWEEP',
    title:
      'Empirical over-release horizon: remaining-life grid across the predicted delta - SKEW_MARGIN crossover',
    contractRef: 'F-H01-4 boundary (R9/GM-16)',
    direction: 'fast',
    offsetMs: k.DELTA_MS,
    probes: k.SWEEP_GRID_MS.map((lifeMs, index) => ({
      probeId: `SKEW-03-P${index + 1}-LIFE-${lifeMs}`,
      kind: 'claimAuthority',
      remainingLifeMsAtReferenceNow: lifeMs,
      claimant: true,
    })),
  },
];

const BY_ID = new Map(FIXTURES.map((fixture) => [fixture.id, fixture]));

/* ------------------------------------------------------------------ plumbing */

function shortId(fixtureId) {
  const match = /^SKEW-(\d+)/.exec(fixtureId);
  return match === null ? String(fixtureId).replace(/[^A-Za-z0-9_]/g, '_') : `s${match[1]}`;
}

/** Builds the JSON-safe probe plan shared by both writers (no secrets). */
function buildPlan(ctx, fixture) {
  const short = shortId(fixture.id);
  return {
    fixtureId: fixture.id,
    direction: fixture.direction,
    offsetMs: fixture.offsetMs,
    referenceNowMs: k.TRUE_NOW_MS,
    deltaMs: k.DELTA_MS,
    epsilonMs: k.EPSILON_MS,
    skewMarginMs: k.SKEW_MARGIN_MS,
    leaseTtlMs: k.LEASE_TTL_MS,
    tenantId: TENANT,
    probes: fixture.probes.map((probe, index) => {
      const tag = `${short}-d${index + 1}`;
      const key = env.makeDeviceKey(tag);
      const expiresAtMs = k.TRUE_NOW_MS + probe.remainingLifeMsAtReferenceNow;
      return {
        probeId: probe.probeId,
        kind: probe.kind,
        deviceTag: tag,
        deviceId: `skew-${short}-device-${index + 1}`,
        deviceKeyId: ctx.crypto.thumbprintB64u(key.spkiB64u),
        devicePublicKey: key.spkiB64u,
        seedOwnerId: `principal-skew-seed-${short}-${index + 1}`,
        claimantOwnerId: probe.claimant === true ? `principal-skew-claim-${short}-${index + 1}` : null,
        expectedEpoch: 1,
        grantId: `skew-grant-${short}-${index + 1}`,
        expiresAtMs,
        activatedAtMs: expiresAtMs - k.LEASE_TTL_MS,
        remainingLifeMsAtReferenceNow: probe.remainingLifeMsAtReferenceNow,
      };
    }),
  };
}

function viewRow(row) {
  if (row === null || row === undefined) return null;
  return {
    ...support.authorityView(row, null),
    expiresAtMs: row.expiresAt ? new Date(row.expiresAt).getTime() : null,
    activatedAtMs: row.activatedAt ? new Date(row.activatedAt).getTime() : null,
  };
}

function sha256FileSafe(file) {
  try {
    return support.sha256File(file);
  } catch {
    return null;
  }
}

function spawnWriter({ role, offsetMs, dbName, planFile, barrierDir, outFile, logFile }) {
  const args = [
    CHILD,
    `--role=${role}`,
    `--offset=${offsetMs}`,
    `--clock=${k.TRUE_NOW_MS}`,
    `--db=${dbName}`,
    `--plan=${planFile}`,
    `--barrier=${barrierDir}`,
    `--out=${outFile}`,
    `--timeoutMs=${k.BARRIER_TIMEOUT_MS}`,
  ];
  const logFd = fs.openSync(logFile, 'a');
  const child = spawn(process.execPath, args, {
    stdio: ['ignore', 'ignore', logFd],
    windowsHide: true,
    cwd: env.WORKTREE,
  });
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
    }, k.CHILD_TIMEOUT_MS);
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
  return { role, offsetMs, pid: child.pid, args, child, logFd, exit, outFile, logFile };
}

async function waitForJson(file, timeoutMs = k.BARRIER_TIMEOUT_MS) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fs.existsSync(file)) {
      try {
        return JSON.parse(fs.readFileSync(file, 'utf8'));
      } catch {
        /* retry until the atomic publish completes */
      }
    }
    // eslint-disable-next-line no-await-in-loop
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`BARRIER_TIMEOUT waiting for ${file}`);
}

function releaseGo(barrierDir, role, payload) {
  const file = path.join(barrierDir, `go-${role}.json`);
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
  fs.renameSync(tmp, file);
}

/* ------------------------------------------------------------------ helpers */

function probeOf(writer, probeId) {
  return writer !== null && Array.isArray(writer.probes)
    ? writer.probes.find((entry) => entry.probeId === probeId) ?? null
    : null;
}

function outcomeOf(probe) {
  return probe === null ? { ok: null, matched: null, errorCode: null } : probe.outcome;
}

/** The exact filter bytes the writer's own product path used for this probe's first CAS. */
function firstCasFilter(writer, planProbe) {
  const probe = probeOf(writer, planProbe.probeId);
  if (probe === null || !Array.isArray(probe.authorityWrites) || probe.authorityWrites.length === 0) {
    return null;
  }
  return probe.authorityWrites[0].filter ?? null;
}

/**
 * DESIRED-LAW evaluation for one probe: did the offset writer transition a lease that was live
 * on the reference timeline? `live` comes from the seeded expiry, not from a clock read.
 */
function overReleaseFor(planProbe, offsetProbe) {
  const outcome = outcomeOf(offsetProbe);
  const live = planProbe.remainingLifeMsAtReferenceNow > 0;
  const matched = typeof outcome.matched === 'number' ? outcome.matched : null;
  const transitioned =
    planProbe.kind === 'pairingCeremony'
      ? outcome.ok === true || outcome.codeIssued === true
      : matched !== null && matched > 0;
  return {
    probeId: planProbe.probeId,
    kind: planProbe.kind,
    remainingLifeMsAtReferenceNow: planProbe.remainingLifeMsAtReferenceNow,
    liveOnReferenceTimeline: live,
    offsetWriterTransitioned: transitioned,
    offsetWriterMatched: matched,
    offsetWriterErrorCode: outcome.errorCode ?? null,
    overRelease: live === true && transitioned === true,
  };
}

function activeCountFor(models, ownerId) {
  return models.DeviceAuthority.countDocuments({ ownerId, tenantId: TENANT, leaseState: 'active' });
}

/* ------------------------------------------------------------------ run */

async function run(fixture) {
  const gate = support.makeChecks();
  const law = support.makeChecks();
  const rundir = support.freshDir(path.join(support.runDir(), 'skew', fixture.id));
  const barrierDir = support.ensureDir(path.join(rundir, 'barrier'));
  const ctx = await support.makeContext({
    tag: `skew-${shortId(fixture.id)}`,
    point: fixture.id,
    mode: 'raw-registry',
    dropOnTeardown: false,
  });
  ctx.clock.set(k.TRUE_NOW_MS);
  const plan = buildPlan(ctx, fixture);
  const planFile = support.writeJson(rundir, 'plan.json', plan);
  const writers = [];
  let cleanup = 'not_attempted';

  try {
    /* Seed: real rows, raw driver, majority+journal. One active lease per owner (uq_owner_active). */
    for (const probe of plan.probes) {
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
        activatedAt: new Date(probe.activatedAtMs),
        expiresAt: new Date(probe.expiresAtMs),
        renewedAt: null,
        renewalCount: 0,
        grantedByPairingSessionId: null,
        registeredAt: new Date(probe.activatedAtMs),
      });
    }

    const seeded = {};
    for (const probe of plan.probes) {
      seeded[probe.probeId] = viewRow(
        await ctx.models.DeviceAuthority.findOne({ _id: probe.deviceId, tenantId: TENANT }).lean(),
      );
    }
    const activeBefore = {};
    for (const probe of plan.probes) {
      activeBefore[probe.seedOwnerId] = await activeCountFor(ctx.models, probe.seedOwnerId);
    }

    /* Two real OS processes, both armed at a file barrier before either may act. */
    for (const spec of [
      { role: 'CORRECT', offsetMs: 0 },
      { role: 'OFFSET', offsetMs: fixture.offsetMs },
    ]) {
      writers.push(
        spawnWriter({
          role: spec.role,
          offsetMs: spec.offsetMs,
          dbName: ctx.dbName,
          planFile,
          barrierDir,
          outFile: path.join(barrierDir, `out-${spec.role}.json`),
          logFile: path.join(rundir, `writer-${spec.role}-stderr.log`),
        }),
      );
    }

    const ready = {};
    for (const writer of writers) {
      // eslint-disable-next-line no-await-in-loop
      ready[writer.role] = await waitForJson(path.join(barrierDir, `ready-${writer.role}.json`));
    }

    /* Disclosed ordering: CORRECT acts first from the pristine preimage; its refusal changes no
       row, so the offset writer then acts on the identical preimage. Both clocks are injected and
       deterministic, so no wall-clock truth is consumed by the ordering. */
    const writerReports = {};
    releaseGo(barrierDir, 'CORRECT', { releasedAt: k.TRUE_NOW_MS, order: 1 });
    writerReports.CORRECT = await waitForJson(path.join(barrierDir, 'out-CORRECT.json'));
    releaseGo(barrierDir, 'OFFSET', { releasedAt: k.TRUE_NOW_MS, order: 2, after: 'CORRECT' });
    writerReports.OFFSET = await waitForJson(path.join(barrierDir, 'out-OFFSET.json'));

    const exits = await Promise.all(writers.map((writer) => writer.exit));
    for (const writer of writers) {
      try {
        fs.closeSync(writer.logFd);
      } catch {
        /* best effort */
      }
    }
    const correct = writerReports.CORRECT;
    const offset = writerReports.OFFSET;

    /* Independent parent read-back with the real model (never the child's word alone). */
    const rowsAfter = {};
    for (const probe of plan.probes) {
      rowsAfter[probe.probeId] = viewRow(
        await ctx.models.DeviceAuthority.findOne({ _id: probe.deviceId, tenantId: TENANT }).lean(),
      );
    }
    const activeAfter = {};
    for (const probe of plan.probes) {
      activeAfter[probe.seedOwnerId] = await activeCountFor(ctx.models, probe.seedOwnerId);
    }

    /* ---------------------------------------------------------- GATE (credibility) */
    const pids = writers.map((writer) => writer.pid);
    const reportedPids = [correct.pid, offset.pid];
    const distinct = new Set([...pids, ...reportedPids].filter((pid) => typeof pid === 'number' && pid > 0));
    gate.eq('exactly two writer processes were spawned', pids.length, 2);
    gate.eq('the two writers are distinct real OS processes', distinct.size, 2);
    gate.eq('both writers exited 0', exits.map((entry) => entry.code), [0, 0]);
    gate.ok(
      'both writers reached the file barrier before acting',
      correct.barrierReached === true && offset.barrierReached === true,
      { CORRECT: correct.barrierReached, OFFSET: offset.barrierReached },
    );
    gate.eq('the CORRECT writer ran with offset 0', [correct.offsetMs, correct.clockNowMs], [0, k.TRUE_NOW_MS]);
    gate.eq(
      'the OFFSET writer ran with the injected offset',
      [offset.offsetMs, offset.clockNowMs],
      [fixture.offsetMs, k.TRUE_NOW_MS + fixture.offsetMs],
    );
    gate.eq(
      'both writers executed every planned probe',
      [correct.probeCount, offset.probeCount],
      [plan.probes.length, plan.probes.length],
    );
    gate.ok('neither writer hit a fatal error', correct.fatal === null && offset.fatal === null, {
      CORRECT: correct.fatal,
      OFFSET: offset.fatal,
    });

    /* ---------------------------------------------------------- LAW: control arm (CORRECT) */
    for (const probe of plan.probes) {
      const correctProbe = probeOf(correct, probe.probeId);
      const observed = outcomeOf(correctProbe);
      /* The CORRECT arm's own read-back: the parent's final read-back happens after the offset
         writer has also run, so the control arm must be judged on its own observation. */
      const rowAfter = correctProbe === null ? null : correctProbe.rowAfter;
      const seed = seeded[probe.probeId];
      if (probe.kind === 'renewAuthority') {
        law.eq(
          `CORRECT writer refused renewal of ${probe.probeId} (expired on the reference timeline)`,
          [observed.matched, observed.errorCode],
          [0, 'LEASE_EXPIRED'],
        );
        law.eq(
          `CORRECT writer left ${probe.probeId} unchanged`,
          [rowAfter.expiresAtMs, rowAfter.epoch, rowAfter.ownerId, rowAfter.leaseState],
          [seed.expiresAtMs, seed.epoch, seed.ownerId, seed.leaseState],
        );
      } else if (probe.kind === 'claimAuthority') {
        law.eq(
          `CORRECT writer refused the claim on ${probe.probeId} with a frozen live-lease rejection`,
          [observed.matched, observed.errorCode],
          [0, 'DEVICE_ALREADY_PAIRED_USE_RENEW'],
        );
        law.eq(
          `CORRECT writer left ${probe.probeId} owned by the seed owner at the seed epoch`,
          [rowAfter.ownerId, rowAfter.epoch, rowAfter.leaseState],
          [seed.ownerId, seed.epoch, seed.leaseState],
        );
      } else if (probe.kind === 'releaseLapsedLease') {
        law.eq(
          `CORRECT writer's lazy release 0-matched on ${probe.probeId}`,
          [observed.matched, observed.errorCode],
          [0, null],
        );
        law.eq(
          `CORRECT writer left ${probe.probeId} active at the seed epoch`,
          [rowAfter.leaseState, rowAfter.epoch],
          ['active', seed.epoch],
        );
      } else if (probe.kind === 'pairingCeremony') {
        law.eq(
          `CORRECT writer's ceremony was refused at the issue step on ${probe.probeId}`,
          [observed.ceremonyStage, observed.errorCode, observed.codeIssued],
          ['issue', 'DEVICE_ALREADY_PAIRED_USE_RENEW', false],
        );
        law.eq(
          `CORRECT writer left ${probe.probeId} owned by the seed owner at the seed epoch`,
          [rowAfter.ownerId, rowAfter.epoch, rowAfter.leaseState],
          [seed.ownerId, seed.epoch, seed.leaseState],
        );
      }
    }

    /* ---------------------------------------------------------- LAW: treatment arm (OFFSET) */
    const overReleases = plan.probes.map((probe) => {
      const entry = overReleaseFor(probe, probeOf(offset, probe.probeId));
      const offsetProbe = probeOf(offset, probe.probeId);
      const rowAfter = offsetProbe === null ? null : offsetProbe.rowAfter;
      const seed = seeded[probe.probeId];
      return {
        ...entry,
        pastExpiryRenewal:
          probe.kind === 'renewAuthority' &&
          probe.remainingLifeMsAtReferenceNow < 0 &&
          entry.offsetWriterMatched !== null &&
          entry.offsetWriterMatched > 0,
        offsetWriterRowAfter: rowAfter,
        seedRow: seed,
        parentReadBackMatchesOffsetWriter:
          rowAfter !== null &&
          rowsAfter[probe.probeId] !== null &&
          rowAfter.expiresAtMs === rowsAfter[probe.probeId].expiresAtMs &&
          rowAfter.epoch === rowsAfter[probe.probeId].epoch &&
          rowAfter.ownerId === rowsAfter[probe.probeId].ownerId &&
          rowAfter.leaseState === rowsAfter[probe.probeId].leaseState,
        offsetWriterFirstCasFilter: firstCasFilter(offset, probe),
        correctWriterFirstCasFilter: firstCasFilter(correct, probe),
      };
    });
    for (const entry of overReleases) {
      law.eq(
        `the parent's independent read-back matches the offset writer's observation for ${entry.probeId}`,
        entry.parentReadBackMatchesOffsetWriter,
        true,
      );
    }
    for (const entry of overReleases) {
      const label = `${entry.probeId} (${entry.kind}, reference life ${entry.remainingLifeMsAtReferenceNow} ms)`;
      if (entry.kind === 'renewAuthority') {
        const observed = outcomeOf(probeOf(offset, entry.probeId));
        law.eq(
          `OFFSET writer accepted a renewal only strictly before true expiry for ${label}`,
          [observed.matched, observed.errorCode],
          [0, 'LEASE_EXPIRED'],
        );
      } else if (entry.kind === 'pairingCeremony') {
        const observed = outcomeOf(probeOf(offset, entry.probeId));
        law.eq(`OFFSET writer did not issue a pairing code for a live lease at ${label}`, [
          observed.ceremonyOk === true,
          observed.codeIssued === true,
        ], [false, false]);
      } else {
        const observed = outcomeOf(probeOf(offset, entry.probeId));
        law.eq(`OFFSET writer did not transition the live lease at ${label}`, observed.matched, 0);
      }
    }

    /* The account axis: freeing a live lease removes its owner's active row (uq_owner_active). */
    const accountAxis = plan.probes.map((probe) => ({
      probeId: probe.probeId,
      seedOwnerId: probe.seedOwnerId,
      activeBefore: activeBefore[probe.seedOwnerId],
      activeAfter: activeAfter[probe.seedOwnerId],
      freed: activeBefore[probe.seedOwnerId] === 1 && activeAfter[probe.seedOwnerId] === 0,
    }));
    const freedByOffset = accountAxis.filter((entry) => entry.freed === true);
    law.eq(
      'no seed owner lost its active lease (the account axis was not freed by the offset writer)',
      freedByOffset.map((entry) => entry.probeId),
      [],
    );

    /* Empirical horizon: only meaningful for the claim CAS, and only when the grid spans the
       crossover from both sides. Other probe kinds (renewal) are excluded on purpose. */
    const claimEntries = overReleases.filter((entry) => entry.kind === 'claimAuthority');
    const matchedLives = claimEntries
      .filter((entry) => entry.offsetWriterMatched !== null && entry.offsetWriterMatched > 0)
      .map((entry) => entry.remainingLifeMsAtReferenceNow);
    const refusedLives = claimEntries
      .filter((entry) => entry.offsetWriterMatched === 0)
      .map((entry) => entry.remainingLifeMsAtReferenceNow);
    const measuredHorizonMs = matchedLives.length > 0 ? Math.max(...matchedLives) : null;
    if (matchedLives.length > 0 && refusedLives.length > 0) {
      law.eq(
        'the measured over-release horizon equals delta - SKEW_MARGIN_MS',
        measuredHorizonMs,
        k.PREDICTED_OVER_RELEASE_HORIZON_MS,
      );
      law.ok(
        'the refused side of the grid starts exactly one millisecond past the horizon',
        Math.min(...refusedLives) === measuredHorizonMs + 1,
        { minRefusedLifeMs: Math.min(...refusedLives), horizonMs: measuredHorizonMs },
      );
    }

    /* ---------------------------------------------------------- findings + status */
    const violations = overReleases.filter((entry) => entry.overRelease === true);
    const pastExpiryRenewals = overReleases.filter((entry) => entry.pastExpiryRenewal === true);
    const reproduced = violations.length > 0 || pastExpiryRenewals.length > 0;
    const gateStatus = support.statusFromChecks(gate.checks);
    const lawStatus = support.statusFromChecks(law.checks);
    const gateOk = gate.failed().length === 0;
    const lawOk = law.failed().length === 0;
    const status = gateOk !== true ? 'HARNESS_FAIL' : lawOk !== true ? 'PRODUCT_FAIL' : 'PASS';
    const exitCode = status === 'HARNESS_FAIL' ? 4 : status === 'PRODUCT_FAIL' ? 5 : 0;

    const finding = {
      id: 'H01-F-H01-4',
      counterexampleReproduced: reproduced,
      referenceTrace:
        'C:/Users/Aryan/Desktop/codellm/cbhr-rdc/evidence/gate-closure-002/reviews/H01-authorization-concurrency.md (F-H01-4 minimal counterexample trace; F-H01-1 claim-chain dislodge)',
      statement:
        reproduced
          ? 'The Mongo-side lease-state writers carry no pinned clock discipline: a writer whose injected clock is offset by delta transitions leases that are still live on the reference timeline (claim / lazy release / real pairing), and a writer offset the other way accepts a renewal for a lease that already expired on the reference timeline. The horizon is exactly delta - SKEW_MARGIN_MS of remaining life.'
          : 'Every offset writer refused to transition a lease that was live on the reference timeline, and no offset writer renewed a lease already expired on it.',
      overReleases: violations.map((entry) => ({
        probeId: entry.probeId,
        kind: entry.kind,
        referenceRemainingLifeMs: entry.remainingLifeMsAtReferenceNow,
        offsetWriterMatched: entry.offsetWriterMatched,
        offsetWriterErrorCode: entry.offsetWriterErrorCode,
        offsetWriterFirstCasFilter: entry.offsetWriterFirstCasFilter,
        correctWriterFirstCasFilter: entry.correctWriterFirstCasFilter,
      })),
      measuredOverReleaseHorizonMs: measuredHorizonMs,
      predictedOverReleaseHorizonMs: k.PREDICTED_OVER_RELEASE_HORIZON_MS,
      pastExpiryRenewals: pastExpiryRenewals.map((entry) => ({
        probeId: entry.probeId,
        referenceRemainingLifeMs: entry.remainingLifeMsAtReferenceNow,
        offsetWriterMatched: entry.offsetWriterMatched,
        offsetWriterFirstCasFilter: entry.offsetWriterFirstCasFilter,
        correctWriterFirstCasFilter: entry.correctWriterFirstCasFilter,
        seededExpiresAtMs: entry.seedRow ? entry.seedRow.expiresAtMs : null,
        renewedExpiresAtMs: entry.offsetWriterRowAfter ? entry.offsetWriterRowAfter.expiresAtMs : null,
        renewedEpoch: entry.offsetWriterRowAfter ? entry.offsetWriterRowAfter.epoch : null,
      })),
      mechanisms: [
        ...violations.map((entry) => ({
          class: 'over-release',
          probeId: entry.probeId,
          kind: entry.kind,
          referenceRemainingLifeMs: entry.remainingLifeMsAtReferenceNow,
          offsetWriterMatched: entry.offsetWriterMatched,
          offsetWriterErrorCode: entry.offsetWriterErrorCode,
        })),
        ...pastExpiryRenewals.map((entry) => ({
          class: 'past-expiry-renewal',
          probeId: entry.probeId,
          kind: entry.kind,
          referenceRemainingLifeMs: entry.remainingLifeMsAtReferenceNow,
          offsetWriterMatched: entry.offsetWriterMatched,
          offsetWriterErrorCode: entry.offsetWriterErrorCode,
        })),
      ],
      notAProductFix:
        'Evidence only. No product byte was changed and no assertion was weakened; the corrective boundary (pin a clock authority / max acceptable skew for lease-state CAS writers, or reject stale-clock writers) is a GM decision.',
    };

    cleanup = await support.fence.dropOwnDatabase(ctx.client, ctx.dbName);

    return {
      id: fixture.id,
      title: fixture.title,
      contractRef: fixture.contractRef,
      tier: 'E2',
      kind: 'skew',
      direction: fixture.direction,
      offsetMs: fixture.offsetMs,
      runnerPid: process.pid,
      productClaim: status === 'PRODUCT_FAIL',
      status,
      exitCode,
      findingRecorded: reproduced,
      finding,
      gate: { status: gateStatus.status, failedCount: gateStatus.failedCount, passedCount: gateStatus.passedCount, checks: gate.checks },
      desiredLaw: { status: lawStatus.status, failedCount: lawStatus.failedCount, passedCount: lawStatus.passedCount, failedAssertions: lawStatus.failedAssertions, checks: law.checks },
      plan: {
        referenceNowMs: k.TRUE_NOW_MS,
        deltaMs: k.DELTA_MS,
        epsilonMs: k.EPSILON_MS,
        skewMarginMs: k.SKEW_MARGIN_MS,
        leaseTtlMs: k.LEASE_TTL_MS,
        predictedOverReleaseHorizonMs: k.PREDICTED_OVER_RELEASE_HORIZON_MS,
        probes: plan.probes.map((probe) => ({
          probeId: probe.probeId,
          kind: probe.kind,
          deviceId: probe.deviceId,
          seedOwnerId: probe.seedOwnerId,
          claimantOwnerId: probe.claimantOwnerId,
          expectedEpoch: probe.expectedEpoch,
          grantId: probe.grantId,
          expiresAtMs: probe.expiresAtMs,
          remainingLifeMsAtReferenceNow: probe.remainingLifeMsAtReferenceNow,
        })),
      },
      dbName: ctx.dbName,
      seededRows: seeded,
      rowsAfter,
      overReleases,
      accountAxis,
      activeBefore,
      activeAfter,
      writers: {
        CORRECT: {
          pid: correct.pid,
          ppid: correct.ppid,
          offsetMs: correct.offsetMs,
          clockNowMs: correct.clockNowMs,
          probeCount: correct.probeCount,
          barrierReached: correct.barrierReached,
          fatal: correct.fatal,
          durationMs: correct.durationMs,
        },
        OFFSET: {
          pid: offset.pid,
          ppid: offset.ppid,
          offsetMs: offset.offsetMs,
          clockNowMs: offset.clockNowMs,
          probeCount: offset.probeCount,
          barrierReached: offset.barrierReached,
          fatal: offset.fatal,
          durationMs: offset.durationMs,
        },
      },
      realReturns: { writers: writerReports },
      processEvidence: {
        spawnCommands: writers.map((writer) => `${process.execPath} ${writer.args.join(' ')}`),
        stdio: 'ignore + stderr to file (piped child stdio is EPERM in this sandbox)',
        transport: 'file barrier (ready/go) + file results; no pipe',
        exits,
        ready,
        barrierDir: path.relative(env.WORKTREE, barrierDir).replace(/\\/g, '/'),
        readyFiles: ['CORRECT', 'OFFSET'].map((role) => ({
          role,
          path: path.relative(env.WORKTREE, path.join(barrierDir, `ready-${role}.json`)).replace(/\\/g, '/'),
          sha256: sha256FileSafe(path.join(barrierDir, `ready-${role}.json`)),
        })),
        outFiles: ['CORRECT', 'OFFSET'].map((role) => ({
          role,
          path: path.relative(env.WORKTREE, path.join(barrierDir, `out-${role}.json`)).replace(/\\/g, '/'),
          sha256: sha256FileSafe(path.join(barrierDir, `out-${role}.json`)),
        })),
        planFile: path.relative(env.WORKTREE, planFile).replace(/\\/g, '/'),
      },
      cleanup,
      provenance: support.provenance(ctx, {
        twoClockDisclosure:
          'Two real OS processes; each writer owns ONE injected deterministic clock (offset 0 and offset delta). No wall-clock value participates in any lease decision or assertion: TRUE_NOW is the fixture reference timeline carried by the correct writer.',
        orderingDisclosure:
          'Both writers are armed at the file barrier before either acts. The CORRECT writer is released first from the pristine preimage; its refusal changes no row, so the offset writer acts on the identical preimage.',
        productPath:
          'Every transition is a real createAuthorityService / createPairingSessionService call over the frozen createModels(mongoose) registry against the real replica set. No raw-driver analog, no behavioural facade, no stub, no retry.',
        expectedEpochDisclosure:
          'The seeded generation (epoch 1) is exactly what the product freezes for a ceremony (pairingSessionService mints claim.expectedEpoch from the authority row), so no harness-invented epoch enters the claim CAS.',
        secretsDisclosure:
          'No minted pairing code, private key, pepper or signature is recorded: only codeIssued / codeDigits and signaturePresent.',
      }),
    };
  } catch (err) {
    return {
      id: fixture.id,
      title: fixture.title,
      contractRef: fixture.contractRef,
      tier: 'E2',
      kind: 'skew',
      runnerPid: process.pid,
      productClaim: false,
      status: 'HARNESS_FAIL',
      exitCode: 4,
      gate: { status: 'HARNESS_FAIL', checks: gate.checks },
      desiredLaw: { status: 'NOT_EVALUATED', checks: law.checks },
      error: `${err.name}: ${err.message}`,
      errorStack: String(err.stack ?? '').split('\n').slice(0, 8),
      dbName: ctx.dbName,
      cleanup,
    };
  } finally {
    for (const writer of writers) {
      if (writer.child.exitCode === null) {
        try {
          writer.child.kill();
        } catch {
          /* best effort */
        }
      }
    }
    cleanup = await support.fence.dropOwnDatabase(ctx.client, ctx.dbName).catch(() => cleanup);
    await ctx.teardown().catch(() => {});
  }
}

module.exports = { FIXTURES, BY_ID, run, buildPlan, overReleaseFor, CHILD };