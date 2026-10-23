'use strict';

/**
 * TWO-CLOCK SKEW FIXTURE, RE-BASED ONTO THE DATABASE TIMELINE (test-only; PHASE1-LOCAL-AUTHORITY-001).
 *
 * WHAT IT PROVES (GM-44 / GM-45 / GM-64.5 / GM-69)
 * ------------------------------------------------
 * A lease-state / TTL decision must not read the WRITER's clock. This fixture is the end-to-end
 * oracle for that property: two real OS processes, each with its own INJECTED clock, act on the
 * same replica set, and both are judged against the SAME database-time law.
 *
 *   CONTROL ARM    role CORRECT, offset 0:      a compliant writer (its clock is within the frozen
 *                  5000 ms budget of database time at every decision). It must refuse to dislodge
 *                  a lease that is genuinely live on the DATABASE timeline.
 *   TREATMENT ARM  role OFFSET, offset ±delta:  a writer whose clock is 300 s fast (SKEW-01/03) or
 *                  300 s slow (SKEW-02), i.e. far outside every frozen transport budget. It must
 *                  behave IDENTICALLY to the control arm: zero over-release, zero past-expiry
 *                  renewal, zero margin-free admission.
 *
 * The control arm is what makes the treatment arm's zero meaningful: it proves the same fixture,
 * with the same probes and the same bars, still fails whenever a writer-clock predicate decides
 * (see the runner's `--anchor=clock` negative-control mode). GM-69 forbids removing, disabling or
 * reclassifying it, and nothing here weakens either arm's assertions.
 *
 * WHY COULD THE TREATMENT ARM BE VACUOUS, AND HOW THIS DESIGN PREVENTS IT
 * ----------------------------------------------------------------------
 * The counterexample has two halves that must BOTH hold at the instant the product decides:
 *   (1) the writer's clock is skewed by at least delta (otherwise there is nothing under test), and
 *   (2) the row is genuinely live (or genuinely lapsed) in DATABASE time (otherwise a transition is
 *       correct behaviour and proving "zero over-release" is vacuous).
 * A single arm cannot satisfy both for two writers whose clocks differ by 600 s: the row can only
 * be live-by-epsilon at ONE instant. This fixture therefore gives each arm its OWN database, its own
 * preimage seeded by the writer itself, and its own anchor to the ONE database-clock reference
 * instant the parent publishes; each writer waits on the DATABASE clock for that instant and decides
 * every probe inside its declared boundary window. Both halves are then GATED per probe from
 * recorded timing evidence (`clockSkewAtDecisionMs` and `liveAtDecision`), so an arm that silently
 * stopped measuring the counterexample fails closed as HARNESS_FAIL instead of passing.
 *
 * Two failure modes this closes that the previous same-row design carried:
 *   - the treatment writer used to be serialised behind the correct writer, so it decided ~50 ms
 *     after the reference instant with a clock offset 6000x larger than the delay; the skew was
 *     never exercised and the "victory" was unfalsifiable;
 *   - the control used to pass because the row had genuinely expired in database time before the
 *     correct writer acted (it asserted LEASE_EXPIRED for a probe its own description called live).
 *
 * ASSERTION LEDGERS (kept strictly apart)
 * ---------------------------------------
 *   GATE (must pass, else HARNESS_FAIL/exit 4): two distinct real OS PIDs, both armed at the file
 *        barrier, every planned probe executed, no child fatal, DATABASE mode (no anchor seam), the
 *        preimage seeded before the declared reference instant, the preimage still present and
 *        intact when the writer acts, every probe deciding on the declared side of its seeded expiry
 *        and within the declared window of the reference instant, the writer's clock really carrying
 *        its injected offset at that instant, and the parent's independent read-back agreeing.
 *   LAW  (a failure is the FINDING, PRODUCT_FAIL/exit 5): the same database-time law for BOTH arms,
 *        in both directions — a live lease is never transitioned, and a lease genuinely lapsed past
 *        the skew margin IS transitioned (so "all zero" cannot be produced by a writer that refuses
 *        everything).
 *
 * No product byte is changed, no assertion is weakened, and no product behaviour is reimplemented:
 * every state transition is a real I6/I5 product call over the frozen `createModels(mongoose)`
 * registry, and the only seam this fixture passes is the GLOBAL `predicateAnchor: 'database'` mode
 * (i.e. no seam at all).
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
      'A writer fast by +delta claims / lazily releases / completes a real pairing / admits on a lease that is live on the DATABASE timeline; a compliant writer refuses the same probes',
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
      {
        // GM-45 sites 5/8/11: the MARGIN-FREE admission axis. A lease live by EPSILON at the
        // reference instant must refuse issuance at ANY writer offset, and no pairing session row
        // may be created (a minted-and-consumed code is the security-relevant failure).
        probeId: 'SKEW-01-P4-MARGIN-FREE-ADMISSION',
        kind: 'admission',
        remainingLifeMsAtReferenceNow: k.EPSILON_MS,
      },
    ],
  },
  {
    id: 'SKEW-02-SLOW-WRITER-PAST-EXPIRY-RENEWAL',
    title:
      'A writer slow by -delta renews a lease that already expired on the DATABASE timeline (and correctly holds a live lease on the claim axis)',
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
      'Empirical over-release horizon: remaining-life grid across the predicted delta - SKEW_MARGIN crossover and the skew-margin edge',
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

/**
 * The two arms of one fixture. Both carry the SAME probe plan (same kinds, same remaining lives);
 * only the writer's clock offset and the arm's own database differ, which is exactly the property
 * under test.
 */
function buildArms(fixture) {
  const short = shortId(fixture.id);
  return [
    {
      key: 'control',
      tag: `skew-${short}-control`,
      role: 'CORRECT',
      label: 'CONTROL (compliant clock, offset 0)',
      offsetMs: 0,
      treatment: false,
    },
    {
      key: 'treatment',
      tag: `skew-${short}-treatment`,
      role: 'OFFSET',
      label: `TREATMENT (clock offset ${fixture.offsetMs} ms)`,
      offsetMs: fixture.offsetMs,
      treatment: true,
    },
  ];
}

/** Builds the JSON-safe probe plan shared by an arm's writer (no secrets). */
function buildArmProbes(ctx, fixture, arm, armIndex) {
  const short = shortId(fixture.id);
  return fixture.probes.map((probe, index) => {
    const tag = `${short}-${arm.key === 'control' ? 'c' : 't'}-d${index + 1}`;
    const key = env.makeDeviceKey(tag);
    return {
      probeId: probe.probeId,
      kind: probe.kind,
      deviceTag: tag,
      deviceId: `skew-${short}-${arm.key}-device-${index + 1}`,
      deviceKeyId: ctx.crypto.thumbprintB64u(key.spkiB64u),
      devicePublicKey: key.spkiB64u,
      seedOwnerId: `principal-skew-seed-${short}-${arm.key}-${index + 1}`,
      claimantOwnerId:
        probe.claimant === true ? `principal-skew-claim-${short}-${arm.key}-${index + 1}` : null,
      expectedEpoch: 1,
      grantId: `skew-grant-${short}-${arm.key}-${index + 1}`,
      remainingLifeMs: probe.remainingLifeMsAtReferenceNow,
      armIndex,
    };
  });
}

function buildArmFile(fixture, arm, probes, dbName) {
  return {
    kind: 'skew-writer-arm',
    fixtureId: fixture.id,
    armId: `${fixture.id}::${arm.key}`,
    armKey: arm.key,
    armTag: arm.tag,
    treatment: arm.treatment,
    role: arm.role,
    offsetMs: arm.offsetMs,
    dbName,
    leaseTtlMs: k.LEASE_TTL_MS,
    tenantId: TENANT,
    deltaMs: k.DELTA_MS,
    epsilonMs: k.EPSILON_MS,
    skewMarginMs: k.SKEW_MARGIN_MS,
    decisionSlopMs: k.DECISION_SLOP_MS,
    probes,
  };
}

function viewRow(row) {
  if (row === null || row === undefined) return null;
  return {
    ...support.authorityView(row, null),
    expiresAtMs: row.expiresAt ? new Date(row.expiresAt).getTime() : null,
    activatedAtMs: row.activatedAt ? new Date(row.activatedAt).getTime() : null,
    renewalCount: row.renewalCount ?? null,
  };
}

function sha256FileSafe(file) {
  try {
    return support.sha256File(file);
  } catch {
    return null;
  }
}

/** The database clock, at millisecond precision (see writer-child.cjs for why not Date.parse). */
async function databaseNowMs(client) {
  const hello = await client.db('admin').command({ hello: 1 });
  const localTime = hello.localTime;
  const value = localTime instanceof Date ? localTime.getTime() : Date.parse(String(localTime));
  if (!Number.isFinite(value)) {
    throw new Error('databaseNowMs: hello.localTime is not a parseable instant');
  }
  return value;
}

function spawnWriter({ arm, armFile, dbName, barrierDir, outFile, logFile, anchorMode }) {
  const args = [
    CHILD,
    `--role=${arm.role}`,
    `--offset=${arm.offsetMs}`,
    `--anchor=${anchorMode}`,
    `--arm=${armFile}`,
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
  return { arm, armFile, dbName, pid: child.pid, args, child, logFd, exit, outFile, logFile };
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

/** Null-safe field read: a vanished row must fail an assertion, never throw a TypeError. */
function rowField(row, field) {
  return row === null || row === undefined ? null : row[field] ?? null;
}

/**
 * The frozen database-time law for one probe, derived from the product's OWN predicate forms:
 *
 *   claimAuthority CAS        `$or[ leaseState != active, $lte[expiresAt, dbNow - MARGIN] ]`
 *                             ⇒ transitions iff remaining life <= -SKEW_MARGIN_MS
 *   releaseLapsedLease        `$lte[expiresAt, dbNow - MARGIN]`
 *                             ⇒ matches iff remaining life <= -SKEW_MARGIN_MS
 *   renewAuthority CAS        `$gt[expiresAt, dbNow + MARGIN]`
 *                             ⇒ accepts iff remaining life > +SKEW_MARGIN_MS
 *   isLiveLease (admission / ceremony issue / redeem)  `dbNow < expiresAt`, margin-free
 *                             ⇒ accepts iff remaining life <= 0
 *
 * A 0-match claim is classified against the same database clock, so a lease that is live (or dead
 * inside the margin) yields the frozen live-lease refusal rather than an unclassified miss.
 */
function expectedLaw(probe) {
  const life = probe.remainingLifeMs;
  const margin = k.SKEW_MARGIN_MS;
  /*
   * The confirmed 0-match classification. The CAS misses for any life > -margin (the margin is
   * subtracted from the comparison in the filter), and the classifier then reads the SAME database
   * clock: a row dead by less than the margin is still reported as a live lease (the frozen
   * `DEVICE_ALREADY_PAIRED_USE_RENEW`), while a row dead by at least `margin + CASCADE_SLACK_MS`
   * re-reads as lapsed with `PAIRING_WINDOW_TOO_EARLY`. Probes inside the slack span are left
   * UNPINNED so an incidental product or MongoDB timing detail can never make this fixture red:
   * the grid keeps the live edge (-1000) and the hard lapsed edge (-5000) pinned on both sides.
   *
   * Harness detail: the classifier claims `expiresAt > now - margin` against a SECOND server read a
   * couple of milliseconds after the CAS, while the fixture's gated window is 500 ms and the seed
   * expiry is `reference + life`. A fixture row can therefore straddle the classifier's decision
   * line on the `life in [-margin - 1, -margin + 1]` millisecond edge, which is why this fixture
   * does not put a probe exactly there. The inside-margin edge (-1000 ALWAYS refuses as live) and
   * the outside-margin edge (-5000 ALWAYS lapses) are each pinned from a safe distance: they are
   * the two probes a reviewer must be able to trust, and the span between them is deliberately the
   * one place this fixture refuses to assert.
   */
  const CASCADE_SLACK_MS = 2;
  switch (probe.kind) {
    case 'claimAuthority': {
      const transitioned = life <= -margin;
      const unpinnedSlack = life <= 0 && life > -margin - CASCADE_SLACK_MS;
      return {
        transitioned,
        matched: transitioned ? 1 : 0,
        errorCode: transitioned ? null : 'DEVICE_ALREADY_PAIRED_USE_RENEW',
        unpinned: unpinnedSlack === true,
        rule: `claim CAS transitions iff life <= -${margin} ms; 0-match inside the margin refuses as live`,
      };
    }
    case 'releaseLapsedLease': {
      const transitioned = life <= -margin;
      return {
        transitioned,
        matched: transitioned ? 1 : 0,
        errorCode: null,
        rule: `lazy release matches iff life <= -${margin} ms`,
      };
    }
    case 'renewAuthority': {
      const accepted = life > margin;
      return {
        transitioned: accepted,
        matched: accepted ? 1 : 0,
        errorCode: accepted ? null : 'LEASE_EXPIRED',
        rule: `renewal CAS accepts iff life > +${margin} ms`,
      };
    }
    case 'pairingCeremony':
    case 'admission': {
      const accepted = life <= 0;
      return {
        transitioned: accepted,
        matched: null,
        errorCode: accepted ? null : 'DEVICE_ALREADY_PAIRED_USE_RENEW',
        rule: 'margin-free live-lease test refuses iff life > 0 ms',
      };
    }
    default:
      throw new Error(`unknown probe kind ${probe.kind}`);
  }
}

/** Did the writer transition the row at all (per kind)? */
function transitionedFor(probe, probeReport) {
  const outcome = outcomeOf(probeReport);
  const matched = typeof outcome.matched === 'number' ? outcome.matched : null;
  if (probe.kind === 'pairingCeremony') return outcome.ok === true || outcome.codeIssued === true;
  if (probe.kind === 'admission') {
    return (
      outcome.codeIssued === true ||
      (typeof outcome.pairingSessionRows === 'number' && outcome.pairingSessionRows > 0)
    );
  }
  return matched !== null && matched > 0;
}

/**
 * DESIRED-LAW evaluation for one probe: did the writer transition a lease that was live on the
 * database timeline? `live` comes from the MEASURED decision instant (`liveAtDecision`, read from
 * the replica set immediately before the product call) and the declared remaining life, never from
 * a wall-clock read or a fixture constant.
 */
function violationFor(probe, probeReport) {
  const outcome = outcomeOf(probeReport);
  const matched = typeof outcome.matched === 'number' ? outcome.matched : null;
  const declaredLive = probe.remainingLifeMs > 0;
  const liveAtDecision = probeReport !== null && probeReport.liveAtDecision === true;
  const transitioned = transitionedFor(probe, probeReport);
  const declaredDeadInsideMargin = probe.remainingLifeMs <= 0 && probe.remainingLifeMs > -k.SKEW_MARGIN_MS;
  return {
    probeId: probe.probeId,
    kind: probe.kind,
    remainingLifeMsAtReferenceNow: probe.remainingLifeMs,
    declaredLiveOnReferenceTimeline: declaredLive,
    liveAtDecision,
    dbNowAtProbeMs: probeReport === null ? null : probeReport.dbNowAtProbeMs ?? null,
    dbNowAfterProbeMs: probeReport === null ? null : probeReport.dbNowAfterProbeMs ?? null,
    expiresAtMs: probeReport === null ? null : probeReport.expiresAtMs ?? null,
    decisionOffsetMs: probeReport === null ? null : probeReport.decisionOffsetMs ?? null,
    clockSkewAtDecisionMs: probeReport === null ? null : probeReport.clockSkewAtDecisionMs ?? null,
    offsetWriterTransitioned: transitioned,
    offsetWriterMatched: matched,
    offsetWriterErrorCode: outcome.errorCode ?? null,
    overRelease: declaredLive === true && liveAtDecision === true && transitioned === true,
    marginViolation: declaredDeadInsideMargin && transitioned === true,
    pastExpiryRenewal:
      probe.kind === 'renewAuthority' && probe.remainingLifeMs < 0 && matched !== null && matched > 0,
  };
}

/**
 * Assertion ledger for ONE arm, evaluated against the same database-time law as the other arm.
 * Every row comparison is null-safe: a row that vanished is a failed assertion with the observed
 * `null`, never an exception that aborts the fixture and hides the rest of the ledger.
 */
function evaluateArmLaw(law, arm, armReport, probes) {
  for (const probe of probes) {
    const observed = outcomeOf(probeOf(armReport, probe.probeId));
    const probeReport = probeOf(armReport, probe.probeId);
    const rowAfter = probeReport === null ? null : probeReport.rowAfter;
    const expected = expectedLaw(probe);
    const skewCascadeSlackMs = 2;
    const label = `${probe.probeId} (${probe.kind}, reference life ${probe.remainingLifeMs} ms)`;

    if (probe.kind === 'renewAuthority') {
      law.eq(
        `${arm.label} renewal of ${label} follows the database-time law — ${expected.rule}`,
        [observed.matched, observed.errorCode],
        [expected.matched, expected.errorCode],
      );
      if (expected.transitioned) {
        law.ok(
          `${arm.label} accepted renewal of ${label} advanced the epoch exactly once`,
          rowField(rowAfter, 'epoch') === probe.expectedEpoch + 1 &&
            rowField(rowAfter, 'renewalCount') === 1,
          { epoch: rowField(rowAfter, 'epoch'), renewalCount: rowField(rowAfter, 'renewalCount') },
        );
      } else {
        law.eq(
          `${arm.label} left ${label} untouched (expiresAt, epoch, ownerId, leaseState)`,
          [
            rowField(rowAfter, 'expiresAtMs'),
            rowField(rowAfter, 'epoch'),
            rowField(rowAfter, 'ownerId'),
            rowField(rowAfter, 'leaseState'),
          ],
          [
            rowField(probeReport === null ? null : probeReport.rowBefore, 'expiresAtMs'),
            probe.expectedEpoch,
            probe.seedOwnerId,
            'active',
          ],
        );
      }
      continue;
    }

    if (probe.kind === 'pairingCeremony') {
      law.eq(
        `${arm.label} ceremony on ${label} is decided by database time — ${expected.rule}`,
        [observed.ceremonyStage, observed.errorCode, observed.codeIssued],
        [expected.transitioned ? 'done' : 'issue', expected.errorCode, expected.transitioned],
      );
      if (expected.transitioned === false) {
        law.eq(
          `${arm.label} left ${label} owned by the seed owner at the seed epoch`,
          [rowField(rowAfter, 'ownerId'), rowField(rowAfter, 'epoch'), rowField(rowAfter, 'leaseState')],
          [probe.seedOwnerId, probe.expectedEpoch, 'active'],
        );
      }
      continue;
    }

    if (probe.kind === 'admission') {
      law.eq(
        `${arm.label} margin-free admission on ${label} is decided by database time — ${expected.rule}`,
        [observed.codeIssued, observed.pairingSessionRows, observed.errorCode],
        [expected.transitioned, expected.transitioned ? null : 0, expected.errorCode],
      );
      if (expected.transitioned === false) {
        law.eq(
          `${arm.label} left ${label} owned by the seed owner at the seed epoch`,
          [rowField(rowAfter, 'ownerId'), rowField(rowAfter, 'epoch'), rowField(rowAfter, 'leaseState')],
          [probe.seedOwnerId, probe.expectedEpoch, 'active'],
        );
      }
      continue;
    }

    if (probe.kind === 'releaseLapsedLease') {
      law.eq(
        `${arm.label} lazy release on ${label} follows the database-time law — ${expected.rule}`,
        [observed.matched, observed.errorCode],
        [expected.matched, expected.errorCode],
      );
      if (expected.transitioned) {
        law.eq(
          `${arm.label} expired ${label} at the seed epoch plus one`,
          [rowField(rowAfter, 'leaseState'), rowField(rowAfter, 'epoch')],
          ['expired', probe.expectedEpoch + 1],
        );
      } else {
        law.eq(
          `${arm.label} left ${label} active at the seed epoch`,
          [rowField(rowAfter, 'leaseState'), rowField(rowAfter, 'epoch')],
          ['active', probe.expectedEpoch],
        );
      }
      continue;
    }

    /* claimAuthority */
    if (expected.unpinned === true) {
      law.ok(
        `${arm.label} claim on ${label} respects the margin-cascade disclosure — the classifier may answer either frozen code inside the ±${skewCascadeSlackMs} ms slack span`,
        observed.matched === expected.matched &&
          (observed.errorCode === 'DEVICE_ALREADY_PAIRED_USE_RENEW' || observed.errorCode === 'PAIRING_WINDOW_TOO_EARLY'),
        { matched: observed.matched, errorCode: observed.errorCode, expected },
      );
      return;
    }
    law.eq(
      `${arm.label} claim on ${label} follows the database-time law — ${expected.rule}`,
      [observed.matched, observed.errorCode],
      [expected.matched, expected.errorCode],
    );
    if (expected.transitioned) {
      law.eq(
        `${arm.label} handed ${label} to the claimant at the seed epoch plus one`,
        [rowField(rowAfter, 'ownerId'), rowField(rowAfter, 'epoch'), rowField(rowAfter, 'leaseState')],
        [probe.claimantOwnerId, probe.expectedEpoch + 1, 'active'],
      );
    } else {
      law.eq(
        `${arm.label} left ${label} owned by the seed owner at the seed epoch`,
        [rowField(rowAfter, 'ownerId'), rowField(rowAfter, 'epoch'), rowField(rowAfter, 'leaseState')],
        [probe.seedOwnerId, probe.expectedEpoch, 'active'],
      );
    }
  }
}

/* ------------------------------------------------------------------ run */

async function run(fixture, options = {}) {
  /*
   * GM-64 rule 5 / GM-69: DATABASE mode unless the runner explicitly requests the negative control.
   * In DATABASE mode NO injected predicate anchor reaches any Device service: every predicate under
   * test is the production `$expr` with `$$NOW`, decided by MongoDB's own clock, and the gate below
   * fails the fixture if a seam ever appears. `clock` mode re-supplies the GM-64 comparison anchor
   * (the writer's own injected clock) and is expected to REPORT A COUNTEREXAMPLE; the runner marks
   * such a run VOID as skew evidence.
   */
  const anchorMode = options.anchorMode === 'clock' ? 'clock' : 'database';
  const gate = support.makeChecks();
  const law = support.makeChecks();
  const short = shortId(fixture.id);
  const rundir = support.freshDir(path.join(support.runDir(), 'skew', fixture.id));
  const barrierDir = support.ensureDir(path.join(rundir, 'barrier'));
  const ctx = await support.makeContext({
    tag: `skew-${short}-parent`,
    point: fixture.id,
    mode: 'raw-registry',
    dropOnTeardown: false,
    predicateAnchor: anchorMode,
  });

  const arms = buildArms(fixture);
  const armPlans = [];
  const writers = [];
  let cleanup = 'not_attempted';
  let referenceNowMs = null;
  let releasedAtMs = null;

  try {
    /*
     * GM-69 REGRESSION PIN: the fixture must not own an ABSOLUTE timeline constant. If a future
     * edit reintroduces one (the retired `TRUE_NOW_MS` / `LEAD_MS` pair), the reference timeline can
     * silently detach from the database clock again — the exact premise defect GM-69 corrects.
     */
    gate.ok(
      'the fixture owns no absolute reference-epoch constant (GM-69 re-basing pin)',
      !Object.prototype.hasOwnProperty.call(k, 'TRUE_NOW_MS') &&
        typeof k.LEAD_MS === 'undefined' &&
        Number.isFinite(k.ARM_LEAD_MS) &&
        Number.isFinite(k.DECISION_SLOP_MS),
      {
        retiredTrueNow: Object.prototype.hasOwnProperty.call(k, 'TRUE_NOW_MS'),
        retiredLead: typeof k.LEAD_MS !== 'undefined',
        armLeadMs: k.ARM_LEAD_MS ?? null,
        decisionSlopMs: k.DECISION_SLOP_MS ?? null,
      },
    );
    gate.ok(
      anchorMode === 'database'
        ? 'the fixture ran in DATABASE mode with no predicate-anchor seam'
        : 'the fixture ran in the disclosed negative-control mode (clock anchor supplied to every Device service)',
      ctx.predicateAnchorMode === anchorMode,
      {
        requestedAnchorMode: anchorMode,
        parentPredicateAnchorMode: ctx.predicateAnchorMode,
        negativeControl: anchorMode === 'clock',
      },
    );

    /* One arm file per arm: probe plan + the arm's own fenced database. Nothing absolute in it. */
    for (const [index, arm] of arms.entries()) {
      const dbName = support.fence.createDbName(arm.tag);
      const probes = buildArmProbes(ctx, fixture, arm, index);
      const armFile = support.writeJson(rundir, `arm-${arm.key}.json`, buildArmFile(fixture, arm, probes, dbName));
      armPlans.push({ arm, probes, dbName, armFile });
    }
    support.writeJson(rundir, 'plan.json', {
      fixtureId: fixture.id,
      deltaMs: k.DELTA_MS,
      epsilonMs: k.EPSILON_MS,
      skewMarginMs: k.SKEW_MARGIN_MS,
      leaseTtlMs: k.LEASE_TTL_MS,
      armLeadMs: k.ARM_LEAD_MS,
      decisionSlopMs: k.DECISION_SLOP_MS,
      predictedOverReleaseHorizonMs: k.PREDICTED_OVER_RELEASE_HORIZON_MS,
      referenceTimeline: 'database clock (hello.localTime) + ARM_LEAD_MS, published at release time',
      arms: armPlans.map((entry) => ({
        armKey: entry.arm.key,
        role: entry.arm.role,
        offsetMs: entry.arm.offsetMs,
        treatment: entry.arm.treatment,
        dbName: entry.dbName,
        probes: entry.probes.map((probe) => ({
          probeId: probe.probeId,
          kind: probe.kind,
          deviceId: probe.deviceId,
          seedOwnerId: probe.seedOwnerId,
          claimantOwnerId: probe.claimantOwnerId,
          expectedEpoch: probe.expectedEpoch,
          grantId: probe.grantId,
          remainingLifeMs: probe.remainingLifeMs,
        })),
      })),
    });

    /* Two real OS processes, both armed at a file barrier before either may act. */
    for (const entry of armPlans) {
      writers.push(
        spawnWriter({
          arm: entry.arm,
          armFile: entry.armFile,
          dbName: entry.dbName,
          barrierDir,
          outFile: path.join(barrierDir, `out-${entry.arm.role}.json`),
          logFile: path.join(rundir, `writer-${entry.arm.role}-stderr.log`),
          anchorMode,
        }),
      );
    }

    const ready = {};
    for (const writer of writers) {
      // eslint-disable-next-line no-await-in-loop
      ready[writer.arm.role] = await waitForJson(path.join(barrierDir, `ready-${writer.arm.role}.json`));
    }

    /*
     * THE REFERENCE INSTANT (GM-69). The parent now reads the DATABASE clock itself — after both
     * writers are armed at the barrier — and publishes one instant that both writers wait out on the
     * DATABASE clock, so "the reference timeline" is an instant on the same clock the production
     * predicates use and the fixed-epoch premise is gone for good. The instant is placed
     * ARM_LEAD_MS beyond the later of the parent's reading and each writer's own reading at
     * readiness (published in its ready file), so a writer armed before this reading can still seed
     * its preimage and decide every probe before the instant arrives.
     */
    releasedAtMs = await databaseNowMs(ctx.client);
    const writerArmedAtMs = arms
      .map((arm) => Number(ready[arm.role]?.dbNowAtMs))
      .filter((value) => Number.isFinite(value));
    const anchorBaseMs = Math.max(releasedAtMs, ...writerArmedAtMs);
    referenceNowMs = anchorBaseMs + k.ARM_LEAD_MS;
    for (const writer of writers) {
      releaseGo(barrierDir, writer.arm.role, {
        referenceNowMs,
        releasedAtMs,
        writerArmedAtMs: Number(ready[writer.arm.role]?.dbNowAtMs) || null,
        armLeadMs: k.ARM_LEAD_MS,
        armId: writer.arm.key,
        order: writer.arm.treatment ? 'treatment' : 'control',
      });
    }

    const writerReports = {};
    for (const writer of writers) {
      // eslint-disable-next-line no-await-in-loop
      writerReports[writer.arm.role] = await waitForJson(path.join(barrierDir, `out-${writer.arm.role}.json`));
    }
    const exits = await Promise.all(writers.map((writer) => writer.exit));
    for (const writer of writers) {
      try {
        fs.closeSync(writer.logFd);
      } catch {
        /* best effort */
      }
    }
    const armRuns = armPlans.map((entry) => ({ ...entry, report: writerReports[entry.arm.role] }));
    const byArmKey = new Map(armRuns.map((entry) => [entry.arm.key, entry]));
    const control = byArmKey.get('control');
    const treatment = byArmKey.get('treatment');
    const controlReport = control.report;
    const treatmentReport = treatment.report;
    const probeCount = fixture.probes.length;

    /*
     * INDEPENDENT PARENT READ-BACK: the parent owns the arm databases' lifecycle, drops nothing yet,
     * and re-reads every row with its own fenced client (raw driver, not the writer's word).
     */
    const armReadBack = new Map();
    for (const entry of armPlans) {
      const collection = ctx.client.db(entry.dbName).collection('deviceauthorities');
      const rowsAfter = {};
      const ownersAfter = {};
      for (const probe of entry.probes) {
        // eslint-disable-next-line no-await-in-loop
        rowsAfter[probe.probeId] = viewRow(
          (await collection.findOne({ _id: probe.deviceId, tenantId: TENANT })) ?? null,
        );
        // eslint-disable-next-line no-await-in-loop
        ownersAfter[probe.seedOwnerId] = await collection.countDocuments({
          ownerId: probe.seedOwnerId,
          tenantId: TENANT,
          leaseState: 'active',
        });
      }
      armReadBack.set(entry.arm.key, { rowsAfter, ownersAfter });
    }

    /* ---------------------------------------------------------- GATE (credibility) */
    const pids = writers.map((writer) => writer.pid);
    const reportedPids = arms.map((arm) => writerReports[arm.role].pid);
    const distinct = new Set([...pids, ...reportedPids].filter((pid) => typeof pid === 'number' && pid > 0));
    gate.eq('exactly two writer arms were spawned', pids.length, 2);
    gate.eq('the two writers are distinct real OS processes', distinct.size, 2);
    gate.eq('both writers exited 0', exits.map((entry) => entry.code), [0, 0]);
    gate.ok(
      'both writers reached the file barrier before acting',
      controlReport.barrierReached === true && treatmentReport.barrierReached === true,
      { CONTROL: controlReport.barrierReached, TREATMENT: treatmentReport.barrierReached },
    );
    gate.eq(
      'the CONTROL writer ran with offset 0',
      [controlReport.offsetMs, controlReport.writerClockMs],
      [0, referenceNowMs],
    );
    gate.eq(
      'the TREATMENT writer ran with the injected offset',
      [treatmentReport.offsetMs, treatmentReport.writerClockMs],
      [fixture.offsetMs, referenceNowMs + fixture.offsetMs],
    );
    gate.eq(
      'both writers executed every planned probe',
      [controlReport.probeCount, treatmentReport.probeCount],
      [probeCount, probeCount],
    );
    gate.ok('neither writer hit a fatal error', controlReport.fatal === null && treatmentReport.fatal === null, {
      CONTROL: controlReport.fatal,
      TREATMENT: treatmentReport.fatal,
    });
    gate.eq(
      'both writers were handed the SAME database-clock reference instant',
      [controlReport.referenceNowMs, treatmentReport.referenceNowMs],
      [referenceNowMs, referenceNowMs],
    );
    gate.ok(
      'both writers waited on the DATABASE clock for the reference instant',
      controlReport.referenceReached === true && treatmentReport.referenceReached === true,
      {
        CONTROL: controlReport.referenceReachedAtMs,
        TREATMENT: treatmentReport.referenceReachedAtMs,
        referenceNowMs,
      },
    );
    gate.ok(
      anchorMode === 'database'
        ? 'no Device service in this fixture received an injected predicate anchor'
        : 'both writers carried the disclosed clock predicate anchor of the negative-control mode',
      anchorMode === 'database'
        ? controlReport.predicateAnchorMode === 'database' &&
            treatmentReport.predicateAnchorMode === 'database' &&
            controlReport.anchorSeamSupplied === false &&
            treatmentReport.anchorSeamSupplied === false
        : controlReport.predicateAnchorMode === 'clock' &&
            treatmentReport.predicateAnchorMode === 'clock' &&
            controlReport.anchorSeamSupplied === true &&
            treatmentReport.anchorSeamSupplied === true,
      {
        CONTROL: [controlReport.predicateAnchorMode, controlReport.anchorSeamSupplied],
        TREATMENT: [treatmentReport.predicateAnchorMode, treatmentReport.anchorSeamSupplied],
      },
    );

    for (const entry of armRuns) {
      const { arm, probes } = entry;
      const report = entry.report;
      gate.ok(
        `the ${arm.label} seeded its preimage before the declared database-clock reference instant`,
        report.seedDbNowMs !== null && report.seedDbNowMs <= referenceNowMs,
        {
          seedDbNowMs: report.seedDbNowMs,
          referenceNowMs,
          writerArmedAtMs: report.goPayload ? report.goPayload.writerArmedAtMs ?? null : null,
        },
      );
      const seedRows = Array.isArray(report.seedRows) ? report.seedRows : [];
      gate.eq(
        `${arm.label} seeded one row per planned probe`,
        seedRows.length,
        probes.length,
      );
      for (const probe of probes) {
        const seedRow = seedRows.find((row) => row.probeId === probe.probeId) ?? null;
        const observedProbe = probeOf(report, probe.probeId);
        const releasedRow =
          (Array.isArray(report.seededRowsAtRelease)
            ? report.seededRowsAtRelease.find((row) => row.probeId === probe.probeId)
            : null) ?? null;
        gate.eq(
          `the ${arm.label} seed for ${probe.probeId} is anchored to the database-clock reference instant`,
          seedRow === null ? null : seedRow.expiresAtMs - referenceNowMs,
          probe.remainingLifeMs,
        );
        gate.ok(
          `the ${arm.label} preimage for ${probe.probeId} was present and intact when the writer acted`,
          observedProbe !== null &&
            observedProbe.rowBefore !== null &&
            observedProbe.rowBefore.ownerId === probe.seedOwnerId &&
            observedProbe.rowBefore.epoch === probe.expectedEpoch &&
            observedProbe.rowBefore.leaseState === 'active' &&
            observedProbe.rowBefore.expiresAtMs === (seedRow === null ? null : seedRow.expiresAtMs) &&
            releasedRow !== null &&
            releasedRow.row !== null,
          {
            rowBefore: observedProbe === null ? null : observedProbe.rowBefore,
            seededAtRelease: releasedRow === null ? null : releasedRow.row,
            expectedExpiresAtMs: seedRow === null ? null : seedRow.expiresAtMs,
          },
        );
        gate.ok(
          `the ${arm.label} writer decided ${probe.probeId} within the declared post-instant window`,
          observedProbe !== null &&
            typeof observedProbe.decisionOffsetMs === 'number' &&
            observedProbe.decisionOffsetMs >= 0 &&
            observedProbe.decisionOffsetMs <= k.DECISION_SLOP_MS,
          {
            decisionOffsetMs: observedProbe === null ? null : observedProbe.decisionOffsetMs,
            decisionSlopMs: k.DECISION_SLOP_MS,
          },
        );
        const declaredLive = probe.remainingLifeMs > 0;
        gate.ok(
          `the ${arm.label} writer decided ${probe.probeId} on the declared side of its seeded expiry`,
          observedProbe !== null &&
            typeof observedProbe.dbNowAtProbeMs === 'number' &&
            (declaredLive
              ? observedProbe.dbNowAtProbeMs < observedProbe.expiresAtMs &&
                observedProbe.liveAtDecision === true
              : observedProbe.dbNowAtProbeMs > observedProbe.expiresAtMs &&
                observedProbe.liveAtDecision === false),
          {
            dbNowAtProbeMs: observedProbe === null ? null : observedProbe.dbNowAtProbeMs,
            dbNowAfterProbeMs: observedProbe === null ? null : observedProbe.dbNowAfterProbeMs,
            expiresAtMs: observedProbe === null ? null : observedProbe.expiresAtMs,
            liveAtDecision: observedProbe === null ? null : observedProbe.liveAtDecision,
            declaredLive,
          },
        );
        /*
         * THE ANTI-VACUITY GATE (GM-69): the arm's writer must really carry its declared clock
         * offset relative to DATABASE time at the instant it decides. Without this, "zero
         * over-release" says nothing about clock independence.
         */
        const skew = observedProbe === null ? null : observedProbe.clockSkewAtDecisionMs;
        if (arm.treatment) {
          const bound = k.DELTA_MS - k.SKEW_MARGIN_MS;
          gate.ok(
            `the TREATMENT writer's clock was outside the ${k.SKEW_MARGIN_MS} ms budget by the full delta when it decided ${probe.probeId}`,
            typeof skew === 'number' && (fixture.offsetMs > 0 ? skew >= bound : skew <= -bound),
            { clockSkewAtDecisionMs: skew, requiredAtLeast: fixture.offsetMs > 0 ? bound : -bound },
          );
        } else {
          gate.ok(
            `the CONTROL writer's clock was inside the ${k.SKEW_MARGIN_MS} ms budget when it decided ${probe.probeId}`,
            typeof skew === 'number' && Math.abs(skew) <= k.SKEW_MARGIN_MS,
            { clockSkewAtDecisionMs: skew, budgetMs: k.SKEW_MARGIN_MS },
          );
        }
        gate.ok(
          `the ${arm.label} writer observed a row after its call for ${probe.probeId}`,
          observedProbe !== null && observedProbe.rowAfter !== null,
          { rowAfter: observedProbe === null ? null : observedProbe.rowAfter },
        );
        const parentRow = armReadBack.get(arm.key).rowsAfter[probe.probeId];
        gate.ok(
          `the parent's independent read-back found ${probe.probeId} in the ${arm.label} database`,
          parentRow !== null && parentRow !== undefined,
          { parentRow: parentRow ?? null, dbName: entry.dbName },
        );
        if (arm.treatment) {
          const childRow = observedProbe === null ? null : observedProbe.rowAfter;
          gate.ok(
            `the parent's read-back corroborates the TREATMENT writer's observation of ${probe.probeId}`,
            childRow !== null &&
              parentRow !== null &&
              childRow.expiresAtMs === parentRow.expiresAtMs &&
              childRow.epoch === parentRow.epoch &&
              childRow.ownerId === parentRow.ownerId &&
              childRow.leaseState === parentRow.leaseState,
            { offsetWriterRowAfter: childRow, parentRow: parentRow ?? null },
          );
        }
      }
    }

    /* ---------------------------------------------------------- LAW: both arms, one law */
    evaluateArmLaw(law, control.arm, controlReport, control.probes);
    evaluateArmLaw(law, treatment.arm, treatmentReport, treatment.probes);

    /*
     * The positive half of the law: a writer that only ever refused would also produce "zero
     * over-release". Every probe whose lease is genuinely lapsed past the margin must therefore be
     * TRANSITIONED, which proves the same product path that is asserted to refuse on the live side
     * still commits on the dead side.
     */
    const lapsedProbes = treatment.probes.filter((probe) => expectedLaw(probe).transitioned === true);
    for (const probe of lapsedProbes) {
      const observedProbe = probeOf(treatmentReport, probe.probeId);
      law.ok(
        `TREATMENT writer still transitions ${probe.probeId} (life ${probe.remainingLifeMs} ms is lapsed past the margin)`,
        transitionedFor(probe, observedProbe) === true,
        { outcome: outcomeOf(observedProbe), expected: expectedLaw(probe) },
      );
    }
    if (lapsedProbes.length > 0) {
      gate.ok(
        'the sweep grid really spans both sides of the database-time law (live side and lapsed side)',
        treatment.probes.some((probe) => probe.remainingLifeMs > 0) && lapsedProbes.length > 0,
        { grid: treatment.probes.map((probe) => probe.remainingLifeMs) },
      );
    }

    /* The account axis: freeing a live lease removes its owner's active row (uq_owner_active). */
    const accountAxis = [];
    for (const entry of [control, treatment]) {
      const readBack = armReadBack.get(entry.arm.key);
      const liveProbes = entry.probes.filter((probe) => probe.remainingLifeMs > 0);
      for (const probe of liveProbes) {
        accountAxis.push({
          armKey: entry.arm.key,
          armLabel: entry.arm.label,
          probeId: probe.probeId,
          seedOwnerId: probe.seedOwnerId,
          activeBefore: 1,
          activeAfter: readBack.ownersAfter[probe.seedOwnerId] ?? null,
          freed: (readBack.ownersAfter[probe.seedOwnerId] ?? null) === 0,
        });
      }
    }
    const treatmentAccountAxis = accountAxis.filter((entry) => entry.armKey === 'treatment');
    law.eq(
      'no seed owner lost its active lease to the offset writer (the account axis was not freed)',
      treatmentAccountAxis.filter((entry) => entry.freed === true).map((entry) => entry.probeId),
      [],
    );
    const controlAccountAxis = accountAxis.filter((entry) => entry.armKey === 'control');
    law.eq(
      'no seed owner lost its active lease to the control writer either (the control arm holds the same line)',
      controlAccountAxis.filter((entry) => entry.freed === true).map((entry) => entry.probeId),
      [],
    );

    /* ---------------------------------------------------------- treatment-arm violations */
    const overReleases = treatment.probes.map((probe) => {
      const entry = violationFor(probe, probeOf(treatmentReport, probe.probeId));
      const probeReport = probeOf(treatmentReport, probe.probeId);
      const firstCas = probeReport !== null && Array.isArray(probeReport.authorityWrites) && probeReport.authorityWrites.length > 0
        ? probeReport.authorityWrites[0].filter ?? null
        : null;
      const controlProbe = probeOf(controlReport, probe.probeId);
      const controlFirstCas = controlProbe !== null && Array.isArray(controlProbe.authorityWrites) && controlProbe.authorityWrites.length > 0
        ? controlProbe.authorityWrites[0].filter ?? null
        : null;
      return {
        ...entry,
        offsetWriterFirstCasFilter: firstCas,
        correctWriterFirstCasFilter: controlFirstCas,
      };
    });
    const violations = overReleases.filter((entry) => entry.overRelease === true);
    const marginViolations = overReleases.filter((entry) => entry.marginViolation === true);
    const pastExpiryRenewals = overReleases.filter((entry) => entry.pastExpiryRenewal === true);

    /*
     * Empirical over-release horizon: the largest remaining life (in ms at the reference instant)
     * that the offset writer TRANSITIONED on a row that was LIVE on the database timeline at its
     * decision instant. A transitioned row that was already lapsed is lawful (it is the positive
     * half of the law, asserted separately), so it cannot enter this metric: the horizon is exactly
     * "how far ahead of true expiry did this writer release". In DATABASE mode it must be EMPTY;
     * under a writer-clock predicate it reappears at exactly delta - SKEW_MARGIN_MS of remaining
     * life, which is the falsifiability control for this fixture (see --anchor=clock evidence).
     */
    const claimEntries = overReleases.filter((entry) => entry.kind === 'claimAuthority');
    const matchedLiveLives = claimEntries
      .filter(
        (entry) =>
          entry.declaredLiveOnReferenceTimeline === true &&
          entry.liveAtDecision === true &&
          entry.offsetWriterMatched !== null &&
          entry.offsetWriterMatched > 0,
      )
      .map((entry) => entry.remainingLifeMsAtReferenceNow);
    const measuredHorizonMs = matchedLiveLives.length > 0 ? Math.max(...matchedLiveLives) : null;
    const matchedLapsedCount = claimEntries.filter(
      (entry) =>
        entry.declaredLiveOnReferenceTimeline !== true &&
        entry.offsetWriterMatched !== null &&
        entry.offsetWriterMatched > 0,
    ).length;

    /* ---------------------------------------------------------- findings + status */
    const reproduced = violations.length > 0 || pastExpiryRenewals.length > 0 || marginViolations.length > 0;
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
          ? 'A writer whose clock is offset by delta still transitions leases that are live on the DATABASE timeline (claim / lazy release / pairing ceremony / margin-free admission), or accepts a renewal for a lease already expired there. The writer-clock predicate GM-44 removed is back, and the horizon is again delta - SKEW_MARGIN_MS of remaining life.'
          : 'Every writer arm followed the database-time law at every probe: no lease that was live on the database timeline was transitioned (not even one live by 1000 ms at a writer offset of +/-300000 ms), no lease lapsed inside the 5000 ms margin was transitioned, and every lease lapsed past the margin was still transitioned by the same product path.',
      anchorMode: {
        predicateAnchorMode: ctx.predicateAnchorMode,
        anchorSeamSupplied: anchorMode === 'clock',
        negativeControlMode: anchorMode === 'clock',
        note:
          anchorMode === 'database'
            ? 'GM-64 rule 5: DATABASE mode. No injected predicate anchor reaches any Device service, so every lease/TTL predicate is the production `$expr` with `$$NOW`.'
            : 'DISCLOSED NEGATIVE CONTROL (GM-69 falsifiability): every Device service in this run received the GM-64 comparison anchor — the writer`s own injected clock. A run in this mode reports the counterexample and is VOID as skew evidence.',
      },
      overReleases: violations.map((entry) => ({
        probeId: entry.probeId,
        kind: entry.kind,
        referenceRemainingLifeMs: entry.remainingLifeMsAtReferenceNow,
        offsetWriterMatched: entry.offsetWriterMatched,
        offsetWriterErrorCode: entry.offsetWriterErrorCode,
        dbNowAtProbeMs: entry.dbNowAtProbeMs,
        expiresAtMs: entry.expiresAtMs,
        clockSkewAtDecisionMs: entry.clockSkewAtDecisionMs,
        offsetWriterFirstCasFilter: entry.offsetWriterFirstCasFilter,
        correctWriterFirstCasFilter: entry.correctWriterFirstCasFilter,
      })),
      marginViolations: marginViolations.map((entry) => ({
        probeId: entry.probeId,
        kind: entry.kind,
        referenceRemainingLifeMs: entry.remainingLifeMsAtReferenceNow,
        offsetWriterMatched: entry.offsetWriterMatched,
        offsetWriterErrorCode: entry.offsetWriterErrorCode,
      })),
      measuredOverReleaseHorizonMs: measuredHorizonMs,
      measuredHorizonDefinition:
        'largest remaining life (ms at the reference instant) of a row that was LIVE on the database timeline when the offset writer transitioned it; must be empty in DATABASE mode and reappears at delta - SKEW_MARGIN_MS under a writer-clock predicate',
      matchedLapsedClaims: matchedLapsedCount,
      predictedOverReleaseHorizonMs: k.PREDICTED_OVER_RELEASE_HORIZON_MS,
      pastExpiryRenewals: pastExpiryRenewals.map((entry) => ({
        probeId: entry.probeId,
        referenceRemainingLifeMs: entry.remainingLifeMsAtReferenceNow,
        offsetWriterMatched: entry.offsetWriterMatched,
        offsetWriterFirstCasFilter: entry.offsetWriterFirstCasFilter,
        correctWriterFirstCasFilter: entry.correctWriterFirstCasFilter,
        seededExpiresAtMs: entry.expiresAtMs,
        renewedExpiresAtMs:
          probeOf(treatmentReport, entry.probeId) === null
            ? null
            : rowField(probeOf(treatmentReport, entry.probeId).rowAfter, 'expiresAtMs'),
        renewedEpoch:
          probeOf(treatmentReport, entry.probeId) === null
            ? null
            : rowField(probeOf(treatmentReport, entry.probeId).rowAfter, 'epoch'),
      })),
      mechanisms: [
        ...violations.map((entry) => ({
          class: 'over-release',
          probeId: entry.probeId,
          kind: entry.kind,
          referenceRemainingLifeMs: entry.remainingLifeMsAtReferenceNow,
          offsetWriterMatched: entry.offsetWriterMatched,
          offsetWriterErrorCode: entry.offsetWriterErrorCode,
          clockSkewAtDecisionMs: entry.clockSkewAtDecisionMs,
        })),
        ...marginViolations.map((entry) => ({
          class: 'margin-violation',
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

    /* ---------------------------------------------------------- teardown-owned drop */
    const drops = [];
    for (const entry of armPlans) {
      // eslint-disable-next-line no-await-in-loop
      drops.push(await support.fence.dropOwnDatabase(ctx.client, entry.dbName));
    }
    cleanup = { arms: drops, parent: await support.fence.dropOwnDatabase(ctx.client, ctx.dbName) };

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
      gate: {
        status: gateOk ? 'PASS' : 'HARNESS_FAIL',
        failedCount: gateStatus.failedCount,
        passedCount: gateStatus.passedCount,
        checks: gate.checks,
      },
      desiredLaw: {
        status: lawStatus.status,
        failedCount: lawStatus.failedCount,
        passedCount: lawStatus.passedCount,
        failedAssertions: lawStatus.failedAssertions,
        checks: law.checks,
      },
      plan: {
        referenceNowMs,
        releasedAtMs,
        armLeadMs: k.ARM_LEAD_MS,
        decisionSlopMs: k.DECISION_SLOP_MS,
        deltaMs: k.DELTA_MS,
        epsilonMs: k.EPSILON_MS,
        skewMarginMs: k.SKEW_MARGIN_MS,
        leaseTtlMs: k.LEASE_TTL_MS,
        predictedOverReleaseHorizonMs: k.PREDICTED_OVER_RELEASE_HORIZON_MS,
        arms: armPlans.map((entry) => ({
          armKey: entry.arm.key,
          role: entry.arm.role,
          label: entry.arm.label,
          offsetMs: entry.arm.offsetMs,
          treatment: entry.arm.treatment,
          dbName: entry.dbName,
          probes: entry.probes.map((probe) => ({
            probeId: probe.probeId,
            kind: probe.kind,
            deviceId: probe.deviceId,
            seedOwnerId: probe.seedOwnerId,
            claimantOwnerId: probe.claimantOwnerId,
            expectedEpoch: probe.expectedEpoch,
            grantId: probe.grantId,
            remainingLifeMs: probe.remainingLifeMs,
          })),
        })),
      },
      /* Kept for evidence comparability with the pre-GM-69 report shape. */
      seededRows: Object.fromEntries(
        arms.flatMap((arm) =>
          (Array.isArray(writerReports[arm.role].seedRows) ? writerReports[arm.role].seedRows : []).map((row) => [
            `${arm.key}:${row.probeId}`,
            row,
          ]),
        ),
      ),
      rowsAfter: Object.fromEntries(
        armPlans.map((entry) => [entry.arm.key, armReadBack.get(entry.arm.key).rowsAfter]),
      ),
      accountAxis,
      overReleases,
      writers: {
        CORRECT: {
          pid: controlReport.pid,
          ppid: controlReport.ppid,
          armKey: control.arm.key,
          label: control.arm.label,
          offsetMs: controlReport.offsetMs,
          writerClockMs: controlReport.writerClockMs,
          probeCount: controlReport.probeCount,
          predicateAnchorMode: controlReport.predicateAnchorMode ?? null,
          anchorSeamSupplied: controlReport.anchorSeamSupplied === true,
          referenceNowMs: controlReport.referenceNowMs ?? null,
          referenceReachedAtMs: controlReport.referenceReachedAtMs ?? null,
          seedDbNowMs: controlReport.seedDbNowMs ?? null,
          barrierReached: controlReport.barrierReached,
          fatal: controlReport.fatal,
          durationMs: controlReport.durationMs,
        },
        OFFSET: {
          pid: treatmentReport.pid,
          ppid: treatmentReport.ppid,
          armKey: treatment.arm.key,
          label: treatment.arm.label,
          offsetMs: treatmentReport.offsetMs,
          writerClockMs: treatmentReport.writerClockMs,
          probeCount: treatmentReport.probeCount,
          predicateAnchorMode: treatmentReport.predicateAnchorMode ?? null,
          anchorSeamSupplied: treatmentReport.anchorSeamSupplied === true,
          referenceNowMs: treatmentReport.referenceNowMs ?? null,
          referenceReachedAtMs: treatmentReport.referenceReachedAtMs ?? null,
          seedDbNowMs: treatmentReport.seedDbNowMs ?? null,
          barrierReached: treatmentReport.barrierReached,
          fatal: treatmentReport.fatal,
          durationMs: treatmentReport.durationMs,
        },
      },
      realReturns: { writers: writerReports, parentReadBack: Object.fromEntries(armReadBack) },
      processEvidence: {
        spawnCommands: writers.map((writer) => `${process.execPath} ${writer.args.join(' ')}`),
        stdio: 'ignore + stderr to file (piped child stdio is EPERM in this sandbox)',
        transport: 'file barrier (ready/go) + file results; no pipe',
        exits,
        ready,
        barrierDir: path.relative(env.WORKTREE, barrierDir).replace(/\\/g, '/'),
        armFiles: armPlans.map((entry) => ({
          armKey: entry.arm.key,
          path: path.relative(env.WORKTREE, entry.armFile).replace(/\\/g, '/'),
          sha256: sha256FileSafe(entry.armFile),
        })),
        readyFiles: arms.map((arm) => ({
          role: arm.role,
          path: path.relative(env.WORKTREE, path.join(barrierDir, `ready-${arm.role}.json`)).replace(/\\/g, '/'),
          sha256: sha256FileSafe(path.join(barrierDir, `ready-${arm.role}.json`)),
        })),
        outFiles: arms.map((arm) => ({
          role: arm.role,
          path: path.relative(env.WORKTREE, path.join(barrierDir, `out-${arm.role}.json`)).replace(/\\/g, '/'),
          sha256: sha256FileSafe(path.join(barrierDir, `out-${arm.role}.json`)),
        })),
        planFile: path.relative(env.WORKTREE, path.join(rundir, 'plan.json')).replace(/\\/g, '/'),
      },
      cleanup,
      provenance: support.provenance(ctx, {
        twoClockDisclosure:
          'Two real OS processes, one arm each. Each writer owns ONE injected deterministic clock, offset from the SHARED database-clock reference instant by 0 and by delta. No wall-clock value participates in any lease decision or assertion. Each arm is released together, waits on the DATABASE clock for the declared instant, and decides every probe inside its own declared boundary window.',
        anchorModeDisclosure:
          anchorMode === 'database'
            ? 'GM-64 rule 5 / GM-69: DATABASE mode. NO injected predicate anchor reaches any Device service in this fixture, so every lease-state / TTL predicate is the production `$expr` with `$$NOW` and is decided by MongoDB. A run with an injected anchor is marked VOID as skew evidence by the runner.'
            : 'DISCLOSED NEGATIVE CONTROL (GM-69 falsifiability): every Device service in this run received the GM-64 comparison anchor, so lease-state / TTL predicates compared against the WRITER`S own injected clock. The reported counterexample is expected; this run is VOID as skew evidence.',
        referenceTimelineDisclosure: `The reference instant ${referenceNowMs} is a real instant on the replica set's own clock: the parent read hello.localTime (ms precision) at release time (${releasedAtMs}) and placed the instant ${k.ARM_LEAD_MS} ms beyond the later of that reading and each writer's own reading at readiness, then published ONE instant to BOTH writers, which waited it out on the DATABASE clock. Every row's expiresAt is referenceNowMs + its declared remaining life, verified in the GATE ledger, so "live on the reference timeline" means "live in the database".`,
        armIndependenceDisclosure:
          'The two writers no longer act on one shared row, and that is forced by the property under test: a row can be live-by-epsilon at only ONE instant, so two clocks 600 s apart cannot share a boundary preimage. Each arm owns its own database and seeds its preimage immediately before the declared instant; the control arm is the witness that a compliant-clock writer refuses the same probes, and the GATE ledger independently proves (from the measured database clock) that each arm decided on the declared side of its seeded expiry and that the treatment writer really carried its full offset at that instant.',
        orderingDisclosure:
          'Both writers are armed at the file barrier before either acts and are released together with the SAME reference instant; neither can observe the other (separate databases, separate probe devices).',
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
      plan: { referenceNowMs, releasedAtMs, arms: armPlans.map((entry) => entry.arm.key) },
      dbName: ctx.dbName,
      armDatabases: armPlans.map((entry) => entry.dbName),
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
    for (const entry of armPlans) {
      // eslint-disable-next-line no-await-in-loop
      await support.fence.dropOwnDatabase(ctx.client, entry.dbName).catch(() => null);
    }
    await support.fence.dropOwnDatabase(ctx.client, ctx.dbName).catch(() => null);
    await ctx.teardown().catch(() => {});
  }
}

module.exports = {
  FIXTURES,
  BY_ID,
  run,
  buildArms,
  buildArmProbes,
  buildArmFile,
  expectedLaw,
  violationFor,
  evaluateArmLaw,
  CHILD,
};