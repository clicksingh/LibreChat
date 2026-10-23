'use strict';

/**
 * I9 E1/E2 fixture registry (lane I9, PHASE1-LOCAL-AUTHORITY-001 / W2-B).
 *
 * Every fixture records the frozen assertion plan it will execute once the I6 authority
 * service and the I5 pairing service exist. While those product services are absent the
 * product fixtures resolve to BLOCKED_PENDING_I6_I5 and NEVER to PASS.
 *
 * Only the control fixtures (kind starts with 'control-' or 'harness-') execute real
 * work, and they exercise the real MongoDB index engine or the harness transport, never
 * a product service.
 */

const serviceLoader = require('./service-loader.cjs');
const harness = require('./harness.cjs');

const TENANT = 'tenant-w2b-i9';
const OWNER_A = 'owner-a-w2b-i9';
const OWNER_B = 'owner-b-w2b-i9';

const CAS_CLAIM_FILTER = {
  identityState: { $ne: 'retired' },
  $or: [
    { leaseState: { $in: ['never', 'expired', 'revoked'] } },
    { leaseState: 'active', expiresAt: { $lte: 'now - SKEW_MARGIN_MS' } },
  ],
};

const FIXTURES = [
  {
    id: 'E1-ONEPC-GRANT-CAS',
    tier: 'E1',
    kind: 'product',
    requires: ['I6'],
    runner: 'inline',
    title: 'strict one-PC/account grant CAS',
    assertionPlan: {
      contract: 'PM-INTERFACE-FREEZE §8 claimAuthority + §10a C/D',
      steps: [
        'seed authority rows D1 and D2 for one owner O in one tenant (identityState pending, leaseState never)',
        'claim D1 for O through the I6 claim CAS at injected clock T',
        'claim D2 for O through the same CAS',
      ],
      expected: [
        'first claim: matched 1, leaseState active, grantId minted (22-char base64url), expiresAt === activatedAt + 172800000, epoch 1',
        'second claim: rejected; either DEVICE_ALREADY_PAIRED_USE_RENEW from the live-lease predicate or ONE_DEVICE_PER_ACCOUNT from E11000 on observed keyPattern {ownerId:1,tenantId:1}',
        'after the burst countDocuments({ownerId:O,tenantId,leaseState:"active"}) === 1 (real index, not a pre-CAS scan)',
        'graceful path: a row already leaseState expired/revoked for O is claimable again with a NEW grantId (never the old one, G-2)',
      ],
    },
  },
  {
    id: 'E1-T16-P1-STALE-OWNER-REVOKE',
    tier: 'E1',
    kind: 'product',
    requires: ['I6'],
    runner: 'inline',
    title: 'P1 stale-owner revoke',
    assertionPlan: {
      contract: 'PM-INTERFACE-FREEZE §10a D; TEST-MATRIX T16',
      steps: [
        'owner A claims device D at injected clock T (grant gA, epoch eA)',
        'advance injected clock to T + 48h + 1h',
        'owner B claims D (grant gB, epoch eB); assert authorize(B, D, gB, eB) === true',
        'owner A submits revokeLease({deviceId:D, ownerId:A, epoch:eA}) using the stale epoch',
      ],
      expected: [
        'stale revoke returns NOT_OWNER_OR_STALE with matched 0',
        'authority row epoch unchanged by the stale revoke (no write at all)',
        'B remains authorized; the revocation sweep is disabled for the whole fixture',
      ],
    },
  },
  {
    id: 'E1-T17-P2-CLAIM-VS-ACTIVE-PC',
    tier: 'E1',
    kind: 'product',
    requires: ['I6'],
    runner: 'inline',
    title: 'P2 owner claim versus an active PC',
    assertionPlan: {
      contract: 'PM-INTERFACE-FREEZE §10a C; TEST-MATRIX T17',
      steps: [
        'owner A claims PC1 at T; owner B claims PC1 at T + 48h + 1h',
        'owner A then claims a second PC (PC2) with no revoke of PC1',
      ],
      expected: [
        'authorize(B, PC1, gB, eB) === true',
        'authorize(A, PC2, gA2, eA2) === true',
        'PC1.prevOwner/prevGrantId/prevEpoch untouched by the PC2 claim (no cross-row write)',
        'the per-owner account axis stays at one active row per tenant, enforced by uq_owner_active',
      ],
    },
  },
  {
    id: 'E2-T7-ONEPC-TWO-PC-RACE',
    tier: 'E2',
    kind: 'product',
    requires: ['I6'],
    runner: 'two-process',
    title: 'one account claim race across two real PCs and two OS processes (N>=50)',
    assertionPlan: {
      contract: 'PM-INTERFACE-FREEZE §10a C; TEST-MATRIX T7',
      steps: [
        'seed two authority rows D1, D2 both claimable for owner O',
        'spawn exactly two OS processes (shards A|B), N>=50 attempts total, same database',
        'both children drive the real I6 claimAuthority CAS; result transport is file-based, stdio inherit/ignore only',
      ],
      expected: [
        'exactly one winner across the two shards',
        'countDocuments({ownerId:O,tenantId,leaseState:"active"}) === 1',
        'loser returns ONE_DEVICE_PER_ACCOUNT (or DEVICE_ALREADY_PAIRED_USE_RENEW) and never a blind retry',
        'two distinct recorded child PIDs',
      ],
    },
  },
  {
    id: 'E2-T8-TWO-OWNERS-ONE-PC-RACE',
    tier: 'E2',
    kind: 'product',
    requires: ['I6'],
    runner: 'two-process',
    title: 'two accounts versus one PC, claim race across two OS processes (N>=50)',
    assertionPlan: {
      contract: 'PM-INTERFACE-FREEZE §10a C; TEST-MATRIX T8',
      steps: [
        'seed one claimable authority row D',
        'spawn two OS processes; shard A claims D for owner O1, shard B claims D for owner O2, N>=50 attempts total',
      ],
      expected: [
        'countDocuments({_id:D,leaseState:"active"}) === 1',
        'winning ownerId is exactly one of O1|O2; the loser gets a 0-match class error (fail closed)',
        'authorize(winner, grantId, epoch) === true and authorize(loser, ...) === false',
        'epoch incremented exactly once',
      ],
    },
  },
  {
    id: 'E2-V24T15-REVOKE-VS-CLAIM-RACE',
    tier: 'E2',
    kind: 'product',
    requires: ['I6'],
    runner: 'two-process',
    title: 'lease revoke versus fresh-owner claim across two OS processes (N>=50)',
    assertionPlan: {
      contract: 'PM-INTERFACE-FREEZE §10a C/D; TEST-MATRIX V24-T15',
      /**
       * PLAN AMENDED 2026-10-22 under explicit owner ruling.
       *
       * The original text demanded genuine one-CAS contention ("exactly one CAS matches; loser
       * matched 0; epoch delta exactly 1"). Independent verification (T4/T5) proved that condition
       * is STRUCTURALLY UNREACHABLE under the frozen protocol: issuePairingSession refuses a device
       * that holds a live lease (DEVICE_ALREADY_PAIRED_USE_RENEW, pairingSessionService.js ~L1200),
       * so a challenger's claim ceremony can only be armed AFTER the revoke has committed. The
       * measured burst therefore has no contention window at all: 25 revoke matches + 25 claim
       * matches over 25 rounds, zero failed-closed arms, epoch delta 2.
       *
       * The owner ruled (2026-10-22) that the plan be amended to the realizable sequential
       * expectation rather than reinterpreting it silently or changing frozen protocol behaviour.
       * The fixture now asserts the sequenced law below; the un-reachable contention property is
       * recorded as an explicit residual gap, NOT claimed as tested.
       */
      amended: {
        at: '2026-10-22',
        authority: 'owner ruling (option: amend the plan to the realizable sequential expectation)',
        supersedes:
          'exactly one CAS matches; loser matched 0, never a blind write; epoch delta exactly 1',
        rationale:
          'one-CAS contention is unreachable while the protocol forbids arming a claim during a live lease; the reachable law is a sequenced revoke-then-claim',
      },
      steps: [
        'seed one device D with a live lease held by owner A (grant gA, epoch eA)',
        'process A issues revokeLease({ownerId:A, epoch:eA}) inside the shared window',
        'process B arms the real pairing ceremony AFTER the revoke commits (the protocol forbids earlier arming) and then claims D for owner B using the epoch the PRODUCT frozen in mintPairingClaimChallenge',
        'N>=50 attempts total; both processes share one database',
      ],
      expected: [
        'the revoke matches exactly once per raced row (epoch eA -> eA+1) and never rotates the grant (G-2)',
        'the fresh-owner claim then matches exactly once per raced row (epoch eA+1 -> eA+2) against the revoked row',
        'no attempt blind-writes: every CAS transition that matched is accounted for, and epoch delta equals the number of matched transitions (monotone)',
        'no live authorization remains for the seeded owner after the sequence',
        'each raced row ends in exactly one of the two legal end states: {leaseState revoked} or {leaseState active under the new owner}',
        'RESIDUAL GAP (not tested): a regression permitting two conflicting writes inside a contended revoke/claim window would NOT be detected, because no such window can be constructed under the frozen protocol',
      ],
    },
  },
  {
    id: 'E1-V24T04-CODE-TTL-300S',
    tier: 'E1',
    kind: 'product',
    requires: ['I5'],
    runner: 'inline',
    title: '300s pairing-code timeout boundary (299999 / 300000 / 300001)',
    assertionPlan: {
      contract: 'PM-INTERFACE-FREEZE B; TEST-MATRIX V24-T04',
      steps: [
        'issue a pairing session with injected clock T (expiresAt = T + 300000, bare predicate, no margin)',
        'redeem at T + 299999, T + 300000 and T + 300001',
      ],
      expected: [
        'T+299999: redemption CAS matches; state claim_pending, attemptsUsed 1',
        'T+300000: 0-match; uniform INVALID_OR_EXPIRED_CODE; state stays open or expired, never claim_pending',
        'T+300001: same uniform error',
        'no SKEW_MARGIN is ever applied to a pairing-session predicate',
      ],
    },
  },
  {
    id: 'E1-V24T03-CODE-COLLISION',
    tier: 'E1',
    kind: 'product',
    requires: ['I5'],
    runner: 'inline',
    title: 'forced same-tenant lookupTag collision and bounded regeneration',
    assertionPlan: {
      contract: 'PM-INTERFACE-FREEZE §7/§9; TEST-MATRIX V24-T03',
      steps: [
        'force two pairing issuances in one tenant to compute the identical lookupTag',
        'allow at most MAX_CODE_REGENERATIONS === 3 regenerations',
      ],
      expected: [
        'observed E11000 with keyPattern exactly {tenantId:1,lookupTag:1}',
        'no partial write: exactly one non-terminal session for that tag',
        'regenerations are bounded; the 4th collision yields CODE_ISSUANCE_EXHAUSTED (409)',
        'the plaintext six-digit code is never persisted or logged',
      ],
    },
  },
  {
    id: 'E1-T09-T10-LEASE-48H-MARGIN',
    tier: 'E1',
    kind: 'product',
    requires: ['I6'],
    runner: 'inline',
    title: '48h lease TTL and the 5s renewal margin boundaries',
    assertionPlan: {
      contract: 'PM-INTERFACE-FREEZE §10a G margin table',
      steps: [
        'grant at injected clock T so expiresAt = T + 172800000',
        'probe authorize at T+172799999, T+172800000, T+172804999, T+172805000',
        'probe renewAuthority at T+172794999 and T+172795000',
      ],
      expected: [
        'authorize ALLOW at T+172799999; DENY at T+172800000 (bare now < expiresAt)',
        'T+172800000..T+172804999 is the dead zone: issuance proceeds, claim lapsed clause does not match -> PAIRING_WINDOW_TOO_EARLY, recovery is a fresh session',
        'T+172805000: guarded lazy release matches (expiresAt <= now - 5000), leaseState expired, epoch +1',
        'renewal succeeds at T+172794999 (grantId rotates, epoch+1, renewalCount+1, expiresAt advances) and fails LEASE_EXPIRED at T+172795000',
        'the guard is expiresAt + SKEW_MARGIN === 5000, never a different constant',
      ],
    },
  },
  {
    id: 'E1-T20-AUDIT-UNCERTAINTY',
    tier: 'E1',
    kind: 'product',
    requires: ['I6'],
    runner: 'inline',
    title: 'audit sink delivery uncertainty after a committed CAS',
    assertionPlan: {
      contract: 'Governor G-5; PM-INTERFACE-FREEZE §8',
      steps: [
        'commit an authority CAS through I6 with a working audit sink',
        'replace the audit sink with one that throws, then commit a second CAS',
        're-read the authority row with the real model',
      ],
      expected: [
        'AUDIT_DELIVERY_UNCERTAIN (500) is surfaced; no silent pass',
        'the second authority CAS is NOT rolled back (single-document CAS committed independently of the audit write)',
        'read-back proves the committed epoch/grantId; the missing audit line is detectable',
        'required audit fields deviceId, epoch, actor, reasonCode are always present (G-5, not the stale freeze §2.4)',
        'no raw code, private key, pepper, auth header, raw IP, file/command content or lookupTag is ever persisted',
      ],
    },
  },
  {
    id: 'E1-T20-CRASH-AFTER-SPEND',
    tier: 'E1',
    kind: 'product',
    requires: ['I6', 'I5'],
    runner: 'crash-product',
    title: 'crash after each write (challenge spend -> LP-3 consume -> LP-4 claim -> revoke -> retire)',
    assertionPlan: {
      contract: 'PM-INTERFACE-FREEZE §9; TEST-MATRIX T20/V24-T11',
      steps: [
        'child performs the real product write then exits with a sentinel before the next step',
        'a separate verifier process re-reads durable state and never trusts in-memory data',
      ],
      expected: [
        'c2 (after challenge spend): challenges.consumedAt != null, session still claim_pending, authority unchanged; approve fails closed',
        'c3 (after LP-3 consume): session consumed with grantedGrantId null, authority leaseState unchanged, fresh session recovers',
        'c4 (after LP-4 claim): active lease with CSPRNG grantId and expiresAt === activatedAt + 172800000',
        'c5 (after revoke): leaseState revoked, epoch+1, prevGrantId/prevEpoch written, re-pair succeeds',
        'c6 (after retire): identityState retired, every admission denies, in-tenant re-registration of the same deviceKeyId is DEVICE_ALREADY_REGISTERED',
        'global: no crash point may leave a state that authorizes without a live committed lease',
      ],
    },
  },
  {
    id: 'E1-V24T12-SWEEP-DISABLED-RERUN',
    tier: 'E1',
    kind: 'product',
    requires: ['I6'],
    runner: 'sweep-product',
    title: 'all sweep-sensitive traces re-run with the repair sweep effect absent',
    assertionPlan: {
      contract: 'TEST-MATRIX V24-T12; commission §5.2/§5.6',
      steps: [
        'run the decision set T16, T17, V24-T09, V24-T10, V24-T13 twice with a byte-identical assertion body',
        'CBHR_PHASE1_SWEEP=enabled for the first run and =disabled for the second',
      ],
      expected: [
        'decision vectors are identical (same sha256) across both runs',
        'in the disabled run, rows that only the sweep would have flipped are still not expired, yet no authorization decision changes',
        'sweepReliantDecisions === 0: no authorization decision may depend on the background sweep',
      ],
    },
  },
  {
    id: 'NC-NAIVE-NOINDEX',
    tier: 'CONTROL',
    kind: 'negative-control',
    requires: [],
    runner: 'naive-noindex',
    title: 'naive check-then-insert without the account-axis index produces invalid authority (EXPECTED_FAIL)',
    assertionPlan: {
      contract: 'TEST-MATRIX line 108; PM-INTERFACE-FREEZE §5',
      steps: [
        'two actual OS processes each read {ownerId,tenantId,leaseState:"active"} before either writes, then each insertOne a new active authority row for the SAME owner',
        'uq_owner_active is deliberately NOT created in this database',
      ],
      expected: [
        'countDocuments({ownerId,tenantId,leaseState:"active"}) === 2 (the product invariant R1 is violated)',
        'two distinct recorded child PIDs, N>=50 attempts total',
        'status EXPECTED_FAIL with productInvariantViolated true; rowsActive !== 2 is HARNESS_FAIL (the fixture must exercise the race, TEST-MATRIX line 108)',
      ],
    },
  },
  {
    id: 'NC-NAIVE-INDEX',
    tier: 'CONTROL',
    kind: 'negative-control',
    requires: [],
    runner: 'naive-index',
    title: 'the same naive check-then-insert caught by uq_owner_active (control complement)',
    assertionPlan: {
      contract: 'G-1; PM-INTERFACE-FREEZE §2.1',
      steps: [
        'identical naive read-then-insert burst across two OS processes',
        'uq_owner_active {ownerId:1,tenantId:1} unique partial {leaseState:"active"} IS created first (raw driver, engine-level)',
      ],
      expected: [
        'exactly one insert succeeds; the second fails E11000 with observed keyPattern {ownerId:1,tenantId:1}',
        'countDocuments({ownerId,tenantId,leaseState:"active"}) === 1',
        'this proves the negative control is non-vacuous and that the frozen index shape catches it; it is an ENGINE-level result and NOT a schema-driven or product-service proof',
      ],
    },
  },
  {
    id: 'NC-DB-FENCE',
    tier: 'CONTROL',
    kind: 'harness-control',
    requires: [],
    runner: 'inline',
    title: 'self-owned database fence rejects any pre-existing or non-w2b target',
    assertionPlan: {
      contract: 'commission addendum (lab DB isolation); G-7',
      steps: [
        'evaluate the harness fence against protected names and a foreign name without opening a connection',
      ],
      expected: [
        'cbhr_rdc_phase1_preflight_20261010 and cbhr_rdc_phase1_governor_nullgrant_probe_20261010 are refused',
        'a w2r_/other-prefix name is refused; a well-formed cbhr_rdc_phase1_w2b_<id>_<stamp> name is accepted',
        'no connection is attempted on refusal',
      ],
    },
  },
  {
    id: 'NC-CRASH-HARNESS',
    tier: 'CONTROL',
    kind: 'harness-control',
    requires: [],
    runner: 'crash-selftest',
    title: 'crash transport self-test (write then process.exit sentinel, verifier re-reads)',
    assertionPlan: {
      contract: 'PM-INTERFACE-FREEZE §9 crash mechanism',
      steps: [
        'child inserts a durable marker document then exits with sentinel code 7 before any second step',
        'a separate verifier process re-reads the durable document',
      ],
      expected: [
        'observed child exit code === 7 (crash really happened)',
        'the marker document is durable after the crash',
        'witnessCount in the child result file is 0, proving the child never reached its post-write step',
        'this is a harness transport control, NOT a product crash-point result',
      ],
    },
  },
  {
    id: 'NC-SWEEP-KNOB',
    tier: 'CONTROL',
    kind: 'harness-control',
    requires: [],
    runner: 'sweep-selftest',
    title: 'sweep control knob and decision-vector hash-equality self-test',
    assertionPlan: {
      contract: 'PM-INTERFACE-FREEZE §10a; TEST-MATRIX V24-T12',
      steps: [
        'run one deterministic decision vector twice with CBHR_PHASE1_SWEEP=enabled and =disabled',
        'sha256(JSON.stringify(decisions)) must be identical across both runs',
      ],
      expected: [
        'the knob is read as a single env var and the assertion body is byte-identical between runs',
        'identical: true, sweepReliantDecisions: 0',
        'this is a harness control for the knob/hash mechanism; the product V24-T12 sweep-disabled re-run stays BLOCKED_PENDING_I6_I5',
      ],
    },
  },
];

function productBlocked(fixture) {
  const probe = serviceLoader.probe();
  const status = probe.status === 'AVAILABLE' ? 'BLOCKED_NOT_WIRED' : probe.status;
  return {
    id: fixture.id,
    tier: fixture.tier,
    kind: fixture.kind,
    title: fixture.title,
    status,
    exitCode: 2,
    productClaim: false,
    requires: fixture.requires,
    reason:
      status === 'BLOCKED_NOT_WIRED'
        ? 'I6/I5 exist but fixture execution wiring is deferred to the authorized post-I4/I6/I5 integration test round'
        : probe.reason,
    serviceProbe: {
      status: probe.status,
      deviceDir: probe.deviceDir,
      missing: probe.missing,
      shapeProblems: probe.shapeProblems,
      noFallbackInstalled: true,
    },
    assertionPlan: fixture.assertionPlan,
  };
}

function runDbFenceControl(fixture) {
  const cases = [
    { name: 'cbhr_rdc_phase1_preflight_20261010', expected: 'refused' },
    { name: 'cbhr_rdc_phase1_governor_nullgrant_probe_20261010', expected: 'refused' },
    { name: 'cbhr_rdc_phase1_w2r_x4_20261012', expected: 'refused' },
    { name: 'devices_prod', expected: 'refused' },
    { name: 'cbhr_rdc_phase1_w2b_nc_dbfence_20261012T000000_ab12cd', expected: 'accepted' },
  ];
  const results = cases.map((entry) => {
    const problems = harness.dbNameProblems(entry.name);
    const observed = problems.length === 0 ? 'accepted' : 'refused';
    return { name: entry.name, expected: entry.expected, observed, problems };
  });
  const failures = results.filter((entry) => entry.observed !== entry.expected);
  return {
    id: fixture.id,
    tier: fixture.tier,
    kind: fixture.kind,
    title: fixture.title,
    status: failures.length === 0 ? 'PASS' : 'PRODUCT_FAIL',
    exitCode: failures.length === 0 ? 0 : 5,
    productClaim: false,
    connectionAttempted: false,
    results,
    failures,
    assertionPlan: fixture.assertionPlan,
  };
}

module.exports = {
  TENANT,
  OWNER_A,
  OWNER_B,
  CAS_CLAIM_FILTER,
  FIXTURES,
  productBlocked,
  runDbFenceControl,
};

if (require.main === module) {
  const inline = FIXTURES.filter((fixture) => fixture.runner === 'inline').map((fixture) =>
    fixture.id === 'NC-DB-FENCE' ? runDbFenceControl(fixture) : productBlocked(fixture),
  );
  process.stdout.write(`${JSON.stringify({ fixtures: FIXTURES.map((f) => f.id), inline })}\n`);
}
