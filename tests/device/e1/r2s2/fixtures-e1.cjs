'use strict';

/**
 * W3-B R2 S2-T E1/E0 rows (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Rows S2T-01, S2T-02, S2T-04, S2T-05, S2T-06, S2T-07, S2T-08. Every E1 row actually invokes the
 * target product API (real `createModels(mongoose)` models, real `AuditEvent` sink) and records the
 * observed result. No `compositionBlocked()`/`compositionFailView()` shortcut exists in this file.
 *
 * Cross-cutting truthful observation (recorded, never worked around): the real `AuditEvent` schema
 * marks BOTH `actor` and `reasonCode` as `required: true` (packages/data-schemas/src/schema/auditEvent.ts:57-66),
 * while the product's authority audit emitter passes `reasonCode: null` for grant/renew/revoke
 * (authorityService.js:320-334). The real sink therefore rejects the event with a Mongoose
 * ValidationError, and the product surfaces `AUDIT_DELIVERY_UNCERTAIN` AFTER the CAS has committed.
 * That is reported as part of each row's `actual`; it is never bypassed with a fake or raw-driver sink.
 */

const fs = require('node:fs');
const path = require('node:path');

const { withRowDb, envelopeView, errorView, env, ledger, w3a } = require('./harness.cjs');

const { STATUS } = ledger;

function sliceSource(absolute, from, to) {
  if (!fs.existsSync(absolute)) return null;
  return fs
    .readFileSync(absolute, 'utf8')
    .split('\n')
    .slice(from - 1, to)
    .map((line, index) => `${from + index}: ${line.trim()}`)
    .join('\n');
}

function productSrc(relative, from, to) {
  return sliceSource(path.join(env.DEVICE_DIR, relative), from, to);
}

function worktreeSrc(relative, from, to) {
  return sliceSource(path.join(env.WORKTREE, relative), from, to);
}

/** Source anchors are supplementary E0 evidence only; they never substitute for an invocation. */
function staticAnchors() {
  return {
    claimArgs: 'api/server/services/Device/authorityService.js:516-537',
    claimFilter: 'api/server/services/Device/authorityService.js:106-118',
    casLaw: 'api/server/services/Device/authorityService.js:247-265',
    auditEmit: 'api/server/services/Device/authorityService.js:320-356',
    errorMap: 'api/server/services/Device/errors.js:1-20',
    auditSchema: 'packages/data-schemas/src/schema/auditEvent.ts:24-66',
    challengeSchema: 'packages/data-schemas/src/schema/challenge.ts:17-63',
    pairingClaimSubdoc: 'packages/data-schemas/src/schema/pairingSession.ts:93-99',
  };
}

function grantProof(deviceId, now) {
  return {
    ownerConfirmedAt: new Date(now),
    endpointSignatureVerifiedAt: new Date(now),
    verifiedKeyId: `key-${deviceId}`,
    localApprovalNonceHash: 's2t-lab-nonce-hash',
  };
}

function authoritySnapshot(row) {
  if (row === null || row === undefined) return null;
  return {
    _id: row._id,
    tenantId: row.tenantId,
    epoch: row.epoch,
    leaseState: row.leaseState,
    identityState: row.identityState,
    ownerId: row.ownerId,
    grantId: row.grantId,
    prevEpoch: row.prevEpoch,
    prevGrantId: row.prevGrantId,
    grantedByPairingSessionId: row.grantedByPairingSessionId ?? null,
  };
}

function sameAuthority(before, after) {
  const keys = ['epoch', 'leaseState', 'identityState', 'ownerId', 'grantId', 'prevEpoch', 'prevGrantId'];
  return keys.every((key) => before[key] === after[key]);
}

const COMPONENT_TIER_NOTE = 'component tier follows the row tier; E0 anchors are supplementary only';

async function s2t01(ctx) {
  const deviceId = 's2t-01-device';
  const ceremonyEpoch = 0;
  await ctx.seedAuthority({
    _id: deviceId,
    epoch: ceremonyEpoch,
    leaseState: 'never',
    identityState: 'pending',
  });
  const before = authoritySnapshot(await ctx.readAuthorityRow(deviceId));
  const authority = ctx.composeAuthority();
  const args = {
    deviceId,
    tenantId: ctx.TENANT,
    ownerId: ctx.OWNER_A,
    sessionId: 's2t-01-pairing-session',
    grantProof: grantProof(deviceId, ctx.clock.now()),
  };
  const argsKeys = Object.keys(args);
  const expectedEpochPresent = Object.prototype.hasOwnProperty.call(args, 'expectedEpoch');
  const envelope = await authority.claimAuthority(args);
  const after = authoritySnapshot(await ctx.readAuthorityRow(deviceId));
  const view = envelopeView(envelope);
  const successAuditRows = ctx.audit.outcomes.filter((entry) => entry.ok === true).length;

  return {
    status: STATUS.EXPECTED_RED,
    productMethodInvoked: true,
    actual: {
      scenario: 'claimAuthority invoked WITHOUT expectedEpoch against a claimable authority row at epoch g=0',
      invocation: {
        method: 'authorityService.claimAuthority',
        argsKeys,
        expectedEpochPresentInArgs: expectedEpochPresent,
        ceremonyEpochSupplied: null,
      },
      fixtureAuthorityEpoch: ceremonyEpoch,
      authorityBefore: before,
      authorityAfter: after,
      epochDelta: after.epoch - before.epoch,
      authorityMutated: !sameAuthority(before, after),
      envelope: view,
      productTookCasSuccessPath: view.matched > 0,
      successAuditRowsPersisted: successAuditRows,
      auditSinkAttempts: ctx.audit.outcomes,
      afterCasAuditInteraction:
        'the claim CAS committed (epoch 0 -> 1), then the real AuditEvent sink rejected the grant event (reasonCode required, product passes null) and the product surfaced AUDIT_DELIVERY_UNCERTAIN 500; 0 audit rows persisted',
      contractMismatch:
        "frozen oracle requires {ok:false, error.code:'PAIRING_CEREMONY_REQUIRED', httpStatus:400} with zero authority mutation; observed ok:false / AUDIT_DELIVERY_UNCERTAIN 500 and epoch 0 -> 1",
      staticAnchors: {
        claimArgs: productSrc('authorityService.js', 516, 537),
        claimFilter: productSrc('authorityService.js', 106, 118),
        errorMap: productSrc('errors.js', 1, 20),
      },
    },
    components: [
      {
        name: 'missing_expected_epoch_refused_with_pairing_ceremony_required',
        oracle:
          "claimAuthority without expectedEpoch returns {ok:false, error.code:'PAIRING_CEREMONY_REQUIRED', httpStatus:400}",
        actual: `observed ok=${view.ok} error.code=${view.error ? view.error.code : null} error.httpStatus=${view.error ? view.error.httpStatus : null}`,
        met: view.ok === false && view.error !== null && view.error.code === 'PAIRING_CEREMONY_REQUIRED' && view.error.httpStatus === 400,
        tier: 'E1',
      },
      {
        name: 'zero_authority_mutation',
        oracle: 'the authority row is byte-identical after the refused claim',
        actual: `epoch ${before.epoch} -> ${after.epoch}; leaseState ${before.leaseState} -> ${after.leaseState}; identityState ${before.identityState} -> ${after.identityState}; ownerId ${before.ownerId} -> ${after.ownerId}`,
        met: sameAuthority(before, after),
        tier: 'E1',
      },
      {
        name: 'zero_success_audit',
        oracle: 'no success audit row is persisted for the refused claim',
        actual: `${successAuditRows} success audit rows persisted (deviceauthorityevents); the product attempted 1 grant audit which the real schema rejected`,
        met: successAuditRows === 0,
        tier: 'E1',
      },
      {
        name: 'product_method_invoked',
        oracle: 'claimAuthority was actually invoked against genuine Mongoose models',
        actual: `invoked with args keys ${JSON.stringify(argsKeys)}; matched=${view.matched}`,
        met: true,
        tier: 'E1',
      },
    ],
    notes: COMPONENT_TIER_NOTE,
  };
}

async function s2t02(ctx) {
  const deviceId = 's2t-02-device';
  const ceremonyEpoch = 0;
  const authorityEpoch = 1;
  await ctx.seedAuthority({
    _id: deviceId,
    epoch: authorityEpoch,
    leaseState: 'revoked',
    identityState: 'active',
    ownerId: ctx.OWNER_B,
    grantId: 's2t-02-prev-grant',
    prevEpoch: 0,
    prevGrantId: 's2t-02-origin-grant',
    revokedAt: new Date(ctx.clock.now() - 60000),
    revokedBy: ctx.OWNER_B,
  });
  const before = authoritySnapshot(await ctx.readAuthorityRow(deviceId));
  const authority = ctx.composeAuthority();
  const args = {
    deviceId,
    tenantId: ctx.TENANT,
    ownerId: ctx.OWNER_A,
    sessionId: 's2t-02-pairing-session',
    expectedEpoch: ceremonyEpoch,
    grantProof: grantProof(deviceId, ctx.clock.now()),
  };
  const envelope = await authority.claimAuthority(args);
  const after = authoritySnapshot(await ctx.readAuthorityRow(deviceId));
  const view = envelopeView(envelope);
  const successAuditRows = ctx.audit.outcomes.filter((entry) => entry.ok === true).length;
  const grantAuditEventsQueued = ctx.audit.events.filter((event) => event.kind === 'grant').length;

  return {
    status: STATUS.EXPECTED_RED,
    productMethodInvoked: true,
    actual: {
      scenario: 'claimAuthority invoked with stale expectedEpoch g=0 against an authority row already at g+1=1',
      invocation: {
        method: 'authorityService.claimAuthority',
        argsKeys: Object.keys(args),
        expectedEpochSupplied: ceremonyEpoch,
        authorityEpochObservedAtMint: authorityEpoch,
        argumentAcceptedBySignature: false,
      },
      authorityBefore: before,
      authorityAfter: after,
      epochDelta: after.epoch - before.epoch,
      authorityMutated: !sameAuthority(before, after),
      envelope: view,
      matchedCount: view.matched,
      crossGenerationTransitionsObserved: view.matched === 1 ? 1 : 0,
      productTookCasSuccessPath: view.matched > 0,
      grantAuditEventsQueued,
      successAuditRowsPersisted: successAuditRows,
      auditSinkAttempts: ctx.audit.outcomes,
      afterCasAuditInteraction:
        'the stale-generation claim CAS still matched (no epoch conjunct), the epoch advanced 1 -> 2, then the real AuditEvent sink rejected the grant event (reasonCode required, product passes null) and the product surfaced AUDIT_DELIVERY_UNCERTAIN 500',
      contractMismatch:
        'frozen oracle requires PAIRING_CEREMONY_STALE 409, matched 0 and an unchanged row; observed matched 1, epoch 1 -> 2 and AUDIT_DELIVERY_UNCERTAIN 500',
      staticAnchors: {
        claimFilter: productSrc('authorityService.js', 106, 118),
        claimArgs: productSrc('authorityService.js', 516, 537),
        errorMap: productSrc('errors.js', 1, 20),
      },
    },
    components: [
      {
        name: 'stale_ceremony_refused_with_pairing_ceremony_stale',
        oracle: "stale expectedEpoch returns {ok:false, error.code:'PAIRING_CEREMONY_STALE', httpStatus:409}",
        actual: `observed ok=${view.ok} error.code=${view.error ? view.error.code : null} error.httpStatus=${view.error ? view.error.httpStatus : null}`,
        met: view.error !== null && view.error.code === 'PAIRING_CEREMONY_STALE' && view.error.httpStatus === 409,
        tier: 'E1',
      },
      {
        name: 'matched_zero',
        oracle: 'the stale generation CAS matches zero documents',
        actual: `observed matched=${view.matched}`,
        met: view.matched === 0,
        tier: 'E1',
      },
      {
        name: 'row_unchanged',
        oracle: 'the authority row is unchanged by a stale ceremony',
        actual: `epoch ${before.epoch} -> ${after.epoch}; leaseState ${before.leaseState} -> ${after.leaseState}; ownerId ${before.ownerId} -> ${after.ownerId}; grantId ${before.grantId}`,
        met: sameAuthority(before, after),
        tier: 'E1',
      },
      {
        name: 'no_auto_retry',
        oracle: 'no automatic ceremony re-arm or blind non-idempotent retry occurs',
        actual: `exactly ${grantAuditEventsQueued} grant audit event(s) queued from exactly one CAS success path; ${view.matched === 1 ? '1' : '0'} generation transition(s) observed`,
        met: view.matched === 1 && grantAuditEventsQueued === 1,
        tier: 'E1',
      },
      {
        name: 'zero_success_audit',
        oracle: 'no success audit row is persisted for a stale ceremony',
        actual: `${successAuditRows} success audit rows persisted; the attempted grant audit was rejected by the real AuditEvent schema`,
        met: successAuditRows === 0,
        tier: 'E1',
      },
    ],
    notes: COMPONENT_TIER_NOTE,
  };
}

async function s2t04(ctx) {
  const now = ctx.clock.now();
  const staleId = 's2t-04-stale-ceremony-device';
  const freshId = 's2t-04-fresh-ceremony-device';
  const live = { expiresAt: new Date(now + 172800000), activatedAt: new Date(now) };

  await ctx.seedAuthority({
    _id: staleId,
    epoch: 0,
    leaseState: 'active',
    identityState: 'active',
    ownerId: ctx.OWNER_A,
    grantId: 's2t-04-stale-grant-0',
    ...live,
  });
  await ctx.seedAuthority({
    _id: freshId,
    epoch: 0,
    leaseState: 'active',
    identityState: 'active',
    ownerId: ctx.OWNER_B,
    grantId: 's2t-04-fresh-grant-0',
    ...live,
  });

  const authority = ctx.composeAuthority();

  const staleBefore = authoritySnapshot(await ctx.readAuthorityRow(staleId));
  const revokeStaleEnvelope = await authority.revokeLease({
    deviceId: staleId,
    tenantId: ctx.TENANT,
    ownerId: ctx.OWNER_A,
    epoch: 0,
  });
  const staleAfterRevoke = authoritySnapshot(await ctx.readAuthorityRow(staleId));
  const staleClaimEnvelope = await authority.claimAuthority({
    deviceId: staleId,
    tenantId: ctx.TENANT,
    ownerId: ctx.OWNER_A,
    sessionId: 's2t-04-stale-pairing-session',
    expectedEpoch: 0,
    grantProof: grantProof(staleId, now),
  });
  const staleAfterClaim = authoritySnapshot(await ctx.readAuthorityRow(staleId));

  const freshBefore = authoritySnapshot(await ctx.readAuthorityRow(freshId));
  const revokeFreshEnvelope = await authority.revokeLease({
    deviceId: freshId,
    tenantId: ctx.TENANT,
    ownerId: ctx.OWNER_B,
    epoch: 0,
  });
  const freshAfterRevoke = authoritySnapshot(await ctx.readAuthorityRow(freshId));
  const freshClaimEnvelope = await authority.claimAuthority({
    deviceId: freshId,
    tenantId: ctx.TENANT,
    ownerId: ctx.OWNER_B,
    sessionId: 's2t-04-fresh-pairing-session',
    expectedEpoch: 1,
    grantProof: grantProof(freshId, now),
  });
  const freshAfterClaim = authoritySnapshot(await ctx.readAuthorityRow(freshId));

  const staleView = envelopeView(staleClaimEnvelope);
  const freshView = envelopeView(freshClaimEnvelope);
  const successAuditRows = ctx.audit.outcomes.filter((entry) => entry.ok === true).length;

  return {
    status: STATUS.EXPECTED_RED,
    productMethodInvoked: true,
    actual: {
      scenario:
        'generation-changing revoke at g -> g+1 through the product service, then (a) a STALE ceremony pinned to g and (b) a FRESH ceremony pinned to g+1 both invoked against claimable revoked rows',
      staleRow: {
        deviceId: staleId,
        authorityBefore: staleBefore,
        revokeEnvelope: envelopeView(revokeStaleEnvelope),
        authorityAfterRevoke: staleAfterRevoke,
        staleCeremonyEnvelope: staleView,
        authorityAfterStaleCeremony: staleAfterClaim,
        staleCeremonyTransitionedGeneration: staleView.matched === 1,
        epochDeltaTotal: staleAfterClaim.epoch - staleBefore.epoch,
      },
      freshRow: {
        deviceId: freshId,
        authorityBefore: freshBefore,
        revokeEnvelope: envelopeView(revokeFreshEnvelope),
        authorityAfterRevoke: freshAfterRevoke,
        freshCeremonyEnvelope: freshView,
        authorityAfterFreshCeremony: freshAfterClaim,
        freshCeremonyTransitionedGeneration: freshView.matched === 1,
        epochDeltaTotal: freshAfterClaim.epoch - freshBefore.epoch,
      },
      noFabricatedRegrantViaDirectDb: true,
      fabricatedFreshRegrant: false,
      successAuditRowsPersisted: successAuditRows,
      auditSinkAttempts: ctx.audit.outcomes,
      afterCasAuditInteraction:
        'every committed CAS (revoke and claim) surfaced AUDIT_DELIVERY_UNCERTAIN because the real AuditEvent schema rejects the product reasonCode:null; the authority mutation itself committed (verified by raw driver read-back)',
      contractMismatch:
        'frozen oracle requires the stale g ceremony to be refused (PAIRING_CEREMONY_STALE 409) and only the fresh g+1 ceremony to proceed; observed BOTH ceremonies transition the generation (stale row epoch 0 -> 1 -> 2, fresh row epoch 0 -> 1 -> 2)',
      staticAnchors: {
        claimFilter: productSrc('authorityService.js', 106, 118),
        revokeImpl: productSrc('authorityService.js', 823, 848),
        errorMap: productSrc('errors.js', 1, 20),
      },
    },
    components: [
      {
        name: 'generation_changing_revoke_committed',
        oracle: 'revokeLease at g commits a generation change to g+1 on both fixture rows',
        actual: `stale row epoch ${staleBefore.epoch} -> ${staleAfterRevoke.epoch} (leaseState ${staleAfterRevoke.leaseState}); fresh row epoch ${freshBefore.epoch} -> ${freshAfterRevoke.epoch} (leaseState ${freshAfterRevoke.leaseState})`,
        met:
          staleAfterRevoke.epoch === staleBefore.epoch + 1 &&
          staleAfterRevoke.leaseState === 'revoked' &&
          freshAfterRevoke.epoch === freshBefore.epoch + 1 &&
          freshAfterRevoke.leaseState === 'revoked',
        tier: 'E1',
      },
      {
        name: 'fresh_ceremony_at_g_plus_1_may_claim',
        oracle: 'a FRESH ceremony observing g+1 may claim the revoked row through the product service',
        actual: `observed ok=${freshView.ok} matched=${freshView.matched} error.code=${freshView.error ? freshView.error.code : null}; epoch ${freshBefore.epoch} -> ${freshAfterClaim.epoch}`,
        met: freshView.matched === 1 && freshAfterClaim.epoch === freshBefore.epoch + 2,
        tier: 'E1',
      },
      {
        name: 'stale_ceremony_at_g_may_not_claim',
        oracle: 'a STALE ceremony pinned to g is refused and performs zero authority mutation',
        actual: `observed ok=${staleView.ok} matched=${staleView.matched} error.code=${staleView.error ? staleView.error.code : null}; epoch ${staleBefore.epoch} -> ${staleAfterClaim.epoch}; leaseState ${staleAfterClaim.leaseState}`,
        met: staleView.matched === 0 && staleAfterClaim.epoch === staleBefore.epoch + 1,
        tier: 'E1',
      },
      {
        name: 'stale_classification_is_pairing_ceremony_stale',
        oracle: "the stale ceremony is classified PAIRING_CEREMONY_STALE (409)",
        actual: `observed error.code=${staleView.error ? staleView.error.code : null} httpStatus=${staleView.error ? staleView.error.httpStatus : null}`,
        met: staleView.error !== null && staleView.error.code === 'PAIRING_CEREMONY_STALE',
        tier: 'E1',
      },
    ],
    notes: COMPONENT_TIER_NOTE,
  };
}

async function s2t05(ctx) {
  const now = ctx.clock.now();
  const challenge = ctx.models.Challenge;
  const pairingSession = ctx.models.PairingSession;

  const schemaPaths = {
    challengeBoundEpoch: Boolean(challenge.schema.path('boundEpoch')),
    pairingClaimExpectedEpoch: Boolean(pairingSession.schema.path('claim.expectedEpoch')),
    pairingClaimChallengeRef: Boolean(pairingSession.schema.path('claim.challengeRef')),
    pairingClaimOpenedAt: Boolean(pairingSession.schema.path('claim.openedAt')),
    challengeSelectablePaths: Object.keys(challenge.schema.paths).sort(),
    pairingClaimSubdocPaths: Object.keys(pairingSession.schema.paths)
      .filter((key) => key.startsWith('claim.'))
      .sort(),
  };

  const challengeDocs = await challenge.create(
    [
      {
        challengeHash: 's2t-05-challenge-hash',
        purpose: 'pairing-claim',
        deviceId: 's2t-05-device',
        deviceKeyId: 'key-s2t-05-device',
        tenantId: ctx.TENANT,
        boundPairingSessionId: 's2t-05-pairing-session',
        boundOwnerId: ctx.OWNER_A,
        boundGrantId: 's2t-05-grant',
        boundEpoch: 7,
        issuedAt: new Date(now),
        expiresAt: new Date(now + 120000),
        consumedAt: null,
      },
    ],
    { writeConcern: env.WRITE_CONCERN },
  );
  const challengeDoc = challengeDocs[0];

  const sessionDocs = await pairingSession.create(
    [
      {
        tenantId: ctx.TENANT,
        deviceId: 's2t-05-device',
        deviceKeyId: 'key-s2t-05-device',
        lookupTag: 's2t-05-lookup-tag',
        state: 'claim_pending',
        pendingOwnerId: ctx.OWNER_A,
        attemptsUsed: 1,
        issuedAt: new Date(now),
        expiresAt: new Date(now + 300000),
        claimedAt: new Date(now),
        claim: {
          challengeRef: 's2t-05-challenge-ref',
          expectedEpoch: 5,
          openedAt: new Date(now),
        },
        consumedAt: null,
        grantedGrantId: null,
        issuedFromSourceHash: null,
        deviceSessionId: null,
      },
    ],
    { writeConcern: env.WRITE_CONCERN },
  );
  const sessionDoc = sessionDocs[0];

  const rawChallenge = await ctx.client
    .db(ctx.dbName)
    .collection(challenge.collection.name)
    .findOne({ _id: challengeDoc._id });
  const rawSession = await ctx.client
    .db(ctx.dbName)
    .collection(pairingSession.collection.name)
    .findOne({ _id: sessionDoc._id });
  const leanChallenge = await challenge.findOne({ _id: challengeDoc._id }).lean();
  const leanSession = await pairingSession.findOne({ _id: sessionDoc._id }).lean();

  const challengeFieldPresent = (doc) =>
    doc !== null && doc !== undefined && Object.prototype.hasOwnProperty.call(doc, 'boundEpoch');
  const claimSubdoc = (doc) => (doc && typeof doc.claim === 'object' && doc.claim !== null ? doc.claim : null);

  return {
    status: STATUS.EXPECTED_RED,
    productMethodInvoked: true,
    actual: {
      scenario:
        'genuine createModels(mongoose) Challenge + PairingSession round-trip for Challenge.boundEpoch and PairingSession.claim.{expectedEpoch,challengeRef}',
      invocation: {
        method: 'Challenge.create / PairingSession.create / findOne().lean() (real createModels(mongoose) models)',
        challengeCollection: challenge.collection.name,
        pairingSessionCollection: pairingSession.collection.name,
      },
      schemaPaths,
      challenge: {
        modelRoundTripBoundEpoch: challengeDoc.boundEpoch ?? null,
        leanBoundEpoch: leanChallenge ? (leanChallenge.boundEpoch ?? null) : null,
        rawDriverHasBoundEpoch: challengeFieldPresent(rawChallenge),
        rawDriverKeys: rawChallenge ? Object.keys(rawChallenge).sort() : null,
        rawDriverBoundEpoch: challengeFieldPresent(rawChallenge) ? rawChallenge.boundEpoch : null,
        rawDriverChallengeHash: rawChallenge ? rawChallenge.challengeHash : null,
      },
      pairingSession: {
        modelRoundTripClaim: sessionDoc.claim ? sessionDoc.claim.toObject() : null,
        leanClaim: claimSubdoc(leanSession),
        rawDriverClaim: claimSubdoc(rawSession),
        rawDriverClaimKeys: claimSubdoc(rawSession) ? Object.keys(claimSubdoc(rawSession)).sort() : null,
        rawDriverExpectedEpoch: claimSubdoc(rawSession) ? (claimSubdoc(rawSession).expectedEpoch ?? null) : null,
        rawDriverChallengeRef: claimSubdoc(rawSession) ? (claimSubdoc(rawSession).challengeRef ?? null) : null,
      },
      contractMismatch:
        'F2/X-4/X-5 approve Challenge.boundEpoch and PairingSession.claim.expectedEpoch as mandatory new fields; both are absent from the frozen schemas, so Mongoose strict mode strips them and no round-trip is possible. claim.challengeRef is present and does round-trip.',
      staticAnchors: {
        challengeSchema: worktreeSrc('packages/data-schemas/src/schema/challenge.ts', 17, 63),
        pairingClaimSubdoc: worktreeSrc('packages/data-schemas/src/schema/pairingSession.ts', 93, 99),
      },
    },
    components: [
      {
        name: 'challenge_boundEpoch_schema_path',
        oracle: 'Challenge has a declared boundEpoch schema path (F2/X-5 mandatory)',
        actual: `Challenge.schema.path('boundEpoch') = ${schemaPaths.challengeBoundEpoch ? 'declared' : 'undefined'}; declared paths = ${JSON.stringify(schemaPaths.challengeSelectablePaths)}`,
        met: schemaPaths.challengeBoundEpoch,
        tier: 'E1',
      },
      {
        name: 'challenge_boundEpoch_roundtrip',
        oracle: 'a written boundEpoch is readable back through the genuine model and the raw driver',
        actual: `model round-trip = ${JSON.stringify(challengeDoc.boundEpoch ?? null)}; lean = ${JSON.stringify(leanChallenge ? (leanChallenge.boundEpoch ?? null) : null)}; raw driver field present = ${challengeFieldPresent(rawChallenge)}`,
        met: challengeFieldPresent(rawChallenge) && rawChallenge.boundEpoch === 7,
        tier: 'E1',
      },
      {
        name: 'pairing_claim_expectedEpoch_schema_path',
        oracle: 'PairingSession.claim.expectedEpoch is a declared schema path (F2/X-4 mandatory)',
        actual: `PairingSession.schema.path('claim.expectedEpoch') = ${schemaPaths.pairingClaimExpectedEpoch ? 'declared' : 'undefined'}; claim subdoc paths = ${JSON.stringify(schemaPaths.pairingClaimSubdocPaths)}`,
        met: schemaPaths.pairingClaimExpectedEpoch,
        tier: 'E1',
      },
      {
        name: 'pairing_claim_expectedEpoch_roundtrip',
        oracle: 'a written claim.expectedEpoch is readable back through the genuine model and the raw driver',
        actual: `lean claim = ${JSON.stringify(claimSubdoc(leanSession))}; raw driver claim keys = ${JSON.stringify(claimSubdoc(rawSession) ? Object.keys(claimSubdoc(rawSession)).sort() : null)}`,
        met: claimSubdoc(rawSession) !== null && claimSubdoc(rawSession).expectedEpoch === 5,
        tier: 'E1',
      },
      {
        name: 'pairing_claim_challengeRef_roundtrip',
        oracle: 'claim.challengeRef is populated and round-trips (F2)',
        actual: `raw driver challengeRef = ${JSON.stringify(claimSubdoc(rawSession) ? (claimSubdoc(rawSession).challengeRef ?? null) : null)}`,
        met: claimSubdoc(rawSession) !== null && claimSubdoc(rawSession).challengeRef === 's2t-05-challenge-ref',
        tier: 'E1',
      },
    ],
    notes: COMPONENT_TIER_NOTE,
  };
}

async function s2t06(ctx) {
  const errors = w3a.product.errors;
  const DeviceError = errors.DeviceError;
  const required = [
    { code: 'PAIRING_CEREMONY_STALE', requiredHttpStatus: 409 },
    { code: 'PAIRING_CEREMONY_REQUIRED', requiredHttpStatus: 400 },
    { code: 'AUDIT_EVENT_SHAPE_INVALID', requiredHttpStatus: 500 },
  ];
  const constructed = required.map((entry) => {
    const error = new DeviceError(entry.code, `${entry.code} probe`);
    const json = error.toJSON();
    return {
      code: entry.code,
      requiredHttpStatus: entry.requiredHttpStatus,
      observedHttpStatus: json.httpStatus,
      presentInErrorMap: Object.prototype.hasOwnProperty.call(errors.DEVICE_ERROR_CODES, entry.code),
      mapValue: errors.DEVICE_ERROR_CODES[entry.code] ?? null,
      match: json.httpStatus === entry.requiredHttpStatus,
      serialized: json,
    };
  });
  const constructedSites = env.scanConstructedErrorCodes();
  const staticCompleteness = required.map((entry) => ({
    code: entry.code,
    presentInErrorMap: Object.prototype.hasOwnProperty.call(errors.DEVICE_ERROR_CODES, entry.code),
    constructedInProductBytes:
      constructedSites.find((site) => site.code === entry.code) ?? null,
  }));

  return {
    status: STATUS.EXPECTED_RED,
    productMethodInvoked: true,
    actual: {
      scenario:
        'construct DeviceError for the three F9 codes and require exact 409/400/500, plus a static completeness scan of every constructed DeviceError code against the frozen map',
      invocation: {
        method: 'new DeviceError(code) from api/server/services/Device/errors.js (real product byte)',
        errorMapSize: Object.keys(errors.DEVICE_ERROR_CODES).length,
      },
      constructed,
      staticCompleteness,
      allConstructedCodesFromProductBytes: constructedSites.map((site) => site.code),
      contractMismatch:
        'F9 requires exactly three new map entries PAIRING_CEREMONY_STALE=409, PAIRING_CEREMONY_REQUIRED=400, AUDIT_EVENT_SHAPE_INVALID=500; none of the three exists in the frozen map, so the first two fall back to the fail-closed default 500 and no product site constructs any of them',
      staticAnchors: { errorMap: productSrc('errors.js', 1, 20) },
    },
    components: [
      ...constructed.map((entry) => ({
        name: `device_error_${entry.code}_http_status`,
        oracle: `${entry.code} => ${entry.requiredHttpStatus}`,
        actual: `observed httpStatus=${entry.observedHttpStatus} (presentInErrorMap=${entry.presentInErrorMap}, mapValue=${JSON.stringify(entry.mapValue)})`,
        met: entry.match,
        tier: 'E0',
      })),
      {
        name: 'error_map_completeness',
        oracle: 'all three F9 codes are present in DEVICE_ERROR_CODES with the exact required status',
        actual: `absent codes = ${JSON.stringify(staticCompleteness.filter((entry) => !entry.presentInErrorMap).map((entry) => entry.code))}; constructed-in-product-bytes = ${JSON.stringify(staticCompleteness.filter((entry) => entry.constructedInProductBytes !== null).map((entry) => entry.code))}`,
        met: staticCompleteness.every((entry) => entry.presentInErrorMap),
        tier: 'E0',
      },
      {
        name: 'device_error_constructor_invoked',
        oracle: 'the real product DeviceError constructor is invoked for each code',
        actual: `invoked for ${constructed.map((entry) => entry.code).join(', ')}`,
        met: true,
        tier: 'E0',
      },
    ],
    notes:
      'E0/E1 row: the F9 error-catalogue oracle is a pure in-memory + static-product-byte proof (executed tier E0); the DB and real AuditEvent models are still composed and connected as the row precondition.',
  };
}

/** Disclosed in-test instrumented authority model: reads delegate to the real model, the single
 * write returns a caller-injected unusable matched count. Used only by S2T-07. */
function instrumentedAuthorityRegistry(registry, injection, recorder) {
  const deviceAuthority = new Proxy(registry.DeviceAuthority, {
    get(target, property) {
      if (property === 'updateOne') {
        return async (filter, update, options) => {
          recorder.push({
            model: 'DeviceAuthority',
            method: 'updateOne',
            filter,
            payloadKind: Array.isArray(update) ? 'pipeline' : 'update',
            pipeline: Array.isArray(update) ? update : null,
            options,
            injectedResult: injection.label,
          });
          return {
            acknowledged: true,
            matchedCount: injection.value,
            modifiedCount: injection.value,
            upsertedCount: 0,
          };
        };
      }
      const value = Reflect.get(target, property);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
  return { ...registry, DeviceAuthority: deviceAuthority };
}

async function s2t07Subcase(ctx, { label, deviceId, injected, expectedEnvelopeCode }) {
  await ctx.seedAuthority({
    _id: deviceId,
    epoch: 0,
    leaseState: 'never',
    identityState: 'pending',
  });
  const audit = env.makeRealAuditSink(ctx.models, ctx.clock);
  const recorder = [];
  const registry = instrumentedAuthorityRegistry(ctx.registry, injected, recorder);
  const authority = ctx.composeAuthority({ registry, audit });
  const before = authoritySnapshot(await ctx.readAuthorityRow(deviceId));
  const envelope = await authority.claimAuthority({
    deviceId,
    tenantId: ctx.TENANT,
    ownerId: ctx.OWNER_C,
    sessionId: `s2t-07-session-${label}`,
    expectedEpoch: 0,
    grantProof: grantProof(deviceId, ctx.clock.now()),
  });
  const after = authoritySnapshot(await ctx.readAuthorityRow(deviceId));
  const view = envelopeView(envelope);
  const persistedAuditRows = audit.outcomes.filter((entry) => entry.ok === true).length;
  const queuedAuditEvents = audit.events.length;
  return {
    label,
    injectedMatchedCount: injected.label,
    injectedMatchedCountTypeof: typeof injected.value,
    injectedMatchedCountIsFinite: Number.isFinite(injected.value),
    recorder,
    authorityBefore: before,
    authorityAfter: after,
    authorityMutated: !sameAuthority(before, after),
    envelope: view,
    productTookCasSuccessPath: view.matched > 0,
    grantAuditEventsQueued: queuedAuditEvents,
    persistedAuditRows,
    auditSinkAttempts: audit.outcomes,
    expectedEnvelopeCode,
  };
}

async function s2t07(ctx) {
  const nan = await s2t07Subcase(ctx, {
    label: 'matchedCount=NaN',
    deviceId: 's2t-07-nan-device',
    injected: { value: Number.NaN, label: 'NaN (typeof number, Number.isFinite false)' },
    expectedEnvelopeCode: 'WRITE_OUTCOME_UNCERTAIN',
  });
  const two = await s2t07Subcase(ctx, {
    label: 'matchedCount=2',
    deviceId: 's2t-07-two-device',
    injected: { value: 2, label: '2' },
    expectedEnvelopeCode: 'WRITE_OUTCOME_UNCERTAIN',
  });

  const nanMet =
    nan.envelope.ok === false &&
    nan.envelope.error !== null &&
    nan.envelope.error.code === 'WRITE_OUTCOME_UNCERTAIN' &&
    nan.persistedAuditRows === 0;
  const twoMet =
    two.envelope.ok === false &&
    two.envelope.error !== null &&
    two.envelope.error.code === 'WRITE_OUTCOME_UNCERTAIN' &&
    two.persistedAuditRows === 0;

  return {
    status: STATUS.EXPECTED_RED,
    productMethodInvoked: true,
    actual: {
      scenario:
        'instrumented authority model: performUpdate result acknowledged=true with matchedCount NaN, and separately matchedCount 2; the real claimAuthority operation is invoked in both sub-cases',
      nan,
      two,
      contractMismatch:
        'F1/F2 require non-finite or matchedCount>1 to be WRITE_OUTCOME_UNCERTAIN with no success audit. NaN reaches WRITE_OUTCOME_UNCERTAIN only incidentally through the 0-match classifier (the type guard passes NaN), while matchedCount=2 is treated as a successful CAS transition and the product attempts a grant audit.',
      staticAnchors: { casLaw: productSrc('authorityService.js', 247, 265), claimSuccess: productSrc('authorityService.js', 592, 605) },
    },
    components: [
      {
        name: 'nan_matched_count_fails_closed',
        oracle: 'matchedCount NaN => WRITE_OUTCOME_UNCERTAIN and no success audit',
        actual: `envelope ok=${nan.envelope.ok} matched=${nan.envelope.matched} error.code=${nan.envelope.error ? nan.envelope.error.code : null}; authority mutated=${nan.authorityMutated}; persisted audit rows=${nan.persistedAuditRows}; note: reached via the 0-match classifier, not a non-finite guard`,
        met: nanMet,
        tier: 'E1',
      },
      {
        name: 'matched_count_above_one_fails_closed',
        oracle: 'matchedCount 2 => WRITE_OUTCOME_UNCERTAIN and no success audit (never treated as success)',
        actual: `envelope ok=${two.envelope.ok} matched=${two.envelope.matched} error.code=${two.envelope.error ? two.envelope.error.code : null}; productTookCasSuccessPath=${two.productTookCasSuccessPath}; grant audit events queued=${two.grantAuditEventsQueued}; persisted audit rows=${two.persistedAuditRows}; authority mutated=${two.authorityMutated}`,
        met: twoMet,
        tier: 'E1',
      },
      {
        name: 'zero_success_audit_both_subcases',
        oracle: 'no success audit row is persisted for either unusable matched count',
        actual: `persisted success audit rows: NaN=${nan.persistedAuditRows}, 2=${two.persistedAuditRows}; the real AuditEvent schema also rejects reasonCode:null so the queued grant event cannot persist`,
        met: nan.persistedAuditRows === 0 && two.persistedAuditRows === 0,
        tier: 'E1',
      },
      {
        name: 'instrumented_write_is_disclosed',
        oracle: 'the injected write result is disclosed and no real mutation is attributed to it',
        actual: `injected updateOne calls recorded: NaN=${nan.recorder.length}, 2=${two.recorder.length}; authority mutated by the injected write: NaN=${nan.authorityMutated}, 2=${two.authorityMutated}`,
        met: nan.recorder.length === 1 && two.recorder.length === 1,
        tier: 'E1',
      },
    ],
    notes: COMPONENT_TIER_NOTE,
  };
}

async function s2t08(ctx) {
  const now = ctx.clock.now();
  const cases = [
    {
      name: 'live_lease_same_epoch',
      deviceId: 's2t-08-live-device',
      seed: {
        _id: 's2t-08-live-device',
        epoch: 0,
        leaseState: 'active',
        identityState: 'active',
        ownerId: ctx.OWNER_A,
        grantId: 's2t-08-live-grant',
        activatedAt: new Date(now - 60000),
        expiresAt: new Date(now + 172800000),
      },
      expectedCode: 'DEVICE_ALREADY_PAIRED_USE_RENEW',
      expectedHttpStatus: 409,
    },
    {
      name: 'lapsed_inside_skew_margin_same_epoch',
      deviceId: 's2t-08-skew-device',
      seed: {
        _id: 's2t-08-skew-device',
        epoch: 0,
        leaseState: 'active',
        identityState: 'active',
        ownerId: ctx.OWNER_B,
        grantId: 's2t-08-skew-grant',
        activatedAt: new Date(now - 60000),
        expiresAt: new Date(now - 1000),
      },
      expectedCode: 'PAIRING_WINDOW_TOO_EARLY',
      expectedHttpStatus: 409,
    },
    {
      name: 'retired_same_epoch',
      deviceId: 's2t-08-retired-device',
      seed: {
        _id: 's2t-08-retired-device',
        epoch: 0,
        leaseState: 'revoked',
        identityState: 'retired',
        ownerId: ctx.OWNER_C,
        grantId: 's2t-08-retired-grant',
        retiredAt: new Date(now - 1000),
        retiredBy: ctx.OWNER_C,
      },
      expectedCode: 'DEVICE_IDENTITY_REVOKED',
      expectedHttpStatus: 409,
    },
  ];

  const authority = ctx.composeAuthority();
  const observed = [];
  for (const entry of cases) {
    // eslint-disable-next-line no-await-in-loop
    await ctx.seedAuthority(entry.seed);
    // eslint-disable-next-line no-await-in-loop
    const before = authoritySnapshot(await ctx.readAuthorityRow(entry.deviceId));
    // eslint-disable-next-line no-await-in-loop
    const envelope = await authority.claimAuthority({
      deviceId: entry.deviceId,
      tenantId: ctx.TENANT,
      ownerId: ctx.OWNER_A,
      sessionId: `s2t-08-session-${entry.name}`,
      expectedEpoch: 0,
      grantProof: grantProof(entry.deviceId, now),
    });
    // eslint-disable-next-line no-await-in-loop
    const after = authoritySnapshot(await ctx.readAuthorityRow(entry.deviceId));
    const view = envelopeView(envelope);
    observed.push({
      name: entry.name,
      expectedCode: entry.expectedCode,
      expectedHttpStatus: entry.expectedHttpStatus,
      ceremonyExpectedEpoch: 0,
      authorityEpochBefore: before.epoch,
      authorityEpochAfter: after.epoch,
      sameEpochProvenByReread: before.epoch === after.epoch && before.epoch === 0,
      stateAtZeroMatch: { leaseState: before.leaseState, identityState: before.identityState, expiresAt: before.expiresAt ?? entry.seed.expiresAt },
      envelope: view,
      matchedZero: view.matched === 0,
      classificationMatchesFrozenNonStaleRule:
        view.error !== null &&
        view.error.code === entry.expectedCode &&
        view.error.httpStatus === entry.expectedHttpStatus,
      fabricatedPairingCeremonyStale: view.error !== null && view.error.code === 'PAIRING_CEREMONY_STALE',
      rowUnchanged: sameAuthority(before, after),
    });
  }
  const successAuditRows = ctx.audit.outcomes.filter((entry) => entry.ok === true).length;
  const staleCodeInErrorMap = Object.prototype.hasOwnProperty.call(
    w3a.product.errors.DEVICE_ERROR_CODES,
    'PAIRING_CEREMONY_STALE',
  );

  const allMet = observed.every(
    (entry) =>
      entry.matchedZero &&
      entry.sameEpochProvenByReread &&
      entry.classificationMatchesFrozenNonStaleRule &&
      entry.fabricatedPairingCeremonyStale === false &&
      entry.rowUnchanged,
  );

  return {
    status: allMet ? STATUS.PASS_CURRENT : STATUS.EXPECTED_RED,
    productMethodInvoked: true,
    actual: {
      scenario:
        'three forced claim 0-matches where a raw-driver re-read proves the SAME expected epoch at g=0 and the row is in a non-stale denial/ambiguous state (live lease, lease lapsed inside the 5 s skew margin, retired identity)',
      observed,
      successAuditRowsPersisted: successAuditRows,
      pairingCeremonyStaleCodeInErrorMap: staleCodeInErrorMap,
      fabricatedPairingCeremonyStale: observed.some((entry) => entry.fabricatedPairingCeremonyStale),
      frozenRule:
        'F2: on a claim 0-match, retired => DEVICE_IDENTITY_REVOKED; observed epoch differs => PAIRING_CEREMONY_STALE; live lease at the same generation => the applicable frozen live-state denial; otherwise WRITE_OUTCOME_UNCERTAIN',
      staticAnchors: {
        claimMissClassifier: productSrc('authorityService.js', 458, 509),
        errorMap: productSrc('errors.js', 1, 20),
      },
    },
    components: observed.map((entry) => ({
      name: `${entry.name}_non_stale_classification`,
      oracle: `a 0-match with the SAME epoch is classified ${entry.expectedCode} (${entry.expectedHttpStatus}) and never PAIRING_CEREMONY_STALE`,
      actual: `observed matched=${entry.envelope.matched} error.code=${entry.envelope.error ? entry.envelope.error.code : null} httpStatus=${entry.envelope.error ? entry.envelope.error.httpStatus : null}; epoch ${entry.authorityEpochBefore} -> ${entry.authorityEpochAfter}; same-epoch proven by re-read=${entry.sameEpochProvenByReread}`,
      met:
        entry.matchedZero &&
        entry.sameEpochProvenByReread &&
        entry.classificationMatchesFrozenNonStaleRule &&
        entry.fabricatedPairingCeremonyStale === false,
      tier: 'E1',
    })),
  };
}

const ROWS = [
  {
    id: 'S2T-01',
    tier: 'E1',
    tag: 's2t01missingexpectedepoch',
    expectedOracle:
      "PASS iff claimAuthority invoked WITHOUT expectedEpoch returns {ok:false, error.code:'PAIRING_CEREMONY_REQUIRED', httpStatus:400} with zero authority mutation and zero success audit",
    run: s2t01,
  },
  {
    id: 'S2T-02',
    tier: 'E1',
    tag: 's2t02staleexpectedepoch',
    expectedOracle:
      "PASS iff a stale expectedEpoch g against an authority row at g+1 returns PAIRING_CEREMONY_STALE 409 with matched 0, an unchanged row, no auto-retry and no success audit",
    run: s2t02,
  },
  {
    id: 'S2T-04',
    tier: 'E1',
    tag: 's2t04freshsequentialregrant',
    expectedOracle:
      'PASS iff after a product-service generation-changing revoke at g -> g+1 a FRESH ceremony at g+1 may claim while the stale g ceremony may not (PAIRING_CEREMONY_STALE), with no fabricated regrant through a direct DB update',
    run: s2t04,
  },
  {
    id: 'S2T-05',
    tier: 'E1',
    tag: 's2t05schemaroundtrip',
    expectedOracle:
      'PASS iff Challenge.boundEpoch and PairingSession.claim.expectedEpoch + claim.challengeRef round-trip through the genuine Mongoose schemas/models',
    run: s2t05,
  },
  {
    id: 'S2T-06',
    tier: 'E0/E1',
    tag: 's2t06errorcatalogue',
    expectedOracle:
      'PASS iff DeviceError for PAIRING_CEREMONY_STALE/PAIRING_CEREMONY_REQUIRED/AUDIT_EVENT_SHAPE_INVALID yields exactly 409/400/500 and all three codes are present in the frozen error map and constructed product-side',
    run: s2t06,
  },
  {
    id: 'S2T-07',
    tier: 'E1',
    tag: 's2t07matchedcount',
    expectedOracle:
      'PASS iff an authority performUpdate result with acknowledged=true and matchedCount NaN or 2 yields WRITE_OUTCOME_UNCERTAIN with zero success audit, and matched>0 is never treated as success',
    run: s2t07,
  },
  {
    id: 'S2T-08',
    tier: 'E1',
    tag: 's2t08nonstaleclassify',
    expectedOracle:
      'PASS iff a forced 0-match whose re-read proves the SAME expected epoch is classified by the documented non-stale rule and PAIRING_CEREMONY_STALE is never fabricated merely because matched=0',
    run: s2t08,
  },
];

module.exports = { ROWS };