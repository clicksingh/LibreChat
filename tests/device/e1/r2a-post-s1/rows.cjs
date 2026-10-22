'use strict';

/**
 * W3-B R2-T0A supplemental row definitions (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Rows T0A-02 .. T0A-07 (T0A-01 is the E2 two-process row in fixtures-e2.cjs). Every row:
 *   1. opens its own fenced r2/t0a database;
 *   2. loads the genuine `createModels(mongoose)` registry and the real `AuditEvent` model sink;
 *   3. seeds its preimage with real model writes (majority+journal);
 *   4. attempts genuine composition with the RAW registry (no facade, no shim, no guard bypass);
 *   5. records the truthful stop, the preserved intended oracle, and any read-only static evidence.
 */

const fs = require('node:fs');
const path = require('node:path');

const ctx = require('./ctx.cjs');
const env = require('./env.cjs');
const probes = require('./probes.cjs');
const results = require('./results.cjs');

const TENANT = env.w3a.TENANT;
const OTHER_TENANT = env.w3a.OTHER_TENANT;
const OWNER_A = env.w3a.OWNER_A;

/** F17 acceptance vocabulary asserted verbatim by T0A-07. */
const ONE_PC_ACCEPTANCE_VOCABULARY = 'ONE ACTIVE DEVICE IDENTITY per (ownerId,tenantId)';

const CONSENT_BINDING_SYMBOLS = Object.freeze([
  'boundTenantId',
  'boundOwnerId',
  'boundDeviceId',
  'boundPairingSessionId',
  'boundChallengeRef',
]);

function anchorLines(hits, max = 8) {
  return hits.slice(0, max).map((h) => `${h.file}:${h.line}`);
}

function component(name, oracle, actual, met, tier, extra = {}) {
  return { name, oracle, actual, met, tier, ...extra };
}

/** Scopes the consent-binding check to `requireLocalConsent` only. */
function consentVerifierProbe() {
  const fn = probes.extractFunction(probes.PRODUCT_FILES.pairingSessionService, /async function requireLocalConsent/);
  const inVerifier = CONSENT_BINDING_SYMBOLS.filter((symbol) => fn.text !== null && fn.text.includes(symbol));
  return { fn, inVerifier, absentInVerifier: CONSENT_BINDING_SYMBOLS.filter((s) => !inVerifier.includes(s)) };
}

/* ------------------------------------------------------------------ T0A-02 */

async function buildT0A02(context) {
  const oracle =
    'verifyLocalConsent must return a server-validated structured verdict, never bare true. A bare true verdict, or an approved verdict carrying a null localApprovalNonceHash, MUST be refused with ENDPOINT_CONSENT_REQUIRED and zero challenge spend, zero session consume and zero authority write.';
  const composition = context.compose();
  const rejected = composition.filter((c) => c.accepted === false);
  const gate = env.compositionFailView(composition, oracle, {
    scenario: 'approvePairingClaim with a bare-true local-consent verdict and with an approved/null-nonce verdict',
    intendedBareTrueProbe: "verifyLocalConsent -> true ; expect {ok:false, error.code:'ENDPOINT_CONSENT_REQUIRED'}",
    intendedNullNonceProbe: "verifyLocalConsent -> {ok:true, nonceHash:null} ; expect ENDPOINT_CONSENT_REQUIRED",
  });

  const auditControl = await context.auditControl();
  await ctx.seedAuthority(context, { _id: 't0a02-device', deviceKeyId: 't0a02-key' });
  await ctx.seedPairingSession(context, {
    deviceId: 't0a02-device',
    deviceKeyId: 't0a02-key',
    pendingOwnerId: OWNER_A,
  });

  const consent = consentVerifierProbe();
  const grantedExpr = probes.excerpt(probes.PRODUCT_FILES.pairingSessionService, /const granted = verdict === true/, 1, 3);
  const nonceFallback = probes.excerpt(probes.PRODUCT_FILES.pairingSessionService, /let nonceHash = null;/, 1, 15);
  const nonceHashField = probes.symbolScan('localApprovalNonceHash', [
    probes.PRODUCT_FILES.pairingSessionService,
    probes.PRODUCT_FILES.deviceAuthoritySchema,
  ]);

  return {
    status: results.STATUS.EXPECTED_RED,
    tierExecuted: 'E1',
    blockedAtFactoryComposition: rejected.length > 0,
    pendingOracle: oracle,
    actual: {
      ...gate,
      auditSinkControl: auditControl,
      staticEvidence: {
        tier: 'E0',
        isProductBehavior: false,
        bareTrueAcceptedByCurrentBytes: grantedExpr.found,
        grantedExpressionAnchor: grantedExpr.anchors,
        grantedExpressionExcerpt: grantedExpr.text,
        nullNonceHashFallbackAnchor: nonceFallback.anchors,
        nullNonceHashFallbackExcerpt: nonceFallback.text,
        consentVerifierScope: { file: consent.fn.file, startLine: consent.fn.startLine, endLine: consent.fn.endLine },
        verdictBindingFieldsInConsentVerifier: consent.inVerifier,
        verdictBindingFieldsAbsentFromConsentVerifier: consent.absentInVerifier,
        localApprovalNonceHashSymbol: { present: nonceHashField.present, anchors: anchorLines(nonceHashField.hits) },
        finding:
          'Current bytes accept a bare `true` verdict (`verdict === true`) and accept `{ok:true}` with no verdict-binding comparison inside requireLocalConsent; nonceHash legitimately falls back to null, so grantProof.localApprovalNonceHash can be null. F14 requires ENDPOINT_CONSENT_REQUIRED instead.',
      },
    },
    sourceAnchors: [
      ...new Set([
        ...rejected.map((c) => c.guardAnchor),
        ...grantedExpr.anchors.map((a) => `${grantedExpr.file}:${a.line}`),
        ...nonceFallback.anchors.map((a) => `${nonceFallback.file}:${a.line}`),
      ]),
    ],
    components: [
      component(
        'bare_true_verdict_rejected',
        'verifyLocalConsent -> true must yield ENDPOINT_CONSENT_REQUIRED',
        'not executed: genuine-model factory composition gate stopped the service before any claim call',
        false,
        'E1',
      ),
      component(
        'null_nonce_hash_verdict_rejected',
        'approved verdict with null localApprovalNonceHash must yield ENDPOINT_CONSENT_REQUIRED',
        'not executed: genuine-model factory composition gate stopped the service before any claim call',
        false,
        'E1',
      ),
      component(
        'zero_spend_consume_authority_write',
        'zero challenge spend, zero session consume, zero authority write on refusal',
        'unreachable at E1; DB read-back shows only the seeded preimage (no product method ran, so no product write occurred)',
        false,
        'E1',
      ),
      component(
        'current_bytes_accept_bare_true',
        'current pre-repair bytes must NOT accept a bare true consent verdict',
        `current bytes DO accept it: ${grantedExpr.anchors.map((a) => `${grantedExpr.file}:${a.line}`).join(', ')}`,
        false,
        'E0',
        { isProductBehavior: false },
      ),
    ],
    notes:
      'EXPECTED_RED at the known genuine-Mongoose factory composition gate (blockedAtFactoryComposition). The E0 static excerpt shows the exact pre-repair acceptance of bare true; it is supplementary evidence, not an E1 certification.',
  };
}

/* ------------------------------------------------------------------ T0A-03 */

const MISMATCH_KINDS = Object.freeze(['tenant', 'owner', 'device', 'session', 'challenge']);

async function buildT0A03(context) {
  const oracle =
    'A structured consent verdict whose bound tenant/owner/device/session/challenge disagrees with trusted server/session truth MUST fail BEFORE any spend or write (ENDPOINT_CONSENT_REQUIRED with zero challenge spend, zero session consume, zero authority write).';
  const composition = context.compose();
  const rejected = composition.filter((c) => c.accepted === false);
  const gate = env.compositionFailView(composition, oracle, {
    scenario: 'one fixture iterating all five consent binding mismatches',
    mismatchKinds: [...MISMATCH_KINDS],
    intendedProbe:
      'for kind in [tenant,owner,device,session,challenge]: verifyLocalConsent -> {ok:true, nonceHash, bound*:<mismatched>} ; expect ENDPOINT_CONSENT_REQUIRED',
  });

  const auditControl = await context.auditControl();
  await ctx.seedAuthority(context, { _id: 't0a03-device', deviceKeyId: 't0a03-key' });
  await ctx.seedPairingSession(context, {
    deviceId: 't0a03-device',
    deviceKeyId: 't0a03-key',
    pendingOwnerId: OWNER_A,
  });

  const consent = consentVerifierProbe();
  const fileLevelScans = CONSENT_BINDING_SYMBOLS.map((symbol) => probes.symbolScan(symbol, [probes.PRODUCT_FILES.pairingSessionService]));

  const components = MISMATCH_KINDS.map((kind) =>
    component(
      `consent_binding_mismatch_${kind}`,
      `verdict.bound${kind[0].toUpperCase()}${kind.slice(1)} != trusted ${kind} truth must yield ENDPOINT_CONSENT_REQUIRED before spend/write`,
      'not executed: genuine-model factory composition gate stopped the service before any claim call',
      false,
      'E1',
    ),
  );
  components.push(
    component(
      'current_bytes_compare_verdict_bindings',
      'the product consent verifier must compare every verdict binding field to trusted truth',
      `binding fields referenced inside requireLocalConsent: ${consent.inVerifier.length}/5 (${consent.inVerifier.join(', ') || 'none'})`,
      consent.inVerifier.length === CONSENT_BINDING_SYMBOLS.length,
      'E0',
      { isProductBehavior: false },
    ),
  );

  return {
    status: results.STATUS.EXPECTED_RED,
    tierExecuted: 'E1',
    blockedAtFactoryComposition: rejected.length > 0,
    pendingOracle: oracle,
    actual: {
      ...gate,
      auditSinkControl: auditControl,
      staticEvidence: {
        tier: 'E0',
        isProductBehavior: false,
        consentVerifierScope: { file: consent.fn.file, startLine: consent.fn.startLine, endLine: consent.fn.endLine },
        verdictBindingFieldsInConsentVerifier: consent.inVerifier,
        verdictBindingFieldsAbsentFromConsentVerifier: consent.absentInVerifier,
        bindingSymbolsAnywhereInFile: fileLevelScans.map((b) => ({
          symbol: b.symbol,
          presentInFile: b.present,
          anchors: anchorLines(b.hits),
          note: 'boundOwnerId/boundPairingSessionId appear only in the challenge-spend bound object, not in the consent verdict check',
        })),
        finding:
          'requireLocalConsent accepts any verdict with ok === true and never compares boundTenantId/boundOwnerId/boundDeviceId/boundPairingSessionId/boundChallengeRef to trusted truth.',
      },
    },
    sourceAnchors: [
      ...new Set([
        ...rejected.map((c) => c.guardAnchor),
        `${consent.fn.file}:${consent.fn.startLine}`,
      ]),
    ],
    components,
    notes:
      'EXPECTED_RED at the genuine-model factory composition gate; all five binding mismatches share one fixture and each preserves its own intended E1 oracle.',
  };
}

/* ------------------------------------------------------------------ T0A-04 */

async function buildT0A04(context) {
  const oracle =
    'After a challenge spend and an uncertain/lost DeviceAuthority create response, recovery MUST re-read by trusted {tenantId,deviceKeyId}: if the unique authority row exists, return that registered identity idempotently; if absent, the consumed challenge stays dead and the client MUST obtain a FRESH registration challenge — no second create against the spent challenge.';
  const composition = context.compose();
  const rejected = composition.filter((c) => c.accepted === false);
  const gate = env.compositionFailView(composition, oracle, {
    scenario: 'registration lost-ack recovery after challenge spend, both branches',
    branches: ['committed-and-ack-lost (authority row exists)', 'absent-row (no authority row)'],
  });

  const auditControl = await context.auditControl();

  const spentChallengeA = await ctx.seedChallenge(context, {
    challengeHash: 't0a04-spent-challenge-a',
    purpose: 'registration',
    consumedAt: new Date(context.clock.now()),
  });
  const committed = await ctx.seedAuthority(context, {
    _id: 't0a04-committed-identity',
    deviceKeyId: 't0a04-key-committed',
    identityState: 'pending',
  });
  const rereadA = await context.client
    .db(context.dbName)
    .collection('deviceauthorities')
    .findOne({ tenantId: TENANT, deviceKeyId: 't0a04-key-committed' });

  await ctx.seedChallenge(context, {
    challengeHash: 't0a04-spent-challenge-b',
    purpose: 'registration',
    consumedAt: new Date(context.clock.now()),
  });
  const rereadB = await context.client
    .db(context.dbName)
    .collection('deviceauthorities')
    .findOne({ tenantId: TENANT, deviceKeyId: 't0a04-key-absent' });

  const deviceAuthorityUses = probes.scan(probes.PRODUCT_FILES.registrationService, /db\.DeviceAuthority/);
  const deviceAuthorityReads = deviceAuthorityUses.filter((h) => /findOne|find\(|findOneAndUpdate|countDocuments/.test(h.text));
  const challengeReads = probes.scan(probes.PRODUCT_FILES.registrationService, /db\.Challenge\.(findOne|updateOne|create)/);
  const consumedSpendCas = probes.excerpt(probes.PRODUCT_FILES.registrationService, /consumedAt: null,/, 2, 8);

  return {
    status: results.STATUS.EXPECTED_RED,
    tierExecuted: 'E1',
    blockedAtFactoryComposition: rejected.length > 0,
    pendingOracle: oracle,
    actual: {
      ...gate,
      auditSinkControl: auditControl,
      branchA_committedAndAckLost: {
        seededSpentChallengeHash: spentChallengeA.challengeHash,
        consumedAt: spentChallengeA.consumedAt,
        committedIdentityId: String(committed._id),
        recoveryRereadFilter: { tenantId: TENANT, deviceKeyId: 't0a04-key-committed' },
        recoveryRereadFound: rereadA !== null,
        recoveryRereadIdentityId: rereadA ? String(rereadA._id) : null,
        recoveryRereadIdentityState: rereadA ? rereadA.identityState : null,
        requiredOracle: 'return/recover that registered identity idempotently',
        productRecoveryAvailable: false,
      },
      branchB_absentRow: {
        spentChallengeHash: 't0a04-spent-challenge-b',
        recoveryRereadFilter: { tenantId: TENANT, deviceKeyId: 't0a04-key-absent' },
        recoveryRereadFound: rereadB !== null,
        requiredOracle:
          'consumed challenge remains dead; the client must obtain a FRESH registration challenge; no second create against the spent challenge',
        productRecoveryAvailable: false,
      },
      staticEvidence: {
        tier: 'E0',
        isProductBehavior: false,
        deviceAuthorityUsages: deviceAuthorityUses,
        deviceAuthorityReadUsages: deviceAuthorityReads,
        challengeReadUsages: challengeReads,
        consumedSpendCasAnchors: consumedSpendCas.anchors,
        finding:
          deviceAuthorityReads.length === 0
            ? 'registrationService performs ZERO DeviceAuthority read (only .create); no re-read by {tenantId,deviceKeyId} recovery path exists in the pre-repair bytes.'
            : 'registrationService performs a DeviceAuthority read; inspect the recorded usages.',
      },
    },
    sourceAnchors: [
      ...new Set([...rejected.map((c) => c.guardAnchor), ...deviceAuthorityUses.map((h) => `${h.file}:${h.line}`)]),
    ],
    components: [
      component(
        'branchA_return_existing_identity',
        'authority row committed + ack lost => recovery re-reads trusted {tenantId,deviceKeyId} and returns the existing identity idempotently',
        `data-layer preimage confirms the row exists (${rereadA ? String(rereadA._id) : 'absent'}) but no product recovery path is reachable: composition gate`,
        false,
        'E1',
      ),
      component(
        'branchB_require_fresh_challenge',
        'authority row absent => consumed challenge stays dead and a FRESH challenge is required, no blind second create',
        'no product recovery path is reachable: composition gate',
        false,
        'E1',
      ),
      component(
        'current_bytes_have_recovery_reread',
        'current pre-repair bytes must contain the trusted {tenantId,deviceKeyId} re-read recovery',
        `DeviceAuthority read usages in registrationService: ${deviceAuthorityReads.length}`,
        false,
        'E0',
        { isProductBehavior: false },
      ),
    ],
    notes:
      'EXPECTED_RED at the genuine-model factory composition gate. Both recovery branches are pre-seeded with real model writes (majority+journal) and their data-layer preimages are recorded; the product recovery path itself is absent from the pre-repair bytes.',
  };
}

/* ------------------------------------------------------------------ T0A-05 */

function classifyGrantedByHit(hit) {
  if (hit.text.includes('grantedByPairingSessionId: sessionId')) {
    return 'authority claim pipeline $set (write)';
  }
  if (hit.text.startsWith('grantedByPairingSessionId')) {
    return 'schema/type field declaration';
  }
  return 'unclassified';
}

async function buildT0A05(context) {
  const oracle =
    'When the authority claim committed for a pairing session but the session grant marker/response was lost, recovery via DeviceAuthority.grantedByPairingSessionId MUST return the existing non-null grantId and MUST never mint a second grant; a false claim-refused audit entry for a committed grant is forbidden (surface AUDIT_DELIVERY_UNCERTAIN while preserving committed truth).';
  const composition = context.compose();
  const rejected = composition.filter((c) => c.accepted === false);
  const gate = env.compositionFailView(composition, oracle, {
    scenario: 'pairing-claim lost ack: authority committed, session grant marker lost',
  });

  const auditControl = await context.auditControl();

  const session = await ctx.seedPairingSession(context, {
    deviceId: 't0a05-device',
    deviceKeyId: 't0a05-key',
    pendingOwnerId: OWNER_A,
    state: 'consumed',
    consumedAt: new Date(context.clock.now()),
    grantedGrantId: null,
  });
  const sessionId = String(session._id);

  const committed = await ctx.seedAuthority(context, {
    _id: 't0a05-device',
    deviceKeyId: 't0a05-key',
    identityState: 'active',
    leaseState: 'active',
    epoch: 3,
    ownerId: OWNER_A,
    grantId: 't0a05-grant-existing',
    activatedAt: new Date(context.clock.now()),
    expiresAt: new Date(context.clock.now() + 172800000),
    grantedByPairingSessionId: sessionId,
    grantProof: {
      ownerConfirmedAt: new Date(context.clock.now()),
      endpointSignatureVerifiedAt: new Date(context.clock.now()),
      verifiedKeyId: 't0a05-key',
      localApprovalNonceHash: 't0a05-nonce-hash',
    },
  });

  // The authority row's string _id IS the server-issued deviceId.
  const recoveryReread = await context.client
    .db(context.dbName)
    .collection('deviceauthorities')
    .findOne({ tenantId: TENANT, _id: 't0a05-device' });
  const recoveryRereadBySessionLink = await context.client
    .db(context.dbName)
    .collection('deviceauthorities')
    .findOne({ tenantId: TENANT, grantedByPairingSessionId: sessionId });

  const grantedHits = probes
    .symbolScan('grantedByPairingSessionId', [
      ...probes.DEVICE_SERVICE_FILES,
      probes.PRODUCT_FILES.deviceAuthoritySchema,
      probes.PRODUCT_FILES.modelsIndex,
    ])
    .hits.map((hit) => ({ ...hit, role: classifyGrantedByHit(hit) }));

  const claimRefusedOnUncertain = probes.excerpt(
    probes.PRODUCT_FILES.pairingSessionService,
    /claim === null \|\| typeof claim !== 'object' \|\| claim\.ok !== true/,
    2,
    22,
  );
  const grantMarkAnchor = probes.excerpt(probes.PRODUCT_FILES.pairingSessionService, /\$set: \{ grantedGrantId \}/, 3, 12);

  return {
    status: results.STATUS.EXPECTED_RED,
    tierExecuted: 'E1',
    blockedAtFactoryComposition: rejected.length > 0,
    pendingOracle: oracle,
    actual: {
      ...gate,
      auditSinkControl: auditControl,
      lostAckPreimage: {
        pairingSessionId: sessionId,
        sessionState: session.state,
        sessionGrantedGrantId: session.grantedGrantId,
        committedDeviceId: String(committed._id),
        committedGrantId: committed.grantId,
        committedEpoch: committed.epoch,
        committedGrantedByPairingSessionId: committed.grantedByPairingSessionId,
        recoveryRereadFilter: { tenantId: TENANT, _id: 't0a05-device', note: 'authority _id is the server-issued deviceId' },
        recoveryRereadGrantId: recoveryReread ? recoveryReread.grantId : null,
        recoveryRereadByGrantedByPairingSessionIdFound: recoveryRereadBySessionLink !== null,
        requiredOracle: 'return the existing non-null grantId, never mint a second grant',
        productRecoveryAvailable: false,
      },
      staticEvidence: {
        tier: 'E0',
        isProductBehavior: false,
        grantedByPairingSessionIdHits: grantedHits,
        readOrFilterUses: grantedHits.filter((h) => h.role === 'unclassified').length,
        claimRefusedOnNonOkClaimAnchor: claimRefusedOnUncertain.anchors,
        claimRefusedOnNonOkClaimExcerpt: claimRefusedOnUncertain.text,
        grantMarkerWriteAnchor: grantMarkAnchor.anchors,
        finding:
          'grantedByPairingSessionId exists in the schema and is written by the authority claim pipeline, but NO read/filter path uses it: no idempotent recovery exists, and a non-ok claim result (including post-commit uncertainty) still emits a claim-refused audit entry in the pre-repair bytes.',
      },
    },
    sourceAnchors: [
      ...new Set([
        ...rejected.map((c) => c.guardAnchor),
        ...grantedHits.map((h) => `${h.file}:${h.line}`),
        ...claimRefusedOnUncertain.anchors.map((a) => `${claimRefusedOnUncertain.file}:${a.line}`),
      ]),
    ],
    components: [
      component(
        'recovery_returns_existing_grant_id',
        'lost session grant marker => recovery via grantedByPairingSessionId returns the existing non-null grantId',
        `data-layer preimage: authority row carries grantId=${committed.grantId} linked by grantedByPairingSessionId=${sessionId}; no product recovery path is reachable (composition gate)`,
        false,
        'E1',
      ),
      component(
        'never_mint_second_grant',
        'recovery must never mint a second grant for the same committed claim',
        'not executed: composition gate',
        false,
        'E1',
      ),
      component(
        'no_false_claim_refused_audit',
        'a committed grant must never be recorded as claim-refused',
        'not executed: composition gate; static anchor shows claim-refused is emitted on any non-ok claim result',
        false,
        'E1',
      ),
      component(
        'current_bytes_have_idempotent_recovery',
        'current pre-repair bytes must read grantedByPairingSessionId for recovery',
        `read/filter uses of grantedByPairingSessionId: ${grantedHits.filter((h) => h.role === 'unclassified').length}`,
        false,
        'E0',
        { isProductBehavior: false },
      ),
    ],
    notes:
      'EXPECTED_RED at the genuine-model factory composition gate. The lost-ack preimage (committed authority + consumed session without grant marker) is real and recorded; the F15 recovery read path does not exist in the pre-repair bytes.',
  };
}

/* ------------------------------------------------------------------ T0A-06 */

async function buildT0A06(context) {
  const oracle =
    'No Challenge lookup by challengeHash may omit the trusted tenant conjunct. A foreign-tenant row must be indistinguishable from invalid/expired to the caller, and the model recorder must show NO tenantless/global classifier read. spendChallenge has no bound.tenantId fallback.';
  const composition = context.compose();
  const rejected = composition.filter((c) => c.accepted === false);
  const gate = env.compositionFailView(composition, oracle, {
    scenario: 'tenantless challenge classifier prohibition / foreign-tenant indistinguishability',
  });

  const auditControl = await context.auditControl();
  await ctx.seedChallenge(context, { challengeHash: 't0a06-foreign', purpose: 'registration', tenantId: OTHER_TENANT });
  await ctx.seedChallenge(context, { challengeHash: 't0a06-local', purpose: 'registration', tenantId: TENANT });

  // Detector validity control: the recording proxy delegates to the GENUINE models and must be
  // able to distinguish a tenant-scoped read from a tenantless one.
  const detector = probes.makeTenantlessDetector(context.registry);
  const scopedRead = await detector.instrumented.Challenge.findOne({
    challengeHash: 't0a06-local',
    purpose: 'registration',
    tenantId: TENANT,
  }).lean();
  const tenantlessRead = await detector.instrumented.Challenge.findOne({
    challengeHash: 't0a06-foreign',
    purpose: 'registration',
  }).lean();
  const detectorTenantless = detector.tenantlessReads();
  const entries = detector.recorder.entries;

  const classifier = probes.extractFunction(probes.PRODUCT_FILES.registrationService, /async function classifyForeignTenantChallenge/);
  const classifierCall = probes.excerpt(probes.PRODUCT_FILES.registrationService, /await classifyForeignTenantChallenge/, 2, 4);
  const spendTenantResolution = probes.extractFunction(
    probes.PRODUCT_FILES.authorityService,
    /async function spendChallengeImpl/,
  );
  const tenantFallbackLine = probes.scan(probes.PRODUCT_FILES.authorityService, /bound\.tenantId/);
  const challengeReadsWithHash = probes.scan(probes.PRODUCT_FILES.registrationService, /challengeHash/);

  return {
    status: results.STATUS.EXPECTED_RED,
    tierExecuted: 'E1',
    blockedAtFactoryComposition: rejected.length > 0,
    pendingOracle: oracle,
    actual: {
      ...gate,
      auditSinkControl: auditControl,
      foreignTenantIndistinguishability: {
        foreignRowSeeded: { challengeHash: 't0a06-foreign', tenantId: OTHER_TENANT },
        localRowSeeded: { challengeHash: 't0a06-local', tenantId: TENANT },
        productObservation: 'not executed: composition gate (no product read happened)',
        requiredOracle:
          'foreign-tenant row indistinguishable from invalid/expired (uniform miss); TENANT_MISMATCH may not be derived from discovering a foreign row',
      },
      modelRecorder: {
        recorderKind: 'recording-proxy-over-genuine-mongoose-models (delegating; not a plain-object facade)',
        tenantScopedReadFilter: entries[0] ? entries[0].filter : null,
        tenantScopedReadFound: scopedRead !== null,
        tenantlessReadFilter: entries[1] ? entries[1].filter : null,
        tenantlessReadFound: tenantlessRead !== null,
        detectorDetectedTenantlessReads: detectorTenantless.length,
        productModelReadsRecorded: 0,
        detectorValidity: detectorTenantless.length === 1 && entries.length === 2,
      },
      staticEvidence: {
        tier: 'E0',
        isProductBehavior: false,
        classifyForeignTenantChallengeAnchor: { file: classifier.file, startLine: classifier.startLine, endLine: classifier.endLine },
        classifyForeignTenantChallengeExcerpt: classifier.text,
        classifierCallAnchor: classifierCall.anchors,
        spendChallengeTenantResolutionAnchor: {
          file: spendTenantResolution.file,
          startLine: spendTenantResolution.startLine,
          endLine: spendTenantResolution.endLine,
        },
        boundTenantFallbackLines: tenantFallbackLine,
        challengeHashReferences: challengeReadsWithHash.length,
        finding:
          'Pre-repair bytes contain a tenantless classifier: db.Challenge.findOne({challengeHash, purpose}) with NO tenantId conjunct, plus a spendChallenge fallback that accepts bound.tenantId. F16 forbids both.',
      },
    },
    sourceAnchors: [
      ...new Set([
        ...rejected.map((c) => c.guardAnchor),
        `${classifier.file}:${classifier.startLine}`,
        ...tenantFallbackLine.map((h) => `${h.file}:${h.line}`),
      ]),
    ],
    components: [
      component(
        'no_tenantless_classifier_read',
        'model recorder must show no Challenge read by challengeHash without the trusted tenant',
        'not reachable at E1: composition gate; zero product model reads were executed (product recorder entries 0)',
        false,
        'E1',
      ),
      component(
        'foreign_tenant_row_indistinguishable',
        'foreign-tenant row yields the same uniform invalid/expired outcome as an absent row',
        'not executed: composition gate',
        false,
        'E1',
      ),
      component(
        'detector_validity_control',
        'the tenantless-read detector must positively detect a tenantless read',
        `detector flagged ${detectorTenantless.length} tenantless read(s) out of ${entries.length} recorded read(s)`,
        detectorTenantless.length === 1 && entries.length === 2,
        'E0',
        { isProductBehavior: false },
      ),
      component(
        'current_bytes_tenantless_classifier_present',
        'current pre-repair bytes must contain NO tenantless challenge classifier',
        `classifyForeignTenantChallenge at ${classifier.file}:${classifier.startLine}; spendChallenge bound.tenantId fallback at ${tenantFallbackLine.map((h) => `${h.file}:${h.line}`).join(', ') || 'n/a'}`,
        false,
        'E0',
        { isProductBehavior: false },
      ),
    ],
    notes:
      'EXPECTED_RED at the genuine-model factory composition gate. The detector-validity control proves a tenantless Challenge read WOULD be caught; the pre-repair bytes contain exactly such a classifier statically, but no product read was executed so the E1 recorder trace is empty by construction.',
  };
}

/* ------------------------------------------------------------------ T0A-07 */

async function buildT0A07(context) {
  const oracle =
    'Acceptance vocabulary and effective law must mean exactly ONE ACTIVE DEVICE IDENTITY per (ownerId,tenantId), enforced by the authority row/index and server-issued deviceId; the claim must never assert physical hardware attestation. This row is a spec/test assertion (E0 static control), NOT a product security pass.';
  const composition = context.compose();
  const rejected = composition.filter((c) => c.accepted === false);

  const auditControl = await context.auditControl();

  const indexExcerpt = probes.excerpt(
    probes.PRODUCT_FILES.deviceAuthoritySchema,
    /partialFilterExpression: \{ leaseState: 'active' \}/,
    3,
    2,
  );
  const ownerTenantIndexPresent =
    indexExcerpt.found && probes.scan(probes.PRODUCT_FILES.deviceAuthoritySchema, /ownerId: 1, tenantId: 1/).length > 0;

  // Product-byte vocabulary scan only: the row oracle and the detector source quote the forbidden
  // phrase in order to forbid/detect it, so they are excluded from the affirmative-claim scan.
  const productVocabulary = probes.scanAttestationVocabulary([
    env.DEVICE_DIR,
    path.join(env.DATA_SCHEMAS_DIR, 'schema'),
    path.join(env.DATA_SCHEMAS_DIR, 'models'),
  ]);
  const harnessFiles = probes.walkFiles(env.R2A_DIR, (full) => full.endsWith('.cjs')).filter(
    (full) => !full.endsWith('rows.cjs') && !full.endsWith('probes.cjs'),
  );
  const harnessVocabularyHits = [];
  for (const file of harnessFiles) {
    const text = fs.readFileSync(file, 'utf8').toLowerCase();
    for (const term of probes.attestationTerms()) {
      if (text.includes(term.toLowerCase())) {
        harnessVocabularyHits.push({ file: path.relative(env.WORKTREE, file).replace(/\\/g, '/'), term });
      }
    }
  }

  const rowsText = fs.readFileSync(__filename, 'utf8');
  const onePcVocabularyPresent = rowsText.includes(ONE_PC_ACCEPTANCE_VOCABULARY);
  const historicalOnePc = probes.scan('tests/device/e1/fixtures.cjs', /one-PC/);
  const historicalOnePcW3a = probes.scan('tests/device/e1/w3a/fixture-authority.cjs', /one-PC/);

  const required = [
    component(
      'authority_index_one_active_identity',
      'the authority index must enforce one active device identity per (ownerId,tenantId)',
      `deviceAuthoritySchema index {ownerId:1,tenantId:1} unique partialFilterExpression {leaseState:'active'} present: ${ownerTenantIndexPresent}`,
      ownerTenantIndexPresent,
      'E0',
      { isProductBehavior: false },
    ),
    component(
      'no_hardware_attestation_claim_in_product_bytes',
      'no product byte may claim physical hardware attestation',
      `forbidden attestation terms found across ${productVocabulary.fileCount} product source files: ${productVocabulary.hits.length}`,
      productVocabulary.clean,
      'E0',
      { isProductBehavior: false },
    ),
    component(
      'no_affirmative_attestation_claim_in_harness',
      'the T0A harness assertions may not claim physical hardware attestation',
      `forbidden attestation terms found across ${harnessFiles.length} harness files (row oracle/detector sources excluded because they quote the phrase to forbid/detect it): ${harnessVocabularyHits.length}`,
      harnessVocabularyHits.length === 0,
      'E0',
      { isProductBehavior: false },
    ),
    component(
      'acceptance_vocabulary_states_device_identity',
      'the T0A acceptance vocabulary must state ONE ACTIVE DEVICE IDENTITY per (ownerId,tenantId)',
      `literal acceptance phrase present in tests/device/e1/r2a/rows.cjs: ${onePcVocabularyPresent}`,
      onePcVocabularyPresent,
      'E0',
      { isProductBehavior: false },
    ),
  ];
  const supplementary = [
    component(
      'effective_law_certifiable_through_composition',
      'effective one-active-identity law certifiable through genuine composition',
      `not certifiable: genuine-model factory composition gate (${rejected.length} factories rejected)`,
      false,
      'E1',
      { isProductBehavior: false, required: false },
    ),
  ];
  const allRequiredMet = required.every((c) => c.met === true);

  return {
    status: allRequiredMet ? results.STATUS.PASS_CURRENT : results.STATUS.EXPECTED_RED,
    tierExecuted: 'E0',
    blockedAtFactoryComposition: rejected.length > 0,
    pendingOracle: oracle,
    productClaim: false,
    actual: {
      kind: allRequiredMet ? 'STATIC_CONTROL_SATISFIED' : 'STATIC_CONTROL_VIOLATED',
      scenario: 'one-PC / one-device-identity semantics and vocabulary',
      auditSinkControl: auditControl,
      compositionAttempt: composition,
      staticEvidence: {
        tier: 'E0',
        isProductBehavior: false,
        authorityIndexAnchor: indexExcerpt.anchors,
        authorityIndexExcerpt: indexExcerpt.text,
        oneActiveDeviceIdentityPerOwnerTenant: ownerTenantIndexPresent,
        productVocabulary,
        harnessVocabularyHits,
        acceptanceVocabularyPhrase: ONE_PC_ACCEPTANCE_VOCABULARY,
        acceptanceVocabularyPresent: onePcVocabularyPresent,
        historicalOnePcOccurrences: [...historicalOnePc, ...historicalOnePcW3a],
        historicalOnePcNote:
          'Pre-R2 W3-A fixtures use the historical phrase "one-PC"; F17 defines one-PC as one active DEVICE IDENTITY per (ownerId,tenantId) and forbids only physical-hardware claims, so these immutable historical occurrences are recorded for information and are not violations.',
      },
      supplementary,
    },
    sourceAnchors: indexExcerpt.anchors.map((a) => `${indexExcerpt.file}:${a.line}`),
    components: [...required, ...supplementary],
    notes:
      'E0 static control. Required checks: the authority index enforces one active device identity per (ownerId,tenantId); no hardware-attestation vocabulary exists in the product bytes or in the harness assertions; the F17 acceptance phrase is present verbatim. productClaim is false — this is a vocabulary/spec control, not a product security pass; the E1 effective-law certification remains blocked at the genuine-model composition gate.',
  };
}

const ROW_DEFS = [
  {
    id: 'T0A-02-CONSENT-BARE-TRUE',
    contractRef: 'F14/F18-B',
    tier: 'E1',
    tag: 't0a02consentbaretrue',
    expectedOracle:
      'verifyLocalConsent must return a server-validated structured verdict, never bare true. A bare true verdict, or an approved verdict with null localApprovalNonceHash, MUST be ENDPOINT_CONSENT_REQUIRED with zero challenge spend, zero session consume and zero authority write.',
    build: buildT0A02,
  },
  {
    id: 'T0A-03-CONSENT-BINDING-MISMATCH',
    contractRef: 'F14/F18-C',
    tier: 'E1',
    tag: 't0a03consentbinding',
    expectedOracle:
      'A structured consent verdict whose bound tenant/owner/device/session/challenge disagrees with trusted truth MUST fail BEFORE any spend or write (ENDPOINT_CONSENT_REQUIRED, zero spend/consume/authority write).',
    build: buildT0A03,
  },
  {
    id: 'T0A-04-REGISTRATION-LOST-ACK',
    contractRef: 'F15/F18-D',
    tier: 'E1',
    tag: 't0a04reglostack',
    expectedOracle:
      'After challenge spend and a lost DeviceAuthority create response, recovery MUST re-read trusted {tenantId,deviceKeyId}: return the existing matching identity if committed, otherwise require a FRESH challenge with no blind second create. Both branches recorded.',
    build: buildT0A04,
  },
  {
    id: 'T0A-05-CLAIM-LOST-ACK',
    contractRef: 'F15/F18-E',
    tier: 'E1',
    tag: 't0a05claimlostack',
    expectedOracle:
      'Authority claim committed but session grant marker/response lost: recovery via DeviceAuthority.grantedByPairingSessionId MUST return the existing non-null grantId and never mint a second grant; a false claim-refused audit entry is forbidden.',
    build: buildT0A05,
  },
  {
    id: 'T0A-06-TENANTLESS-CLASSIFIER',
    contractRef: 'F16/F18-F',
    tier: 'E1',
    tag: 't0a06tenantless',
    expectedOracle:
      'No Challenge lookup by challengeHash may omit the trusted tenant. A foreign-tenant row must be indistinguishable from invalid/expired and the model recorder must show NO tenantless/global classifier read; spendChallenge has no bound.tenantId fallback.',
    build: buildT0A06,
  },
  {
    id: 'T0A-07-ONE-PC-SEMANTICS',
    contractRef: 'F17/F18-G',
    tier: 'E0',
    tag: 't0a07onepc',
    expectedOracle:
      'Acceptance vocabulary and effective law must mean exactly ONE ACTIVE DEVICE IDENTITY per (ownerId,tenantId); the claim must never assert physical hardware attestation. Spec/test assertion only, NOT a product security pass.',
    build: buildT0A07,
  },
];

module.exports = { ROW_DEFS, ONE_PC_ACCEPTANCE_VOCABULARY, MISMATCH_KINDS, consentVerifierProbe };