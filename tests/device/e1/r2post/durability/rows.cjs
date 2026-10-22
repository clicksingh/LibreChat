'use strict';

/**
 * W3-B R2 S4T rows S4T-01 … S4T-08 (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Every E1 row actually invokes the frozen product API against genuine `createModels(mongoose)`
 * models on a real Mongo replica set and captures the REAL argument list of the authority-critical
 * write site. Statuses are derived dynamically by `ledger.classifyCreateRow` / `classifyControlRow`;
 * no row's status is hard-coded, and a setup/substrate failure can never be reported as a red row.
 *
 * The exact F8 repair predicate is: "the captured `Model.create` call includes an options object,
 * passed through an unambiguous overload, with `writeConcern.w === 'majority'` and
 * `writeConcern.j === true`". A connection/server default does not satisfy it, and Mongoose 8's
 * `create(doc, options)` form does not either (the second argument becomes a second document —
 * `mongoose/lib/model.js:2681-2701`), so the array form is required.
 *
 * Two of the three authorized create rows (S4T-01, S4T-03) cannot reach their authorized
 * `EXPECTED_RED` state: the authorization makes that state conditional on proven durable row
 * read-back, and the frozen `challenge` / `pairingSession` schemas reject the product's own create
 * rows through Mongoose validation before any write is sent. That is recorded as an explicit
 * `actual.blocker` on the row, never as a red finding.
 */

const {
  HarnessFail,
  connectionWriteConcernProbe,
  env,
  envelopeView,
  errorView,
  w3a,
} = require('./harness.cjs');
const { STATUS, classifyCreateRow, classifyControlRow } = require('./ledger.cjs');
const { isNonEmptyString, writeConcernVerdict } = require('./capture.cjs');

const AUDIT_LABEL = 'real-audit-event-create';
const WC = { w: 'majority', j: true };

const BOUND_EPOCH_ANCHOR =
  'packages/data-schemas/src/schema/challenge.ts:52-60 — boundEpoch: {type: Number, default: null, min: 0, validate: {validator: Number.isInteger}}';
const CLAIM_EPOCH_ANCHOR =
  'packages/data-schemas/src/schema/pairingSession.ts:98-106 — claim.expectedEpoch: {type: Number, default: null, min: 0, validate: {validator: Number.isInteger}}';
const MONGOOSE_CREATE_OVERLOAD_ANCHOR =
  'tests/device/_phase1_evidence/w2-runtime/node_modules/mongoose/lib/model.js:2681-2701 — a non-array first argument makes every argument a document, so `create(doc, options)` is NOT an options overload';

function component(name, oracle, actual, met, tier) {
  return { name, oracle, actual: String(actual), met: met === true, tier };
}

function recordsSince(ctx, mark) {
  return ctx.capture.records.slice(mark);
}

function byLabel(records, label) {
  return records.filter((record) => record.label === label);
}

function sortedKeys(value) {
  return value !== null && typeof value === 'object' ? Object.keys(value).sort() : [];
}

function genuineModelIdentity(key, model) {
  let registered = null;
  try {
    registered = w3a.mongoose.model(key);
  } catch {
    registered = null;
  }
  return {
    modelName: model.modelName ?? null,
    typeofModel: typeof model,
    collection: model.collection ? model.collection.name : null,
    schemaPresent: Boolean(model.schema),
    identityMatchesMongooseRegistration: registered === model,
  };
}

function beginView(result) {
  return {
    ok: result.ok === true,
    challengeHashPresent: isNonEmptyString(result.challengeHash),
    challengeReturnedLength: isNonEmptyString(result.challenge) ? result.challenge.length : null,
    error: result.error ? errorView(result.error) : null,
  };
}

/**
 * Independence probe: pass the product's own row shape through the ARRAY-form unambiguous options
 * overload carrying explicit majority+journal. Adding the missing option alone cannot make the write
 * durable, so a reproduced ValidationError proves the substrate rejection is orthogonal to the F8
 * option omission.
 */
async function validatorIndependenceProbe(model, row) {
  const probe = {
    overload: 'Model.create([row], { writeConcern: { w: "majority", j: true } }) (array form)',
    rowShapeKeys: sortedKeys(row),
    requestedWriteConcern: WC,
    threw: false,
    error: null,
    persisted: false,
  };
  try {
    const docs = await model.create([row], { writeConcern: WC });
    probe.persisted = Array.isArray(docs) && docs.length === 1;
  } catch (err) {
    probe.threw = true;
    probe.error = {
      name: err.name ?? null,
      message: err.message ?? null,
      paths: Object.keys(err.errors ?? {}),
      perPath: Object.fromEntries(
        Object.entries(err.errors ?? {}).map(([key, value]) => [key, `${value.name}: ${value.message}`]),
      ),
    };
  }
  return probe;
}

/* ------------------------------------------------------------------ S4T-01 */

async function s4t01(ctx) {
  const challenge = ctx.models.Challenge;
  const registration = ctx.composeRegistration();
  const mark = ctx.capture.records.length;
  ctx.capture.patch(challenge, 'create', 'registration-begin-challenge-create');

  const issuedAtMs = ctx.clock.now();
  const result = await registration.beginRegistration({
    tenantId: ctx.TENANT,
    requestSource: 'lab-local-endpoint',
  });

  const productRecords = recordsSince(ctx, mark);
  const createRecords = byLabel(productRecords, 'registration-begin-challenge-create');
  const verdict = writeConcernVerdict(createRecords);
  const view = beginView(result);

  const rawDoc = view.challengeHashPresent
    ? await ctx.readRawDoc(challenge.collection.name, { challengeHash: result.challengeHash })
    : null;
  const leanDoc = view.challengeHashPresent
    ? await challenge.findOne({ challengeHash: result.challengeHash }).lean()
    : null;

  const durableReadBack =
    rawDoc !== null && rawDoc.challengeHash === result.challengeHash && rawDoc.tenantId === ctx.TENANT;
  const createError = createRecords.length > 0 ? createRecords[0].error : null;

  const productRowShape = {
    challengeHash: result.challengeHash ?? '(unavailable)',
    purpose: 'registration',
    deviceId: null,
    deviceKeyId: null,
    tenantId: ctx.TENANT,
    boundPairingSessionId: null,
    boundOwnerId: null,
    boundGrantId: null,
    issuedAt: new Date(issuedAtMs),
    expiresAt: new Date(issuedAtMs + ctx.constants.REGISTRATION_CHALLENGE_TTL_MS),
    consumedAt: null,
  };
  const capturedKeys = createRecords.length > 0 ? createRecords[0].payloadKeys : [];
  const probe = await validatorIndependenceProbe(challenge, productRowShape);

  const executed = view.ok !== false || createRecords.length === 1;
  const blocker = {
    kind: 'FROZEN_SUBSTRATE_VALIDATOR_REJECTS_PRODUCT_ROW',
    causeClass: 'product/substrate defect (not a fixture defect)',
    authorizedStatus: STATUS.EXPECTED_RED,
    whyTheAuthorizedStatusIsUnreachable:
      'the authorization makes EXPECTED_RED conditional on proven durable row read-back; the frozen challenge schema rejects the product create row through Mongoose validation before any write is sent, so there is no durable row to read back',
    observedCreateError: createError,
    independenceProbe: probe,
    repairPredicateStillIndependentlyObservable:
      'the captured create call has argCount=1 and no options object, so the F8 option omission at this site is proven from the captured arguments regardless of the validator defect',
    staticAnchors: [BOUND_EPOCH_ANCHOR, MONGOOSE_CREATE_OVERLOAD_ANCHOR],
  };

  const components = [
    component(
      'begin_registration_invoked_the_genuine_create_site',
      'beginRegistration passes the tenant policy gate and invokes the genuine Challenge.create site exactly once',
      `Challenge.create calls captured=${createRecords.length} capturedArgCount=${createRecords.length > 0 ? createRecords[0].argCount : null} capturedKeys=${JSON.stringify(capturedKeys)}`,
      createRecords.length === 1,
      'E1',
    ),
    component(
      'begin_registration_returned_a_minted_challenge',
      'beginRegistration returns a success envelope carrying a fresh challenge and its hash',
      `beginOk=${view.ok} challengeHashPresent=${view.challengeHashPresent} returnedLength=${view.challengeReturnedLength} error.code=${view.error ? view.error.code : null} error.message=${view.error ? view.error.message : null}; captured createError=${JSON.stringify(createError)}`,
      view.ok === true && view.challengeHashPresent,
      'E1',
    ),
    component(
      'challenge_row_durable_read_back',
      'the registration challenge row is readable back through the genuine model and the raw driver with consumedAt still null',
      `rawDriverDocPresent=${rawDoc !== null} modelLeanPresent=${leanDoc !== null}`,
      durableReadBack && leanDoc !== null && leanDoc.consumedAt === null,
      'E1',
    ),
    component(
      'challenge_create_carries_explicit_majority_journal',
      "the captured Model.create call includes an options object, via an unambiguous overload, with writeConcern {w:'majority', j:true}",
      `callCount=${verdict.callCount} pinnedCount=${verdict.pinnedCount} missingExplicitOptionsCount=${verdict.missingExplicitOptionsCount} ambiguousOptionsOverloadCount=${verdict.ambiguousOptionsOverloadCount} observed=${JSON.stringify(verdict.calls)}`,
      verdict.allPinned,
      'E1',
    ),
    component(
      'captured_row_shape_matches_the_product_row_shape',
      'the captured create payload keys equal the frozen product row shape read from the product bytes',
      `capturedKeys=${JSON.stringify(capturedKeys)} reconstructedKeys=${JSON.stringify(sortedKeys(productRowShape))} equal=${JSON.stringify(capturedKeys) === JSON.stringify(sortedKeys(productRowShape))}`,
      createRecords.length === 1 &&
        JSON.stringify(capturedKeys) === JSON.stringify(sortedKeys(productRowShape)),
      'E1',
    ),
    component(
      'validator_rejection_is_orthogonal_to_the_missing_option',
      'the same product row shape still fails validation when every argument is the array-form options overload with explicit majority+journal',
      JSON.stringify(probe),
      probe.threw === true && probe.persisted === false,
      'E1',
    ),
    component(
      'genuine_challenge_constructor_used',
      'the Challenge model is the genuine createModels(mongoose) constructor registered on the live connection',
      JSON.stringify(genuineModelIdentity('Challenge', challenge)),
      genuineModelIdentity('Challenge', challenge).typeofModel === 'function' &&
        genuineModelIdentity('Challenge', challenge).identityMatchesMongooseRegistration === true,
      'E1',
    ),
  ];

  return {
    status: classifyCreateRow({
      expected: STATUS.EXPECTED_RED,
      executed,
      durableReadBack,
      explicitMajorityJournal: verdict.allPinned,
    }),
    productMethodInvoked: true,
    components,
    actual: {
      scenario:
        'registrationService.beginRegistration invoked with the fixed trusted tenant policy against the genuine registry; the frozen product bytes call db.Challenge.create(row) with a single argument',
      invocation: {
        method: 'createRegistrationService(...).beginRegistration',
        tenantId: ctx.TENANT,
        requestSource: 'lab-local-endpoint',
      },
      beginResult: view,
      requestedWriteConcern: ctx.WRITE_CONCERN,
      createCallVerdict: verdict,
      createCallError: createError,
      durableReadBack: {
        rawDriverDocPresent: rawDoc !== null,
        modelLeanMatch: leanDoc !== null,
      },
      repairPredicateAbsent: verdict.allPinned === false,
      blocker,
      staticAnchor:
        'api/server/services/Device/registrationService.js:362 — await db.Challenge.create(row) (one argument, no options object)',
    },
  };
}

/* ------------------------------------------------------------------ S4T-02 */

async function s4t02(ctx) {
  const key = w3a.makeDeviceKey('s4t-02');
  const domainTag = ctx.constants.REGISTRATION_DOMAIN;
  const deviceName = 's4t-02-device';
  const platform = 'lab-linux';
  const agentVersion = '1.0.0';
  const nonce = 's4t-02-nonce-0001';
  const challenge = ctx.cryptoSurface.newChallengeNonce();
  const challengeHash = ctx.cryptoSurface.challengeHash(challenge);
  const issuedAt = String(ctx.clock.now());
  const registration = ctx.composeRegistration();

  /**
   * The registration challenge is a FIXTURE row with a valid hash, purpose, tenant and expiry. It is
   * not produced by beginRegistration because that create site is blocked pre-repair (S4T-01); the
   * row under test in this row is the DeviceAuthority registration create.
   */
  await ctx.seedChallenge({
    challengeHash,
    purpose: 'registration',
    tenantId: ctx.TENANT,
    boundEpoch: 0,
    issuedAt: new Date(ctx.clock.now()),
    expiresAt: new Date(ctx.clock.now() + ctx.constants.REGISTRATION_CHALLENGE_TTL_MS),
  });

  const thumbprint = ctx.cryptoSurface.thumbprintB64u(key.spkiB64u);
  const message = ctx.cryptoSurface.canonicalEncode({
    domainTag,
    fields: [
      ctx.TENANT,
      challenge,
      key.spkiB64u,
      thumbprint,
      deviceName,
      platform,
      agentVersion,
      nonce,
      issuedAt,
    ],
  });
  const signatureB64u = w3a.sign(key, message);

  const mark = ctx.capture.records.length;
  ctx.capture.patch(ctx.models.DeviceAuthority, 'create', 'device-authority-registration-create');

  const result = await registration.completeRegistration({
    tenantId: ctx.TENANT,
    devicePublicKey: key.spkiB64u,
    deviceName,
    platform,
    agentVersion,
    domainTag,
    proof: { challenge, nonce, issuedAt, signatureB64u, domainTag },
  });

  const scoped = recordsSince(ctx, mark);
  const createRecords = byLabel(scoped, 'device-authority-registration-create');
  const auditRecords = byLabel(scoped, AUDIT_LABEL);
  const verdict = writeConcernVerdict(createRecords);
  const auditVerdict = writeConcernVerdict(auditRecords);

  const deviceId = isNonEmptyString(result.deviceId) ? result.deviceId : null;
  const rawDoc =
    deviceId !== null
      ? await ctx.readRawDoc(ctx.models.DeviceAuthority.collection.name, { _id: deviceId })
      : null;
  const leanDoc =
    deviceId !== null
      ? await ctx.models.DeviceAuthority.findOne({ _id: deviceId }).lean()
      : null;
  const challengeRaw = await ctx.readRawDoc(ctx.models.Challenge.collection.name, { challengeHash });
  const view = envelopeView(result);

  const durableReadBack =
    rawDoc !== null &&
    rawDoc.tenantId === ctx.TENANT &&
    rawDoc.identityState === 'pending' &&
    rawDoc.leaseState === 'never' &&
    rawDoc.epoch === 0 &&
    rawDoc.deviceKeyId === thumbprint;
  const executed = deviceId !== null && createRecords.length === 1 && durableReadBack;

  const components = [
    component(
      'complete_registration_reached_product_path',
      'completeRegistration verifies the registration PoP, spends the challenge and reaches the DeviceAuthority create site',
      `ok=${view.ok} deviceId=${deviceId} deviceKeyIdMatchesThumbprint=${result.deviceKeyId === thumbprint} error.code=${view.error ? view.error.code : null}; DeviceAuthority.create calls captured=${createRecords.length}; challengeSpent=${challengeRaw !== null && challengeRaw.consumedAt !== null}`,
      deviceId !== null && result.deviceKeyId === thumbprint && createRecords.length === 1,
      'E1',
    ),
    component(
      'device_authority_registration_row_durable_read_back',
      'the pending authority row created by the registration transition is readable back through the genuine model and the raw driver',
      `rawDriverDocPresent=${rawDoc !== null} identityState=${rawDoc ? rawDoc.identityState : null} leaseState=${rawDoc ? rawDoc.leaseState : null} epoch=${rawDoc ? rawDoc.epoch : null} deviceKeyIdMatches=${rawDoc ? rawDoc.deviceKeyId === thumbprint : null}; modelLeanPresent=${leanDoc !== null}`,
      durableReadBack && leanDoc !== null,
      'E1',
    ),
    component(
      'registration_challenge_spent_before_authority_create',
      'the registration challenge was consumed by the single-use CAS before the authority row was inserted',
      `challengeRowPresent=${challengeRaw !== null} consumedAt=${challengeRaw ? JSON.stringify(challengeRaw.consumedAt) : null}`,
      challengeRaw !== null && challengeRaw.consumedAt !== null,
      'E1',
    ),
    component(
      'device_authority_create_carries_explicit_majority_journal',
      "the captured DeviceAuthority.create call includes an options object, via an unambiguous overload, with writeConcern {w:'majority', j:true}",
      `callCount=${verdict.callCount} pinnedCount=${verdict.pinnedCount} missingExplicitOptionsCount=${verdict.missingExplicitOptionsCount} ambiguousOptionsOverloadCount=${verdict.ambiguousOptionsOverloadCount} observed=${JSON.stringify(verdict.calls)}`,
      verdict.allPinned,
      'E1',
    ),
    component(
      'real_audit_event_create_carries_explicit_majority_journal',
      "the genuine product auditSink adapter writes AuditEvent with an explicit writeConcern {w:'majority', j:true}",
      `callCount=${auditVerdict.callCount} pinnedCount=${auditVerdict.pinnedCount} observed=${JSON.stringify(auditVerdict.calls)}; auditSinkOutcomes=${JSON.stringify(ctx.audit.outcomes)}`,
      auditVerdict.callCount === 1 && auditVerdict.allPinned,
      'E1',
    ),
    component(
      'genuine_device_authority_constructor_used',
      'the DeviceAuthority model is the genuine createModels(mongoose) constructor registered on the live connection',
      JSON.stringify(genuineModelIdentity('DeviceAuthority', ctx.models.DeviceAuthority)),
      genuineModelIdentity('DeviceAuthority', ctx.models.DeviceAuthority).typeofModel === 'function' &&
        genuineModelIdentity('DeviceAuthority', ctx.models.DeviceAuthority)
          .identityMatchesMongooseRegistration === true,
      'E1',
    ),
  ];

  return {
    status: classifyCreateRow({
      expected: STATUS.EXPECTED_RED,
      executed,
      durableReadBack,
      explicitMajorityJournal: verdict.allPinned,
    }),
    productMethodInvoked: true,
    components,
    actual: {
      scenario:
        'registrationService.completeRegistration invoked with a valid Ed25519 registration PoP over the frozen canonical form and a fixture registration challenge; the frozen product bytes call db.DeviceAuthority.create(row) with a single argument',
      invocation: {
        method: 'createRegistrationService(...).completeRegistration',
        tenantId: ctx.TENANT,
        domainTag,
        challengeSource: 'fixture row (beginRegistration is blocked pre-repair by the S4T-01 validator defect)',
        challengeSpentByCas: challengeRaw !== null && challengeRaw.consumedAt !== null,
      },
      envelope: view,
      auditSinkOutcomes: ctx.audit.outcomes,
      requestedWriteConcern: ctx.WRITE_CONCERN,
      createCallVerdict: verdict,
      auditCreateVerdict: auditVerdict,
      durableReadBack: {
        rawDriverDocPresent: rawDoc !== null,
        rawIdentityState: rawDoc ? rawDoc.identityState : null,
        rawLeaseState: rawDoc ? rawDoc.leaseState : null,
        rawEpoch: rawDoc ? rawDoc.epoch : null,
        rawDeviceKeyIdMatchesThumbprint: rawDoc ? rawDoc.deviceKeyId === thumbprint : null,
        modelLeanPresent: leanDoc !== null,
      },
      repairPredicateAbsent: verdict.allPinned === false,
      staticAnchor:
        'api/server/services/Device/registrationService.js:672 — await db.DeviceAuthority.create(row) (one argument, no options object)',
    },
  };
}

/* ------------------------------------------------------------------ S4T-03 */

async function s4t03(ctx) {
  const key = w3a.makeDeviceKey('s4t-03');
  const deviceId = 's4t-03-device';
  const deviceKeyId = `key-${deviceId}`;

  await ctx.seedAuthority({
    _id: deviceId,
    tenantId: ctx.TENANT,
    deviceKeyId,
    devicePublicKey: key.spkiB64u,
    identityState: 'pending',
    leaseState: 'never',
    epoch: 0,
  });

  const domainTag = ctx.constants.PAIRING_OPEN_DOMAIN;
  const nonce = 's4t-03-nonce-0001';
  const issuedAtMs = ctx.clock.now();
  const issuedAt = String(issuedAtMs);
  const message = ctx.cryptoSurface.canonicalEncode({
    domainTag,
    fields: [ctx.TENANT, deviceId, deviceKeyId, nonce, issuedAt],
  });
  const signatureB64u = w3a.sign(key, message);

  const pairing = ctx.composePairing();
  const mark = ctx.capture.records.length;
  ctx.capture.patch(ctx.models.PairingSession, 'create', 'pairing-session-issue-create');
  ctx.capture.patch(ctx.models.PairingSession, 'updateOne', 'pairing-session-supersede-update');

  const result = await pairing.issuePairingSession({
    tenantId: ctx.TENANT,
    deviceId,
    deviceKeyId,
    domainTag,
    proof: { nonce, issuedAt, signatureB64u, domainTag },
  });

  const productRecords = recordsSince(ctx, mark);
  const createRecords = byLabel(productRecords, 'pairing-session-issue-create');
  const supersedeRecords = byLabel(productRecords, 'pairing-session-supersede-update');
  const verdict = writeConcernVerdict(createRecords);
  const supersedeVerdict = writeConcernVerdict(supersedeRecords);

  const created = result.pairingSession ?? null;
  const sessionObjectId = created !== null && created._id !== undefined ? created._id : null;
  const rawDoc =
    sessionObjectId !== null
      ? await ctx.readRawDoc(ctx.models.PairingSession.collection.name, { _id: sessionObjectId })
      : null;
  const leanDoc =
    sessionObjectId !== null
      ? await ctx.models.PairingSession.findOne({ _id: sessionObjectId }).lean()
      : null;

  const durableReadBack =
    rawDoc !== null &&
    rawDoc.tenantId === ctx.TENANT &&
    rawDoc.state === 'open' &&
    isNonEmptyString(rawDoc.lookupTag) &&
    rawDoc.deviceId === deviceId;
  const createError = createRecords.length > 0 ? createRecords[0].error : null;

  const productRowShape = {
    tenantId: ctx.TENANT,
    deviceId,
    deviceKeyId,
    lookupTag: ctx.cryptoSurface.computeLookupTag({
      code: '000000',
      tenantId: ctx.TENANT,
      pepperLookup: ctx.pepperLookup,
    }),
    state: 'open',
    pendingOwnerId: null,
    attemptsUsed: 0,
    issuedAt: new Date(issuedAtMs),
    expiresAt: new Date(issuedAtMs + ctx.constants.CODE_TTL_MS),
    claimedAt: null,
    claim: { challengeRef: null, openedAt: null },
    consumedAt: null,
    grantedGrantId: null,
    issuedFromSourceHash: null,
    deviceSessionId: null,
  };
  const capturedKeys = createRecords.length > 0 ? createRecords[0].payloadKeys : [];
  const probe = await validatorIndependenceProbe(ctx.models.PairingSession, productRowShape);

  const executed = createRecords.length === 1;
  const blocker = {
    kind: 'FROZEN_SUBSTRATE_VALIDATOR_REJECTS_PRODUCT_ROW',
    causeClass: 'product/substrate defect (not a fixture defect)',
    authorizedStatus: STATUS.EXPECTED_RED,
    whyTheAuthorizedStatusIsUnreachable:
      'the authorization makes EXPECTED_RED conditional on proven durable session read-back; the frozen pairingSession schema rejects the product create row through Mongoose validation before any write is sent, so there is no durable session to read back',
    observedCreateError: createError,
    independenceProbe: probe,
    repairPredicateStillIndependentlyObservable:
      'the captured create call has argCount=1 and no options object, so the F8 option omission at this site is proven from the captured arguments regardless of the validator defect',
    staticAnchors: [CLAIM_EPOCH_ANCHOR, MONGOOSE_CREATE_OVERLOAD_ANCHOR],
  };

  const components = [
    component(
      'issue_pairing_session_invoked_the_genuine_create_site',
      'issuePairingSession verifies the device PoP against the DB-stored key, completes the guarded supersede update and invokes the genuine PairingSession.create site exactly once',
      `create calls captured=${createRecords.length} supersede update calls captured=${supersedeRecords.length} capturedArgCount=${createRecords.length > 0 ? createRecords[0].argCount : null} capturedKeys=${JSON.stringify(capturedKeys)}`,
      createRecords.length === 1 && supersedeRecords.length === 1,
      'E1',
    ),
    component(
      'issue_pairing_session_returned_a_minted_code',
      'issuePairingSession returns a success envelope carrying the one-time pairing code and the created session',
      `issueOk=${result.ok === true} codeReturnedLength=${isNonEmptyString(result.code) ? result.code.length : null} error.code=${result.error ? result.error.code : null} error.message=${result.error ? result.error.message : null}; captured createError=${JSON.stringify(createError)}`,
      result.ok === true && isNonEmptyString(result.code),
      'E1',
    ),
    component(
      'pairing_session_row_durable_read_back',
      'the open pairing session is readable back through the genuine model and the raw driver',
      `rawDriverDocPresent=${rawDoc !== null} modelLeanPresent=${leanDoc !== null}`,
      durableReadBack && leanDoc !== null,
      'E1',
    ),
    component(
      'pairing_session_create_carries_explicit_majority_journal',
      "the captured PairingSession.create call includes an options object, via an unambiguous overload, with writeConcern {w:'majority', j:true}",
      `callCount=${verdict.callCount} pinnedCount=${verdict.pinnedCount} missingExplicitOptionsCount=${verdict.missingExplicitOptionsCount} ambiguousOptionsOverloadCount=${verdict.ambiguousOptionsOverloadCount} observed=${JSON.stringify(verdict.calls)}`,
      verdict.allPinned,
      'E1',
    ),
    component(
      'supersede_update_carries_explicit_majority_journal',
      "the genuine PairingSession.updateOne supersede path carries writeConcern {w:'majority', j:true}",
      `callCount=${supersedeVerdict.callCount} pinnedCount=${supersedeVerdict.pinnedCount} observed=${JSON.stringify(supersedeVerdict.calls)}`,
      supersedeVerdict.callCount === 1 && supersedeVerdict.allPinned,
      'E1',
    ),
    component(
      'captured_row_shape_matches_the_product_row_shape',
      'the captured create payload keys equal the frozen product row shape read from the product bytes',
      `capturedKeys=${JSON.stringify(capturedKeys)} reconstructedKeys=${JSON.stringify(sortedKeys(productRowShape))} equal=${JSON.stringify(capturedKeys) === JSON.stringify(sortedKeys(productRowShape))}`,
      createRecords.length === 1 &&
        JSON.stringify(capturedKeys) === JSON.stringify(sortedKeys(productRowShape)),
      'E1',
    ),
    component(
      'validator_rejection_is_orthogonal_to_the_missing_option',
      'the same product row shape still fails validation when passed through the array-form options overload with explicit majority+journal',
      JSON.stringify(probe),
      probe.threw === true && probe.persisted === false,
      'E1',
    ),
    component(
      'genuine_pairing_session_constructor_used',
      'the PairingSession model is the genuine createModels(mongoose) constructor registered on the live connection',
      JSON.stringify(genuineModelIdentity('PairingSession', ctx.models.PairingSession)),
      genuineModelIdentity('PairingSession', ctx.models.PairingSession).typeofModel === 'function' &&
        genuineModelIdentity('PairingSession', ctx.models.PairingSession)
          .identityMatchesMongooseRegistration === true,
      'E1',
    ),
  ];

  return {
    status: classifyCreateRow({
      expected: STATUS.EXPECTED_RED,
      executed,
      durableReadBack,
      explicitMajorityJournal: verdict.allPinned,
    }),
    productMethodInvoked: true,
    components,
    actual: {
      scenario:
        'pairingSessionService.issuePairingSession invoked with a valid Ed25519 pairing-open PoP against a genuine seeded authority row; the frozen product bytes call db.PairingSession.create(row) with a single argument',
      invocation: {
        method: 'createPairingSessionService(...).issuePairingSession',
        tenantId: ctx.TENANT,
        deviceId,
        deviceKeyId,
        domainTag,
      },
      envelope: {
        ok: result.ok === true,
        codeReturnedLength: isNonEmptyString(result.code) ? result.code.length : null,
        pairingSessionId: sessionObjectId !== null ? String(sessionObjectId) : null,
        error: result.error ? errorView(result.error) : null,
      },
      requestedWriteConcern: ctx.WRITE_CONCERN,
      createCallVerdict: verdict,
      supersedeUpdateVerdict: supersedeVerdict,
      createCallError: createError,
      durableReadBack: {
        rawDriverDocPresent: rawDoc !== null,
        modelLeanPresent: leanDoc !== null,
      },
      repairPredicateAbsent: verdict.allPinned === false,
      blocker,
      staticAnchor:
        'api/server/services/Device/pairingSessionService.js:805 — await db.PairingSession.create(row) (one argument, no options object)',
    },
  };
}

/* ------------------------------------------------------------------ S4T-04 */

async function s4t04(ctx) {
  const key = w3a.makeDeviceKey('s4t-04');
  const domainTag = ctx.constants.REGISTRATION_DOMAIN;
  const registration = ctx.composeRegistration();
  const challengeModel = ctx.models.Challenge;

  const challenge = ctx.cryptoSurface.newChallengeNonce();
  const registrationChallengeHash = ctx.cryptoSurface.challengeHash(challenge);
  await ctx.seedChallenge({
    challengeHash: registrationChallengeHash,
    purpose: 'registration',
    tenantId: ctx.TENANT,
    boundEpoch: 0,
    issuedAt: new Date(ctx.clock.now()),
    expiresAt: new Date(ctx.clock.now() + ctx.constants.REGISTRATION_CHALLENGE_TTL_MS),
  });

  const thumbprint = ctx.cryptoSurface.thumbprintB64u(key.spkiB64u);
  const nonce = 's4t-04-nonce-0001';
  const issuedAt = String(ctx.clock.now());
  const message = ctx.cryptoSurface.canonicalEncode({
    domainTag,
    fields: [
      ctx.TENANT,
      challenge,
      key.spkiB64u,
      thumbprint,
      's4t-04-device',
      'lab-linux',
      '1.0.0',
      nonce,
      issuedAt,
    ],
  });
  const signatureB64u = w3a.sign(key, message);

  const mark = ctx.capture.records.length;
  ctx.capture.patch(challengeModel, 'updateOne', 'challenge-spend-cas');
  const completed = await registration.completeRegistration({
    tenantId: ctx.TENANT,
    devicePublicKey: key.spkiB64u,
    deviceName: 's4t-04-device',
    platform: 'lab-linux',
    agentVersion: '1.0.0',
    domainTag,
    proof: { challenge, nonce, issuedAt, signatureB64u, domainTag },
  });
  const registrationSpendRecords = byLabel(recordsSince(ctx, mark), 'challenge-spend-cas');
  const registrationSpendVerdict = writeConcernVerdict(registrationSpendRecords);
  const spentRaw = await ctx.readRawDoc(challengeModel.collection.name, {
    challengeHash: registrationChallengeHash,
  });

  const spendHash = ctx.cryptoSurface.challengeHash(ctx.cryptoSurface.newChallengeNonce());
  const pairingSessionId = 's4t-04-pairing-session';
  const authorityDeviceId = 's4t-04-authority-device';
  const authorityDeviceKeyId = `key-${authorityDeviceId}`;
  await ctx.seedChallenge({
    challengeHash: spendHash,
    purpose: 'pairing-claim',
    deviceId: authorityDeviceId,
    deviceKeyId: authorityDeviceKeyId,
    boundPairingSessionId: pairingSessionId,
    boundOwnerId: ctx.OWNER_A,
    boundEpoch: 0,
  });

  const authority = ctx.composeAuthority();
  const mark2 = ctx.capture.records.length;
  const spend = await authority.spendChallenge({
    challengeHash: spendHash,
    purpose: 'pairing-claim',
    tenantId: ctx.TENANT,
    bound: {
      boundPairingSessionId: pairingSessionId,
      boundOwnerId: ctx.OWNER_A,
      deviceId: authorityDeviceId,
      deviceKeyId: authorityDeviceKeyId,
      boundEpoch: 0,
    },
  });
  const authoritySpendRecords = byLabel(recordsSince(ctx, mark2), 'challenge-spend-cas');
  const authoritySpendVerdict = writeConcernVerdict(authoritySpendRecords);
  const authoritySpentRaw = await ctx.readRawDoc(challengeModel.collection.name, {
    challengeHash: spendHash,
  });

  const identity = genuineModelIdentity('Challenge', challengeModel);
  const executed =
    spentRaw !== null &&
    spend !== null &&
    registrationSpendVerdict.callCount + authoritySpendVerdict.callCount >= 2;

  const components = [
    component(
      'registration_completion_challenge_spend_committed',
      'the registration completion path consumed the challenge through db.Challenge.updateOne',
      `deviceId=${completed.deviceId} consumedAt=${spentRaw ? JSON.stringify(spentRaw.consumedAt) : null} registrationSpendCallCount=${registrationSpendVerdict.callCount}`,
      spentRaw !== null && spentRaw.consumedAt !== null && isNonEmptyString(completed.deviceId),
      'E1',
    ),
    component(
      'registration_challenge_spend_carries_majority_journal',
      "the registrationService challenge spend passes writeConcern {w:'majority', j:true}",
      `callCount=${registrationSpendVerdict.callCount} pinnedCount=${registrationSpendVerdict.pinnedCount} observed=${JSON.stringify(registrationSpendVerdict.calls)}`,
      registrationSpendVerdict.callCount === 1 && registrationSpendVerdict.allPinned,
      'E1',
    ),
    component(
      'authority_spend_challenge_carries_majority_journal',
      "authorityService.spendChallenge passes writeConcern {w:'majority', j:true} on the Challenge CAS",
      `callCount=${authoritySpendVerdict.callCount} pinnedCount=${authoritySpendVerdict.pinnedCount} observed=${JSON.stringify(authoritySpendVerdict.calls)}`,
      authoritySpendVerdict.callCount === 1 && authoritySpendVerdict.allPinned,
      'E1',
    ),
    component(
      'authority_spend_challenge_committed',
      'the fenced challenge-spend CAS matched exactly one document and consumed the row',
      `spend.matched=${spend ? spend.matched : null} spend.ok=${spend ? spend.ok : null} consumedAt=${authoritySpentRaw ? JSON.stringify(authoritySpentRaw.consumedAt) : null}`,
      spend !== null &&
        spend.ok === true &&
        spend.matched === 1 &&
        authoritySpentRaw !== null &&
        authoritySpentRaw.consumedAt !== null,
      'E1',
    ),
    component(
      'genuine_challenge_constructor_used',
      'the Challenge model is the genuine createModels(mongoose) constructor registered on the live connection',
      JSON.stringify(identity),
      identity.typeofModel === 'function' && identity.identityMatchesMongooseRegistration === true,
      'E1',
    ),
  ];

  return {
    status: classifyControlRow({ expected: STATUS.PASS_CURRENT, executed, components }),
    productMethodInvoked: true,
    components,
    actual: {
      scenario:
        'two real challenge-spend paths: (A) registrationService.completeRegistration spends a fixture registration challenge; (B) authorityService.spendChallenge consumes a fixture pairing-claim challenge',
      registrationSpend: {
        envelope: envelopeView(completed),
        challengeSource: 'fixture row',
        challengeConsumedAt: spentRaw ? spentRaw.consumedAt : null,
        verdict: registrationSpendVerdict,
      },
      authoritySpend: {
        envelope: envelopeView(spend),
        challengeSource: 'fixture row',
        challengeConsumedAt: authoritySpentRaw ? authoritySpentRaw.consumedAt : null,
        verdict: authoritySpendVerdict,
      },
      requestedWriteConcern: ctx.WRITE_CONCERN,
      staticAnchors: [
        'registrationService.js:609-619 — db.Challenge.updateOne(filter, update, { writeConcern: AUTHORITY_WRITE_CONCERN })',
        'authorityService.js:255-258 — performUpdate(model, filter, update) always passes { writeConcern: AUTHORITY_WRITE_CONCERN }',
      ],
    },
  };
}

/* ------------------------------------------------------------------ S4T-05 */

async function s4t05(ctx) {
  const now = ctx.clock.now();
  const deviceId = 's4t-05-device';
  await ctx.seedAuthority({
    _id: deviceId,
    tenantId: ctx.TENANT,
    deviceKeyId: `key-${deviceId}`,
    devicePublicKey: w3a.labKey.spkiB64u,
    identityState: 'active',
    leaseState: 'active',
    ownerId: ctx.OWNER_A,
    grantId: 's4t-05-grant-0',
    activatedAt: new Date(now),
    expiresAt: new Date(now + ctx.constants.LEASE_TTL_MS),
  });

  const authority = ctx.composeAuthority();
  const before = await ctx.readAuthorityRow(deviceId);
  const mark = ctx.capture.records.length;
  ctx.capture.patch(ctx.models.DeviceAuthority, 'updateOne', 'authority-cas-revoke');
  const envelope = await authority.revokeLease({
    deviceId,
    tenantId: ctx.TENANT,
    ownerId: ctx.OWNER_A,
    epoch: 0,
  });
  const scoped = recordsSince(ctx, mark);
  const casRecords = byLabel(scoped, 'authority-cas-revoke');
  const auditRecords = byLabel(scoped, AUDIT_LABEL);
  const verdict = writeConcernVerdict(casRecords);
  const auditVerdict = writeConcernVerdict(auditRecords);
  const after = await ctx.readAuthorityRow(deviceId);
  const view = envelopeView(envelope);
  const identity = genuineModelIdentity('DeviceAuthority', ctx.models.DeviceAuthority);

  const executed = casRecords.length === 1 && before !== null && after !== null;

  const components = [
    component(
      'authority_cas_transition_committed',
      'the accepted S2 revoke transition commits exactly one generation change on the genuine authority row',
      `matched=${view.matched} epoch ${before ? before.epoch : null} -> ${after ? after.epoch : null}; leaseState ${before ? before.leaseState : null} -> ${after ? after.leaseState : null}; error.code=${view.error ? view.error.code : null}`,
      view.matched === 1 &&
        before !== null &&
        after !== null &&
        after.epoch === before.epoch + 1 &&
        after.leaseState === 'revoked',
      'E1',
    ),
    component(
      'authority_cas_update_carries_majority_journal',
      "the authority CAS update carries writeConcern {w:'majority', j:true}",
      `callCount=${verdict.callCount} pinnedCount=${verdict.pinnedCount} observed=${JSON.stringify(verdict.calls)}`,
      verdict.callCount === 1 && verdict.allPinned,
      'E1',
    ),
    component(
      'real_audit_event_create_carries_explicit_majority_journal',
      'the post-CAS real AuditEvent write goes through the genuine auditSink adapter with an explicit majority+journal concern',
      `callCount=${auditVerdict.callCount} pinnedCount=${auditVerdict.pinnedCount} observed=${JSON.stringify(auditVerdict.calls)}; auditSinkOutcomes=${JSON.stringify(ctx.audit.outcomes)}`,
      auditVerdict.callCount === 1 && auditVerdict.allPinned,
      'E1',
    ),
    component(
      'genuine_device_authority_constructor_used',
      'the DeviceAuthority model is the genuine createModels(mongoose) constructor registered on the live connection',
      JSON.stringify(identity),
      identity.typeofModel === 'function' && identity.identityMatchesMongooseRegistration === true,
      'E1',
    ),
  ];

  return {
    status: classifyControlRow({ expected: STATUS.PASS_CURRENT, executed, components }),
    productMethodInvoked: true,
    components,
    actual: {
      scenario:
        'one real accepted-S2 authority transition (revokeLease at g -> g+1) executed through the genuine authority service against the genuine DeviceAuthority model',
      invocation: {
        method: 'createAuthorityService(...).revokeLease',
        deviceId,
        epoch: 0,
        ownerId: ctx.OWNER_A,
      },
      envelope: view,
      authorityBefore: before,
      authorityAfter: after,
      casVerdict: verdict,
      auditCreateVerdict: auditVerdict,
      auditSinkOutcomes: ctx.audit.outcomes,
      requestedWriteConcern: ctx.WRITE_CONCERN,
      staticAnchor:
        'authorityService.js:852-857 + 255-258 — revokeLease -> performUpdate(db.DeviceAuthority, filter, pipeline) with { writeConcern: AUTHORITY_WRITE_CONCERN }',
    },
  };
}

/* ------------------------------------------------------------------ S4T-06 */

async function s4t06(ctx) {
  const key = w3a.makeDeviceKey('s4t-06');
  const issueDeviceId = 's4t-06-issue-device';
  const issueDeviceKeyId = `key-${issueDeviceId}`;
  await ctx.seedAuthority({
    _id: issueDeviceId,
    tenantId: ctx.TENANT,
    deviceKeyId: issueDeviceKeyId,
    devicePublicKey: key.spkiB64u,
    identityState: 'pending',
    leaseState: 'never',
    epoch: 0,
  });

  const domainTag = ctx.constants.PAIRING_OPEN_DOMAIN;
  const nonce = 's4t-06-nonce-0001';
  const issuedAt = String(ctx.clock.now());
  const message = ctx.cryptoSurface.canonicalEncode({
    domainTag,
    fields: [ctx.TENANT, issueDeviceId, issueDeviceKeyId, nonce, issuedAt],
  });
  const signatureB64u = w3a.sign(key, message);

  const pairing = ctx.composePairing();
  const mark = ctx.capture.records.length;
  ctx.capture.patch(ctx.models.PairingSession, 'updateOne', 'pairing-session-update');
  ctx.capture.patch(
    ctx.models.PairingSession,
    'findOneAndUpdate',
    'pairing-session-find-one-and-update',
  );

  const issued = await pairing.issuePairingSession({
    tenantId: ctx.TENANT,
    deviceId: issueDeviceId,
    deviceKeyId: issueDeviceKeyId,
    domainTag,
    proof: { nonce, issuedAt, signatureB64u, domainTag },
  });

  const rejoinCode = '424242';
  const rejoinTag = ctx.cryptoSurface.computeLookupTag({
    code: rejoinCode,
    tenantId: ctx.TENANT,
    pepperLookup: ctx.pepperLookup,
  });
  const rejoinNow = ctx.clock.now();
  await ctx.seedPairingSession({
    tenantId: ctx.TENANT,
    deviceId: 's4t-06-rejoin-device',
    deviceKeyId: 'key-s4t-06-rejoin-device',
    lookupTag: rejoinTag,
    state: 'claim_pending',
    pendingOwnerId: ctx.OWNER_A,
    attemptsUsed: 1,
    claimedAt: new Date(rejoinNow),
    issuedAt: new Date(rejoinNow),
    expiresAt: new Date(rejoinNow + ctx.constants.CODE_TTL_MS),
  });

  const redeemCode = '313131';
  const redeemTag = ctx.cryptoSurface.computeLookupTag({
    code: redeemCode,
    tenantId: ctx.TENANT,
    pepperLookup: ctx.pepperLookup,
  });
  const redeemNow = ctx.clock.now();
  const seededOpenSession = await ctx.seedPairingSession({
    tenantId: ctx.TENANT,
    deviceId: 's4t-06-redeem-device',
    deviceKeyId: 'key-s4t-06-redeem-device',
    lookupTag: redeemTag,
    state: 'open',
    attemptsUsed: 0,
    issuedAt: new Date(redeemNow),
    expiresAt: new Date(redeemNow + ctx.constants.CODE_TTL_MS),
  });

  const rejoined = await pairing.rejoinPendingPairing({
    tenantId: ctx.TENANT,
    ownerId: ctx.OWNER_A,
    code: rejoinCode,
  });
  const redeemed = await pairing.redeemPairingCode({
    tenantId: ctx.TENANT,
    ownerId: ctx.OWNER_A,
    code: redeemCode,
  });

  const scoped = recordsSince(ctx, mark);
  const writeRecords = scoped.filter(
    (record) =>
      record.label === 'pairing-session-update' ||
      record.label === 'pairing-session-find-one-and-update',
  );
  const verdict = writeConcernVerdict(writeRecords);
  const updateVerdict = writeConcernVerdict(byLabel(scoped, 'pairing-session-update'));
  const findOneAndUpdateVerdict = writeConcernVerdict(
    byLabel(scoped, 'pairing-session-find-one-and-update'),
  );

  const rejoinRaw = await ctx.readRawDoc(ctx.models.PairingSession.collection.name, {
    lookupTag: rejoinTag,
  });
  const redeemRaw =
    seededOpenSession._id !== undefined
      ? await ctx.readRawDoc(ctx.models.PairingSession.collection.name, {
          _id: seededOpenSession._id,
        })
      : null;

  const identity = genuineModelIdentity('PairingSession', ctx.models.PairingSession);
  const executed = writeRecords.length >= 2 && rejoinRaw !== null && redeemRaw !== null;

  const components = [
    component(
      'pairing_session_update_and_consume_paths_reached_product_code',
      'issuePairingSession supersede, rejoinPendingPairing and redeemPairingCode all reach the genuine PairingSession update statics',
      `supersedeUpdateCalls=${updateVerdict.callCount} (issueOk=${issued.ok === true}, creation blocked by the disclosed S4T-03 validator defect); rejoinOk=${rejoined.ok === true} rejoinError.code=${rejoined.error ? rejoined.error.code : null}; redeemOk=${redeemed.ok === true} redeemError.code=${redeemed.error ? redeemed.error.code : null}`,
      updateVerdict.callCount === 1 &&
        findOneAndUpdateVerdict.callCount === 2 &&
        rejoined.ok === true &&
        redeemed.ok === true,
      'E1',
    ),
    component(
      'pairing_session_writes_carry_majority_journal',
      "every genuine PairingSession update/consume write in the issue/rejoin/redeem path passes writeConcern {w:'majority', j:true}",
      `callCount=${verdict.callCount} pinnedCount=${verdict.pinnedCount} observed=${JSON.stringify(verdict.calls)}`,
      verdict.callCount >= 3 && verdict.allPinned,
      'E1',
    ),
    component(
      'redeem_consume_transition_durable',
      'the redeemed session is durably claim_pending with the trusted owner and the attempt counter applied',
      `rawPresent=${redeemRaw !== null} state=${redeemRaw ? redeemRaw.state : null} pendingOwnerId=${redeemRaw ? redeemRaw.pendingOwnerId : null} attemptsUsed=${redeemRaw ? redeemRaw.attemptsUsed : null}`,
      redeemRaw !== null &&
        redeemRaw.state === 'claim_pending' &&
        redeemRaw.pendingOwnerId === ctx.OWNER_A &&
        redeemRaw.attemptsUsed === 1,
      'E1',
    ),
    component(
      'rejoin_update_transition_durable',
      'the same-owner rejoin increments attemptsUsed without leaving claim_pending',
      `rawPresent=${rejoinRaw !== null} state=${rejoinRaw ? rejoinRaw.state : null} pendingOwnerId=${rejoinRaw ? rejoinRaw.pendingOwnerId : null} attemptsUsed=${rejoinRaw ? rejoinRaw.attemptsUsed : null}`,
      rejoinRaw !== null && rejoinRaw.state === 'claim_pending' && rejoinRaw.attemptsUsed === 2,
      'E1',
    ),
    component(
      'genuine_pairing_session_constructor_used',
      'the PairingSession model is the genuine createModels(mongoose) constructor registered on the live connection',
      JSON.stringify(identity),
      identity.typeofModel === 'function' && identity.identityMatchesMongooseRegistration === true,
      'E1',
    ),
  ];

  return {
    status: classifyControlRow({ expected: STATUS.PASS_CURRENT, executed, components }),
    productMethodInvoked: true,
    components,
    actual: {
      scenario:
        'three genuine PairingSession write paths: the guarded supersede updateOne during issuance, the same-owner rejoin findOneAndUpdate, and the redeem findOneAndUpdate consume CAS',
      issue: {
        envelope: envelopeView(issued),
        note: 'the subsequent PairingSession.create is blocked pre-repair by the disclosed S4T-03 validator defect; the supersede updateOne under test still ran',
      },
      rejoin: { envelope: envelopeView(rejoined) },
      redeem: { envelope: envelopeView(redeemed) },
      writeVerdict: verdict,
      supersedeUpdateVerdict: updateVerdict,
      rejoinAndRedeemFindOneAndUpdateVerdict: findOneAndUpdateVerdict,
      durableReadBack: {
        rejoinRawPresent: rejoinRaw !== null,
        rejoinState: rejoinRaw ? rejoinRaw.state : null,
        rejoinAttemptsUsed: rejoinRaw ? rejoinRaw.attemptsUsed : null,
        redeemRawPresent: redeemRaw !== null,
        redeemState: redeemRaw ? redeemRaw.state : null,
        redeemPendingOwnerId: redeemRaw ? redeemRaw.pendingOwnerId : null,
        redeemAttemptsUsed: redeemRaw ? redeemRaw.attemptsUsed : null,
      },
      requestedWriteConcern: ctx.WRITE_CONCERN,
      staticAnchors: [
        'pairingSessionService.js:592-596 — supersede updateOne with { writeConcern: AUTHORITY_WRITE_CONCERN }',
        'pairingSessionService.js:933-944 — rejoin findOneAndUpdate with { new: true, writeConcern: AUTHORITY_WRITE_CONCERN }',
        'pairingSessionService.js:878-895 — redeem findOneAndUpdate with { new: true, writeConcern: AUTHORITY_WRITE_CONCERN }',
      ],
    },
  };
}

/* ------------------------------------------------------------------ S4T-07 */

async function s4t07(ctx) {
  const identity = {};
  for (const key of env.DEVICE_MODELS) {
    identity[key] = genuineModelIdentity(key, ctx.models[key]);
  }
  const registryTypeof = {};
  for (const key of Object.keys(ctx.registry)) {
    registryTypeof[key] = typeof ctx.registry[key];
  }
  const composition = env.attemptComposition(ctx.models, {
    clock: ctx.clock,
    cryptoSurface: ctx.cryptoSurface,
    audit: ctx.audit,
    tenantPolicy: ctx.tenantPolicy,
    consent: ctx.consent.verify.bind(ctx.consent),
    pepperLookup: ctx.pepperLookup,
  });
  const connectionProbe = await connectionWriteConcernProbe({
    client: ctx.client,
    uri: ctx.uri,
    mongoose: w3a.mongoose,
  });
  const topologyProbe = {
    setName: ctx.topology.setName,
    isWritablePrimary: ctx.topology.isWritablePrimary,
    serverVersion: ctx.topology.serverVersion,
    driverVersion: ctx.driverVersion,
    nodeVersion: ctx.topology.nodeVersion,
    pid: ctx.topology.pid,
    databaseName: ctx.topology.dbName,
  };

  const modelsAllGenuine = env.DEVICE_MODELS.every(
    (key) =>
      identity[key].typeofModel === 'function' &&
      identity[key].schemaPresent === true &&
      identity[key].identityMatchesMongooseRegistration === true,
  );
  const compositionAccepted = composition.every((attempt) => attempt.accepted === true);
  const executed =
    topologyProbe.serverVersion !== null &&
    Object.keys(identity).length === env.DEVICE_MODELS.length &&
    composition.length === 3;

  const components = [
    component(
      'mongo_topology_matches_frozen_lab',
      'Mongo 7.0.43, replica set cbhrRdcP1, writable primary, mongodb driver 6.21.0',
      JSON.stringify(topologyProbe),
      topologyProbe.serverVersion === '7.0.43' &&
        topologyProbe.setName === 'cbhrRdcP1' &&
        topologyProbe.isWritablePrimary === true &&
        topologyProbe.driverVersion === '6.21.0',
      'E1',
    ),
    component(
      'genuine_mongoose_model_constructors_no_facade',
      'each device model is the genuine createModels(mongoose) constructor (typeof function, schema present, identity-equal to the live mongoose registration)',
      JSON.stringify(identity),
      modelsAllGenuine,
      'E1',
    ),
    component(
      'frozen_factories_accept_the_raw_registry',
      'all three frozen factories compose against the RAW registry object (no plain-object facade exists in this lane)',
      JSON.stringify(composition),
      compositionAccepted,
      'E1',
    ),
    component(
      'no_connection_level_majority_journal_default',
      'no connection/generation-level write concern is masking the create-site option omission: the driver/connection default is absent and the server default RW concern carries no journal:true',
      JSON.stringify(connectionProbe),
      connectionProbe.connectionLevelWriteConcernAbsent === true &&
        connectionProbe.connectionLevelMajorityJournalResolved === false &&
        connectionProbe.serverDefaultJournalTrue === false,
      'E1',
    ),
    component(
      'registry_registered_on_the_live_connection',
      'the registry used by the rows is the one registered on the live mongoose connection used to write',
      `mongooseDatabaseName=${w3a.mongoose.connection.db ? w3a.mongoose.connection.db.databaseName : null} fencedDbName=${ctx.dbName}`,
      w3a.mongoose.connection.db !== undefined &&
        w3a.mongoose.connection.db.databaseName === ctx.dbName,
      'E1',
    ),
  ];

  return {
    status: classifyControlRow({ expected: STATUS.PASS_CURRENT, executed, components }),
    productMethodInvoked: true,
    components,
    actual: {
      scenario:
        'real-substrate control: topology, driver version, genuine model-constructor identity, raw-registry factory composition and the connection/server write-concern default probe',
      topologyProbe,
      modelIdentity: identity,
      registryTypeof,
      composition,
      connectionProbe,
      staticAnchors: [
        'packages/data-schemas/src/models/index.ts — createModels(mongoose) returns genuine Model constructors',
        'tests/device/e1/r2post/durability/harness.cjs — the raw registry is passed to the factories; no facade is constructed',
      ],
    },
  };
}

/* ------------------------------------------------------------------ S4T-08 */

/**
 * S4T-08 NAMESPACE/INTEGRITY (E0). Pure hash/namespace integrity: no product method is invoked, so
 * `productMethodInvoked` is reported truthfully as false.
 */
function runS4T08(facts) {
  const {
    preflight,
    postRunHashes,
    dependencySurface,
    priorLaneEvidence,
    namespaceAudit,
    fenceOrderingProbe,
    cleanupDrops,
  } = facts;

  const hashesUnchanged =
    preflight.ok === true &&
    postRunHashes.ok === true &&
    postRunHashes.entries.every((entry) => entry.match === true);

  const components = [
    component(
      'binding_source_hashes_unchanged',
      'all six authorized binding sources still hash to their frozen values after the run',
      `preflightOk=${preflight.ok} postRunOk=${postRunHashes.ok} problems=${JSON.stringify(postRunHashes.problems)}`,
      hashesUnchanged,
      'E0',
    ),
    component(
      'dependency_surface_unchanged',
      'the composed dependency surface (binding sources + device model/schema pairs + barrels) is byte-identical before and after the run',
      `files=${dependencySurface.before.count} unchanged=${dependencySurface.comparison.unchanged} changed=${JSON.stringify(dependencySurface.comparison.changed)} missingAfter=${JSON.stringify(dependencySurface.comparison.missingAfter)}`,
      dependencySurface.comparison.unchanged === true,
      'E0',
    ),
    component(
      'prior_lane_evidence_untouched',
      'accepted S1/S2/S3/T0/T0A/T1/T1R durable evidence bytes are unchanged by this lane',
      `files=${priorLaneEvidence.before.count} unchanged=${priorLaneEvidence.comparison.unchanged} changed=${JSON.stringify(priorLaneEvidence.comparison.changed)} missingAfter=${JSON.stringify(priorLaneEvidence.comparison.missingAfter)}`,
      priorLaneEvidence.comparison.unchanged === true,
      'E0',
    ),
    component(
      'all_owned_databases_dropped',
      'no cbhr_rdc_phase1_r2_s4t_* database survives the run',
      `leftovers=${JSON.stringify(namespaceAudit.leftovers)} identical=${namespaceAudit.identical} ok=${namespaceAudit.ok}; cleanupDrops=${JSON.stringify(cleanupDrops)}`,
      namespaceAudit.ok === true && namespaceAudit.leftovers.length === 0,
      'E0',
    ),
    component(
      'no_foreign_database_changes',
      'no database outside the s4t namespace was created or removed',
      `foreignCreated=${JSON.stringify(namespaceAudit.foreignCreated)} foreignRemoved=${JSON.stringify(namespaceAudit.foreignRemoved)} identical=${namespaceAudit.identical}`,
      namespaceAudit.foreignCreated.length === 0 &&
        namespaceAudit.foreignRemoved.length === 0 &&
        namespaceAudit.identical === true,
      'E0',
    ),
    component(
      'fence_refused_foreign_names_before_client_construction',
      'every foreign/hostile database name is refused by the fence before any MongoClient is constructed',
      `probed=${fenceOrderingProbe.probed} allRefusedBeforeClientConstruction=${fenceOrderingProbe.allRefusedBeforeClientConstruction}`,
      fenceOrderingProbe.allRefusedBeforeClientConstruction === true,
      'E0',
    ),
    component(
      'runner_owned_cleanup_drops_succeeded',
      'every runner-owned database drop reported success',
      JSON.stringify(cleanupDrops),
      Array.isArray(cleanupDrops) && cleanupDrops.every((entry) => entry.dropped === true),
      'E0',
    ),
  ];

  const executed =
    preflight !== null &&
    postRunHashes !== null &&
    dependencySurface.before !== null &&
    priorLaneEvidence.before !== null &&
    namespaceAudit !== null &&
    fenceOrderingProbe !== null;

  return {
    status: classifyControlRow({ expected: STATUS.PASS_CURRENT, executed, components }),
    productMethodInvoked: false,
    components,
    actual: {
      scenario:
        'E0 namespace/integrity row: binding-source hash re-verification, dependency-surface byte comparison, prior-lane evidence byte comparison, server-wide database inventory diff and fence-ordering proof',
      preflightHashes: preflight.hashes,
      postRunHashes: postRunHashes.hashes,
      postRunHashProblems: postRunHashes.problems,
      dependencySurface: {
        files: dependencySurface.before.count,
        comparison: dependencySurface.comparison,
      },
      priorLaneEvidence: {
        files: priorLaneEvidence.before.count,
        comparison: priorLaneEvidence.comparison,
      },
      namespaceAudit,
      cleanupDrops,
      fenceOrderingProbe: {
        gateOrder: fenceOrderingProbe.gateOrder,
        probed: fenceOrderingProbe.probed,
        allRefusedBeforeClientConstruction: fenceOrderingProbe.allRefusedBeforeClientConstruction,
        refusedNames: fenceOrderingProbe.results.filter((entry) => entry.refused).map((entry) => entry.dbName),
        detailArtifact: 'tests/device/e1/r2post/durability/artifacts/S4T-FENCE-PROBE.json',
      },
    },
  };
}

/* ------------------------------------------------------------------ registry */

const ROWS = [
  {
    id: 'S4T-01',
    tier: 'E1',
    tag: 's4t01registrationchallengecreate',
    expectedOracle:
      "PASS iff beginRegistration's genuine Challenge.create call carries an explicit options object, via an unambiguous overload, with writeConcern {w:'majority', j:true}, with the row durably readable back; current expected state EXPECTED_RED",
    repairPredicate:
      "captured Challenge.create call includes an array-form options object with writeConcern.w==='majority' and writeConcern.j===true",
    run: s4t01,
  },
  {
    id: 'S4T-02',
    tier: 'E1',
    tag: 's4t02deviceauthoritycreate',
    expectedOracle:
      "PASS iff completeRegistration's genuine DeviceAuthority.create call carries an explicit options object, via an unambiguous overload, with writeConcern {w:'majority', j:true}, with the pending authority row durably readable back; current expected state EXPECTED_RED",
    repairPredicate:
      "captured DeviceAuthority.create call includes an array-form options object with writeConcern.w==='majority' and writeConcern.j===true",
    run: s4t02,
  },
  {
    id: 'S4T-03',
    tier: 'E1',
    tag: 's4t03pairingsessioncreate',
    expectedOracle:
      "PASS iff issuePairingSession's genuine PairingSession.create call carries an explicit options object, via an unambiguous overload, with writeConcern {w:'majority', j:true}, with the session durably readable back; current expected state EXPECTED_RED",
    repairPredicate:
      "captured PairingSession.create call includes an array-form options object with writeConcern.w==='majority' and writeConcern.j===true",
    run: s4t03,
  },
  {
    id: 'S4T-04',
    tier: 'E1',
    tag: 's4t04challengespendcontrol',
    expectedOracle:
      "PASS iff every real Challenge.updateOne spend path (registrationService completion and authorityService.spendChallenge) carries writeConcern {w:'majority', j:true}",
    repairPredicate: null,
    run: s4t04,
  },
  {
    id: 'S4T-05',
    tier: 'E1',
    tag: 's4t05authoritycascontrol',
    expectedOracle:
      "PASS iff one real accepted-S2 authority CAS transition (revokeLease) commits through a DeviceAuthority.updateOne carrying writeConcern {w:'majority', j:true}",
    repairPredicate: null,
    run: s4t05,
  },
  {
    id: 'S4T-06',
    tier: 'E1',
    tag: 's4t06pairingsessionupdatecontrol',
    expectedOracle:
      "PASS iff every genuine PairingSession update/consume write in the issue-supersede, rejoin and redeem paths carries writeConcern {w:'majority', j:true}",
    repairPredicate: null,
    run: s4t06,
  },
  {
    id: 'S4T-07',
    tier: 'E1',
    tag: 's4t07realsubstratecontrol',
    expectedOracle:
      'PASS iff Mongo 7.0.43 on replica set cbhrRdcP1 with a writable primary, driver 6.21.0, genuine model constructors with no composition facade, and no connection/server write-concern default that could mask a missing create-site option',
    repairPredicate: null,
    run: s4t07,
  },
];

module.exports = { ROWS, runS4T08, component, byLabel, genuineModelIdentity };
