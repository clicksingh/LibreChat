'use strict';

/**
 * W3-B R2 T2-F4 nine authorized rows (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Each row drives the REAL frozen product service bytes against a GENUINE Mongoose/Mongo
 * connection inside a REAL AsyncLocalStorage context taken from the frozen `tenantContext.ts`
 * singleton, counts genuine model invocations, and derives its status from those observations —
 * never from a hard-coded expectation.
 *
 * The row ids, order, required behaviour and authorized current states are the nine rows of
 * `GOVERNOR-W3B-R2-T2-F4-TRUST-TEST-AUTHORIZATION-20261015.md`; the machine-checkable form of that
 * table lives in `./expected.cjs`.
 */

const fs = require('node:fs');

const expected = require('./expected.cjs');
const preimages = require('./preimages.cjs');
const harness = require('./harness.cjs');

const { als, errorView, sameDoc } = harness;
const STATUS = expected.STATUS;

function component(id, met, observed) {
  return { id, met: met === true, observed };
}

function allMet(components) {
  return components.length > 0 && components.every((entry) => entry.met === true);
}

function metById(components, id) {
  const found = components.find((entry) => entry.id === id);
  return found !== undefined && found.met === true;
}

/**
 * Enters a real ALS context through the frozen module's own storage. `null` means "no ALS context
 * is entered at all" — the row then records the genuine absence observed at call time.
 */
async function runInAls(tenantIdOrNull, fn) {
  if (tenantIdOrNull === null) {
    const alsAtCall = als.getTenantId();
    return { alsAtCall, result: await fn() };
  }
  return als.tenantStorage.run({ tenantId: tenantIdOrNull }, async () => {
    const alsAtCall = als.getTenantId();
    const result = await fn();
    return { alsAtCall, result };
  });
}

function envelopeOf(value) {
  return value !== null && typeof value === 'object' ? value : {};
}

function errorCodeOf(value) {
  const error = envelopeOf(value).error;
  return error !== null && typeof error === 'object' ? (error.code ?? null) : null;
}

/** EXPECTED_RED finish: fidelity failure is HARNESS_FAIL; a met predicate is UNEXPECTED_GREEN. */
function finishRed({ components, fidelityIds, predicateIds, productCalls, actual }) {
  const productMethodInvoked = productCalls > 0;
  if (!fidelityIds.every((id) => metById(components, id))) {
    return { status: STATUS.HARNESS_FAIL, productMethodInvoked, actual, components };
  }
  const predicateMet = predicateIds.every((id) => metById(components, id));
  const executed = productMethodInvoked || predicateMet;
  const status = expected.classifyRow({
    authorizedStatus: STATUS.EXPECTED_RED,
    predicateMet,
    executed,
    componentsMet: predicateMet,
  });
  return {
    status,
    productMethodInvoked: executed,
    actual: { ...actual, predicateMet, predicateIds, fidelityIds },
    components,
  };
}

function finishPass({ components, executed, productCalls, actual }) {
  const componentsMet = allMet(components);
  const status = expected.classifyRow({
    authorizedStatus: STATUS.PASS_CURRENT,
    predicateMet: componentsMet,
    executed: executed === true,
    componentsMet,
  });
  return {
    status,
    productMethodInvoked: executed === true || productCalls > 0,
    actual: { ...actual, componentsMet },
    components,
  };
}

const ROWS = [
  {
    id: 'T2F4-01',
    order: 1,
    tier: 'E1',
    title: 'AUTHORITY_ALS_MISMATCH',
    tag: 'T2F4_01_authority_als_mismatch',
    authorizedStatus: STATUS.EXPECTED_RED,
    async run(ctx) {
      const deviceId = 't2f4-01-device';
      await ctx.seedAuthority({ _id: deviceId, deviceKeyId: 't2f4-01-device-key' });
      const before = await ctx.rawDocView('deviceauthorities', { _id: deviceId });
      const mark = ctx.counter.mark();
      const service = ctx.composeAuthority({ tenantContext: ctx.tenantContextFor(false) });
      const observed = await runInAls(ctx.OTHER_TENANT, () =>
        service.claimAuthority({
          deviceId,
          tenantId: ctx.TENANT,
          ownerId: ctx.OWNER_A,
          expectedEpoch: 0,
          sessionId: null,
        }),
      );
      const calls = ctx.countsSince(mark, harness.AUTHORITY_MUTATION_MODELS);
      const after = await ctx.rawDocView('deviceauthorities', { _id: deviceId });
      const envelope = envelopeOf(observed.result);
      const components = [
        component('als-context-at-call-is-B', observed.alsAtCall === ctx.OTHER_TENANT, {
          observed: observed.alsAtCall ?? null,
          expected: ctx.OTHER_TENANT,
        }),
        component('error-code-is-TENANT_MISMATCH', errorCodeOf(envelope) === 'TENANT_MISMATCH', {
          observedError: errorView(envelope.error),
        }),
        component('zero-DeviceAuthority-and-Challenge-model-calls', calls.total === 0, {
          total: calls.total,
          byModel: calls.byModel,
        }),
        component('authority-row-unchanged', sameDoc(before, after), {
          rowBefore: before,
          rowAfter: after,
        }),
      ];
      return finishRed({
        components,
        fidelityIds: ['als-context-at-call-is-B'],
        predicateIds: [
          'error-code-is-TENANT_MISMATCH',
          'zero-DeviceAuthority-and-Challenge-model-calls',
          'authority-row-unchanged',
        ],
        productCalls: calls.total,
        actual: {
          scenario: 'real ALS tenant B + trusted args.tenantId tenant A; representative authority mutation',
          authorityMutation: 'authorityService.claimAuthority',
          alsObservedAtCall: observed.alsAtCall ?? null,
          trustedTenantId: ctx.TENANT,
          alsTenantId: ctx.OTHER_TENANT,
          envelope: harness.envelopeView(envelope),
          modelCalls: calls,
          rowBefore: before,
          rowAfter: after,
          rowChanged: !sameDoc(before, after),
        },
      });
    },
  },
  {
    id: 'T2F4-02',
    order: 2,
    tier: 'E1',
    title: 'AUTHORITY_SYSTEM_ALS',
    tag: 'T2F4_02_authority_system_als',
    authorizedStatus: STATUS.EXPECTED_RED,
    async run(ctx) {
      const deviceId = 't2f4-02-device';
      await ctx.seedAuthority({ _id: deviceId, deviceKeyId: 't2f4-02-device-key' });
      const before = await ctx.rawDocView('deviceauthorities', { _id: deviceId });
      const mark = ctx.counter.mark();
      const service = ctx.composeAuthority({ tenantContext: ctx.tenantContextFor(false) });
      const observed = await runInAls(als.SYSTEM_TENANT_ID, () =>
        service.claimAuthority({
          deviceId,
          tenantId: ctx.TENANT,
          ownerId: ctx.OWNER_A,
          expectedEpoch: 0,
          sessionId: null,
        }),
      );
      const calls = ctx.countsSince(mark, harness.AUTHORITY_MUTATION_MODELS);
      const after = await ctx.rawDocView('deviceauthorities', { _id: deviceId });
      const envelope = envelopeOf(observed.result);
      const components = [
        component('als-context-at-call-is-__SYSTEM__', observed.alsAtCall === als.SYSTEM_TENANT_ID, {
          observed: observed.alsAtCall ?? null,
          expected: als.SYSTEM_TENANT_ID,
          systemTenantIdFromRealModule: als.SYSTEM_TENANT_ID,
        }),
        component('error-code-is-TENANT_MISMATCH', errorCodeOf(envelope) === 'TENANT_MISMATCH', {
          observedError: errorView(envelope.error),
        }),
        component('zero-DeviceAuthority-and-Challenge-model-calls', calls.total === 0, {
          total: calls.total,
          byModel: calls.byModel,
        }),
        component('authority-row-unchanged', sameDoc(before, after), {
          rowBefore: before,
          rowAfter: after,
        }),
      ];
      return finishRed({
        components,
        fidelityIds: ['als-context-at-call-is-__SYSTEM__'],
        predicateIds: [
          'error-code-is-TENANT_MISMATCH',
          'zero-DeviceAuthority-and-Challenge-model-calls',
          'authority-row-unchanged',
        ],
        productCalls: calls.total,
        actual: {
          scenario: 'real ALS __SYSTEM__ + trusted args.tenantId tenant A; representative authority mutation',
          authorityMutation: 'authorityService.claimAuthority',
          alsObservedAtCall: observed.alsAtCall ?? null,
          trustedTenantId: ctx.TENANT,
          envelope: harness.envelopeView(envelope),
          modelCalls: calls,
          rowBefore: before,
          rowAfter: after,
          rowChanged: !sameDoc(before, after),
        },
      });
    },
  },
  {
    id: 'T2F4-03',
    order: 3,
    tier: 'E1',
    title: 'AUTHORITY_ALS_ABSENT',
    tag: 'T2F4_03_authority_als_absent',
    authorizedStatus: STATUS.EXPECTED_RED,
    async run(ctx) {
      const deviceId = 't2f4-03-device';
      await ctx.seedAuthority({ _id: deviceId, deviceKeyId: 't2f4-03-device-key' });
      const before = await ctx.rawDocView('deviceauthorities', { _id: deviceId });
      const mark = ctx.counter.mark();
      const tenantContext = ctx.tenantContextFor(false);
      const service = ctx.composeAuthority({ tenantContext });
      const observed = await runInAls(null, () =>
        service.claimAuthority({
          deviceId,
          tenantId: ctx.TENANT,
          ownerId: ctx.OWNER_A,
          expectedEpoch: 0,
          sessionId: null,
        }),
      );
      const calls = ctx.countsSince(mark, harness.AUTHORITY_MUTATION_MODELS);
      const after = await ctx.rawDocView('deviceauthorities', { _id: deviceId });
      const envelope = envelopeOf(observed.result);
      const components = [
        component('als-context-at-call-is-undefined', observed.alsAtCall === undefined, {
          observed: observed.alsAtCall ?? null,
          observedIsUndefined: observed.alsAtCall === undefined,
        }),
        component('injected-alsAbsencePermitted-is-false', tenantContext.alsAbsencePermitted === false, {
          injected: tenantContext.alsAbsencePermitted,
          getActiveTenantIdIsRealModuleFunction: tenantContext.getActiveTenantId === als.getTenantId,
        }),
        component('error-code-is-TENANT_MISMATCH', errorCodeOf(envelope) === 'TENANT_MISMATCH', {
          observedError: errorView(envelope.error),
        }),
        component('zero-DeviceAuthority-and-Challenge-model-calls', calls.total === 0, {
          total: calls.total,
          byModel: calls.byModel,
        }),
        component('authority-row-unchanged', sameDoc(before, after), {
          rowBefore: before,
          rowAfter: after,
        }),
      ];
      return finishRed({
        components,
        fidelityIds: ['als-context-at-call-is-undefined', 'injected-alsAbsencePermitted-is-false'],
        predicateIds: [
          'error-code-is-TENANT_MISMATCH',
          'zero-DeviceAuthority-and-Challenge-model-calls',
          'authority-row-unchanged',
        ],
        productCalls: calls.total,
        actual: {
          scenario: 'genuine ALS absence + alsAbsencePermitted=false + trusted args.tenantId tenant A',
          authorityMutation: 'authorityService.claimAuthority',
          alsObservedAtCall: observed.alsAtCall ?? null,
          injectedAlsAbsencePermitted: tenantContext.alsAbsencePermitted,
          envelope: harness.envelopeView(envelope),
          modelCalls: calls,
          rowBefore: before,
          rowAfter: after,
          rowChanged: !sameDoc(before, after),
        },
      });
    },
  },
  {
    id: 'T2F4-04',
    order: 4,
    tier: 'E1',
    title: 'PAIRING_ALS_MISMATCH',
    tag: 'T2F4_04_pairing_als_mismatch',
    authorizedStatus: STATUS.EXPECTED_RED,
    async run(ctx) {
      const deviceId = 't2f4-04-device';
      const deviceKeyId = 't2f4-04-device-key';
      await ctx.seedAuthority({
        _id: deviceId,
        deviceKeyId,
        devicePublicKey: ctx.labKey.spkiB64u,
        identityState: 'pending',
        leaseState: 'never',
        epoch: 0,
      });
      const sessionsBefore = await ctx.countCollection('pairingsessions');
      const mark = ctx.counter.mark();
      const service = ctx.composePairing({ tenantContext: ctx.tenantContextFor(false) });
      const observed = await runInAls(ctx.OTHER_TENANT, async () => {
        const nonce = ctx.cryptoSurface.newChallengeNonce();
        const issuedAt = String(ctx.clock.now());
        const message = ctx.cryptoSurface.canonicalEncode({
          domainTag: ctx.constants.PAIRING_OPEN_DOMAIN,
          fields: [ctx.TENANT, deviceId, deviceKeyId, nonce, issuedAt],
        });
        const signatureB64u = ctx.sign(ctx.labKey, message);
        return service.issuePairingSession({
          tenantId: ctx.TENANT,
          deviceId,
          deviceKeyId,
          domainTag: ctx.constants.PAIRING_OPEN_DOMAIN,
          proof: { nonce, issuedAt, signatureB64u },
        });
      });
      const calls = ctx.countsSince(mark, harness.PAIRING_PATH_MODELS);
      const sessionsAfter = await ctx.countCollection('pairingsessions');
      const envelope = envelopeOf(observed.result);
      const components = [
        component('als-context-at-call-is-B', observed.alsAtCall === ctx.OTHER_TENANT, {
          observed: observed.alsAtCall ?? null,
          expected: ctx.OTHER_TENANT,
        }),
        component('error-code-is-TENANT_MISMATCH', errorCodeOf(envelope) === 'TENANT_MISMATCH', {
          observedError: errorView(envelope.error),
        }),
        component('zero-DeviceAuthority-and-PairingSession-model-calls', calls.total === 0, {
          total: calls.total,
          byModel: calls.byModel,
        }),
        component('no-pairing-session-row-created', sessionsAfter === sessionsBefore, {
          sessionsBefore,
          sessionsAfter,
        }),
      ];
      return finishRed({
        components,
        fidelityIds: ['als-context-at-call-is-B'],
        predicateIds: [
          'error-code-is-TENANT_MISMATCH',
          'zero-DeviceAuthority-and-PairingSession-model-calls',
          'no-pairing-session-row-created',
        ],
        productCalls: calls.total,
        actual: {
          scenario: 'real ALS tenant B + trusted tenant A; representative authenticated pairing path',
          authenticatedPath: 'pairingSessionService.issuePairingSession (real Ed25519 pairing-open proof)',
          alsObservedAtCall: observed.alsAtCall ?? null,
          trustedTenantId: ctx.TENANT,
          proofVerifiedByProduct: envelope.ok === true,
          envelope: harness.envelopeView(envelope),
          modelCalls: calls,
          sessionsBefore,
          sessionsAfter,
        },
      });
    },
  },
  {
    id: 'T2F4-05',
    order: 5,
    tier: 'E1',
    title: 'REGISTRATION_ALS_ABSENT_APPROVED',
    tag: 'T2F4_05_registration_als_absent_approved',
    authorizedStatus: STATUS.PASS_CURRENT,
    async run(ctx) {
      const tenantPolicy = ctx.makeTenantPolicy([ctx.TENANT]);
      const tenantContext = ctx.tenantContextFor(true);
      const service = ctx.composeRegistration({ tenantContext, tenantPolicy });
      const mark = ctx.counter.mark();
      const observed = await runInAls(null, () =>
        service.beginRegistration({
          tenantId: ctx.TENANT,
          requestSource: 't2f4-lab-request-source',
        }),
      );
      const calls = ctx.countsSince(mark, harness.REGISTRATION_MODELS);
      const envelope = envelopeOf(observed.result);
      const persisted =
        typeof envelope.challengeHash === 'string' && envelope.challengeHash.length > 0
          ? await ctx.rawDoc('challenges', { challengeHash: envelope.challengeHash })
          : null;
      const components = [
        component('als-context-at-call-is-undefined', observed.alsAtCall === undefined, {
          observed: observed.alsAtCall ?? null,
          observedIsUndefined: observed.alsAtCall === undefined,
        }),
        component('injected-alsAbsencePermitted-is-true', tenantContext.alsAbsencePermitted === true, {
          injected: tenantContext.alsAbsencePermitted,
          getActiveTenantIdIsRealModuleFunction: tenantContext.getActiveTenantId === als.getTenantId,
        }),
        component(
          'tenant-policy-consulted-with-trusted-tenant',
          tenantPolicy.calls.length >= 1 && tenantPolicy.calls[0].tenantId === ctx.TENANT,
          { calls: tenantPolicy.calls },
        ),
        component(
          'begin-registration-returns-ok-with-challenge-and-hash',
          envelope.ok === true &&
            typeof envelope.challenge === 'string' &&
            envelope.challenge.length > 0 &&
            typeof envelope.challengeHash === 'string' &&
            envelope.challengeHash.length > 0,
          {
            ok: envelope.ok === true,
            challengePresent: typeof envelope.challenge === 'string' && envelope.challenge.length > 0,
            challengeReturnedToCallerOnly: true,
            challengeChars: typeof envelope.challenge === 'string' ? envelope.challenge.length : 0,
            challengeHashPresent:
              typeof envelope.challengeHash === 'string' && envelope.challengeHash.length > 0,
          },
        ),
        component(
          'genuine-Challenge-row-persisted-in-fenced-db',
          persisted !== null &&
            persisted !== undefined &&
            persisted.tenantId === ctx.TENANT &&
            persisted.purpose === 'registration' &&
            persisted.consumedAt === null,
          { persisted: harness.stableDocView(persisted) },
        ),
        component('Challenge.create-invoked-on-genuine-model', calls.total > 0, {
          total: calls.total,
          byModel: calls.byModel,
        }),
      ];
      return finishPass({
        components,
        executed: true,
        productCalls: calls.total,
        actual: {
          scenario: 'genuine ALS absence + alsAbsencePermitted=true + tenantPolicy true => registration may proceed',
          registrationPath: 'registrationService.beginRegistration',
          alsObservedAtCall: observed.alsAtCall ?? null,
          injectedAlsAbsencePermitted: tenantContext.alsAbsencePermitted,
          policyCalls: tenantPolicy.calls,
          envelope: harness.envelopeView(envelope),
          modelCalls: calls,
          persistedChallengeHash: envelope.challengeHash ?? null,
          persistedRow: harness.stableDocView(persisted),
        },
      });
    },
  },
  {
    id: 'T2F4-06',
    order: 6,
    tier: 'E1',
    title: 'REGISTRATION_ALS_PRESENT_MISMATCH',
    tag: 'T2F4_06_registration_als_present_mismatch',
    authorizedStatus: STATUS.EXPECTED_RED,
    async run(ctx) {
      const tenantPolicy = ctx.makeTenantPolicy([ctx.TENANT]);
      const tenantContext = ctx.tenantContextFor(false);
      const service = ctx.composeRegistration({ tenantContext, tenantPolicy });
      const mark = ctx.counter.mark();
      const observed = await runInAls(ctx.OTHER_TENANT, () =>
        service.beginRegistration({
          tenantId: ctx.TENANT,
          requestSource: 't2f4-lab-request-source',
        }),
      );
      const calls = ctx.countsSince(mark, harness.REGISTRATION_MODELS);
      const envelope = envelopeOf(observed.result);
      const components = [
        component('als-context-at-call-is-B', observed.alsAtCall === ctx.OTHER_TENANT, {
          observed: observed.alsAtCall ?? null,
          expected: ctx.OTHER_TENANT,
        }),
        component('error-code-is-TENANT_MISMATCH', errorCodeOf(envelope) === 'TENANT_MISMATCH', {
          observedError: errorView(envelope.error),
        }),
        component('zero-Challenge-model-calls', calls.total === 0, {
          total: calls.total,
          byModel: calls.byModel,
        }),
      ];
      return finishRed({
        components,
        fidelityIds: ['als-context-at-call-is-B'],
        predicateIds: ['error-code-is-TENANT_MISMATCH', 'zero-Challenge-model-calls'],
        productCalls: calls.total,
        actual: {
          scenario: 'active ALS tenant B + trusted tenant A + tenantPolicy true; registration begin',
          registrationPath: 'registrationService.beginRegistration',
          alsObservedAtCall: observed.alsAtCall ?? null,
          trustedTenantId: ctx.TENANT,
          policyCalls: tenantPolicy.calls,
          envelope: harness.envelopeView(envelope),
          modelCalls: calls,
          challengesPersistedInFencedDb: await ctx.countCollection('challenges'),
        },
      });
    },
  },
  {
    id: 'T2F4-07',
    order: 7,
    tier: 'E1',
    title: 'REGISTRATION_ALS_ABSENT_NOT_PERMITTED',
    tag: 'T2F4_07_registration_als_absent_not_permitted',
    authorizedStatus: STATUS.EXPECTED_RED,
    async run(ctx) {
      const tenantPolicy = ctx.makeTenantPolicy([ctx.TENANT]);
      const tenantContext = ctx.tenantContextFor(false);
      const service = ctx.composeRegistration({ tenantContext, tenantPolicy });
      const mark = ctx.counter.mark();
      const observed = await runInAls(null, () =>
        service.beginRegistration({
          tenantId: ctx.TENANT,
          requestSource: 't2f4-lab-request-source',
        }),
      );
      const calls = ctx.countsSince(mark, harness.REGISTRATION_MODELS);
      const envelope = envelopeOf(observed.result);
      const components = [
        component('als-context-at-call-is-undefined', observed.alsAtCall === undefined, {
          observed: observed.alsAtCall ?? null,
          observedIsUndefined: observed.alsAtCall === undefined,
        }),
        component('injected-alsAbsencePermitted-is-false', tenantContext.alsAbsencePermitted === false, {
          injected: tenantContext.alsAbsencePermitted,
          getActiveTenantIdIsRealModuleFunction: tenantContext.getActiveTenantId === als.getTenantId,
        }),
        component('error-code-is-TENANT_MISMATCH', errorCodeOf(envelope) === 'TENANT_MISMATCH', {
          observedError: errorView(envelope.error),
        }),
        component('zero-Challenge-model-calls', calls.total === 0, {
          total: calls.total,
          byModel: calls.byModel,
        }),
      ];
      return finishRed({
        components,
        fidelityIds: ['als-context-at-call-is-undefined', 'injected-alsAbsencePermitted-is-false'],
        predicateIds: ['error-code-is-TENANT_MISMATCH', 'zero-Challenge-model-calls'],
        productCalls: calls.total,
        actual: {
          scenario: 'genuine ALS absence + alsAbsencePermitted=false + tenantPolicy true; registration begin',
          registrationPath: 'registrationService.beginRegistration',
          alsObservedAtCall: observed.alsAtCall ?? null,
          injectedAlsAbsencePermitted: tenantContext.alsAbsencePermitted,
          policyCalls: tenantPolicy.calls,
          envelope: harness.envelopeView(envelope),
          modelCalls: calls,
          challengesPersistedInFencedDb: await ctx.countCollection('challenges'),
        },
      });
    },
  },
  {
    id: 'T2F4-08',
    order: 8,
    tier: 'E1',
    title: 'SPEND_CHALLENGE_BOUND_TENANT_FALLBACK',
    tag: 'T2F4_08_spend_challenge_bound_tenant_fallback',
    authorizedStatus: STATUS.EXPECTED_RED,
    async run(ctx) {
      const challengeHash = ctx.cryptoSurface.challengeHash(ctx.cryptoSurface.newChallengeNonce());
      await ctx.seedChallenge({
        challengeHash,
        purpose: 'registration',
        tenantId: ctx.TENANT,
        consumedAt: null,
        expiresAt: new Date(ctx.clock.now() + ctx.constants.REGISTRATION_CHALLENGE_TTL_MS),
      });
      const before = await ctx.rawDocView('challenges', { challengeHash });
      // Top-level tenantId is deliberately ABSENT; `bound` is the only tenant source supplied.
      const callArgs = {
        challengeHash,
        purpose: 'registration',
        bound: { tenantId: ctx.TENANT },
      };
      const topLevelOmitted = !Object.prototype.hasOwnProperty.call(callArgs, 'tenantId');
      const boundSupplied =
        callArgs.bound !== null &&
        typeof callArgs.bound === 'object' &&
        callArgs.bound.tenantId === ctx.TENANT;
      const mark = ctx.counter.mark();
      const service = ctx.composeAuthority({ tenantContext: ctx.tenantContextFor(false) });
      const observed = await runInAls(ctx.TENANT, () => service.spendChallenge(callArgs));
      const calls = ctx.countsSince(mark, harness.AUTHORITY_MUTATION_MODELS);
      const after = await ctx.rawDocView('challenges', { challengeHash });
      const envelope = envelopeOf(observed.result);
      const components = [
        component('top-level-tenantId-was-omitted-from-the-call-args', topLevelOmitted, {
          callArgKeys: Object.keys(callArgs).sort(),
        }),
        component('bound-tenantId-was-supplied-as-the-only-tenant-source', boundSupplied, {
          bound: callArgs.bound,
        }),
        component('error-code-is-TENANT_MISMATCH', errorCodeOf(envelope) === 'TENANT_MISMATCH', {
          observedError: errorView(envelope.error),
        }),
        component('zero-Challenge-model-calls', calls.total === 0, {
          total: calls.total,
          byModel: calls.byModel,
        }),
        component('challenge-row-unchanged', sameDoc(before, after), {
          rowBefore: before,
          rowAfter: after,
        }),
      ];
      return finishRed({
        components,
        fidelityIds: [
          'top-level-tenantId-was-omitted-from-the-call-args',
          'bound-tenantId-was-supplied-as-the-only-tenant-source',
        ],
        predicateIds: [
          'error-code-is-TENANT_MISMATCH',
          'zero-Challenge-model-calls',
          'challenge-row-unchanged',
        ],
        productCalls: calls.total,
        actual: {
          scenario:
            'authorityService.spendChallenge with top-level tenantId omitted and bound.tenantId supplied (ALS tenant A also active, so the bound-container fallback is the only violation probed)',
          authorityMutation: 'authorityService.spendChallenge',
          alsObservedAtCall: observed.alsAtCall ?? null,
          callArgKeys: Object.keys(callArgs).sort(),
          envelope: harness.envelopeView(envelope),
          modelCalls: calls,
          rowBefore: before,
          rowAfter: after,
          rowChanged: !sameDoc(before, after),
        },
      });
    },
  },
  {
    id: 'T2F4-09',
    order: 9,
    tier: 'E1',
    title: 'REAL_ALS_SYSTEM_CONTROL',
    tag: 'T2F4_09_real_als_system_control',
    authorizedStatus: STATUS.PASS_CURRENT,
    async run(ctx) {
      const insideTenantA = await als.tenantStorage.run({ tenantId: ctx.TENANT }, async () => als.getTenantId());
      const outside = als.getTenantId();
      const insideSystem = await als.tenantStorage.run(
        { tenantId: als.SYSTEM_TENANT_ID },
        async () => als.getTenantId(),
      );
      const runAsSystemValue = await als.runAsSystem(async () => als.getTenantId());
      const afterRunAsSystem = als.getTenantId();
      const scopedTenantA = await als.tenantStorage.run({ tenantId: ctx.TENANT }, async () =>
        als.scopedCacheKey('t2f4-base'),
      );
      const scopedSystem = await als.tenantStorage.run({ tenantId: als.SYSTEM_TENANT_ID }, async () =>
        als.scopedCacheKey('t2f4-base'),
      );
      const scopedAbsent = als.scopedCacheKey('t2f4-base');
      const identity = als.resolveTenantStorageIdentity();

      const tenantContextPreimage = preimages.PREIMAGES.find((entry) => entry.id === 'tenantContext.ts');
      const tenantIsolationPreimage = preimages.PREIMAGES.find(
        (entry) => entry.id === 'tenantIsolation.ts',
      );
      const contextBytesMatch = als.tenantContextSha256 === tenantContextPreimage.expected;
      const isolationBytesMatch = als.tenantIsolationSha256 === tenantIsolationPreimage.expected;

      const pluginSource = fs.readFileSync(als.TENANT_ISOLATION_TS, 'utf8');
      const pluginProvidesExplicitTenantMismatch = pluginSource.includes('TENANT_MISMATCH');
      const pluginIsQueryFilterMiddleware =
        pluginSource.includes('schema.pre(') && pluginSource.includes('this.where({ tenantId })');
      const strictModeEnv = process.env.TENANT_ISOLATION_STRICT ?? null;

      const distinct = new Set([insideTenantA, outside, insideSystem]);

      const components = [
        component(
          'storage-is-native-AsyncLocalStorage-instance',
          als.storageIsNativeAsyncLocalStorage === true && ctx.alsStorage === als.tenantStorage,
          {
            isNativeAsyncLocalStorage: als.storageIsNativeAsyncLocalStorage,
            moduleKind: als.moduleKind,
            modulePath: als.TENANT_CONTEXT_TS,
          },
        ),
        component('SYSTEM_TENANT_ID-is-frozen-sentinel', als.SYSTEM_TENANT_ID === '__SYSTEM__', {
          observed: als.SYSTEM_TENANT_ID,
        }),
        component(
          'three-contexts-pairwise-distinguishable',
          insideTenantA === ctx.TENANT &&
            outside === undefined &&
            insideSystem === als.SYSTEM_TENANT_ID &&
            distinct.size === 3,
          { insideTenantA: insideTenantA ?? null, outside: outside ?? null, insideSystem: insideSystem ?? null, distinctCount: distinct.size },
        ),
        component(
          'frozen-module-bytes-match-authorized-preimages',
          contextBytesMatch && isolationBytesMatch,
          {
            tenantContextTs: {
              path: 'packages/data-schemas/src/config/tenantContext.ts',
              observed: als.tenantContextSha256,
              authorized: tenantContextPreimage.expected,
              match: contextBytesMatch,
            },
            tenantIsolationTs: {
              path: 'packages/data-schemas/src/models/plugins/tenantIsolation.ts',
              observed: als.tenantIsolationSha256,
              authorized: tenantIsolationPreimage.expected,
              match: isolationBytesMatch,
            },
          },
        ),
        component(
          'runAsSystem-yields-SYSTEM-and-restores-absence',
          runAsSystemValue === als.SYSTEM_TENANT_ID && afterRunAsSystem === undefined,
          { runAsSystemValue: runAsSystemValue ?? null, afterRunAsSystem: afterRunAsSystem ?? null },
        ),
        component(
          'scopedCacheKey-behaviour-matches-frozen-bytes',
          scopedTenantA === `t2f4-base:${ctx.TENANT}` &&
            scopedSystem === 't2f4-base' &&
            scopedAbsent === 't2f4-base',
          { tenantA: scopedTenantA, system: scopedSystem, absent: scopedAbsent },
        ),
        component(
          'rows-used-the-frozen-module-singleton',
          identity.sameModuleInstance === true && identity.sameStorageInstance === true,
          { ...identity, storageUsedByRowsIsModuleSingleton: ctx.alsStorage === als.tenantStorage },
        ),
        component(
          'plugin-recorded-as-not-the-safety-boundary',
          pluginProvidesExplicitTenantMismatch === false && pluginIsQueryFilterMiddleware === true,
          {
            pluginPath: 'packages/data-schemas/src/models/plugins/tenantIsolation.ts',
            pluginKind: 'mongoose-query/update pre-middleware (filter injection)',
            pluginProvidesExplicitTenantMismatch,
            pluginIsQueryFilterMiddleware,
            tenantIsolationStrictEnv: strictModeEnv,
            strictDefaultOff: strictModeEnv !== 'true',
            treatedAsSafetyBoundary: false,
            trustGateLocation:
              'ALS + trusted-argument tenant comparison inside the Device service bytes, BEFORE any model read/write (rows T2F4-01..T2F4-08)',
            reason:
              'the plugin injects/omits query filters and has no frozen TENANT_MISMATCH refusal, and in non-strict mode it passes through when no ALS context is active, so it cannot be the tenant-authority boundary',
          },
        ),
      ];
      return finishPass({
        components,
        executed: true,
        productCalls: 0,
        actual: {
          scenario: 'real frozen tenantContext.ts executed through the pinned I10 bridge; real node AsyncLocalStorage semantics',
          tierDisclosure:
            'actual tier E1 (real product TS bytes executed in-process); the plugin-byte invariance check is E0-grade read-only',
          tenantContextModulePath: als.TENANT_CONTEXT_TS,
          tenantIsolationPath: als.TENANT_ISOLATION_TS,
          observations: {
            insideTenantA: insideTenantA ?? null,
            outside: outside ?? null,
            insideSystem: insideSystem ?? null,
            runAsSystemValue: runAsSystemValue ?? null,
            afterRunAsSystem: afterRunAsSystem ?? null,
            scopedTenantA,
            scopedSystem,
            scopedAbsent,
            systemTenantId: als.SYSTEM_TENANT_ID,
            storageIsNativeAsyncLocalStorage: als.storageIsNativeAsyncLocalStorage,
          },
        },
      });
    },
  },
];

module.exports = {
  ROWS,
  runInAls,
  component,
  allMet,
  metById,
};