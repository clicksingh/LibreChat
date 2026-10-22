'use strict';

/**
 * R2-TRUST-PAIRING — hostile rows H-11..H-21 (challenge single-use/freshness, ALS/tenant, principals).
 *
 * All rows are E1 and every one of them starts with the genuine composition attempt. Rows whose
 * first truthful failure is the frozen factory guard are EXPECTED_RED / FACTORY_COMPOSITION_FAIL
 * with the frozen oracle preserved as `pendingOracle`. E0 static components are labelled and never
 * promoted to a product claim.
 */

const fs = require('node:fs');
const path = require('node:path');

const { runFixture, compositionBlocked } = require('./ctx.cjs');
const { STATUS } = require('./results.cjs');
const env = require('./env.cjs');

const AUTHORITY = 'authorityService.js';
const PAIRING = 'pairingSessionService.js';
const REGISTRATION = 'registrationService.js';

function slice(absolute, from, to) {
  if (!fs.existsSync(absolute)) return null;
  return fs
    .readFileSync(absolute, 'utf8')
    .split('\n')
    .slice(from - 1, to)
    .map((line, index) => `${from + index}: ${line.trim()}`)
    .join('\n');
}

const src = (relative, from, to) => slice(path.join(env.DEVICE_DIR, relative), from, to);
const srcWorktree = (relative, from, to) => slice(path.join(env.WORKTREE, relative), from, to);

const ANCHORS = {
  spendChallenge: 'api/server/services/Device/authorityService.js:958-1000',
  retireImpl: 'api/server/services/Device/authorityService.js:882-950',
  retireAdminNull: 'api/server/services/Device/authorityService.js:937',
  guardAuthority: 'api/server/services/Device/authorityService.js:174-189',
  guardRegistration: 'api/server/services/Device/registrationService.js:166-189',
  guardPairing: 'api/server/services/Device/pairingSessionService.js:182-230',
  registrationTenantPolicy: 'api/server/services/Device/registrationService.js:264-300',
  tenantIsolationPlugin: 'packages/data-schemas/src/models/plugins/tenantIsolation.ts',
};

function absence(names) {
  const found = env.staticSurfaceAbsence(names);
  return names.map((name) => ({
    name,
    oracle: `${name} exists in the Device service bytes and the Phase-1 schema/model bytes`,
    actual: found[name].present
      ? `present in ${found[name].hits.join(', ')}`
      : 'absent from the Device service bytes and the Phase-1 schema/model bytes',
    met: found[name].present,
    tier: 'E0',
  }));
}

function fixtures() {
  return [
    {
      id: 'R2-H11-PAIRING-OPEN-REPLAY',
      hostileRows: ['H-11'],
      tier: 'E1',
      group: 'R2-TRUST-PAIRING',
      expectedOracle: 'PASS iff replaying an identical captured pairing-open proof is a strict no-op (uniform failure) and the PairingSession/code counts are unchanged',
      build: async (ctx) =>
        compositionBlocked(ctx, {
          pendingOracle: 'second identical pairing-open proof => strict no-op, zero new PairingSession rows, zero new codes',
          extraActual: { scenario: 'identical captured pairing-open proof submitted twice' },
          components: absence(['OPEN_CHALLENGE_TTL_MS', 'consumeSessionClaim']),
        }),
    },
    {
      id: 'R2-H12-SERVER-CHALLENGE-FRESHNESS',
      hostileRows: ['H-12'],
      tier: 'E1',
      group: 'R2-TRUST-PAIRING',
      expectedOracle: 'PASS iff a caller-signed issuedAt = server mint time + 60000 yields a uniform miss and zero Challenge.updateOne calls',
      build: async (ctx) =>
        compositionBlocked(ctx, {
          pendingOracle: 'caller-supplied issuedAt offset by +60000 from the server-minted challenge => uniform miss, Challenge.updateOne count 0',
          extraActual: { scenario: 'pairing-open challenge minted at t0, proof presented with signed issuedAt = t0+60000' },
          components: absence(['OPEN_CHALLENGE_TTL_MS', 'CLAIM_CHALLENGE_TTL_MS']),
        }),
    },
    {
      id: 'R2-H13-ALS-TENANT-MISMATCH',
      hostileRows: ['H-13'],
      tier: 'E1',
      group: 'R2-TRUST-PAIRING',
      expectedOracle: 'PASS iff ALS tenant B vs trusted authenticated tenant A yields TENANT_MISMATCH with an empty model recorder',
      build: async (ctx) =>
        compositionBlocked(ctx, {
          pendingOracle: 'validated tenant A vs active ALS tenant B => TENANT_MISMATCH, 0 model calls',
          extraActual: { scenario: 'active ALS tenant B while the adapter passes authenticated tenant A' },
          components: absence(['getActiveTenantId', 'alsAbsencePermitted', 'AsyncLocalStorage', 'getTenantId']),
        }),
    },
    {
      id: 'R2-H14-SYSTEM-TENANT-BYPASS',
      hostileRows: ['H-14'],
      tier: 'E1',
      group: 'R2-TRUST-PAIRING',
      expectedOracle: 'PASS iff a device CAS inside runAsSystem yields TENANT_MISMATCH (or requires an explicit, present system capability) with no silent tenant-conjunct skip',
      build: async (ctx) =>
        compositionBlocked(ctx, {
          pendingOracle: 'device CAS under runAsSystem => TENANT_MISMATCH unless an explicit system capability is present',
          extraActual: { scenario: 'device CAS executed inside runAsSystem', tenantIsolationPlugin: srcWorktree(ANCHORS.tenantIsolationPlugin, 1, 40) },
          components: absence(['SYSTEM_TENANT_ID', 'runAsSystem', 'skipTenantIsolation']),
        }),
    },
    {
      id: 'R2-H15-ALS-ABSENT-AUTHENTICATED',
      hostileRows: ['H-15'],
      tier: 'E1',
      group: 'R2-TRUST-PAIRING',
      expectedOracle: 'PASS iff ALS absent with alsAbsencePermitted:false on an authenticated claim yields TENANT_MISMATCH and 0 writes',
      build: async (ctx) =>
        compositionBlocked(ctx, {
          pendingOracle: 'ALS absent + alsAbsencePermitted:false + authenticated claim => TENANT_MISMATCH, writes 0',
          extraActual: { scenario: 'ALS absent, alsAbsencePermitted:false, authenticated claim' },
          components: absence(['alsAbsencePermitted', 'getActiveTenantId']),
        }),
    },
    {
      id: 'R2-H16-REGISTRATION-ALS-ABSENT',
      hostileRows: ['H-16'],
      tier: 'E1',
      group: 'R2-TRUST-PAIRING',
      expectedOracle: 'PASS iff unauthenticated registration with ALS absent + alsAbsencePermitted:true succeeds only for a policy-approved tenant and returns REGISTRATION_TENANT_NOT_PERMITTED otherwise',
      build: async (ctx) => {
        const constructed = env.scanConstructedErrorCodes().find((e) => e.code === 'REGISTRATION_TENANT_NOT_PERMITTED') ?? null;
        const blocked = compositionBlocked(ctx, {
          pendingOracle: 'policy-approved tenant => ok; non-approved tenant => REGISTRATION_TENANT_NOT_PERMITTED (403)',
          extraActual: { scenario: 'ALS absent, alsAbsencePermitted:true, unauthenticated registration', policySource: src(REGISTRATION, 264, 300), constructedSitesForCode: constructed },
          components: [
            {
              name: 'registration_tenant_policy_enforced',
              oracle: 'tenantPolicy.validateRegistrationTenant is evaluated before any model read/write and its refusal maps to REGISTRATION_TENANT_NOT_PERMITTED',
              actual: constructed === null ? 'REGISTRATION_TENANT_NOT_PERMITTED is never constructed by a product site' : `constructed at ${constructed.sites.join(', ')}`,
              met: false,
              tier: 'E0',
            },
            ...absence(['alsAbsencePermitted']),
          ],
        });
        return blocked;
      },
    },
    {
      id: 'R2-H17-BOUND-TENANT-NO-AUTHORITY',
      hostileRows: ['H-17'],
      tier: 'E1',
      group: 'R2-TRUST-PAIRING',
      expectedOracle: "PASS iff spendChallenge with empty args.tenantId and bound.tenantId:'B' yields TENANT_MISMATCH and zero Challenge.updateOne calls",
      build: async (ctx) =>
        compositionBlocked(ctx, {
          pendingOracle: "empty args.tenantId + bound.tenantId:'B' => TENANT_MISMATCH, Challenge.updateOne count 0",
          extraActual: {
            scenario: "spendChallenge({ tenantId: '', bound: { tenantId: 'B' } })",
            spendChallengeSource: src(AUTHORITY, 958, 1000),
          },
          components: [
            {
              name: 'no_nested_bound_tenant_fallback',
              oracle: 'tenantId comes only from trusted top-level server context; bound.tenantId confers nothing',
              actual: 'spendChallengeImpl still falls back to nested bound.tenantId when args.tenantId is empty (authorityService.js:959-963)',
              met: false,
              tier: 'E0',
            },
          ],
        }),
    },
    {
      id: 'R2-H18-CALLER-ROLE-REJECTED',
      hostileRows: ['H-18'],
      tier: 'E1',
      group: 'R2-TRUST-PAIRING',
      expectedOracle: "PASS iff retireIdentity({actor:'x', role:'admin'}) yields REQUEST_SUPPLIED_IDENTITY_REJECTED with 0 writes and no audit row",
      build: async (ctx) => {
        const constructed = env.scanConstructedErrorCodes().find((e) => e.code === 'REQUEST_SUPPLIED_IDENTITY_REJECTED') ?? null;
        return compositionBlocked(ctx, {
          pendingOracle: "caller-supplied role => REQUEST_SUPPLIED_IDENTITY_REJECTED (400), writes 0, audit rows 0",
          extraActual: {
            scenario: "retireIdentity({ actor: 'x', role: 'admin' })",
            retireImplSource: src(AUTHORITY, 882, 950),
            constructedSitesForCode: constructed,
          },
          components: [
            {
              name: 'caller_role_confers_no_authority',
              oracle: 'no caller-supplied role/ownerId/admin flag may schedule authority or audit truth',
              actual: 'retireIdentityImpl reads role from args and writes it verbatim into the audit reasonCode (authorityService.js:887,897,947)',
              met: false,
              tier: 'E0',
            },
          ],
        });
      },
    },
    {
      id: 'R2-H19-TRUSTED-ADMIN-RETIRE',
      hostileRows: ['H-19'],
      tier: 'E1',
      group: 'R2-TRUST-PAIRING',
      expectedOracle: 'PASS iff a server-resolved AdminPrincipal retires another user\'s device with exactly one write and a service-derived reasonCode',
      build: async (ctx) =>
        compositionBlocked(ctx, {
          pendingOracle: "trusted AdminPrincipal retires another owner's device: exactly 1 authority write, reasonCode derived server-side",
          extraActual: { scenario: "valid AdminPrincipal retires another user's device" },
          components: absence(['AdminPrincipal', 'adminPrincipal', 'trustedPrincipal']),
        }),
    },
    {
      id: 'R2-H20-OWNER-NOT-OWNER',
      hostileRows: ['H-20'],
      tier: 'E1',
      group: 'R2-TRUST-PAIRING',
      expectedOracle: 'PASS iff an owner principal retiring a device it does not own yields NOT_OWNER and 0 writes',
      build: async (ctx) =>
        compositionBlocked(ctx, {
          pendingOracle: 'owner-form retire of a non-owned device => NOT_OWNER (403), writes 0',
          extraActual: { scenario: 'owner principal retires a device it does not own' },
          components: [
            {
              name: 'owner_conjunct_present_in_source',
              oracle: 'the owner form binds filter.ownerId to the trusted principal',
              actual: 'retireIdentityImpl sets filter.ownerId = actor for the owner role (authorityService.js:902-904) — E0 source evidence only; E1 certification still requires genuine composition',
              met: true,
              tier: 'E0',
            },
          ],
          notes: 'E0 source evidence suggests this specific conjunct exists; the row still cannot be certified because the first truthful E1 step (factory composition) fails. No product claim is made.',
        }),
    },
    {
      id: 'R2-H21-ADMIN-ZERO-MATCH-EXPLICIT',
      hostileRows: ['H-21'],
      tier: 'E1',
      group: 'R2-TRUST-PAIRING',
      expectedOracle: 'PASS iff an admin 0-match on an already-retired row returns an explicit error code; never { ok:false, error:null }',
      build: async (ctx) =>
        compositionBlocked(ctx, {
          pendingOracle: 'admin 0-match on a retired row => explicit DeviceError code (never error:null)',
          extraActual: { scenario: 'admin 0-match on an already-retired row', retireImplSource: src(AUTHORITY, 916, 950) },
          components: [
            {
              name: 'no_silent_no_op',
              oracle: 'no silent no-op without a code',
              actual: 'retireIdentityImpl returns { ok:false, matched:0, authority, error:null } for a non-owner 0-match (authorityService.js:937)',
              met: false,
              tier: 'E0',
            },
          ],
        }),
    },
  ];
}

module.exports = { id: 'R2-TRUST-PAIRING', fixtures, STATUS };

async function main(record) {
  for (const def of fixtures()) {
    // eslint-disable-next-line no-await-in-loop
    record(await runFixture(def));
  }
}
module.exports.main = main;