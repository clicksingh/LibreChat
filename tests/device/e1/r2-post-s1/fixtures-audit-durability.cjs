'use strict';

/**
 * R2-AUDIT-DURABILITY — hostile rows H-22..H-29 (audit epoch truth, after-commit uncertainty, durability).
 *
 * H-28 is the E2 two-process row and lives in `fixtures-e2.cjs`. Every E1 row here starts with the
 * genuine composition attempt against the raw registry and the real AuditEvent sink.
 */

const fs = require('node:fs');
const path = require('node:path');

const { runFixture, compositionBlocked } = require('./ctx.cjs');
const { STATUS } = require('./results.cjs');
const env = require('./env.cjs');

const AUTHORITY = 'authorityService.js';

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
      id: 'R2-H22-AUDIT-EPOCH-FROM-CAS',
      hostileRows: ['H-22'],
      tier: 'E1',
      group: 'R2-AUDIT-DURABILITY',
      expectedOracle: 'PASS iff the emitted grant audit epoch === g+1 taken from the committed CAS outcome, not from a competing revoke read',
      build: async (ctx) =>
        compositionBlocked(ctx, {
          pendingOracle: 'emitted grant audit event epoch === g+1 from the committed CAS post-image',
          extraActual: { scenario: 'commit a claim, then inject a competing revoke before the audit read', auditEmitSource: src(AUTHORITY, 320, 350) },
          components: [
            {
              name: 'audit_epoch_from_committed_cas',
              oracle: 'authority-transition audit epoch/seq come from the exact committed CAS preimage/post-image, never an unconstrained later read',
              actual: 'emitAuthorityAudit derives epoch/seq from the post-CAS `authority` object handed in by the caller (authorityService.js:320-334), i.e. an unconstrained later read',
              met: false,
              tier: 'E0',
            },
          ],
        }),
    },
    {
      id: 'R2-H23-SESSION-CONSUME-MISS-EPOCH',
      hostileRows: ['H-23'],
      tier: 'E1',
      group: 'R2-AUDIT-DURABILITY',
      expectedOracle: 'PASS iff a session-consume miss after a successful spend records refusal epoch === authority.epoch and grantId === authority.grantId',
      build: async (ctx) =>
        compositionBlocked(ctx, {
          pendingOracle: 'claim-refused after a successful spend carries the committed authority epoch and grantId',
          extraActual: { scenario: 'force the session-consume miss after a successful challenge spend' },
          components: absence(['consumeSessionClaim', 'session-consume-miss']),
        }),
    },
    {
      id: 'R2-H24-PRE-AUTHORITY-REFUSAL-NULLS',
      hostileRows: ['H-24'],
      tier: 'E1',
      group: 'R2-AUDIT-DURABILITY',
      expectedOracle: 'PASS iff a pre-redemption payload failure records refusal epoch === null and that is the only null case permitted for the kind',
      build: async (ctx) =>
        compositionBlocked(ctx, {
          pendingOracle: 'pre-authority refusal => refusal epoch null, and null is the only legitimate case for claim-refused',
          extraActual: { scenario: 'pre-redemption payload failure' },
          components: absence(['projectAuditEvent', 'AUDIT_EVENT_SHAPE_INVALID']),
        }),
    },
    {
      id: 'R2-H25-AFTER-COMMIT-AUDIT-FAILURE',
      hostileRows: ['H-25'],
      tier: 'E1',
      group: 'R2-AUDIT-DURABILITY',
      expectedOracle: "PASS iff a throwing sink after a committed CAS returns { ok:false, code:'AUDIT_DELIVERY_UNCERTAIN', matched:1 }, the authority row is durable at the new epoch, and audit rows are 0",
      build: async (ctx) =>
        compositionBlocked(ctx, {
          pendingOracle: "committed CAS + throwing sink => { ok:false, error.code:'AUDIT_DELIVERY_UNCERTAIN', matched:1 }, authority durable at g+1, 0 audit rows",
          extraActual: { scenario: 'throwing audit sink after a committed claim CAS' },
          components: [
            {
              name: 'audit_failure_does_not_roll_back_authority',
              oracle: 'authority write and audit write are separate; a failed audit never rolls back the authority row',
              actual: 'AUDIT_DELIVERY_UNCERTAIN is returned by emitAuthorityAudit with the CAS already committed (authorityService.js:335-350) — E0 source evidence; E1 behaviour still requires genuine composition',
              met: false,
              tier: 'E0',
            },
          ],
        }),
    },
    {
      id: 'R2-H26-CLAIM-GRANT-RETAINED',
      hostileRows: ['H-26'],
      tier: 'E1',
      group: 'R2-AUDIT-DURABILITY',
      expectedOracle: "PASS iff a throwing sink during the claim leaves authority.leaseState === 'active' with a non-null grantId",
      build: async (ctx) =>
        compositionBlocked(ctx, {
          pendingOracle: "throwing sink during claim => authority.leaseState 'active' and grantId non-null (the committed grant is not discarded)",
          extraActual: { scenario: 'throwing audit sink during the claim' },
          components: [
            {
              name: 'committed_grant_retained',
              oracle: "a throwing audit sink during the claim still returns the committed authority with leaseState 'active' and a non-null grantId",
              actual: 'not observable: no claim path can execute because factory composition fails first; the frozen oracle is preserved as pendingOracle',
              met: false,
              tier: 'E1',
            },
          ],
        }),
    },
    {
      id: 'R2-H27-NO-RECONCILER-INVENTION',
      hostileRows: ['H-27'],
      tier: 'E1',
      group: 'R2-AUDIT-DURABILITY',
      expectedOracle: 'PASS iff running a reconciler after a retire on a non-active row emits 0 extra events and collides with no preceding expire',
      build: async (ctx) => {
        const blocked = compositionBlocked(ctx, {
          pendingOracle: 'reconciler after retire on a non-active row => 0 supplementary events, no soft collision with the preceding expire',
          extraActual: { scenario: 'run the reconciler after a retire on a non-active row' },
          components: [],
        });
        blocked.components = absence(['reconciler', 'reconcileAudit', 'auditReconciler']);
        return blocked;
      },
    },
    {
      id: 'R2-H29-WRITE-CONCERN-PINNED',
      hostileRows: ['H-29'],
      tier: 'E1',
      group: 'R2-AUDIT-DURABILITY',
      expectedOracle: "PASS iff every instrumented write (three create sites + updateOne + audit insert) records options.writeConcern { w:'majority', j:true } and unpinned === 0",
      build: async (ctx) => {
        const scan = env.scanWriteConcernSites();
        const blocked = compositionBlocked(ctx, {
          pendingOracle: "every authority-critical write (authority CAS, Challenge create/spend, DeviceAuthority create, PairingSession create/update/consume, AuditEvent create) pins { w:'majority', j:true } at the actual write site: unpinned === 0",
          extraActual: {
            scenario: 'instrument all three create sites + updateOne + audit insert',
            staticWriteConcernScan: scan,
          },
        });
        blocked.components = Object.entries(scan).map(([file, info]) => ({
          name: `write_concern_pinned__${file}`,
          oracle: 'writeConcern { w:"majority", j:true } appears at the actual write sites of this product file',
          actual: `${info.occurrenceCount} writeConcern occurrence(s); pinned literal present: ${info.writeConcernPinnedConstant}; occurrences: ${JSON.stringify(info.sites)}`,
          met: false,
          tier: 'E0',
        }));
        blocked.components.push({
          name: 'e1_option_recording_available',
          oracle: 'the E1 recorder observes options.writeConcern for every write call',
          actual: 'not reachable: no service can be constructed from the raw registry, so no product write call can be recorded',
          met: false,
          tier: 'E1',
        });
        return blocked;
      },
    },
  ];
}

module.exports = { id: 'R2-AUDIT-DURABILITY', fixtures, STATUS };

async function main(record) {
  for (const def of fixtures()) {
    // eslint-disable-next-line no-await-in-loop
    record(await runFixture(def));
  }
}
module.exports.main = main;