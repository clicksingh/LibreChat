'use strict';

/**
 * W3-B R2 T2-F4 nine-row ledger and authorized-state table
 * (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Every authorized state below is transcribed VERBATIM from
 * `cbhr-rdc/docs/GOVERNOR-W3B-R2-T2-F4-TRUST-TEST-AUTHORIZATION-20261015.md`
 * ("Nine required rows"), in that document's order. The table is machine-checkable so PM can diff
 * actual vs expected: `authorizedStatus` is the frozen expected state and
 * `assertionIds` names the exact predicates the runner evaluates for that row.
 *
 * Truthfulness rules encoded as code:
 *   - the status vocabulary is exactly PASS_CURRENT / EXPECTED_RED / UNEXPECTED_GREEN /
 *     HARNESS_FAIL / ENV_BLOCKED;
 *   - EXPECTED_RED requires a non-null `actual` and `productMethodInvoked === true`;
 *   - a substrate/setup failure can only be HARNESS_FAIL, never a red finding;
 *   - an authorized PASS_CURRENT row whose assertions fail is HARNESS_FAIL, never a red finding.
 */

const fs = require('node:fs');
const path = require('node:path');

const STATUS = Object.freeze({
  PASS_CURRENT: 'PASS_CURRENT',
  EXPECTED_RED: 'EXPECTED_RED',
  UNEXPECTED_GREEN: 'UNEXPECTED_GREEN',
  HARNESS_FAIL: 'HARNESS_FAIL',
  ENV_BLOCKED: 'ENV_BLOCKED',
});

const ROW_KEYS = Object.freeze([
  'id',
  'order',
  'tier',
  'title',
  'status',
  'authorizedStatus',
  'matchesAuthorizedState',
  'productMethodInvoked',
  'expectedOracle',
  'assertionIds',
  'components',
  'actual',
  'dbName',
  'dbDropped',
  'dbReadBack',
  'sourceHashes',
]);

/** Authorized current states, T2-F4 authorization "Nine required rows". */
const AUTHORIZED_STATES = Object.freeze({
  'T2F4-01': STATUS.EXPECTED_RED,
  'T2F4-02': STATUS.EXPECTED_RED,
  'T2F4-03': STATUS.EXPECTED_RED,
  'T2F4-04': STATUS.EXPECTED_RED,
  'T2F4-05': STATUS.PASS_CURRENT,
  'T2F4-06': STATUS.EXPECTED_RED,
  'T2F4-07': STATUS.EXPECTED_RED,
  'T2F4-08': STATUS.EXPECTED_RED,
  'T2F4-09': STATUS.PASS_CURRENT,
});

const EXPECTED_ROWS = Object.freeze([
  Object.freeze({
    id: 'T2F4-01',
    order: 1,
    tier: 'E1',
    title: 'AUTHORITY_ALS_MISMATCH',
    authorizedStatus: STATUS.EXPECTED_RED,
    requiredBehavior:
      'real ALS tenant B with trusted args tenant A: a representative authority mutation returns TENANT_MISMATCH, zero authority/challenge model calls, and the authority row is unchanged',
    assertionIds: [
      'als-context-at-call-is-B',
      'error-code-is-TENANT_MISMATCH',
      'zero-DeviceAuthority-and-Challenge-model-calls',
      'authority-row-unchanged',
    ],
    expectedCurrentObservation:
      'RED: the current authorityService bytes consult no ALS/tenantContext; the claim CAS proceeds on the trusted args tenant and mutates the row',
  }),
  Object.freeze({
    id: 'T2F4-02',
    order: 2,
    tier: 'E1',
    title: 'AUTHORITY_SYSTEM_ALS',
    authorizedStatus: STATUS.EXPECTED_RED,
    requiredBehavior:
      'real ALS __SYSTEM__ with trusted tenant A: TENANT_MISMATCH and zero model calls',
    assertionIds: [
      'als-context-at-call-is-__SYSTEM__',
      'error-code-is-TENANT_MISMATCH',
      'zero-DeviceAuthority-and-Challenge-model-calls',
      'authority-row-unchanged',
    ],
    expectedCurrentObservation:
      'RED: no Phase-1 SYSTEM bypass removal exists in the current bytes; the claim CAS commits for tenant A under a SYSTEM ALS context',
  }),
  Object.freeze({
    id: 'T2F4-03',
    order: 3,
    tier: 'E1',
    title: 'AUTHORITY_ALS_ABSENT',
    authorizedStatus: STATUS.EXPECTED_RED,
    requiredBehavior:
      'no ALS and alsAbsencePermitted=false: TENANT_MISMATCH and zero model calls',
    assertionIds: [
      'als-context-at-call-is-undefined',
      'injected-alsAbsencePermitted-is-false',
      'error-code-is-TENANT_MISMATCH',
      'zero-DeviceAuthority-and-Challenge-model-calls',
      'authority-row-unchanged',
    ],
    expectedCurrentObservation:
      'RED: the current bytes treat a supplied trusted tenantId as sufficient and never consult tenantContext.alsAbsencePermitted',
  }),
  Object.freeze({
    id: 'T2F4-04',
    order: 4,
    tier: 'E1',
    title: 'PAIRING_ALS_MISMATCH',
    authorizedStatus: STATUS.EXPECTED_RED,
    requiredBehavior:
      'real ALS tenant B with trusted tenant A: the representative authenticated pairing path (issuePairingSession) is rejected before ANY DeviceAuthority/PairingSession model call',
    assertionIds: [
      'als-context-at-call-is-B',
      'error-code-is-TENANT_MISMATCH',
      'zero-DeviceAuthority-and-PairingSession-model-calls',
      'no-pairing-session-row-created',
    ],
    expectedCurrentObservation:
      'RED: issuePairingSession reads DeviceAuthority and creates a PairingSession row with no ALS/trusted-tenant gate',
  }),
  Object.freeze({
    id: 'T2F4-05',
    order: 5,
    tier: 'E1',
    title: 'REGISTRATION_ALS_ABSENT_APPROVED',
    authorizedStatus: STATUS.PASS_CURRENT,
    requiredBehavior:
      'no ALS, alsAbsencePermitted=true, tenantPolicy returns true: beginRegistration proceeds and persists a genuine challenge row',
    assertionIds: [
      'als-context-at-call-is-undefined',
      'injected-alsAbsencePermitted-is-true',
      'tenant-policy-consulted-with-trusted-tenant',
      'begin-registration-returns-ok-with-challenge-and-hash',
      'genuine-Challenge-row-persisted-in-fenced-db',
      'Challenge.create-invoked-on-genuine-model',
    ],
    expectedCurrentObservation:
      'PASS_CURRENT: registration is the ALS-absent path and the current policy-gated challenge insert already succeeds',
  }),
  Object.freeze({
    id: 'T2F4-06',
    order: 6,
    tier: 'E1',
    title: 'REGISTRATION_ALS_PRESENT_MISMATCH',
    authorizedStatus: STATUS.EXPECTED_RED,
    requiredBehavior:
      'active ALS tenant B with trusted tenant A and tenant policy true: TENANT_MISMATCH with zero Challenge model calls',
    assertionIds: [
      'als-context-at-call-is-B',
      'error-code-is-TENANT_MISMATCH',
      'zero-Challenge-model-calls',
    ],
    expectedCurrentObservation:
      'RED: beginRegistration ignores ALS entirely and inserts a challenge for the trusted args tenant',
  }),
  Object.freeze({
    id: 'T2F4-07',
    order: 7,
    tier: 'E1',
    title: 'REGISTRATION_ALS_ABSENT_NOT_PERMITTED',
    authorizedStatus: STATUS.EXPECTED_RED,
    requiredBehavior:
      'no ALS and alsAbsencePermitted=false even when tenantPolicy returns true: TENANT_MISMATCH with zero model calls',
    assertionIds: [
      'als-context-at-call-is-undefined',
      'injected-alsAbsencePermitted-is-false',
      'error-code-is-TENANT_MISMATCH',
      'zero-Challenge-model-calls',
    ],
    expectedCurrentObservation:
      'RED: tenantContext.alsAbsencePermitted is never consulted, so the ALS-absent registration path proceeds on policy alone',
  }),
  Object.freeze({
    id: 'T2F4-08',
    order: 8,
    tier: 'E1',
    title: 'SPEND_CHALLENGE_BOUND_TENANT_FALLBACK',
    authorizedStatus: STATUS.EXPECTED_RED,
    requiredBehavior:
      'top-level tenantId omitted while bound.tenantId is supplied: must be TENANT_MISMATCH before any Challenge read/update',
    assertionIds: [
      'top-level-tenantId-was-omitted-from-the-call-args',
      'bound-tenantId-was-supplied-as-the-only-tenant-source',
      'error-code-is-TENANT_MISMATCH',
      'zero-Challenge-model-calls',
      'challenge-row-unchanged',
    ],
    expectedCurrentObservation:
      'RED: spendChallenge falls back to bound.tenantId, so a nested caller container selects tenant authority and the challenge is consumed',
  }),
  Object.freeze({
    id: 'T2F4-09',
    order: 9,
    tier: 'E1',
    title: 'REAL_ALS_SYSTEM_CONTROL',
    authorizedStatus: STATUS.PASS_CURRENT,
    requiredBehavior:
      'the actual tenantContext.ts tenantStorage/getTenantId/SYSTEM_TENANT_ID prove tenant A, undefined and __SYSTEM__ contexts are distinguishable; the tenantIsolation plugin remains byte-unchanged and is not treated as the safety boundary',
    assertionIds: [
      'storage-is-native-AsyncLocalStorage-instance',
      'SYSTEM_TENANT_ID-is-frozen-sentinel',
      'three-contexts-pairwise-distinguishable',
      'frozen-module-bytes-match-authorized-preimages',
      'runAsSystem-yields-SYSTEM-and-restores-absence',
      'scopedCacheKey-behaviour-matches-frozen-bytes',
      'rows-used-the-frozen-module-singleton',
      'plugin-recorded-as-not-the-safety-boundary',
    ],
    expectedCurrentObservation:
      'PASS_CURRENT: real ALS + the frozen sentinel already distinguish all three contexts; the plugin is unchanged and is not the trust gate',
  }),
]);

/**
 * Row-09 tier disclosure (the authorization permits E1-or-E0 and demands the actual tier be stated).
 */
const TIER_NOTES = Object.freeze({
  'T2F4-01': 'E1: real product authorityService bytes + genuine Mongoose/Mongo with real ALS context',
  'T2F4-02': 'E1: real product authorityService bytes + genuine Mongoose/Mongo with real ALS context',
  'T2F4-03': 'E1: real product authorityService bytes + genuine Mongoose/Mongo with genuine ALS absence',
  'T2F4-04': 'E1: real product pairingSessionService/authorityService bytes + genuine Mongoose/Mongo',
  'T2F4-05': 'E1: real product registrationService bytes + genuine Mongoose/Mongo (positive control)',
  'T2F4-06': 'E1: real product registrationService bytes + genuine Mongoose/Mongo with real ALS context',
  'T2F4-07': 'E1: real product registrationService bytes + genuine Mongoose/Mongo with genuine ALS absence',
  'T2F4-08': 'E1: real product authorityService bytes + genuine Mongoose/Mongo Challenge CAS',
  'T2F4-09':
    'E1 (actual tier): the real frozen tenantContext.ts product bytes are executed through the pinned I10 bridge and real node AsyncLocalStorage semantics are observed; no DB. The plugin-byte invariance component is an E0-grade read-only digest check carried inside the same row.',
});

/** Derives a row status from its own observations; never hard-coded. */
function classifyRow({ authorizedStatus, predicateMet, executed, componentsMet }) {
  if (executed !== true) {
    return STATUS.HARNESS_FAIL;
  }
  if (authorizedStatus === STATUS.EXPECTED_RED) {
    return predicateMet === true ? STATUS.UNEXPECTED_GREEN : STATUS.EXPECTED_RED;
  }
  if (authorizedStatus === STATUS.PASS_CURRENT) {
    return componentsMet === true ? STATUS.PASS_CURRENT : STATUS.HARNESS_FAIL;
  }
  return STATUS.HARNESS_FAIL;
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeJson(file, value) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  return file;
}

function writeText(file, text) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, text, 'utf8');
  return file;
}

function makeRow({
  id,
  order,
  tier,
  title,
  status,
  expectedOracle,
  assertionIds = [],
  productMethodInvoked,
  actual,
  components = [],
  dbName = null,
  dbDropped = null,
  dbReadBack = null,
  sourceHashes,
}) {
  if (!Object.values(STATUS).includes(status)) {
    throw new Error(`row ${id}: unknown status ${status}`);
  }
  if ((status === STATUS.EXPECTED_RED || status === STATUS.UNEXPECTED_GREEN) && (actual === null || actual === undefined)) {
    throw new Error(`row ${id}: ${status} without an observed actual`);
  }
  if (status === STATUS.EXPECTED_RED && productMethodInvoked !== true) {
    throw new Error(`row ${id}: EXPECTED_RED without productMethodInvoked=true`);
  }
  const authorizedStatus = AUTHORIZED_STATES[id] ?? null;
  const row = {
    id,
    order,
    tier,
    title,
    status,
    authorizedStatus,
    matchesAuthorizedState: authorizedStatus !== null && authorizedStatus === status,
    productMethodInvoked: productMethodInvoked === true,
    expectedOracle: String(expectedOracle),
    assertionIds,
    components,
    actual,
    dbName,
    dbDropped,
    dbReadBack,
    sourceHashes,
  };
  const keys = Object.keys(row);
  if (keys.length !== ROW_KEYS.length || keys.some((key, index) => key !== ROW_KEYS[index])) {
    throw new Error(`row ${id}: key drift ${keys.join(',')}`);
  }
  return row;
}

function summarise(rows) {
  const byStatus = {};
  for (const row of rows) {
    byStatus[row.status] = (byStatus[row.status] ?? 0) + 1;
  }
  const unauthorized = rows.filter((row) => row.matchesAuthorizedState !== true).map((row) => row.id);
  const harnessFailureIds = rows.filter((row) => row.status === STATUS.HARNESS_FAIL).map((row) => row.id);
  const order = rows.map((row) => row.id);
  return {
    rows: rows.length,
    byStatus,
    harnessFailures: byStatus[STATUS.HARNESS_FAIL] ?? 0,
    harnessFailureIds,
    fixtureDefectRows: harnessFailureIds,
    unauthorizedStateRows: unauthorized,
    rowOrder: order,
    expectedOrder: EXPECTED_ROWS.map((row) => row.id),
    orderMatchesAuthorization: order.join(',') === EXPECTED_ROWS.map((row) => row.id).join(','),
    allRowsMatchAuthorizedState:
      rows.length === Object.keys(AUTHORIZED_STATES).length && unauthorized.length === 0,
  };
}

function rawError(err) {
  return {
    name: (err && err.name) || 'Error',
    code: (err && err.code) || null,
    message: (err && err.message) || String(err),
    stack: (err && err.stack) || null,
    problems: err && Array.isArray(err.problems) ? err.problems : null,
    clientCreated: err && typeof err.clientCreated === 'boolean' ? err.clientCreated : null,
  };
}

/** Writes every artifact into the runner-owned `run-<id>` evidence directory. */
class RunWriter {
  constructor({ runDir }) {
    this.runDir = ensureDir(runDir);
    this.artifacts = [];
    this.lines = [];
  }

  log(line) {
    this.lines.push(line);
    process.stdout.write(`${line}\n`);
  }

  writeArtifact(name, value) {
    const file = writeJson(path.join(this.runDir, name), value);
    this.artifacts.push({ file: path.basename(file), bytes: fs.statSync(file).size });
    return file;
  }

  writeLedger(ledger) {
    return this.writeArtifact('T2F4-LEDGER.json', ledger);
  }

  flushLog(name = 'T2F4-RUN-STDOUT.log') {
    return writeText(path.join(this.runDir, name), `${this.lines.join('\n')}\n`);
  }
}

module.exports = {
  STATUS,
  ROW_KEYS,
  AUTHORIZED_STATES,
  EXPECTED_ROWS,
  TIER_NOTES,
  classifyRow,
  ensureDir,
  writeJson,
  writeText,
  makeRow,
  summarise,
  rawError,
  RunWriter,
};