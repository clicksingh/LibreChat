'use strict';

/**
 * T1R audit Mongo fence (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Fail-closed rules, enforced BEFORE any MongoClient is constructed:
 *   - the ONLY accepted connection string is the frozen lab URI at 127.0.0.1:27027,
 *     replicaSet=cbhrRdcP1 (reused read-only from `tests/device/e1/w3a/fence.cjs`);
 *   - the ONLY accepted database names match `cbhr_rdc_phase1_r2_t1r_<unique>`;
 *   - every w3/w2/w1/w0/r1/r2-t0/r2s2/preflight/governor/production/system name is refused;
 *   - the run may only add/remove its own t1r databases.
 *
 * Nothing under `w3a/**` or `r2/**` is written; only the proven primitives are imported.
 */

const path = require('node:path');
const nodeCrypto = require('node:crypto');

// eslint-disable-next-line global-require, import/no-dynamic-require
const w3aFence = require(path.resolve(__dirname, '..', '..', 'w3a', 'fence.cjs'));

const DB_PREFIX = 'cbhr_rdc_phase1_r2_t1r_';
const DB_NAME_PATTERN = /^cbhr_rdc_phase1_r2_t1r_[A-Za-z0-9_]+$/;

const FROZEN_URI = w3aFence.FROZEN_URI;

const SYSTEM_DATABASES = ['admin', 'local', 'config'];

/** Databases that pre-date this lane and must be left byte-untouched. */
const PROTECTED_DATABASES = [
  'cbhr_rdc_phase1_preflight_20261010',
  'cbhr_rdc_phase1_governor_nullgrant_probe_20261010',
];

/** Explicit refusals beyond the generic "must be an r2/t1r name" rule. */
const FORBIDDEN_NAME_PATTERNS = [
  { pattern: /^cbhr_rdc_phase1_preflight/i, reason: 'pre-existing preflight database' },
  { pattern: /^cbhr_rdc_phase1_governor/i, reason: 'pre-existing governor probe database' },
  { pattern: /^cbhr_rdc_phase1_w3/i, reason: 'immutable historical w3 lane database' },
  { pattern: /^cbhr_rdc_phase1_w2/i, reason: 'immutable historical w2 lane database' },
  { pattern: /^cbhr_rdc_phase1_w1/i, reason: 'immutable historical w1 lane database' },
  { pattern: /^cbhr_rdc_phase1_w0/i, reason: 'immutable historical w0 lane database' },
  { pattern: /^cbhr_rdc_phase1_r1/i, reason: 'immutable historical r1 lane database' },
  { pattern: /^cbhr_rdc_phase1_r2_t0/i, reason: 'foreign r2/t0 lane database' },
  { pattern: /^cbhr_rdc_phase1_r2_s2/i, reason: 'foreign r2/s2 lane database' },
  { pattern: /^cbhr_rdc_phase1_r2_(post|a|s)/i, reason: 'foreign r2 lane database' },
  { pattern: /^(devices_prod|deviceauthorities|librechat|production|prod|test)$/i, reason: 'production-like name' },
];

function checkDbName(name) {
  const problems = [];
  if (typeof name !== 'string' || name.length === 0) {
    return ['database name is required'];
  }
  if (!DB_NAME_PATTERN.test(name)) {
    problems.push(`database name must match ${DB_NAME_PATTERN} (observed ${name})`);
  }
  if (name.length > 63) {
    problems.push('database name exceeds the 63-byte Mongo limit');
  }
  if (SYSTEM_DATABASES.includes(name)) {
    problems.push(`${name} is a Mongo system database`);
  }
  for (const entry of FORBIDDEN_NAME_PATTERNS) {
    if (entry.pattern.test(name)) {
      problems.push(`${name} is forbidden: ${entry.reason}`);
    }
  }
  return problems;
}

function checkUri(uri) {
  if (uri !== FROZEN_URI) {
    return [`uri must be exactly the frozen lab connection string (observed ${String(uri)})`];
  }
  return [];
}

class T1rFenceViolation extends Error {
  constructor(problems, detail) {
    super(`FENCE_VIOLATION: ${problems.join('; ')}`);
    this.name = 'T1rFenceViolation';
    this.code = 'FENCE_VIOLATION';
    this.status = 'BLOCKED_FENCE';
    this.problems = problems;
    /** Proof that the refusal happened before any client construction. */
    this.clientCreated = false;
    Object.assign(this, detail ?? {});
  }
}

function assertDbName(name, detail) {
  const problems = checkDbName(name);
  if (problems.length > 0) {
    throw new T1rFenceViolation(problems, { dbName: name, ...(detail ?? {}) });
  }
  return true;
}

function assertUri(uri, detail) {
  const problems = checkUri(uri);
  if (problems.length > 0) {
    throw new T1rFenceViolation(problems, { uri, ...(detail ?? {}) });
  }
  return true;
}

/** Builds a uniquely suffixed, self-owned r2/t1r database name. */
function createDbName(tag, crypto = nodeCrypto) {
  const id = String(tag).replace(/[^A-Za-z0-9_]/g, '_');
  const stamp = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
  const suffix = crypto.randomBytes(4).toString('hex');
  const budget = 63 - DB_PREFIX.length - suffix.length - 2;
  const trimmed =
    id.length <= budget
      ? id
      : `${id.slice(0, Math.max(1, budget - 9))}_${crypto.createHash('sha256').update(id).digest('hex').slice(0, 8)}`;
  return `${DB_PREFIX}${trimmed}_${suffix}_${stamp}`.slice(0, 63);
}

function isOwnedDb(name) {
  return (
    typeof name === 'string' &&
    DB_NAME_PATTERN.test(name) &&
    !FORBIDDEN_NAME_PATTERNS.some((e) => e.pattern.test(name))
  );
}

/**
 * Opens the guarded driver connection used for the namespace audit and every drop.
 * The fence runs first; an MongoClient is constructed only after the fence passes.
 */
async function connectGuarded({ dbName, uri = FROZEN_URI, appName = 'cbhr-phase1-r2-t1r-audit', timeoutMs = 5000 }) {
  assertUri(uri, { phase: 'pre-connect' });
  assertDbName(dbName, { phase: 'pre-connect' });
  const driver = w3aFence.loadDriver();
  const client = new driver.MongoClient(uri, {
    serverSelectionTimeoutMS: timeoutMs,
    connectTimeoutMS: timeoutMs,
    retryWrites: false,
    directConnection: true,
    appName: String(appName).slice(0, 60),
  });
  let connected = false;
  try {
    await client.connect();
    connected = true;
    const db = client.db(dbName);
    const hello = await db.command({ hello: 1 });
    const build = await db.command({ buildInfo: 1 });
    const topology = {
      setName: hello.setName ?? null,
      isWritablePrimary: hello.isWritablePrimary === true,
      serverVersion: build.version,
      driverVersion: driver.version,
      driverPath: driver.driverPath,
      nodeVersion: process.version,
      pid: process.pid,
    };
    const problems = [];
    if (topology.setName !== w3aFence.REQUIRED_REPLICA_SET) {
      problems.push(`replica set must be ${w3aFence.REQUIRED_REPLICA_SET} (observed ${topology.setName})`);
    }
    if (topology.isWritablePrimary !== true) {
      problems.push('connected member is not the writable primary');
    }
    if (topology.serverVersion !== w3aFence.REQUIRED_SERVER_VERSION) {
      problems.push(`server version must be ${w3aFence.REQUIRED_SERVER_VERSION} (observed ${topology.serverVersion})`);
    }
    if (db.databaseName !== dbName) {
      problems.push(`connected database ${db.databaseName} is not the fenced ${dbName}`);
    }
    if (problems.length > 0) {
      throw new T1rFenceViolation(problems, { phase: 'topology', topology, clientCreated: true });
    }
    return { client, topology, driver };
  } catch (err) {
    if (connected || !(err instanceof T1rFenceViolation)) {
      await client.close().catch(() => {});
    }
    throw err;
  }
}

/** Server-wide database inventory through an already-open (fenced) client. */
async function listDatabases(client) {
  const rows = await client.db().admin().listDatabases({ nameOnly: true });
  return rows.databases.map((entry) => entry.name).sort();
}

/** Compares the server database set before/after against this lane's contract. */
function auditDatabaseSets(before, after) {
  const allowed = (name) => SYSTEM_DATABASES.includes(name) || PROTECTED_DATABASES.includes(name);
  const created = after.filter((name) => !before.includes(name));
  const removed = before.filter((name) => !after.includes(name));
  const foreignCreated = created.filter((name) => !isOwnedDb(name) && !allowed(name));
  const foreignRemoved = removed.filter((name) => !isOwnedDb(name) && !allowed(name));
  const leftoverOwned = after.filter((name) => isOwnedDb(name));
  const protectedBefore = before.filter((name) => PROTECTED_DATABASES.includes(name));
  const protectedAfter = after.filter((name) => PROTECTED_DATABASES.includes(name));
  const protectedChanged = protectedBefore.length !== protectedAfter.length;
  return {
    before,
    after,
    created,
    removed,
    foreignCreated,
    foreignRemoved,
    leftoverOwned,
    protectedBefore,
    protectedAfter,
    protectedChanged,
    ok: foreignCreated.length === 0 && foreignRemoved.length === 0 && leftoverOwned.length === 0 && !protectedChanged,
  };
}

/** Drops a database only when the name is provably r2/t1r-owned. */
async function dropOwnDatabase(client, dbName) {
  if (!isOwnedDb(dbName)) {
    return { dropped: false, dbName, error: 'FENCE_VIOLATION: refusing to drop a non-r2/t1r database' };
  }
  try {
    await client.db(dbName).dropDatabase();
    return { dropped: true, dbName };
  } catch (err) {
    return { dropped: false, dbName, error: `${err.name}: ${err.message}` };
  }
}

module.exports = {
  FROZEN_URI,
  DB_PREFIX,
  DB_NAME_PATTERN,
  SYSTEM_DATABASES,
  PROTECTED_DATABASES,
  FORBIDDEN_NAME_PATTERNS,
  REQUIRED_REPLICA_SET: w3aFence.REQUIRED_REPLICA_SET,
  REQUIRED_SERVER_VERSION: w3aFence.REQUIRED_SERVER_VERSION,
  PINNED_DRIVER_VERSION: w3aFence.PINNED_DRIVER_VERSION,
  T1rFenceViolation,
  loadDriver: w3aFence.loadDriver,
  checkDbName,
  checkUri,
  assertDbName,
  assertUri,
  createDbName,
  isOwnedDb,
  connectGuarded,
  listDatabases,
  auditDatabaseSets,
  dropOwnDatabase,
};
