'use strict';

/**
 * W3-A / I11 Mongo fence (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Fail-closed rules enforced here:
 *   - the ONLY accepted connection string is the frozen lab URI at 127.0.0.1:27027
 *     replicaSet=cbhrRdcP1 (no credentials, no multi-host, no tls, no other port);
 *   - the ONLY accepted database names match cbhr_rdc_phase1_w3_<suffix>;
 *   - every w2b/w2c/w2r/preflight/governor/production/system name is refused;
 *   - refusal happens BEFORE a MongoClient is constructed, and the thrown error records
 *     `clientCreated: false` so the control fixture can prove no connection was attempted;
 *   - the run may only add/remove its own w3 databases: any other change to the server's
 *     database set aborts the run.
 *
 * This module never writes outside tests/device/e1/** and never reconfigures Mongo.
 */

const path = require('node:path');

const REQUIRED_HOST = '127.0.0.1';
const REQUIRED_PORT = '27027';
const REQUIRED_REPLICA_SET = 'cbhrRdcP1';
const REQUIRED_SERVER_VERSION = '7.0.43';
const PINNED_DRIVER_VERSION = '6.21.0';

const FROZEN_URI =
  'mongodb://127.0.0.1:27027/?directConnection=true&replicaSet=cbhrRdcP1&serverSelectionTimeoutMS=5000&retryWrites=false';

const DB_PREFIX = 'cbhr_rdc_phase1_w3_';
const DB_NAME_PATTERN = /^cbhr_rdc_phase1_w3_[A-Za-z0-9_]+$/;

/** Names that must never be created, read for data, written or dropped by this lane. */
const FORBIDDEN_NAME_PATTERNS = [
  { pattern: /^cbhr_rdc_phase1_preflight/i, reason: 'pre-existing preflight database' },
  { pattern: /^cbhr_rdc_phase1_governor/i, reason: 'pre-existing governor probe database' },
  { pattern: /^cbhr_rdc_phase1_w2b/i, reason: 'historical w2b lane database' },
  { pattern: /^cbhr_rdc_phase1_w2c/i, reason: 'historical w2c lane database' },
  { pattern: /^cbhr_rdc_phase1_w2r/i, reason: 'historical w2r lane database' },
  { pattern: /^cbhr_rdc_phase1_w1/i, reason: 'historical w1 lane database' },
  { pattern: /^cbhr_rdc_phase1_w0/i, reason: 'historical w0 lane database' },
];

const SYSTEM_DATABASES = ['admin', 'local', 'config'];

/** Databases that already existed before this lane and must be left byte-untouched. */
const PROTECTED_DATABASES = [
  'cbhr_rdc_phase1_preflight_20261010',
  'cbhr_rdc_phase1_governor_nullgrant_probe_20261010',
];

/** Production-looking names: refused by the generic non-w3 rule, listed for evidence. */
const PRODUCTION_LIKE_NAMES = [
  'devices_prod',
  'deviceauthorities',
  'librechat',
  'production',
  'prod',
  'test',
];

const DRIVER_CANDIDATES = [
  path.resolve(__dirname, '..', '..', '_phase1_evidence', 'w2-runtime', 'node_modules'),
  path.resolve(__dirname, '..', '..', '_phase1_evidence', 'runtime', 'node_modules'),
];

const FORBIDDEN_JUNCTION = path.resolve(
  __dirname,
  '..',
  '..',
  '_phase1_evidence',
  'runtime',
  'node_modules',
  'LibreChat',
);

function loadDriver() {
  const fs = require('node:fs');
  for (const root of DRIVER_CANDIDATES) {
    const driverPath = path.join(root, 'mongodb');
    if (driverPath === FORBIDDEN_JUNCTION || driverPath.startsWith(`${FORBIDDEN_JUNCTION}${path.sep}`)) {
      continue;
    }
    const manifest = path.join(driverPath, 'package.json');
    if (!fs.existsSync(manifest)) {
      continue;
    }
    const version = JSON.parse(fs.readFileSync(manifest, 'utf8')).version;
    if (version !== PINNED_DRIVER_VERSION) {
      throw new Error(`DRIVER_VERSION_DRIFT: expected ${PINNED_DRIVER_VERSION}, observed ${version}`);
    }
    // eslint-disable-next-line global-require, import/no-dynamic-require
    return { MongoClient: require(driverPath).MongoClient, driverPath, version };
  }
  throw new Error(`BROKEN_PROBE: vendored mongodb@${PINNED_DRIVER_VERSION} absent`);
}

function checkDbName(name) {
  const problems = [];
  if (typeof name !== 'string' || name.length === 0) {
    return ['database name is required'];
  }
  if (!DB_NAME_PATTERN.test(name)) {
    problems.push(`database name must match ${DB_NAME_PATTERN}`);
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
  const problems = [];
  if (uri !== FROZEN_URI) {
    problems.push(`uri must be exactly the frozen lab connection string (observed ${String(uri)})`);
  }
  return problems;
}

class FenceViolation extends Error {
  constructor(problems, detail) {
    super(`FENCE_VIOLATION: ${problems.join('; ')}`);
    this.name = 'FenceViolation';
    this.code = 'FENCE_VIOLATION';
    this.status = 'BLOCKED_FENCE';
    this.problems = problems;
    this.clientCreated = false;
    Object.assign(this, detail ?? {});
  }
}

function assertDbName(name, detail) {
  const problems = checkDbName(name);
  if (problems.length > 0) {
    throw new FenceViolation(problems, { dbName: name, ...(detail ?? {}) });
  }
  return true;
}

function assertUri(uri, detail) {
  const problems = checkUri(uri);
  if (problems.length > 0) {
    throw new FenceViolation(problems, { uri, ...(detail ?? {}) });
  }
  return true;
}

/** Builds a uniquely-suffixed self-owned database name for one fixture. */
function createDbName(tag, crypto = require('node:crypto')) {
  const id = String(tag).replace(/[^A-Za-z0-9_]/g, '_');
  const stamp = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
  const suffix = crypto.randomBytes(4).toString('hex');
  const budget = 63 - DB_PREFIX.length - suffix.length - 2;
  const trimmed = id.length <= budget ? id : `${id.slice(0, budget - 9)}_${crypto.createHash('sha256').update(id).digest('hex').slice(0, 8)}`;
  return `${DB_PREFIX}${trimmed}_${suffix}_${stamp}`.slice(0, 63);
}

/** True when this database name belongs to the W3-A lane. */
function isOwnedDb(name) {
  return DB_NAME_PATTERN.test(name);
}

/**
 * Opens a guarded connection. The fence runs first; an MongoClient is constructed only
 * after the fence passes, and refusal errors carry `clientCreated: false`.
 */
async function connectGuarded({ dbName, uri = FROZEN_URI, appName = 'cbhr-phase1-w3a-i11', timeoutMs = 5000 }) {
  assertUri(uri, { phase: 'pre-connect' });
  assertDbName(dbName, { phase: 'pre-connect' });
  const driver = loadDriver();
  const client = new driver.MongoClient(uri, {
    serverSelectionTimeoutMS: timeoutMs,
    connectTimeoutMS: timeoutMs,
    retryWrites: false,
    directConnection: true,
    appName,
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
    const topologyProblems = [];
    if (topology.setName !== REQUIRED_REPLICA_SET) {
      topologyProblems.push(`replica set must be ${REQUIRED_REPLICA_SET} (observed ${topology.setName})`);
    }
    if (topology.isWritablePrimary !== true) {
      topologyProblems.push('connected member is not the writable primary');
    }
    if (topology.serverVersion !== REQUIRED_SERVER_VERSION) {
      topologyProblems.push(`server version must be ${REQUIRED_SERVER_VERSION} (observed ${topology.serverVersion})`);
    }
    if (db.databaseName !== dbName) {
      topologyProblems.push(`connected database ${db.databaseName} is not the fenced ${dbName}`);
    }
    if (topologyProblems.length > 0) {
      const err = new FenceViolation(topologyProblems, { phase: 'topology', topology, clientCreated: true });
      throw err;
    }
    return { client, db, topology, driver };
  } catch (err) {
    if (connected || !(err instanceof FenceViolation)) {
      await client.close().catch(() => {});
    }
    throw err;
  }
}

/** Server-wide database inventory; used before and after every run. */
async function listDatabaseNames({ uri = FROZEN_URI } = {}) {
  const { client } = await connectGuarded({ dbName: createDbName('inventory'), uri });
  try {
    const rows = await client.db().admin().listDatabases({ nameOnly: true });
    return rows.databases.map((entry) => entry.name).sort();
  } finally {
    await client.close().catch(() => {});
  }
}

/**
 * Compares the server database set before/after against the lane's contract.
 * `ok:false` must abort the run.
 */
function auditDatabaseSets(before, after) {
  const allowed = (name) => SYSTEM_DATABASES.includes(name) || PROTECTED_DATABASES.includes(name);
  const created = after.filter((name) => !before.includes(name));
  const removed = before.filter((name) => !after.includes(name));
  const foreignCreated = created.filter((name) => !isOwnedDb(name) && !allowed(name));
  const foreignRemoved = removed.filter((name) => !isOwnedDb(name) && !allowed(name));
  const leftoverOwned = after.filter((name) => isOwnedDb(name));
  return {
    before,
    after,
    created,
    removed,
    foreignCreated,
    foreignRemoved,
    leftoverOwned,
    ok: foreignCreated.length === 0 && foreignRemoved.length === 0 && leftoverOwned.length === 0,
  };
}

/** Drops a database only when the name is provably lane-owned. */
async function dropOwnDatabase(client, dbName) {
  assertDbName(dbName, { phase: 'drop' });
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
  PRODUCTION_LIKE_NAMES,
  FORBIDDEN_NAME_PATTERNS,
  REQUIRED_HOST,
  REQUIRED_PORT,
  REQUIRED_REPLICA_SET,
  REQUIRED_SERVER_VERSION,
  PINNED_DRIVER_VERSION,
  FenceViolation,
  loadDriver,
  checkDbName,
  checkUri,
  assertDbName,
  assertUri,
  createDbName,
  isOwnedDb,
  connectGuarded,
  listDatabaseNames,
  auditDatabaseSets,
  dropOwnDatabase,
};

if (require.main === module) {
  const names = [
    'cbhr_rdc_phase1_preflight_20261010',
    'cbhr_rdc_phase1_governor_nullgrant_probe_20261010',
    'cbhr_rdc_phase1_w2b_nc_naive_noindex_20261012_aaaaaa',
    'cbhr_rdc_phase1_w2c_i10_20261012_bbbbbb',
    'cbhr_rdc_phase1_w2r_x4_20261012',
    'devices_prod',
    'admin',
    'local',
    'config',
    'cbhr_rdc_phase1_w3_e1_onepc_00000000000000_deadbeef',
  ];
  process.stdout.write(
    `${JSON.stringify(
      {
        uri: FROZEN_URI,
        results: names.map((name) => ({ name, problems: checkDbName(name), verdict: checkDbName(name).length === 0 ? 'ACCEPT' : 'REFUSE' })),
      },
      null,
      2,
    )}\n`,
  );
}