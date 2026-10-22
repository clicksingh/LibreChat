'use strict';

/**
 * I9 W2-B fixture harness (lane I9, PHASE1-LOCAL-AUTHORITY-001).
 *
 * This module is test scaffolding ONLY. It never claims product behaviour and it
 * never imports a product service. Product-service access is funnelled through
 * ./service-loader.cjs, which reports BLOCKED_PENDING_I6_I5 while the I6 authority
 * service and the I5 pairing service do not exist.
 *
 * Hard local-only rules enforced here:
 *   - the only Mongo host/port/replica-set is 127.0.0.1:27027 replicaSet=cbhrRdcP1
 *   - the only databases this lane may create/drop are cbhr_rdc_phase1_w2b_*
 *   - the vendored driver is resolved through ../driver.cjs (never a bare require)
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const driver = require('../driver.cjs');

const REQUIRED_HOST = '127.0.0.1';
const REQUIRED_PORT = '27027';
const REQUIRED_REPLICA_SET = 'cbhrRdcP1';
const REQUIRED_SERVER_VERSION = '7.0.43';
const PINNED_DRIVER_VERSION = '6.21.0';

const DEFAULT_URI =
  'mongodb://127.0.0.1:27027/?directConnection=true&replicaSet=cbhrRdcP1&serverSelectionTimeoutMS=15000&retryWrites=false';

const DB_PREFIX = 'cbhr_rdc_phase1_w2b_';
const DB_NAME_PATTERN = /^cbhr_rdc_phase1_w2b_[A-Za-z0-9_]+$/;
const DDL_PREFIX = 'cbhr_rdc_phase1_';
const SYSTEM_DATABASES = ['admin', 'local', 'config'];

/** Databases that pre-existed this lane and must never be created, written or dropped. */
const PROTECTED_DATABASES = [
  'cbhr_rdc_phase1_preflight_20261010',
  'cbhr_rdc_phase1_governor_nullgrant_probe_20261010',
];

const LEASE_TTL_MS = 172800000;
const SKEW_MARGIN_MS = 5000;
const CODE_TTL_MS = 300000;
const MAX_ATTEMPTS = 5;
const MAX_CODE_REGENERATIONS = 3;
const N_MIN = 50;

/** Frozen authority index set (engine-level control only; NOT a schema-driven proof). */
const AUTHORITY_INDEXES = [
  { key: { deviceKeyId: 1, tenantId: 1 }, options: { name: 'uq_dev_key', unique: true } },
  {
    key: { ownerId: 1, tenantId: 1 },
    options: { name: 'uq_owner_active', unique: true, partialFilterExpression: { leaseState: 'active' } },
  },
  {
    key: { tenantId: 1, grantId: 1 },
    options: { name: 'uq_grant', unique: true, partialFilterExpression: { grantId: { $type: 'string' } } },
  },
  { key: { leaseState: 1, expiresAt: 1 }, options: { name: 'ix_lease_scan' } },
];

const OWNER_ACTIVE_INDEX = AUTHORITY_INDEXES[1];

/** Fixed injected-clock base (no Date.now() anywhere in assertion bodies). */
const EPOCH_BASE_MS = 1791000000000;

function stamp() {
  const iso = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
  return `${iso}_${crypto.randomBytes(3).toString('hex')}`;
}

function sanitizeId(value) {
  return String(value).replace(/[^A-Za-z0-9_]/g, '_');
}

function makeDbName(fixtureId) {
  const id = sanitizeId(fixtureId);
  const suffix = stamp();
  const maxIdLength = 63 - DB_PREFIX.length - suffix.length - 1;
  if (id.length <= maxIdLength) {
    return `${DB_PREFIX}${id}_${suffix}`;
  }
  const hash = crypto.createHash('sha256').update(id).digest('hex').slice(0, 8);
  const room = Math.max(1, maxIdLength - hash.length - 1);
  return `${DB_PREFIX}${id.slice(0, room)}_${hash}_${suffix}`;
}

function dbNameProblems(name) {
  const problems = [];
  if (typeof name !== 'string' || name.length === 0) {
    return ['db name is required'];
  }
  if (!DB_NAME_PATTERN.test(name)) {
    problems.push(`db name must match ${DB_NAME_PATTERN} (prefix ${DB_PREFIX} required)`);
  }
  if (PROTECTED_DATABASES.includes(name)) {
    problems.push(`db name ${name} is a protected pre-existing database`);
  }
  return problems;
}

function uriProblems(uri) {
  const problems = [];
  if (typeof uri !== 'string' || uri.length === 0) {
    return ['uri is required'];
  }
  if (!uri.startsWith('mongodb://')) {
    return ['uri must start with mongodb://'];
  }
  const authority = uri.slice('mongodb://'.length).split('/')[0].split('?')[0];
  if (authority.includes('@')) {
    problems.push('credentials in the URI are forbidden');
  }
  if (authority.includes(',')) {
    problems.push('multi-host URIs are forbidden');
  }
  let parsed;
  try {
    parsed = new URL(uri);
  } catch {
    return ['uri is not parseable as a single-host mongodb:// URI'];
  }
  if (parsed.hostname !== REQUIRED_HOST) {
    problems.push(`host must be ${REQUIRED_HOST} (observed ${parsed.hostname})`);
  }
  const port = parsed.port === '' ? '27017' : parsed.port;
  if (port !== REQUIRED_PORT) {
    problems.push(`port must be ${REQUIRED_PORT} (observed ${port})`);
  }
  if (parsed.searchParams.get('replicaSet') !== REQUIRED_REPLICA_SET) {
    problems.push(`replicaSet must be ${REQUIRED_REPLICA_SET}`);
  }
  if (parsed.searchParams.get('directConnection') !== 'true') {
    problems.push('directConnection=true is required');
  }
  if (parsed.searchParams.get('tls') === 'true' || parsed.searchParams.get('ssl') === 'true') {
    problems.push('tls/ssl is forbidden for the local lab instance');
  }
  return problems;
}

function foreignDatabaseNames(names, ownDbName) {
  return names.filter(
    (name) => !SYSTEM_DATABASES.includes(name) && name !== ownDbName && !name.startsWith(DDL_PREFIX),
  );
}

/** A deterministic injected clock; never Date.now(), never a sleep. */
function makeClock(startMs) {
  let current = startMs;
  return {
    now: () => current,
    set: (value) => {
      current = value;
    },
    advance: (delta) => {
      current += delta;
    },
  };
}

function tmpRoot(tag) {
  const root = path.join(os.tmpdir(), 'cbhr-phase1-w2b', sanitizeId(tag));
  fs.mkdirSync(root, { recursive: true });
  return root;
}

function writeJsonFile(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function readJsonFile(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

async function connect({ uri = DEFAULT_URI, dbName, appName = 'cbhr-phase1-w2b-i9', timeoutMs = 15000 } = {}) {
  const precondition = [...uriProblems(uri), ...dbNameProblems(dbName)];
  if (precondition.length > 0) {
    const err = new Error(`BLOCKED_PRECONDITION: ${precondition.join('; ')}`);
    err.status = 'BLOCKED_PRECONDITION';
    err.problems = precondition;
    throw err;
  }
  const client = new driver.MongoClient(uri, {
    serverSelectionTimeoutMS: timeoutMs,
    connectTimeoutMS: timeoutMs,
    retryWrites: false,
    directConnection: true,
    appName,
  });
  try {
    await client.connect();
    const db = client.db(dbName);
    const admin = db.admin();
    const hello = await db.command({ hello: 1 });
    const build = await db.command({ buildInfo: 1 });
    const topology = {
      setName: hello.setName ?? null,
      isWritablePrimary: hello.isWritablePrimary === true,
      serverVersion: build.version,
      driverVersion: driver.version,
      nodeVersion: process.version,
      pid: process.pid,
    };
    const topologyProblems = [];
    if (topology.setName !== REQUIRED_REPLICA_SET) {
      topologyProblems.push(`replica set must be ${REQUIRED_REPLICA_SET} (observed ${topology.setName})`);
    }
    if (topology.isWritablePrimary !== true) {
      topologyProblems.push('connected member is not writable primary');
    }
    if (topology.serverVersion !== REQUIRED_SERVER_VERSION) {
      topologyProblems.push(`server version must be ${REQUIRED_SERVER_VERSION} (observed ${topology.serverVersion})`);
    }
    if (topology.driverVersion !== PINNED_DRIVER_VERSION) {
      topologyProblems.push(`driver must be ${PINNED_DRIVER_VERSION} (observed ${topology.driverVersion})`);
    }
    if (topologyProblems.length > 0) {
      const err = new Error(`BLOCKED_PRECONDITION: ${topologyProblems.join('; ')}`);
      err.status = 'BLOCKED_PRECONDITION';
      err.problems = topologyProblems;
      throw err;
    }
    const databaseList = await admin.listDatabases({ nameOnly: true });
    const databaseNames = databaseList.databases.map((entry) => entry.name);
    const foreign = foreignDatabaseNames(databaseNames, dbName);
    const isolation = { databases: databaseNames, foreign };
    return { client, db, topology, isolation };
  } catch (err) {
    await client.close().catch(() => {});
    throw err;
  }
}

async function assertDatabaseIsolation(dbName) {
  const { client, db, topology, isolation } = await connect({ dbName, appName: 'cbhr-phase1-w2b-isolation' });
  try {
    const protectedPresent = PROTECTED_DATABASES.filter((name) => isolation.databases.includes(name));
    return { topology, isolation, protectedPresent };
  } finally {
    await db.dropDatabase().catch(() => {});
    await client.close().catch(() => {});
  }
}

async function createAuthorityIndexes(db) {
  const created = [];
  await db.createCollection('deviceauthorities').catch(() => {});
  const collection = db.collection('deviceauthorities');
  for (const spec of AUTHORITY_INDEXES) {
    await collection.createIndex(spec.key, spec.options);
    created.push(spec.options.name);
  }
  return created;
}

async function dropOwnDatabase(db, dbName) {
  if (!DB_NAME_PATTERN.test(dbName)) {
    return `DROP_REFUSED name_not_w2b ${dbName}`;
  }
  try {
    await db.dropDatabase();
    return `dropped ${dbName}`;
  } catch (err) {
    return `DROP_FAILED ${err.message}`;
  }
}

function captureDuplicate(operation) {
  return operation().then(
    () => ({ duplicate: false }),
    (err) => ({
      duplicate: err !== null && err !== undefined && err.code === 11000,
      code: err === null || err === undefined ? null : err.code,
      keyPattern: err === null || err === undefined ? null : err.keyPattern,
    }),
  );
}

/** Two processes coordinate purely through files in tmpdir; no piped stdio. */
async function waitForFile(file, timeoutMs = 20000, intervalMs = 10) {
  const deadline = Date.now() + timeoutMs;
  while (!fs.existsSync(file)) {
    if (Date.now() > deadline) {
      throw new Error(`BARRIER_TIMEOUT waiting for ${file}`);
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

function emit(report) {
  process.stdout.write(`${JSON.stringify(report)}\n`);
  return report.exitCode ?? 0;
}

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const [flag, inlineValue] = arg.includes('=') ? arg.split(/=(.*)/s, 2) : [arg, null];
    const value = inlineValue !== null ? inlineValue : argv[index + 1];
    const consumeNext = inlineValue === null;
    if (!flag.startsWith('--')) {
      continue;
    }
    const key = flag.slice(2);
    options[key] = value === undefined ? true : value;
    if (consumeNext) {
      index += 1;
    }
  }
  return options;
}

function blocked(id, reason, detail = {}) {
  return { id, status: 'BLOCKED', reason, exitCode: 2, ...detail };
}

module.exports = {
  driver,
  DEFAULT_URI,
  DB_PREFIX,
  DB_NAME_PATTERN,
  DDL_PREFIX,
  SYSTEM_DATABASES,
  PROTECTED_DATABASES,
  REQUIRED_HOST,
  REQUIRED_PORT,
  REQUIRED_REPLICA_SET,
  REQUIRED_SERVER_VERSION,
  PINNED_DRIVER_VERSION,
  LEASE_TTL_MS,
  SKEW_MARGIN_MS,
  CODE_TTL_MS,
  MAX_ATTEMPTS,
  MAX_CODE_REGENERATIONS,
  N_MIN,
  AUTHORITY_INDEXES,
  OWNER_ACTIVE_INDEX,
  EPOCH_BASE_MS,
  stamp,
  sanitizeId,
  makeDbName,
  dbNameProblems,
  uriProblems,
  foreignDatabaseNames,
  makeClock,
  tmpRoot,
  writeJsonFile,
  readJsonFile,
  connect,
  assertDatabaseIsolation,
  createAuthorityIndexes,
  dropOwnDatabase,
  captureDuplicate,
  waitForFile,
  emit,
  parseArgs,
  blocked,
};
