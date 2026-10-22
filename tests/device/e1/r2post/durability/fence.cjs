'use strict';

/**
 * W3-B R2 S4T create-path durability Mongo fence (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Fail-closed rules, proven to run BEFORE any `MongoClient` is constructed:
 *   - the ONLY accepted connection string is the frozen lab URI at 127.0.0.1:27027
 *     `directConnection=true&replicaSet=cbhrRdcP1` (no credentials, no multi-host, no tls, no other
 *     port);
 *   - the ONLY accepted database names match `cbhr_rdc_phase1_r2_s4t_<unique>`;
 *   - EVERY other name is refused, including the accepted r2 T0/S1/S2/S2-T lanes, the immutable
 *     w0/w1/w2/w3/r1 lanes, the pre-existing preflight/governor databases, Mongo system databases and
 *     production-like names;
 *   - the run may only add/remove its own s4t databases.
 *
 * The gate is exposed as an explicit two-step connector so the ordering is observable evidence:
 * `assertPreConnect()` runs the whole fence, and only then may `construct()` build a client. Refusals
 * carry `clientCreated:false` and leave the construction counter untouched.
 *
 * Proven W3-A primitives (driver loading, frozen URI/version constants, topology checks) are reused by
 * import only; nothing under `w3a/**`, `r2/**`, `r2s2/**` or `r2post/audit2/**` is written.
 */

const path = require('node:path');

// eslint-disable-next-line global-require, import/no-dynamic-require
const w3aFence = require(path.resolve(__dirname, '..', '..', 'w3a', 'fence.cjs'));

const DB_PREFIX = 'cbhr_rdc_phase1_r2_s4t_';
const DB_NAME_PATTERN = /^cbhr_rdc_phase1_r2_s4t_[A-Za-z0-9_]+$/;

const FROZEN_URI =
  'mongodb://127.0.0.1:27027/?directConnection=true&replicaSet=cbhrRdcP1&serverSelectionTimeoutMS=5000&retryWrites=false';

const SYSTEM_DATABASES = ['admin', 'local', 'config'];

/** Databases that pre-date this lane and must be left byte-untouched. */
const PROTECTED_DATABASES = [
  'cbhr_rdc_phase1_preflight_20261010',
  'cbhr_rdc_phase1_governor_nullgrant_probe_20261010',
];

/** Explicit refusals beyond the generic "must be an s4t name" rule. */
const FORBIDDEN_NAME_PATTERNS = [
  { pattern: /^cbhr_rdc_phase1_preflight/i, reason: 'pre-existing preflight database' },
  { pattern: /^cbhr_rdc_phase1_governor/i, reason: 'pre-existing governor probe database' },
  { pattern: /^cbhr_rdc_phase1_r2_s2t/i, reason: 'accepted S2-T lane database' },
  { pattern: /^cbhr_rdc_phase1_r2_t0/i, reason: 'accepted post-S1 T0 lane database' },
  { pattern: /^cbhr_rdc_phase1_r2_(?!s4t)/i, reason: 'non-s4t r2 lane database' },
  { pattern: /^cbhr_rdc_phase1_r1/i, reason: 'immutable historical r1 lane database' },
  { pattern: /^cbhr_rdc_phase1_w3/i, reason: 'immutable historical w3 lane database' },
  { pattern: /^cbhr_rdc_phase1_w2/i, reason: 'immutable historical w2 lane database' },
  { pattern: /^cbhr_rdc_phase1_w1/i, reason: 'immutable historical w1 lane database' },
  { pattern: /^cbhr_rdc_phase1_w0/i, reason: 'immutable historical w0 lane database' },
  {
    pattern: /^(devices_prod|deviceauthorities|librechat|production|prod|test)$/i,
    reason: 'production-like name',
  },
];

const PRODUCTION_LIKE_NAMES = [
  'devices_prod',
  'deviceauthorities',
  'librechat',
  'production',
  'prod',
  'test',
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

class S4TFenceViolation extends Error {
  constructor(problems, detail) {
    super(`FENCE_VIOLATION: ${problems.join('; ')}`);
    this.name = 'S4TFenceViolation';
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
    throw new S4TFenceViolation(problems, { dbName: name, ...(detail ?? {}) });
  }
  return true;
}

function assertUri(uri, detail) {
  const problems = checkUri(uri);
  if (problems.length > 0) {
    throw new S4TFenceViolation(problems, { uri, ...(detail ?? {}) });
  }
  return true;
}

/** Builds a uniquely suffixed, self-owned s4t database name for one row. */
function createDbName(tag, crypto = require('node:crypto')) {
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
  return typeof name === 'string' && DB_NAME_PATTERN.test(name);
}

/**
 * The ordering proof: a connector whose fence step is total and whose client construction is counted.
 * `connectGuarded` may only reach `construct()` after `assertPreConnect()` has passed.
 */
function makeConnector({ uri = FROZEN_URI, clientFactory = null } = {}) {
  const state = { uri, clientConstructions: 0, fenceEvaluations: [], constructions: [] };
  return {
    state,
    assertPreConnect(dbName) {
      const problems = [...checkUri(uri), ...checkDbName(dbName)];
      state.fenceEvaluations.push({ dbName, problems, phase: 'pre-connect' });
      if (problems.length > 0) {
        throw new S4TFenceViolation(problems, {
          dbName,
          uri,
          phase: 'pre-connect',
          clientCreated: false,
        });
      }
      return true;
    },
    construct(dbName, clientOptions) {
      state.clientConstructions += 1;
      state.constructions.push({ dbName, at: 'post-fence' });
      if (typeof clientFactory === 'function') {
        return clientFactory(dbName, clientOptions);
      }
      const driver = w3aFence.loadDriver();
      return new driver.MongoClient(uri, clientOptions);
    },
  };
}

/** Opens a guarded connection; the fence runs to completion first. */
async function connectGuarded({
  dbName,
  uri = FROZEN_URI,
  appName = 'cbhr-phase1-r2-s4t',
  timeoutMs = 5000,
  connector = null,
}) {
  const active = connector ?? makeConnector({ uri });
  active.assertPreConnect(dbName);
  const driver = w3aFence.loadDriver();
  const client = active.construct(dbName, {
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
      dbName,
      uri,
    };
    const problems = [];
    if (topology.setName !== w3aFence.REQUIRED_REPLICA_SET) {
      problems.push(
        `replica set must be ${w3aFence.REQUIRED_REPLICA_SET} (observed ${topology.setName})`,
      );
    }
    if (topology.isWritablePrimary !== true) {
      problems.push('connected member is not the writable primary');
    }
    if (topology.serverVersion !== w3aFence.REQUIRED_SERVER_VERSION) {
      problems.push(
        `server version must be ${w3aFence.REQUIRED_SERVER_VERSION} (observed ${topology.serverVersion})`,
      );
    }
    if (db.databaseName !== dbName) {
      problems.push(`connected database ${db.databaseName} is not the fenced ${dbName}`);
    }
    if (problems.length > 0) {
      throw new S4TFenceViolation(problems, { phase: 'topology', topology, clientCreated: true });
    }
    return { client, db, topology, driver, connector: active };
  } catch (err) {
    if (connected || !(err instanceof S4TFenceViolation)) {
      await client.close().catch(() => {});
    }
    throw err;
  }
}

/**
 * Fence ordering probe: every hostile name must be refused with a zero client-construction delta.
 * Runs entirely before any real connection is needed.
 */
function probeFenceOrdering(names = defaultHostileNames()) {
  const results = [];
  for (const name of names) {
    const connector = makeConnector({});
    let refusal = null;
    let constructed = 0;
    try {
      connector.assertPreConnect(name);
    } catch (err) {
      refusal = {
        name: err.name,
        code: err.code,
        problems: err.problems,
        clientCreated: err.clientCreated,
      };
    }
    constructed = connector.state.clientConstructions;
    results.push({
      dbName: name,
      refused: refusal !== null,
      refusal,
      clientConstructions: constructed,
      refusedBeforeClientConstruction: refusal !== null && constructed === 0,
    });
  }
  return {
    gateOrder: 'assertPreConnect (total fence) -> construct (MongoClient)',
    probed: results.length,
    allRefusedBeforeClientConstruction: results.every((entry) => entry.refusedBeforeClientConstruction),
    results,
  };
}

function defaultHostileNames() {
  return [
    'cbhr_rdc_phase1_r2_s2t_s2t01_abcd1234_20261015120000',
    'cbhr_rdc_phase1_r2_t0_h30_composition_deadbeef_20261015120000',
    'cbhr_rdc_phase1_r2_post_s1_diag_abcdef',
    'cbhr_rdc_phase1_preflight_20261010',
    'cbhr_rdc_phase1_governor_nullgrant_probe_20261010',
    'cbhr_rdc_phase1_w3_e1_onepc_20261012_aaaaaa',
    'cbhr_rdc_phase1_w2c_i10_20261012_bbbbbb',
    'cbhr_rdc_phase1_r1_hostile_x',
    'cbhr_rdc_phase1_r2_s4t_',
    'cbhr_rdc_phase1_r2_s4t_bad-name',
    'devices_prod',
    'deviceauthorities',
    'librechat',
    'production',
    'admin',
    'local',
    'config',
    '',
  ];
}

/** Server-wide database inventory. Read-only: the inventory client writes nothing. */
async function listDatabaseNames({ uri = FROZEN_URI, connector = null } = {}) {
  const { client } = await connectGuarded({
    dbName: createDbName('inventory'),
    uri,
    appName: 'cbhr-phase1-r2-s4t-inventory',
    connector,
  });
  try {
    const rows = await client.db().admin().listDatabases({ nameOnly: true });
    return rows.databases.map((entry) => entry.name).sort();
  } finally {
    await client.close().catch(() => {});
  }
}

function sameSet(before, after) {
  return before.length === after.length && before.every((name, index) => name === after[index]);
}

/** Compares the server database set before/after against this lane's contract. */
function auditDatabaseSets(before, after) {
  const allowed = (name) => SYSTEM_DATABASES.includes(name) || PROTECTED_DATABASES.includes(name);
  const created = after.filter((name) => !before.includes(name));
  const removed = before.filter((name) => !after.includes(name));
  const foreignCreated = created.filter((name) => !isOwnedDb(name) && !allowed(name));
  const foreignRemoved = removed.filter((name) => !isOwnedDb(name) && !allowed(name));
  const leftovers = after.filter((name) => isOwnedDb(name));
  const identical = sameSet(before, after);
  return {
    before,
    after,
    created,
    removed,
    foreignCreated,
    foreignRemoved,
    leftovers,
    leftoverOwned: leftovers,
    identical,
    ok:
      identical &&
      foreignCreated.length === 0 &&
      foreignRemoved.length === 0 &&
      leftovers.length === 0,
  };
}

async function dropOwnDatabase(client, dbName) {
  if (!isOwnedDb(dbName)) {
    return {
      dropped: false,
      dbName,
      error: 'FENCE_VIOLATION: refusing to drop a non-s4t database',
    };
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
  PRODUCTION_LIKE_NAMES,
  REQUIRED_REPLICA_SET: w3aFence.REQUIRED_REPLICA_SET,
  REQUIRED_SERVER_VERSION: w3aFence.REQUIRED_SERVER_VERSION,
  PINNED_DRIVER_VERSION: w3aFence.PINNED_DRIVER_VERSION,
  S4TFenceViolation,
  loadDriver: w3aFence.loadDriver,
  checkDbName,
  checkUri,
  assertDbName,
  assertUri,
  createDbName,
  isOwnedDb,
  makeConnector,
  connectGuarded,
  probeFenceOrdering,
  defaultHostileNames,
  listDatabaseNames,
  auditDatabaseSets,
  dropOwnDatabase,
};

if (require.main === module) {
  const probe = probeFenceOrdering();
  process.stdout.write(
    `${JSON.stringify(
      {
        uri: FROZEN_URI,
        dbPrefix: DB_PREFIX,
        refusedBeforeClientConstruction: probe.allRefusedBeforeClientConstruction,
        results: probe.results.map((entry) => ({
          name: entry.dbName,
          verdict: entry.refused ? 'REFUSE' : 'ACCEPT',
          clientConstructions: entry.clientConstructions,
          problems: entry.refusal ? entry.refusal.problems : [],
        })),
      },
      null,
      2,
    )}\n`,
  );
  process.exitCode = probe.allRefusedBeforeClientConstruction ? 0 : 1;
}
