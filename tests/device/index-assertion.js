'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const scope = require('./scope-guard.cjs');

const EXIT = {
  PASS: 0,
  BLOCKED_PRECONDITION: 2,
  BLOCKED_INDEX: 3,
  HARNESS_FAIL: 4,
  PRODUCT_FAIL: 5,
};

const EXIT_STATUS = {
  [EXIT.PASS]: 'PASS',
  [EXIT.BLOCKED_PRECONDITION]: 'BLOCKED',
  [EXIT.BLOCKED_INDEX]: 'BLOCKED',
  [EXIT.HARNESS_FAIL]: 'HARNESS_FAIL',
  [EXIT.PRODUCT_FAIL]: 'PRODUCT_FAIL',
};

const X4_TENANT_ID = 'tenant-x4';
const TTL_DETECTOR_COLLECTION = 'x4_ttl_detector_probe';
const TTL_DETECTOR_SECONDS = 30;

const MANIFEST = [
  {
    collection: 'deviceauthorities',
    required: [
      { label: 'authority_device_key_unique', name: 'uq_dev_key', manifestRef: 'freeze-5', key: { deviceKeyId: 1, tenantId: 1 }, unique: true },
      {
        label: 'authority_owner_active_unique',
        name: 'uq_owner_active',
        manifestRef: 'freeze-5',
        key: { ownerId: 1, tenantId: 1 },
        unique: true,
        partialFilterExpression: { leaseState: 'active' },
      },
      {
        label: 'authority_tenant_grant_unique',
        name: 'uq_grant',
        manifestRef: 'freeze-5',
        key: { tenantId: 1, grantId: 1 },
        unique: true,
        partialFilterExpression: { grantId: { $type: 'string' } },
      },
      { label: 'authority_lease_scan', name: 'ix_lease_scan', manifestRef: 'freeze-5', key: { leaseState: 1, expiresAt: 1 }, unique: false },
    ],
    declared: [],
    forbiddenTtl: true,
  },
  {
    collection: 'pairingsessions',
    required: [
      {
        label: 'pairing_tag_live_unique',
        name: 'uq_tag_live',
        manifestRef: 'freeze-5',
        key: { tenantId: 1, lookupTag: 1 },
        unique: true,
        partialFilterExpression: { state: { $in: ['open', 'claim_pending'] } },
      },
      {
        label: 'pairing_one_live_session_unique',
        name: 'uq_session_dev_live',
        manifestRef: 'freeze-5',
        key: { deviceId: 1, tenantId: 1 },
        unique: true,
        partialFilterExpression: { state: { $in: ['open', 'claim_pending'] } },
      },
      { label: 'pairing_session_expiry_ttl', name: 'ttl_pairing_expiresAt', manifestRef: 'freeze-5', key: { expiresAt: 1 }, unique: false, expireAfterSeconds: 0 },
    ],
    declared: [
      { label: 'pairing_device_state_scan', name: 'ix_dev_state', manifestRef: 'freeze-2.2', key: { deviceId: 1, state: 1 }, unique: false },
      { label: 'pairing_pending_owner_scan', name: 'ix_pending_owner', manifestRef: 'freeze-2.2', key: { pendingOwnerId: 1, claimedAt: -1 }, unique: false },
    ],
    forbiddenTtl: false,
  },
  {
    collection: 'challenges',
    required: [
      { label: 'challenge_hash_unique', name: 'uq_challenge', manifestRef: 'freeze-5', key: { challengeHash: 1 }, unique: true },
      { label: 'challenge_expires_ttl', name: 'ttl_challenge_expiresAt', manifestRef: 'freeze-5', key: { expiresAt: 1 }, unique: false, expireAfterSeconds: 0 },
    ],
    declared: [],
    forbiddenTtl: false,
  },
  {
    collection: 'deviceauthorityevents',
    required: [],
    declared: [
      { label: 'audit_device_ts', name: 'ix_audit_device_ts', manifestRef: 'freeze-2.4', key: { tenantId: 1, deviceId: 1, ts: -1 }, unique: false },
      { label: 'audit_owner_ts', name: 'ix_audit_owner_ts', manifestRef: 'freeze-2.4', key: { tenantId: 1, ownerId: 1, ts: -1 }, unique: false },
    ],
    forbiddenTtl: false,
  },
];

function stamp() {
  const iso = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
  return `${iso}_${crypto.randomBytes(3).toString('hex')}`;
}

function keySignature(key) {
  return Object.keys(key)
    .map((field) => `${field}:${key[field]}`)
    .join('|');
}

function deepEqual(left, right) {
  if (left === right) {
    return true;
  }
  if (left === undefined || right === undefined || left === null || right === null) {
    return false;
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) {
      return false;
    }
    return left.every((value, index) => deepEqual(value, right[index]));
  }
  if (typeof left !== 'object' || typeof right !== 'object') {
    return false;
  }
  const leftKeys = Object.keys(left);
  const rightKeys = Object.keys(right);
  if (leftKeys.length !== rightKeys.length) {
    return false;
  }
  return leftKeys.every((field) => Object.prototype.hasOwnProperty.call(right, field) && deepEqual(left[field], right[field]));
}

function inspectIndex(listIndex) {
  const observed = { name: listIndex.name, key: listIndex.key, unique: listIndex.unique === true };
  if (listIndex.partialFilterExpression !== undefined) {
    observed.partialFilterExpression = listIndex.partialFilterExpression;
  }
  if (listIndex.expireAfterSeconds !== undefined) {
    observed.expireAfterSeconds = listIndex.expireAfterSeconds;
  }
  return observed;
}

function matchesSpec(observed, spec) {
  if (keySignature(observed.key) !== keySignature(spec.key)) {
    return false;
  }
  if (spec.unique === true && observed.unique !== true) {
    return false;
  }
  if (spec.unique === false && observed.unique === true) {
    return false;
  }
  if (!deepEqual(observed.partialFilterExpression, spec.partialFilterExpression)) {
    return false;
  }
  return deepEqual(observed.expireAfterSeconds, spec.expireAfterSeconds);
}

function expectedSpec(spec) {
  const expected = { key: spec.key, unique: spec.unique };
  if (spec.partialFilterExpression !== undefined) {
    expected.partialFilterExpression = spec.partialFilterExpression;
  }
  if (spec.expireAfterSeconds !== undefined) {
    expected.expireAfterSeconds = spec.expireAfterSeconds;
  }
  return expected;
}

function assertManifest(observedIndexes, missingCollections) {
  const missing = [];
  const mismatched = [];
  const forbidden = [];
  const warnings = [];

  for (const entry of MANIFEST) {
    const listed = observedIndexes[entry.collection];
    if (listed === undefined || listed === null) {
      missing.push({
        collection: entry.collection,
        reason: missingCollections.includes(entry.collection) ? 'namespace_not_found' : 'list_indexes_unavailable',
      });
      continue;
    }
    if (!listed.some((index) => index.name === '_id_')) {
      missing.push({ collection: entry.collection, name: '_id_', reason: 'implicit_id_index_absent' });
    }
    for (const spec of entry.required) {
      if (listed.some((index) => matchesSpec(index, spec))) {
        continue;
      }
      mismatched.push({
        collection: entry.collection,
        label: spec.label,
        manifestRef: spec.manifestRef,
        expected: expectedSpec(spec),
        observedSameKey: listed.filter((index) => keySignature(index.key) === keySignature(spec.key)),
      });
    }
    for (const spec of entry.declared) {
      if (!listed.some((index) => matchesSpec(index, spec))) {
        warnings.push({
          collection: entry.collection,
          label: spec.label,
          manifestRef: spec.manifestRef,
          note: 'declared in the frozen schema contract but not gated by the X4 manifest',
        });
      }
    }
    if (entry.forbiddenTtl) {
      for (const index of listed) {
        if (index.expireAfterSeconds !== undefined) {
          forbidden.push({ collection: entry.collection, name: index.name, expireAfterSeconds: index.expireAfterSeconds });
        }
      }
    }
  }
  return { missing, mismatched, forbidden, warnings };
}

async function captureDuplicate(operation) {
  try {
    await operation();
    return { duplicate: false };
  } catch (err) {
    return {
      duplicate: err !== null && err !== undefined && err.code === 11000,
      code: err === null || err === undefined ? null : err.code,
      keyPattern: err === null || err === undefined ? null : err.keyPattern,
      message: err === null || err === undefined ? null : err.message,
    };
  }
}

function authorityRow(id, overrides) {
  return {
    _id: id,
    tenantId: X4_TENANT_ID,
    deviceKeyId: `key-${id}`,
    devicePublicKey: 'x4-probe-public-key',
    identityState: 'pending',
    leaseState: 'never',
    epoch: 0,
    ownerId: null,
    grantId: null,
    ...overrides,
  };
}

async function behavioralProbes(db) {
  const probes = [];
  const failures = [];
  const authority = db.collection('deviceauthorities');
  const record = (id, passed, detail) => {
    probes.push({ id, status: passed ? 'PASS' : 'FAIL', detail });
    if (!passed) {
      failures.push({ id, detail });
    }
  };

  await authority.insertOne(authorityRow('x4-null-1'));
  await authority.insertOne(authorityRow('x4-null-2'));
  record('grant_partial_permits_two_null_grant_rows', true, { tenantId: X4_TENANT_ID, grantId: null });

  await authority.insertOne(authorityRow('x4-grant-a', { grantId: 'grant-dup-1' }));
  const grantDuplicate = await captureDuplicate(() => authority.insertOne(authorityRow('x4-grant-b', { grantId: 'grant-dup-1' })));
  const grantKeyOk = grantDuplicate.duplicate && keySignature(grantDuplicate.keyPattern ?? {}) === keySignature({ tenantId: 1, grantId: 1 });
  record('grant_partial_rejects_duplicate_non_null_grant', grantKeyOk, {
    code: grantDuplicate.code,
    keyPattern: grantDuplicate.keyPattern,
    expectedKeyPattern: { tenantId: 1, grantId: 1 },
  });

  await authority.insertOne(
    authorityRow('x4-owner-a', { grantId: 'grant-own-1', ownerId: 'owner-1', leaseState: 'active', identityState: 'active' }),
  );
  const ownerDuplicate = await captureDuplicate(() =>
    authority.insertOne(
      authorityRow('x4-owner-b', { grantId: 'grant-own-2', ownerId: 'owner-1', leaseState: 'active', identityState: 'active' }),
    ),
  );
  const ownerKeyOk = ownerDuplicate.duplicate && keySignature(ownerDuplicate.keyPattern ?? {}) === keySignature({ ownerId: 1, tenantId: 1 });
  record('owner_active_partial_rejects_second_live_owner_row', ownerKeyOk, {
    code: ownerDuplicate.code,
    keyPattern: ownerDuplicate.keyPattern,
    expectedKeyPattern: { ownerId: 1, tenantId: 1 },
  });

  await authority.insertOne(authorityRow('x4-owner-c', { grantId: 'grant-own-3', ownerId: 'owner-1', leaseState: 'never' }));
  const ownerUpdate = await captureDuplicate(() => authority.updateOne({ _id: 'x4-owner-c' }, { $set: { leaseState: 'active' } }));
  const ownerUpdateOk = ownerUpdate.duplicate && keySignature(ownerUpdate.keyPattern ?? {}) === keySignature({ ownerId: 1, tenantId: 1 });
  record('owner_active_partial_covers_updates', ownerUpdateOk, {
    code: ownerUpdate.code,
    keyPattern: ownerUpdate.keyPattern,
    expectedKeyPattern: { ownerId: 1, tenantId: 1 },
    note: 'non-active row coexisted, then failed on transition to active',
  });

  const detector = db.collection(TTL_DETECTOR_COLLECTION);
  await detector.createIndex({ ttlMarker: 1 }, { name: 'ttl_detector', expireAfterSeconds: TTL_DETECTOR_SECONDS });
  const detectorIndexes = (await detector.listIndexes().toArray()).map(inspectIndex);
  const detectorOk = detectorIndexes.some((index) => index.expireAfterSeconds === TTL_DETECTOR_SECONDS);
  record('ttl_detector_is_falsifiable', detectorOk, { collection: TTL_DETECTOR_COLLECTION, expireAfterSeconds: TTL_DETECTOR_SECONDS });

  return { probes, failures };
}

async function readObservedIndexes(db, collections) {
  const observedIndexes = {};
  const missingCollections = [];
  for (const collection of collections) {
    try {
      observedIndexes[collection] = (await db.collection(collection).listIndexes().toArray()).map(inspectIndex);
    } catch (err) {
      observedIndexes[collection] = null;
      missingCollections.push(collection);
      observedIndexes[`${collection}__error`] = { code: err.code ?? null, message: err.message };
    }
  }
  return { observedIndexes, missingCollections };
}

async function createRequiredIndexes(db) {
  const created = [];
  for (const entry of MANIFEST) {
    const collection = db.collection(entry.collection);
    const existing = await db.listCollections({ name: entry.collection }).toArray();
    if (existing.length === 0) {
      await db.createCollection(entry.collection);
    }
    for (const spec of [...entry.required, ...entry.declared]) {
      const options = { name: spec.name };
      if (spec.unique === true) {
        options.unique = true;
      }
      if (spec.partialFilterExpression !== undefined) {
        options.partialFilterExpression = spec.partialFilterExpression;
      }
      if (spec.expireAfterSeconds !== undefined) {
        options.expireAfterSeconds = spec.expireAfterSeconds;
      }
      await collection.createIndex(spec.key, options);
      created.push({ collection: entry.collection, name: spec.name, manifestRef: spec.manifestRef });
    }
  }
  return created;
}

function parseArgs(argv) {
  const options = { uri: scope.DEFAULT_URI, db: null, out: null, timeoutMs: 15000, keep: false, behavioral: true };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const [flag, inlineValue] = arg.includes('=') ? arg.split(/=(.*)/s, 2) : [arg, null];
    const value = inlineValue !== null ? inlineValue : argv[index + 1];
    const consumeNext = inlineValue === null;
    if (flag === '--uri') {
      options.uri = value;
      if (consumeNext) index += 1;
      continue;
    }
    if (flag === '--db') {
      options.db = value;
      if (consumeNext) index += 1;
      continue;
    }
    if (flag === '--out') {
      options.out = value;
      if (consumeNext) index += 1;
      continue;
    }
    if (flag === '--timeout-ms') {
      options.timeoutMs = Number(value);
      if (consumeNext) index += 1;
      continue;
    }
    if (flag === '--keep') {
      options.keep = true;
      continue;
    }
    if (flag === '--no-behavioral') {
      options.behavioral = false;
    }
  }
  return options;
}

function resolveOutPath(requested) {
  if (requested !== null) {
    return path.resolve(requested);
  }
  return path.join(scope.W2R_RUNTIME_ROOT, 'x4-runs', `x4-${stamp()}.json`);
}

function writeTranscript(outPath, report) {
  try {
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
    return { transcriptPath: outPath, transcriptStatus: 'written' };
  } catch (err) {
    return { transcriptPath: outPath, transcriptStatus: `write_failed: ${err.message}` };
  }
}

function emit(report, exitCode, outPath) {
  const finalReport = {
    ...report,
    exitCode,
    status: EXIT_STATUS[exitCode],
    finishedAt: new Date().toISOString(),
  };
  const transcript = writeTranscript(outPath, finalReport);
  process.stdout.write(`${JSON.stringify({ ...finalReport, ...transcript })}\n`);
  return exitCode;
}

async function runX4(argv) {
  const options = parseArgs(argv);
  const startedAt = new Date().toISOString();
  const dbName = options.db === null ? `cbhr_rdc_phase1_w2r_x4_${stamp()}` : options.db;
  const outPath = resolveOutPath(options.out);
  const base = {
    check: 'X4',
    lane: 'I8R',
    command: ['node', 'tests/device/index-assertion.js', ...argv],
    uri: options.uri,
    db: dbName,
    startedAt,
    assertion: { missing: [], mismatched: [], forbidden: [], warnings: [] },
    behavioral: { probes: [], failures: [] },
  };

  const preconditionProblems = [...scope.localUriProblems(options.uri), ...scope.isolatedDbNameProblems(dbName)];
  if (preconditionProblems.length > 0) {
    return emit({ ...base, stage: 'precondition', problems: preconditionProblems }, EXIT.BLOCKED_PRECONDITION, outPath);
  }

  let driver;
  try {
    driver = require('./driver.cjs');
  } catch (err) {
    return emit(
      { ...base, stage: 'driver', problems: [`BROKEN_PROBE: ${err.message}`] },
      EXIT.HARNESS_FAIL,
      outPath,
    );
  }
  base.driver = { version: driver.version, path: driver.driverPath, nodeVersion: process.version };

  let client = null;
  let cleanup = 'not_attempted';
  try {
    client = new driver.MongoClient(options.uri, {
      serverSelectionTimeoutMS: options.timeoutMs,
      connectTimeoutMS: options.timeoutMs,
      retryWrites: false,
      directConnection: true,
      appName: 'cbhr-phase1-w2r-x4',
    });
    await client.connect();

    const db = client.db(dbName);
    const admin = db.admin();
    const hello = await db.command({ hello: 1 });
    const build = await db.command({ buildInfo: 1 });
    let autoIndexCreation = 'UNVERIFIED_PARAM_ABSENT';
    try {
      const reply = await admin.command({ getParameter: 1, autoIndexCreation: 1 });
      autoIndexCreation = reply.autoIndexCreation ?? 'UNVERIFIED_PARAM_ABSENT';
    } catch {
      autoIndexCreation = 'UNVERIFIED_PARAM_ABSENT';
    }
    const databaseList = await admin.listDatabases({ nameOnly: true });
    const databaseNames = databaseList.databases.map((entry) => entry.name);
    const foreign = scope.foreignDatabaseNames(databaseNames, dbName);

    base.topology = {
      setName: hello.setName ?? null,
      isWritablePrimary: hello.isWritablePrimary === true,
      serverVersion: build.version,
      driverVersion: driver.version,
      nodeVersion: process.version,
      autoIndexCreation,
    };
    base.isolation = { databases: databaseNames, foreign };

    const topologyProblems = [];
    if (base.topology.setName !== scope.REQUIRED_REPLICA_SET) {
      topologyProblems.push(`replica set must be ${scope.REQUIRED_REPLICA_SET} (observed ${base.topology.setName})`);
    }
    if (base.topology.isWritablePrimary !== true) {
      topologyProblems.push('connected member is not writable primary');
    }
    if (base.topology.serverVersion !== scope.REQUIRED_SERVER_VERSION) {
      topologyProblems.push(`server version must be ${scope.REQUIRED_SERVER_VERSION} (observed ${base.topology.serverVersion})`);
    }
    if (foreign.length > 0) {
      topologyProblems.push(`foreign non-w2r databases present: ${foreign.join(', ')}`);
    }
    if (topologyProblems.length > 0) {
      cleanup = 'skipped_before_write';
      return emit({ ...base, stage: 'topology', problems: topologyProblems }, EXIT.BLOCKED_PRECONDITION, outPath);
    }

    base.createdIndexes = await createRequiredIndexes(db);

    const collections = MANIFEST.map((entry) => entry.collection);
    const { observedIndexes, missingCollections } = await readObservedIndexes(db, collections);
    base.observedIndexes = observedIndexes;
    base.assertion = assertManifest(observedIndexes, missingCollections);
    base.missingCollections = missingCollections;

    if (base.assertion.missing.length > 0 || base.assertion.mismatched.length > 0 || base.assertion.forbidden.length > 0) {
      cleanup = await dropOwnDatabase(db, dbName, options.keep);
      return emit({ ...base, stage: 'index-assertion' }, EXIT.BLOCKED_INDEX, outPath);
    }

    if (options.behavioral) {
      base.behavioral = await behavioralProbes(db);
      if (base.behavioral.failures.length > 0) {
        cleanup = await dropOwnDatabase(db, dbName, options.keep);
        return emit({ ...base, stage: 'behavioral' }, EXIT.PRODUCT_FAIL, outPath);
      }
    }

    cleanup = await dropOwnDatabase(db, dbName, options.keep);
    return emit({ ...base, stage: 'complete', cleanup }, EXIT.PASS, outPath);
  } catch (err) {
    return emit(
      { ...base, stage: 'harness', problems: [`${err.name}: ${err.message}`], cleanup },
      EXIT.HARNESS_FAIL,
      outPath,
    );
  } finally {
    if (client !== null) {
      await client.close().catch(() => {});
    }
  }
}

async function dropOwnDatabase(db, dbName, keep) {
  if (!scope.DB_NAME_PATTERN.test(dbName)) {
    return `DROP_REFUSED name_not_w2r ${dbName}`;
  }
  if (keep) {
    return `dropped false (--keep) ${dbName}`;
  }
  try {
    await db.dropDatabase();
    return `dropped ${dbName}`;
  } catch (err) {
    return `DROP_FAILED ${err.message}`;
  }
}

if (require.main === module) {
  runX4(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (err) => {
      process.stdout.write(`${JSON.stringify({ check: 'X4', status: 'HARNESS_FAIL', reason: err.message })}\n`);
      process.exitCode = EXIT.HARNESS_FAIL;
    },
  );
}

module.exports = {
  EXIT,
  MANIFEST,
  X4_TENANT_ID,
  runX4,
  parseArgs,
  matchesSpec,
  keySignature,
  deepEqual,
  inspectIndex,
  assertManifest,
};
