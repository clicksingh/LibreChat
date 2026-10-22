'use strict';

/**
 * Naive check-then-insert strategy (negative control).
 *
 * This is deliberately the pattern the account-axis partial unique index exists to
 * forbid: read "is this owner active anywhere in the tenant?", then insert a new active
 * authority row. It is NOT a product service and it must never be reported as product
 * evidence.
 *
 * The two processes coordinate through a file barrier so the TOCTOU window is
 * deterministic: each process completes its pre-read BEFORE either process writes.
 */

const fs = require('node:fs');
const path = require('node:path');

const harness = require('../e1/harness.cjs');

const id = 'naive-check-then-insert';
const requiresServices = false;
const productClaim = false;

function authorityRow({ deviceId, tenantId, ownerId, deviceKeyId, grantId, now }) {
  return {
    _id: deviceId,
    tenantId,
    deviceKeyId,
    devicePublicKey: `w2b-naive-public-key-${deviceId}`,
    deviceName: 'w2b-naive-control',
    identityState: 'active',
    leaseState: 'active',
    epoch: 1,
    ownerId,
    grantId,
    activatedAt: new Date(now),
    expiresAt: new Date(now + harness.LEASE_TTL_MS),
    renewalCount: 0,
  };
}

async function prepare({ db, fixture, options, seed }) {
  const mode = options.mode === 'with-index' ? 'with-index' : 'no-index';
  await db.createCollection('deviceauthorities').catch(() => {});
  let indexesCreated = [];
  if (mode === 'with-index') {
    indexesCreated = await harness.createAuthorityIndexes(db);
  }
  const tag = harness.stamp();
  return {
    mode,
    indexesCreated,
    seed: seed ?? tag,
    tenantId: seed ? seed.tenantId : 'tenant-w2b-naive',
    ownerId: seed ? seed.ownerId : 'owner-w2b-naive',
    now: harness.EPOCH_BASE_MS,
    fixture: fixture.id,
    shards: {
      A: {
        deviceId: `w2b-naive-A-${tag}`,
        deviceKeyId: `w2b-naive-key-A-${tag}`,
        grantId: `w2b-naive-grant-A-${tag}`,
      },
      B: {
        deviceId: `w2b-naive-B-${tag}`,
        deviceKeyId: `w2b-naive-key-B-${tag}`,
        grantId: `w2b-naive-grant-B-${tag}`,
      },
    },
  };
}

async function childRun({ db, shard, attempts, prepared, barrierDir, resultPath }) {
  const collection = db.collection('deviceauthorities');
  const peer = shard === 'A' ? 'B' : 'A';
  const ownSeed = prepared.shards[shard];

  const preRead = await collection.findOne({
    tenantId: prepared.tenantId,
    ownerId: prepared.ownerId,
    leaseState: 'active',
  });

  fs.writeFileSync(path.join(barrierDir, `${shard}.ready`), String(process.pid), 'utf8');
  await harness.waitForFile(path.join(barrierDir, `${peer}.ready`), 20000);

  const firstInsert = await harness.captureDuplicate(() =>
    collection.insertOne(
      authorityRow({
        deviceId: ownSeed.deviceId,
        tenantId: prepared.tenantId,
        ownerId: prepared.ownerId,
        deviceKeyId: ownSeed.deviceKeyId,
        grantId: ownSeed.grantId,
        now: prepared.now,
      }),
    ),
  );

  let extraSkipped = 0;
  let extraInserts = 0;
  for (let attempt = 1; attempt < attempts; attempt += 1) {
    const active = await collection.findOne({
      tenantId: prepared.tenantId,
      ownerId: prepared.ownerId,
      leaseState: 'active',
    });
    if (active !== null) {
      extraSkipped += 1;
      continue;
    }
    const extra = await harness.captureDuplicate(() =>
      collection.insertOne(
        authorityRow({
          deviceId: `${ownSeed.deviceId}-x${attempt}`,
          tenantId: prepared.tenantId,
          ownerId: prepared.ownerId,
          deviceKeyId: `${ownSeed.deviceKeyId}-x${attempt}`,
          grantId: `${ownSeed.grantId}-x${attempt}`,
          now: prepared.now,
        }),
      ),
    );
    if (extra.duplicate) {
      return {
        shard,
        pid: process.pid,
        attempts,
        preReadActive: preRead !== null,
        firstInsert,
        extraInserts,
        extraSkipped,
        unexpectedDuplicate: extra,
        status: 'HARNESS_FAIL',
        detail: 'an extra insert was rejected although no index should exist in this mode',
      };
    }
    extraInserts += 1;
  }

  await collection.updateOne(
    { _id: ownSeed.deviceId, tenantId: prepared.tenantId },
    { $set: { lastSeenAt: new Date(prepared.now) } },
  ).catch(() => {});

  const result = {
    shard,
    pid: process.pid,
    attempts,
    preReadActive: preRead !== null,
    firstInsert,
    extraInserts,
    extraSkipped,
    status: 'OK',
  };
  if (resultPath) {
    harness.writeJsonFile(resultPath, result);
  }
  return result;
}

async function assertAfterBurst({ db, prepared, childResults }) {
  const rowsActive = await db.collection('deviceauthorities').countDocuments({
    tenantId: prepared.tenantId,
    ownerId: prepared.ownerId,
    leaseState: 'active',
  });
  const pids = childResults.map((entry) => entry.pid);
  const distinctPids = new Set(pids).size;
  const duplicateKeyPatterns = childResults
    .map((entry) => entry.firstInsert)
    .filter((entry) => entry && entry.duplicate)
    .map((entry) => entry.keyPattern ?? null);
  const base = {
    rowsActive,
    distinctPids,
    pids,
    duplicateKeyPatterns,
    mode: prepared.mode,
    indexesCreated: prepared.indexesCreated,
  };

  if (prepared.mode === 'with-index') {
    const caught =
      rowsActive === 1 &&
      distinctPids === 2 &&
      duplicateKeyPatterns.length === 1 &&
      JSON.stringify(duplicateKeyPatterns[0]) === JSON.stringify({ ownerId: 1, tenantId: 1 });
    return {
      ...base,
      status: caught ? 'PASS' : 'HARNESS_FAIL',
      exitCode: caught ? 0 : 4,
      productInvariantViolated: rowsActive > 1,
      evidenceGrade: 'ENGINE_ONLY_NOT_SCHEMA_DRIVEN',
      note: 'uq_owner_active created by the raw driver; this proves index-engine semantics, not product schema declarations',
      detail: caught
        ? 'exactly one active owner row; naive second insert rejected E11000 on {ownerId:1,tenantId:1}'
        : 'control did not observe the expected single active row / E11000 keyPattern',
    };
  }

  const exposedRace = rowsActive === 2 && distinctPids === 2;
  return {
    ...base,
    status: exposedRace ? 'EXPECTED_FAIL' : 'HARNESS_FAIL',
    exitCode: exposedRace ? 0 : 4,
    productInvariantViolated: true,
    evidenceGrade: 'ENGINE_ONLY_NOT_SCHEMA_DRIVEN',
    detail: exposedRace
      ? 'naive check-then-insert produced 2 active owner rows for one tenant/account (product invariant R1 violated as designed)'
      : 'baseline did not expose the race; the fixture is not exercising the TOCTOU window',
  };
}

module.exports = { id, requiresServices, productClaim, prepare, childRun, assertAfterBurst };
