'use strict';

/**
 * Product-service burst strategy for the I9 two-process harness.
 *
 * This strategy exists to drive the real I6 authority CAS across two OS processes.
 * While I6/I5 are absent its children return BLOCKED_PENDING_I6_I5, so the parent
 * reports BLOCKED and never PASS. No fallback implementation is installed here.
 */

const harness = require('./harness.cjs');
const serviceLoader = require('./service-loader.cjs');

const id = 'contract-product-service';
const requiresServices = true;
const productClaim = true;

function seedRows(fixtureId, preparedSeed) {
  return preparedSeed ?? {};
}

async function prepare({ db, fixture, options, seed }) {
  await db.createCollection('deviceauthorities').catch(() => {});
  const indexesCreated = await harness.createAuthorityIndexes(db);
  const tag = harness.stamp();
  const tenantId = (seed && seed.tenantId) || 'tenant-w2b-product';
  const now = harness.EPOCH_BASE_MS;

  const scenario = {
    tenantId,
    ownerA: 'owner-a-w2b-product',
    ownerB: 'owner-b-w2b-product',
    now,
    fixtureId: fixture.id,
    devices: {
      D1: `w2b-prod-D1-${tag}`,
      D2: `w2b-prod-D2-${tag}`,
    },
  };

  const rows = [];
  if (fixture.id === 'E2-T7-ONEPC-TWO-PC-RACE') {
    rows.push(
      {
        _id: scenario.devices.D1,
        tenantId,
        deviceKeyId: `w2b-prod-key-D1-${tag}`,
        devicePublicKey: `w2b-prod-pub-D1-${tag}`,
        identityState: 'pending',
        leaseState: 'never',
        epoch: 0,
        ownerId: null,
        grantId: null,
      },
      {
        _id: scenario.devices.D2,
        tenantId,
        deviceKeyId: `w2b-prod-key-D2-${tag}`,
        devicePublicKey: `w2b-prod-pub-D2-${tag}`,
        identityState: 'pending',
        leaseState: 'never',
        epoch: 0,
        ownerId: null,
        grantId: null,
      },
    );
  } else if (fixture.id === 'E2-T8-TWO-OWNERS-ONE-PC-RACE') {
    rows.push({
      _id: scenario.devices.D1,
      tenantId,
      deviceKeyId: `w2b-prod-key-D1-${tag}`,
      devicePublicKey: `w2b-prod-pub-D1-${tag}`,
      identityState: 'pending',
      leaseState: 'never',
      epoch: 0,
      ownerId: null,
      grantId: null,
    });
  } else if (fixture.id === 'E2-V24T15-REVOKE-VS-CLAIM-RACE') {
    rows.push({
      _id: scenario.devices.D1,
      tenantId,
      deviceKeyId: `w2b-prod-key-D1-${tag}`,
      devicePublicKey: `w2b-prod-pub-D1-${tag}`,
      identityState: 'active',
      leaseState: 'active',
      epoch: 1,
      ownerId: scenario.ownerA,
      grantId: `w2b-prod-grant-A-${tag}`,
      activatedAt: new Date(now),
      expiresAt: new Date(now + harness.LEASE_TTL_MS),
      renewalCount: 0,
    });
  }
  if (rows.length > 0) {
    await db.collection('deviceauthorities').insertMany(rows);
  }
  return { ...scenario, indexesCreated, seedApplied: rows.length, seedRows: seedRows(fixture.id, seed) };
}

async function childRun({ prepared, shard, attempts }) {
  const probe = serviceLoader.probe();
  if (probe.status !== 'AVAILABLE') {
    return {
      shard,
      pid: process.pid,
      attempts,
      status: 'BLOCKED_PENDING_I6_I5',
      serviceProbe: { status: probe.status, missing: probe.missing, shapeProblems: probe.shapeProblems },
      productClaim: false,
      note: 'no product CAS executed; I6/I5 absent',
    };
  }
  return {
    shard,
    pid: process.pid,
    attempts,
    status: 'BLOCKED_PENDING_I6_I5',
    serviceProbe: { status: 'AVAILABLE', missing: [], shapeProblems: [] },
    productClaim: false,
    note: 'I6/I5 exist but fixture execution wiring is deferred to the authorized post-I4/I6/I5 integration test round',
  };
}

async function assertAfterBurst({ childResults }) {
  const blocked = childResults.some((entry) => entry.status === 'BLOCKED_PENDING_I6_I5');
  return {
    status: blocked ? 'BLOCKED_PENDING_I6_I5' : 'BLOCKED_NOT_WIRED',
    exitCode: 2,
    productClaim: false,
    reason: 'product CAS burst requires I6/I5; blocked rather than fabricated',
  };
}

module.exports = { id, requiresServices, productClaim, prepare, childRun, assertAfterBurst };
