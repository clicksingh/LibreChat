'use strict';

/**
 * Shared execution context for the E1/E2 PRODUCT fixtures (lane I9 / task T1).
 *
 * Every product fixture in this directory drives the REAL product bytes:
 *   - api/server/services/Device/authorityService.js        (I6)
 *   - api/server/services/Device/registrationService.js     (I5)
 *   - api/server/services/Device/pairingSessionService.js   (I5)
 *   - api/server/services/Device/retireTrustAdapter.js      (trusted principal seam)
 * against the REAL frozen Mongoose models and a REAL MongoDB replica set at
 * 127.0.0.1:27027 (cbhrRdcP1), each fixture in its own self-owned
 * `cbhr_rdc_phase1_w3_*` database that is dropped in `finally`.
 *
 * There is NO stub, fake, fallback or in-memory substitute anywhere in this directory.
 * What the harness supplies are the frozen SEAMS the contract requires to be injected:
 *   - a deterministic clock (clock.now())
 *   - the trusted tenant context (tenantContext.getActiveTenantId())
 *   - the local-endpoint consent verdict (verifyLocalConsent)
 *   - the renewal-proof verifier (verifyRenewalProof)
 *   - the audit sink (audit)
 *   - the server-controlled tenant allowlist (tenantPolicy)
 * and the DEVICE side of each canonical signature (the device private key signs the exact
 * canonical bytes the product verifies). Every state-changing effect asserted by a fixture is
 * produced by a product call and re-read from MongoDB with the real model.
 */

const support = require('../w3a/support.cjs');
const env = require('../w3a/env.cjs');

const TENANT = env.TENANT;
const LEASE_TTL_MS = env.constants.LEASE_TTL_MS;
const SKEW_MARGIN_MS = env.constants.SKEW_MARGIN_MS;
const HOUR_MS = 3600000;

/**
 * Builds a product context.
 *
 * `mode: 'raw-registry'` means the I6/I5 factories receive the genuine
 * `createModels(mongoose)` registry with only a pass-through recording Proxy around it (no
 * behaviour, no adapter object), so `assertDependencies` sees the real model objects.
 */
async function makeProductContext({ tag, point = null, tenantId = TENANT, principalId = env.OWNER_A } = {}) {
  const ctx = await support.makeContext({
    tag,
    point,
    mode: 'raw-registry',
    tenantId,
    principalId,
  });
  return ctx;
}

/**
 * Registers a device through the REAL I5 registration ceremony and returns its identity.
 * This is a product write: beginRegistration -> completeRegistration.
 */
async function registerDevice(ctx, { deviceName, tag }) {
  const result = await support.registerDevice(ctx, {
    deviceName: deviceName ?? `e1-${tag ?? 'device'}`,
    key: env.makeDeviceKey(tag ?? deviceName ?? 'device'),
  });
  return result;
}

/** Seeds a claimable authority row (setup only; raw driver, majority+journal). */
async function seedClaimableDevice(ctx, tag, overrides = {}) {
  return support.seedDevice(ctx, tag, overrides);
}

/** Real I6 claim CAS. */
async function claim(ctx, { deviceId, ownerId, expectedEpoch, sessionId, grantProof = null, service }) {
  const svc = service ?? ctx.authorityService();
  return svc.claimAuthority({
    deviceId,
    tenantId: ctx.tenantId ?? TENANT,
    ownerId,
    expectedEpoch,
    sessionId,
    grantProof,
  });
}

/** Real I6 revoke CAS. */
async function revoke(ctx, { deviceId, ownerId, epoch, service }) {
  const svc = service ?? ctx.authorityService();
  return svc.revokeLease({ deviceId, tenantId: ctx.tenantId ?? TENANT, ownerId, epoch });
}

/** Real-model read-back of one authority row. */
async function readRow(ctx, deviceId) {
  return ctx.models.DeviceAuthority.findOne({ _id: deviceId, tenantId: ctx.tenantId ?? TENANT }).lean();
}

/** Real-model count of active rows for one owner in the fixture tenant. */
async function countActive(ctx, ownerId) {
  return ctx.models.DeviceAuthority.countDocuments({
    ownerId,
    tenantId: ctx.tenantId ?? TENANT,
    leaseState: 'active',
  });
}

/** Disclosed harness oracle over product-produced durable state (never a product call). */
function authorize(row, { ownerId, epoch, grantId, now }) {
  return support.authorizePredicate(row, { ownerId, epoch, grantId, now });
}

function view(row, now) {
  return support.authorityView(row, now);
}

/** True when the product surface exposes no background sweep at all. */
function productHasNoBackgroundSweep() {
  const names = [];
  for (const file of Object.values(env.PRODUCT_FILES)) {
    const source = require('node:fs').readFileSync(file, 'utf8');
    if (/\bsweep\w*\s*\(/.test(source) && !/CBHR_PHASE1_SWEEP/.test(source)) {
      names.push(file);
    }
  }
  return { exposesSweep: names.length > 0, files: names };
}

module.exports = {
  support,
  env,
  TENANT,
  LEASE_TTL_MS,
  SKEW_MARGIN_MS,
  HOUR_MS,
  makeProductContext,
  registerDevice,
  seedClaimableDevice,
  claim,
  revoke,
  readRow,
  countActive,
  authorize,
  view,
  productHasNoBackgroundSweep,
};
