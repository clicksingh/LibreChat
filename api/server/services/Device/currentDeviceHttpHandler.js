'use strict';

/**
 * Current-device HTTP handlers (`GET /api/devices/current`, `POST /api/devices/current/renew`).
 *
 * OWNER-AUTHORIZED SCOPE (2026-10-22, owner outranks Governor; LOCAL LAB ONLY and requiring
 * Governor ratification later; production G0 remains BLOCKED).
 *
 * TRUST MODEL (identical in shape to `ownerCurrentRetireHandler.js`)
 * - `requireJwtAuth` runs before every handler (wired in `routes/devices.js`).
 * - Both endpoints accept NO request input at all: any route params, query value or body field is
 *   rejected with 400 `REQUEST_SUPPLIED_IDENTITY_REJECTED` before any model method is touched.
 * - The current device is resolved by `currentOwnerDeviceResolver` from the authenticated session
 *   plus the trusted ALS tenant only: the query is the exact trusted tuple
 *   `{tenantId, ownerId:<authenticated id>, identityState:{$in:['active','paired']},
 *   leaseState:'active'}`. A client-supplied `deviceId` is never read and there is no arbitrary
 *   deviceId fallback; historical/revoked/expired identities still require a future opaque handle.
 * - The status projection re-reads the SAME server-resolved device id through the accepted
 *   authority service and echoes only `tenantId`, `deviceId`, `identityState`, `leaseState`,
 *   `epoch` and `expiresAt`. No public key, lookupTag, grantId, grantProof, `prev*` lineage or
 *   `_id` other than the caller's own device id is ever serialized.
 *
 * RESPONSE CONTRACT
 * - `GET /current` 200 `{ ok:true, tenantId, deviceId, identityState, leaseState, epoch, expiresAt }`
 *   404 `UNKNOWN_DEVICE` when the authenticated principal holds no current active device.
 * - `POST /current/renew` 200 `{ ok:true, renewed:true, deviceId, epoch, expiresAt, renewalCount }`
 *   The renewal CAS is the accepted `authorityService.renewAuthority`; the frozen 48h/5s-margin law
 *   lives in that CAS filter (`expiresAt: { $gt: now + SKEW_MARGIN_MS }`), so a renewal inside the
 *   5000 ms margin or after expiry is a truthful miss (409 `LEASE_EXPIRED`) and is NEVER
 *   re-implemented or loosened here.
 *   500 `AUDIT_DELIVERY_UNCERTAIN` with `committed:true` when the CAS matched exactly one row but
 *   the authority audit was not delivered: the renewal is real and must not be reported as a no-op.
 *   Any other miss keeps its classified code/status with `committed:false`.
 *
 * RENEWAL AUTHORIZATION — DISCLOSED LOCAL-LAB LIMITATION
 * `authorityService` requires an injected `verifyRenewalProof` seam and there is NO device-side
 * renewal envelope in this repository (the PHASE0 `CBHR-RENEW-V1` envelope exists only as an
 * unratified proposal). This layer therefore injects a server-owned
 * `createSessionRenewalAuthorization` verifier that authorizes a MANUAL renewal from the
 * authenticated session and binds the SERVER-OBSERVED row truth
 * `{tenantId, ownerPrincipalId, deviceId, grantId, epoch}` — the same session-derived authority
 * model the accepted retire route already uses. It accepts and reads no client proof. It MUST be
 * replaced by the ratified device-proof verifier before any non-lab use; the timing law and every
 * CAS conjunct continue to be enforced by the accepted authority service.
 */

const deviceCrypto = require('./crypto');
const { createAuthorityService } = require('./authorityService');
const { createCurrentOwnerDeviceResolver } = require('./currentOwnerDeviceResolver');
const { DeviceError } = require('./errors');
const {
  assertHttpHandlerDependencies,
  createAuditAccessor,
  guardRequestInput,
  isNonEmptyString,
  resolveTrustedContext,
  sendClassifiedError,
  sendFailClosed,
  toIsoOrNull,
  toObservedEpoch,
} = require('./deviceHttpTrust');

/** Server-owned descriptor for the manual-renewal authorization source (never a client value). */
const RENEWAL_AUTHORIZATION_SOURCE = Object.freeze({ source: 'authenticated-session' });

/** Neither endpoint of this module accepts a single request field. */
const NO_BODY_FIELDS = Object.freeze([]);

/**
 * Server-owned manual-renewal authorization.
 *
 * `verify` is the injected `verifyRenewalProof` seam: it fails closed until `observe` has bound the
 * server-observed row truth immediately before the CAS. The binding deliberately names exactly the
 * fields `authorityService.checkRenewalBinding` cross-checks (`tenantId`, `ownerPrincipalId`,
 * `deviceId`, `grantId`, `epoch`); no binding field can originate in the request.
 */
function createSessionRenewalAuthorization({ tenantId, ownerId, deviceId } = {}) {
  const state = { binding: null };

  async function verify() {
    if (state.binding === null) {
      return { ok: false, binding: null };
    }
    return { ok: true, binding: state.binding };
  }

  function observe({ grantId, epoch } = {}) {
    if (!isNonEmptyString(tenantId) || !isNonEmptyString(ownerId) || !isNonEmptyString(deviceId)) {
      state.binding = null;
      return null;
    }
    state.binding = Object.freeze({
      tenantId,
      ownerPrincipalId: ownerId,
      deviceId,
      grantId: grantId ?? null,
      epoch: epoch ?? null,
    });
    return state.binding;
  }

  return { verify, observe };
}

/** Server-resolved current device row, re-read through the accepted authority service. */
async function readCurrentOwnedRow({ authorityService, resolved }) {
  const row = await authorityService.readAuthority({
    deviceId: resolved.deviceId,
    tenantId: resolved.tenantId,
  });
  const deviceId = row?._id?.toString?.();
  if (
    row === null ||
    row === undefined ||
    row.tenantId !== resolved.tenantId ||
    row.ownerId !== resolved.principalId ||
    deviceId !== resolved.deviceId
  ) {
    return null;
  }
  return row;
}

/** Safe status projection: no key material, no lookupTag, no grantId, no lineage fields. */
function statusBody(row, resolved) {
  return {
    ok: true,
    tenantId: resolved.tenantId,
    deviceId: resolved.deviceId,
    identityState: isNonEmptyString(row.identityState) ? row.identityState : null,
    leaseState: isNonEmptyString(row.leaseState) ? row.leaseState : null,
    epoch: toObservedEpoch(row.epoch),
    expiresAt: toIsoOrNull(row.expiresAt),
  };
}

/**
 * `GET /api/devices/current` — read-only status of the authenticated user's own current device.
 */
function createCurrentDeviceStatusHandler(deps = {}) {
  const {
    db,
    tenantContext,
    clock = { now: () => Date.now() },
    crypto = deviceCrypto,
    logger = null,
    audit,
  } = deps;
  assertHttpHandlerDependencies({ db, tenantContext, label: 'current device status handler' });

  const resolver = createCurrentOwnerDeviceResolver({ db, tenantContext });
  const auditFn = createAuditAccessor({ db, logger, audit });

  return async function currentDeviceStatusHandler(req, res) {
    try {
      if (
        guardRequestInput(req, res, {
          endpoint: 'Current device status',
          allowedBodyFields: NO_BODY_FIELDS,
        })
      ) {
        return;
      }

      const trusted = resolveTrustedContext({ req, tenantContext });
      if (trusted.error) {
        return sendClassifiedError(res, trusted.error);
      }

      const resolved = await resolver.resolveCurrentOwnerDevice({
        authenticatedUser: req?.user,
        logger,
      });
      if (resolved === null) {
        return sendClassifiedError(
          res,
          new DeviceError(
            'UNKNOWN_DEVICE',
            'No current active device identity is available for this authenticated user',
          ),
        );
      }

      const authorityService = createAuthorityService({
        db,
        clock,
        crypto,
        logger,
        audit: auditFn,
        tenantContext,
        verifyRenewalProof: async () => ({ ok: false }),
      });
      const row = await readCurrentOwnedRow({ authorityService, resolved });
      if (row === null) {
        return sendClassifiedError(
          res,
          new DeviceError(
            'UNKNOWN_DEVICE',
            'No current active device identity is available for this authenticated user',
          ),
        );
      }
      return res.status(200).json(statusBody(row, resolved));
    } catch {
      return sendFailClosed(res, 'Current device status failed closed');
    }
  };
}

/**
 * `POST /api/devices/current/renew` — manual renewal, valid strictly before expiry per the frozen
 * 48h/5s-margin law enforced by the accepted authority CAS.
 */
function createCurrentDeviceRenewHandler(deps = {}) {
  const {
    db,
    tenantContext,
    clock = { now: () => Date.now() },
    crypto = deviceCrypto,
    logger = null,
    audit,
  } = deps;
  assertHttpHandlerDependencies({ db, tenantContext, label: 'current device renew handler' });

  const resolver = createCurrentOwnerDeviceResolver({ db, tenantContext });
  const auditFn = createAuditAccessor({ db, logger, audit });

  return async function currentDeviceRenewHandler(req, res) {
    try {
      if (
        guardRequestInput(req, res, {
          endpoint: 'Current device renewal',
          allowedBodyFields: NO_BODY_FIELDS,
        })
      ) {
        return;
      }

      const trusted = resolveTrustedContext({ req, tenantContext });
      if (trusted.error) {
        return sendClassifiedError(res, trusted.error);
      }

      const resolved = await resolver.resolveCurrentOwnerDevice({
        authenticatedUser: req?.user,
        logger,
      });
      if (resolved === null) {
        return sendClassifiedError(
          res,
          new DeviceError(
            'UNKNOWN_DEVICE',
            'No current active device identity is available for this authenticated user',
          ),
        );
      }

      const renewal = createSessionRenewalAuthorization({
        tenantId: resolved.tenantId,
        ownerId: resolved.principalId,
        deviceId: resolved.deviceId,
      });
      const authorityService = createAuthorityService({
        db,
        clock,
        crypto,
        logger,
        audit: auditFn,
        tenantContext,
        verifyRenewalProof: renewal.verify,
      });

      const row = await readCurrentOwnedRow({ authorityService, resolved });
      if (row === null) {
        return sendClassifiedError(
          res,
          new DeviceError(
            'UNKNOWN_DEVICE',
            'No current active device identity is available for this authenticated user',
          ),
        );
      }

      // The binding is the server-observed preimage of the CAS, captured immediately before it.
      renewal.observe({ grantId: row.grantId ?? null, epoch: row.epoch ?? null });

      const result = await authorityService.renewAuthority({
        deviceId: resolved.deviceId,
        tenantId: resolved.tenantId,
        ownerId: resolved.principalId,
        epoch: row.epoch,
        grantId: row.grantId,
        proofInput: RENEWAL_AUTHORIZATION_SOURCE,
      });

      if (result?.ok === true && result?.matched === 1) {
        return res.status(200).json({
          ok: true,
          renewed: true,
          deviceId: resolved.deviceId,
          epoch: toObservedEpoch(result.authority?.epoch),
          expiresAt: toIsoOrNull(result.authority?.expiresAt),
          renewalCount: Number.isInteger(result.authority?.renewalCount)
            ? result.authority.renewalCount
            : null,
        });
      }

      const error = result?.error ?? null;

      if (result?.matched === 1) {
        // Committed CAS whose audit delivery failed: the renewal is real, never a no-op.
        return sendClassifiedError(
          res,
          error ??
            new DeviceError(
              'AUDIT_DELIVERY_UNCERTAIN',
              'Device renewal committed but audit delivery is uncertain',
            ),
          {
            committed: true,
            deviceId: resolved.deviceId,
            epoch: toObservedEpoch(result.authority?.epoch),
            expiresAt: toIsoOrNull(result.authority?.expiresAt),
          },
        );
      }

      // Explicit 0-match (or untrustworthy result): nothing was committed.
      return sendClassifiedError(
        res,
        error ??
          new DeviceError(
            'NOT_OWNER_OR_STALE',
            'No live lease matched the authenticated preimage; nothing was committed',
          ),
        {
          committed: false,
          deviceId: resolved.deviceId,
          epoch: toObservedEpoch(row.epoch),
          expiresAt: toIsoOrNull(row.expiresAt),
        },
      );
    } catch {
      return sendFailClosed(res, 'Current device renewal failed closed');
    }
  };
}

module.exports = {
  createCurrentDeviceStatusHandler,
  createCurrentDeviceRenewHandler,
  createSessionRenewalAuthorization,
  RENEWAL_AUTHORIZATION_SOURCE,
};
