'use strict';

/**
 * Current-owner device retirement handler (`POST /api/devices/current/retire`).
 *
 * TRUST MODEL
 * - The device, tenant and principal are resolved server-side (authenticated JWT user + trusted
 *   tenant context). No client-supplied identity or authority field is ever read: any non-empty
 *   body/query/params is rejected before any resolution or authority call.
 *
 * RESPONSE CONTRACT (frozen here; `committed` is true ONLY when the retire CAS matched 1 row)
 * - 400 `REQUEST_SUPPLIED_IDENTITY_REJECTED`
 *     Client sent identity/authority input. No resolution, no authority call, no `deviceId`,
 *     `epoch` or `committed` keys.
 * - 404 `UNKNOWN_DEVICE`
 *     No current active device identity could be resolved for the authenticated user. No
 *     authority call, no `committed` key.
 * - 200 `{ ok:true, retired:true, deviceId, epoch }`
 *     The CAS matched exactly 1 row and committed, and the authority audit was delivered.
 *     `deviceId` is the server-resolved id; `epoch` is the post-commit epoch read back from the
 *     authority row (`null` when unreadable).
 * - 500 `AUDIT_DELIVERY_UNCERTAIN` `{ ok:false, committed:true, deviceId, epoch, ... }`
 *     The CAS matched exactly 1 row and therefore COMMITTED, but the authority audit event was
 *     not delivered. The retirement is real: it must not be retried or reported as a no-op.
 *     `deviceId`/`epoch` are the committed values.
 * - 4xx/5xx `{ ok:false, code, message, committed:false, deviceId, epoch }`
 *     Nothing was committed (`matched !== 1`, a truthful 0-match, or an untrustworthy write
 *     outcome). `code`/`httpStatus` come from the authority service's classified DeviceError when
 *     one is supplied, so already-classified duplicates keep their existing codes and statuses
 *     (`UNKNOWN_DEVICE` 404, `NOT_OWNER` 403, `DEVICE_IDENTITY_REVOKED` 409,
 *     `NOT_OWNER_OR_STALE` 409, and the genuine `WRITE_OUTCOME_UNCERTAIN`/
 *     `UNCLASSIFIED_DUPLICATE` 500s). A miss the service did not classify is answered with the
 *     frozen 409 `DEVICE_IDENTITY_REVOKED` — a 0-match is never reported as a fabricated 500.
 *     `deviceId` is the server-resolved id and `epoch` is the epoch observed when the request was
 *     resolved (`null` when unavailable); neither is presented as a committed value.
 *
 * The matched===1 path is deliberately unchanged: 200 on `ok`, and `committed:true` plus
 * `AUDIT_DELIVERY_UNCERTAIN` when the audit failed after the commit.
 */

const deviceCrypto = require('./crypto');
const { createAuthorityService } = require('./authorityService');
const { createMongooseAuditSink } = require('./auditSink');
const { createOwnerRetireTrust } = require('./retireTrustAdapter');
const { createCurrentOwnerDeviceResolver } = require('./currentOwnerDeviceResolver');

function hasClientInput(value) {
  return value !== null && typeof value === 'object' && Object.keys(value).length > 0;
}

/** Truthful epoch passthrough: only a server-observed non-negative integer is reported. */
function observedEpoch(resolved) {
  return Number.isInteger(resolved?.epoch) && resolved.epoch >= 0 ? resolved.epoch : null;
}

function createOwnerCurrentRetireHandler({
  db,
  tenantContext,
  clock = { now: () => Date.now() },
  crypto = deviceCrypto,
  logger = null,
  audit,
} = {}) {
  if (db === null || typeof db !== 'object') {
    throw new TypeError('owner current retire handler requires Device models');
  }
  if (
    tenantContext === null ||
    typeof tenantContext !== 'object' ||
    typeof tenantContext.getActiveTenantId !== 'function'
  ) {
    throw new TypeError('owner current retire handler requires trusted tenant context');
  }

  const resolver = createCurrentOwnerDeviceResolver({ db, tenantContext });
  const auditFn =
    typeof audit === 'function'
      ? audit
      : createMongooseAuditSink({ AuditEvent: db.AuditEvent, logger }).audit;

  return async function ownerCurrentRetireHandler(req, res) {
    if (hasClientInput(req?.body) || hasClientInput(req?.query) || hasClientInput(req?.params)) {
      return res.status(400).json({
        ok: false,
        code: 'REQUEST_SUPPLIED_IDENTITY_REJECTED',
        message: 'Current-device retirement does not accept client identity or authority fields',
      });
    }

    const resolved = await resolver.resolveCurrentOwnerDevice({
      authenticatedUser: req?.user,
    });
    if (resolved === null) {
      return res.status(404).json({
        ok: false,
        code: 'UNKNOWN_DEVICE',
        message: 'No current active device identity is available for this authenticated user',
      });
    }

    const trust = createOwnerRetireTrust({
      authenticatedUser: req.user,
      authStrategy: req.authStrategy,
      tenantContext,
      serverResolvedDeviceId: resolved.deviceId,
    });

    const authority = createAuthorityService({
      db,
      clock,
      crypto,
      logger,
      audit: auditFn,
      verifyRenewalProof: async () => ({ ok: false }),
      tenantContext,
      resolveRetirePrincipal: trust.resolveRetirePrincipal,
      verifyRetireAuthorization: trust.verifyRetireAuthorization,
    });

    const result = await authority.retireIdentity({
      tenantId: resolved.tenantId,
      deviceId: resolved.deviceId,
    });

    if (result?.ok === true && result?.matched === 1) {
      return res.status(200).json({
        ok: true,
        retired: true,
        deviceId: resolved.deviceId,
        epoch: result.authority?.epoch ?? null,
      });
    }

    const error = result?.error ?? null;

    if (result?.matched === 1) {
      // Committed CAS whose audit delivery failed (AUDIT_DELIVERY_UNCERTAIN): the retirement is
      // real, so `committed:true` and the committed deviceId/epoch are reported truthfully.
      return res
        .status(Number.isInteger(error?.httpStatus) ? error.httpStatus : 500)
        .json({
          ok: false,
          code: error?.code ?? 'AUDIT_DELIVERY_UNCERTAIN',
          message: error?.message ?? 'Device retirement committed but audit delivery is uncertain',
          committed: true,
          deviceId: resolved.deviceId,
          epoch: result?.authority?.epoch ?? null,
        });
    }

    // Explicit 0-match (or untrustworthy result): nothing was committed. A classified DeviceError
    // keeps its own code/status; an unclassified miss is answered 409 DEVICE_IDENTITY_REVOKED
    // rather than a fabricated 500 WRITE_OUTCOME_UNCERTAIN.
    return res
      .status(Number.isInteger(error?.httpStatus) ? error.httpStatus : 409)
      .json({
        ok: false,
        code: error?.code ?? 'DEVICE_IDENTITY_REVOKED',
        message: error?.message ?? 'No retirable device identity matched; nothing was committed',
        committed: false,
        deviceId: resolved.deviceId,
        epoch: observedEpoch(resolved),
      });
  };
}

module.exports = { createOwnerCurrentRetireHandler };
