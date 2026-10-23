'use strict';

/**
 * Current-device status HTTP handler (`GET /api/devices/current`).
 *
 * OWNER-AUTHORIZED SCOPE (2026-10-22, owner outranks Governor; LOCAL LAB ONLY and requiring
 * Governor ratification later; production G0 remains BLOCKED).
 *
 * TRUST MODEL (identical in shape to `ownerCurrentRetireHandler.js`)
 * - `requireJwtAuth` runs before the handler (wired in `routes/devices.js`).
 * - The endpoint accepts NO request input at all: any route params, query value or body field is
 *   rejected with 400 `REQUEST_SUPPLIED_IDENTITY_REJECTED` before any model method is touched.
 * - The current device is resolved by `currentOwnerDeviceResolver` from the authenticated session
 *   plus the trusted ALS tenant only: the query is the exact trusted tuple
 *   `{tenantId, ownerId:<authenticated id>, identityState:{$in:['active','paired']},
 *   leaseState:'active'}`. A client-supplied `deviceId` is never read and there is no arbitrary
 *   deviceId fallback; historical/revoked/expired identities still require a future opaque handle.
 * - The status projection re-reads the SAME server-resolved device id through the accepted
 *   authority service and echoes only `tenantId`, `deviceId`, `identityState`, `leaseState`,
 *   `epoch`, `expiresAt` and `serverTime`. No public key, lookupTag, grantId, grantProof, `prev*`
 *   lineage or `_id` other than the caller's own device id is ever serialized.
 *
 * RESPONSE CONTRACT
 * - `GET /current` 200
 *   `{ ok:true, tenantId, deviceId, identityState, leaseState, epoch, expiresAt, serverTime }`
 *   `serverTime` is the server's own clock at response time (ISO-8601, `null` if the injected
 *   clock is unreadable). It carries no identity and no authority; it exists solely so the panel
 *   can detect local clock skew instead of trusting the browser's wall clock for lease expiry.
 *   404 `UNKNOWN_DEVICE` when the authenticated principal holds no current active device.
 *
 * NO RENEWAL SURFACE LIVES HERE.
 * `POST /current/renew` is served exclusively by `currentDeviceRenewEnvelopeHandler.js`, which
 * requires a device-signed CBHR-RENEW-V1 envelope (the PC's Ed25519 key), so a browser session
 * cannot renew. The former session-authenticated renewal handler was DELETED rather than left
 * exported: re-wiring it would have restored session-renewable leases, which the renew-nudge
 * boundary forbids (docs/ARCHITECTURE.md boundary 7, D007, GM-12).
 */

const deviceCrypto = require('./crypto');
const { createAuthorityService } = require('./authorityService');
const { createCurrentOwnerDeviceResolver } = require('./currentOwnerDeviceResolver');
const { DeviceError } = require('./errors');
const { assertPredicateAnchorShape } = require('./databaseTime');
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

/** This endpoint accepts not a single request field. */
const NO_BODY_FIELDS = Object.freeze([]);

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

/**
 * The server's own wall clock as an ISO instant, or `null` when the injected clock is unreadable.
 *
 * `serverTime` is the ONLY value in this response that is not read from the device row. It exists
 * because lease expiry is a comparison against time, and a browser's local clock can be arbitrarily
 * wrong (a snapshot-restored VM or a domain-drifted clock can be hours slow). The panel computes
 * `offset = serverTime - localNowAtFetch` and evaluates remaining lease time as
 * `expiresAt - (localNow + offset)`, so an expired lease cannot be displayed as connected merely
 * because the browser's clock disagrees. `null` makes the panel fail closed to `unverified`.
 */
function readServerTime(clock) {
  const now = typeof clock?.now === 'function' ? clock.now() : null;
  return Number.isFinite(now) ? new Date(now).toISOString() : null;
}

/** Safe status projection: no key material, no lookupTag, no grantId, no lineage fields. */
function statusBody(row, resolved, serverTime) {
  return {
    ok: true,
    tenantId: resolved.tenantId,
    deviceId: resolved.deviceId,
    identityState: isNonEmptyString(row.identityState) ? row.identityState : null,
    leaseState: isNonEmptyString(row.leaseState) ? row.leaseState : null,
    epoch: toObservedEpoch(row.epoch),
    expiresAt: toIsoOrNull(row.expiresAt),
    serverTime,
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
    // GM-65 test-only comparison anchor: TESTS ONLY; PRODUCTION MUST OMIT.
    predicateAnchor,
  } = deps;
  assertHttpHandlerDependencies({ db, tenantContext, label: 'current device status handler' });
  assertPredicateAnchorShape(predicateAnchor);

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
        // GM-65: forwarded so any lease-state predicate in this composition shares one timeline.
        predicateAnchor,
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
      return res.status(200).json(statusBody(row, resolved, readServerTime(clock)));
    } catch {
      return sendFailClosed(res, 'Current device status failed closed');
    }
  };
}

module.exports = {
  createCurrentDeviceStatusHandler,
};
