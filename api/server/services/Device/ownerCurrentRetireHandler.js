'use strict';

const deviceCrypto = require('./crypto');
const { createAuthorityService } = require('./authorityService');
const { createMongooseAuditSink } = require('./auditSink');
const { createOwnerRetireTrust } = require('./retireTrustAdapter');
const { createCurrentOwnerDeviceResolver } = require('./currentOwnerDeviceResolver');

function hasClientInput(value) {
  return value !== null && typeof value === 'object' && Object.keys(value).length > 0;
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
    const status = Number.isInteger(error?.httpStatus) ? error.httpStatus : 500;
    return res.status(status).json({
      ok: false,
      code: error?.code ?? 'WRITE_OUTCOME_UNCERTAIN',
      message: error?.message ?? 'Device retirement did not complete cleanly',
      committed: result?.matched === 1,
      deviceId: result?.matched === 1 ? resolved.deviceId : undefined,
      epoch: result?.matched === 1 ? result?.authority?.epoch ?? null : undefined,
    });
  };
}

module.exports = { createOwnerCurrentRetireHandler };
