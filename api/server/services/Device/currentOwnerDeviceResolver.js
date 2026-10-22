'use strict';

function isNonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

function userIdOf(user) {
  const value = user?.id ?? user?._id ?? null;
  if (value === null || value === undefined) {
    return null;
  }
  const normalized = typeof value === 'string' ? value : value.toString?.();
  return isNonEmptyString(normalized) ? normalized : null;
}

function createCurrentOwnerDeviceResolver({ db, tenantContext } = {}) {
  const DeviceAuthority = db?.DeviceAuthority;
  if (
    DeviceAuthority === null ||
    (typeof DeviceAuthority !== 'object' && typeof DeviceAuthority !== 'function') ||
    typeof DeviceAuthority.findOne !== 'function'
  ) {
    throw new TypeError('current owner device resolver requires db.DeviceAuthority.findOne');
  }
  if (
    tenantContext === null ||
    typeof tenantContext !== 'object' ||
    typeof tenantContext.getActiveTenantId !== 'function'
  ) {
    throw new TypeError('current owner device resolver requires tenantContext.getActiveTenantId');
  }

  async function resolveCurrentOwnerDevice({ authenticatedUser, logger } = {}) {
    const principalId = userIdOf(authenticatedUser);
    let tenantId;
    try {
      tenantId = tenantContext.getActiveTenantId();
    } catch (err) {
      if (logger && typeof logger.error === 'function') {
        logger.error('Failed to resolve tenant context', { error: err.message, userId: principalId });
      }
      tenantId = null;
    }
    if (
      !isNonEmptyString(principalId) ||
      !isNonEmptyString(tenantId) ||
      tenantId === '__SYSTEM__'
    ) {
      return null;
    }
    // SECURITY: Enforce tenant isolation - reject if session tenant doesn't match
    if (authenticatedUser?.tenantId !== tenantId) {
      return null;
    }

    let row;
    try {
      row = await DeviceAuthority.findOne({
        tenantId,
        ownerId: principalId,
        identityState: { $in: ['active', 'paired'] },
        leaseState: 'active',
      })
        .readConcern('majority')
        .select({ _id: 1, tenantId: 1, ownerId: 1, leaseState: 1, identityState: 1, epoch: 1 })
        .lean();
    } catch (err) {
      if (logger && typeof logger.error === 'function') {
        logger.error('Device query failed', { error: err.message, tenantId, principalId });
      }
      return null;
    }
    if (
      row === null ||
      typeof row !== 'object' ||
      row.tenantId !== tenantId ||
      row.ownerId !== principalId ||
      row.leaseState !== 'active' ||
      !['active', 'paired'].includes(row.identityState)
    ) {
      return null;
    }
    const deviceId = row._id?.toString?.();
    if (!isNonEmptyString(deviceId)) {
      return null;
    }
    return {
      tenantId,
      principalId,
      deviceId,
      epoch: Number.isInteger(row.epoch) ? row.epoch : null,
    };
  }

  return { resolveCurrentOwnerDevice };
}

module.exports = { createCurrentOwnerDeviceResolver };
