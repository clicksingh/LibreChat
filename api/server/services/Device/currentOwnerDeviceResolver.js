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

  async function resolveCurrentOwnerDevice({ authenticatedUser } = {}) {
    const principalId = userIdOf(authenticatedUser);
    let tenantId;
    try {
      tenantId = tenantContext.getActiveTenantId();
    } catch {
      tenantId = null;
    }
    if (
      !isNonEmptyString(principalId) ||
      !isNonEmptyString(tenantId) ||
      tenantId === '__SYSTEM__'
    ) {
      return null;
    }
    if (
      authenticatedUser?.tenantId !== undefined &&
      authenticatedUser?.tenantId !== null &&
      authenticatedUser.tenantId !== tenantId
    ) {
      return null;
    }

    let row;
    try {
      row = await DeviceAuthority.findOne({
        tenantId,
        ownerId: principalId,
        identityState: { $ne: 'retired' },
        leaseState: 'active',
      })
        .select({ _id: 1, tenantId: 1, ownerId: 1, leaseState: 1, identityState: 1, epoch: 1 })
        .lean();
    } catch {
      return null;
    }
    if (
      row === null ||
      typeof row !== 'object' ||
      row.tenantId !== tenantId ||
      row.ownerId !== principalId ||
      row.leaseState !== 'active' ||
      row.identityState === 'retired'
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
