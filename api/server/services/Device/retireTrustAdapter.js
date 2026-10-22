'use strict';

const crypto = require('node:crypto');
const DEFAULT_TICKET_TTL_MS = 15000;
const DEFAULT_ADMIN_CAPABILITY = 'access:admin';
const SYSTEM_TENANT_ID = '__SYSTEM__';

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

function resolveTrustedContext({ authenticatedUser, tenantContext, serverResolvedDeviceId }) {
  if (
    tenantContext === null ||
    typeof tenantContext !== 'object' ||
    typeof tenantContext.getActiveTenantId !== 'function'
  ) {
    return null;
  }
  let tenantId;
  try {
    tenantId = tenantContext.getActiveTenantId();
  } catch {
    return null;
  }
  const principalId = userIdOf(authenticatedUser);
  if (
    !isNonEmptyString(tenantId) ||
    tenantId === SYSTEM_TENANT_ID ||
    !isNonEmptyString(principalId) ||
    !isNonEmptyString(serverResolvedDeviceId)
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
  return { tenantId, principalId, deviceId: serverResolvedDeviceId };
}

function serverSessionRef({ authStrategy, principalId }) {
  const strategy = isNonEmptyString(authStrategy) ? authStrategy : 'authenticated';
  return `${strategy}:${principalId}`;
}
function createOwnerRetireTrust({
  authenticatedUser,
  authStrategy,
  tenantContext,
  serverResolvedDeviceId,
} = {}) {
  const currentTrusted = () =>
    resolveTrustedContext({ authenticatedUser, tenantContext, serverResolvedDeviceId });

  const resolveRetirePrincipal = async ({ tenantId, deviceId } = {}) => {
    const trusted = currentTrusted();
    if (
      trusted === null ||
      tenantId !== trusted.tenantId ||
      deviceId !== trusted.deviceId
    ) {
      return null;
    }
    return {
      kind: 'owner',
      principalId: trusted.principalId,
      tenantId: trusted.tenantId,
      sessionRef: serverSessionRef({
        authStrategy,
        principalId: trusted.principalId,
      }),
    };
  };

  return {
    get trusted() { return currentTrusted(); },
    resolveRetirePrincipal,
    verifyRetireAuthorization: undefined,
  };
}

function createAdminRetireTrust({
  authenticatedUser,
  authStrategy,
  tenantContext,
  serverResolvedDeviceId,
  getUserPrincipals,
  hasCapabilityForPrincipals,
  clock = { now: () => Date.now() },
  randomId = () => crypto.randomUUID(),
  ticketTtlMs = DEFAULT_TICKET_TTL_MS,
  adminCapability = DEFAULT_ADMIN_CAPABILITY,
} = {}) {
  const currentTrusted = () =>
    resolveTrustedContext({ authenticatedUser, tenantContext, serverResolvedDeviceId });
  if (
    typeof getUserPrincipals !== 'function' ||
    typeof hasCapabilityForPrincipals !== 'function' ||
    clock === null ||
    typeof clock !== 'object' ||
    typeof clock.now !== 'function' ||
    typeof randomId !== 'function' ||
    !Number.isInteger(ticketTtlMs) ||
    ticketTtlMs <= 0 ||
    !isNonEmptyString(adminCapability)
  ) {
    return {
      get trusted() { return currentTrusted(); },
      resolveRetirePrincipal: async () => null,
      verifyRetireAuthorization: async () => ({ ok: false, binding: null }),
    };
  }

  let ticket = null;

  async function hasAdminEligibility(trusted) {
    if (trusted === null) {
      return false;
    }
    try {
      const principals = await getUserPrincipals({
        userId: trusted.principalId,
        role: authenticatedUser?.role,
        tenantId: trusted.tenantId,
      });
      if (!Array.isArray(principals) || principals.length === 0) {
        return false;
      }
      return (
        (await hasCapabilityForPrincipals({
          principals,
          capability: adminCapability,
          tenantId: trusted.tenantId,
        })) === true
      );
    } catch {
      return false;
    }
  }
  const resolveRetirePrincipal = async ({ tenantId, deviceId } = {}) => {
    const trusted = currentTrusted();
    if (
      trusted === null ||
      tenantId !== trusted.tenantId ||
      deviceId !== trusted.deviceId ||
      ticket !== null
    ) {
      return null;
    }
    if (!(await hasAdminEligibility(trusted))) {
      return null;
    }
    const now = clock.now();
    const authorizationEpoch = Number.isSafeInteger(now) && now >= 0 ? now : null;
    let adminGrantRef = null;
    try {
      adminGrantRef = randomId();
    } catch {
      adminGrantRef = null;
    }
    if (authorizationEpoch === null || !isNonEmptyString(adminGrantRef)) {
      return null;
    }
    ticket = {
      adminGrantRef,
      authorizationEpoch,
      principalId: trusted.principalId,
      tenantId: trusted.tenantId,
      deviceId: trusted.deviceId,
      issuedAt: now,
      expiresAt: now + ticketTtlMs,
      consumed: false,
      authStrategy: isNonEmptyString(authStrategy) ? authStrategy : 'authenticated',
    };
    return {
      kind: 'admin',
      principalId: trusted.principalId,
      tenantId: trusted.tenantId,
      adminGrantRef,
      authorizationEpoch,
    };
  };

  const verifyRetireAuthorization = async ({
    tenantId,
    principalId,
    adminGrantRef,
    authorizationEpoch,
    deviceId,
  } = {}) => {
    const trusted = currentTrusted();
    if (trusted === null || ticket === null || ticket.consumed === true) {
      return { ok: false, binding: null };
    }
    const now = clock.now();
    const exact =
      trusted.tenantId === ticket.tenantId &&
      trusted.principalId === ticket.principalId &&
      trusted.deviceId === ticket.deviceId &&
      tenantId === ticket.tenantId &&
      principalId === ticket.principalId &&
      adminGrantRef === ticket.adminGrantRef &&
      authorizationEpoch === ticket.authorizationEpoch &&
      deviceId === ticket.deviceId &&
      Number.isFinite(now) &&
      now >= ticket.issuedAt &&
      now <= ticket.expiresAt;
    if (!exact) {
      return { ok: false, binding: null };
    }

    // Consume before the asynchronous eligibility recheck so a concurrent second
    // verifier call cannot race through the same request-local ticket.
    ticket.consumed = true;
    if (!(await hasAdminEligibility(trusted))) {
      return { ok: false, binding: null };
    }

    return {
      ok: true,
      binding: {
        adminPrincipalId: ticket.principalId,
        scopeTenantId: ticket.tenantId,
        deviceId: ticket.deviceId,
        adminGrantRef: ticket.adminGrantRef,
        authorizationEpoch: ticket.authorizationEpoch,
      },
    };
  };

  return {
    get trusted() { return currentTrusted(); },
    resolveRetirePrincipal,
    verifyRetireAuthorization,
  };
}

module.exports = {
  DEFAULT_TICKET_TTL_MS,
  DEFAULT_ADMIN_CAPABILITY,
  createOwnerRetireTrust,
  createAdminRetireTrust,
};
