/**
 * 8S3D.1 — quota policy resolution + sync to the privileged workspace-quota
 * helper. LibreChat is the POLICY authority (default/group/user/project
 * precedence, resolved from Mongo); workspace-quota-helper remains the
 * final HARD-LIMIT actuator (XFS project quota) — this module is the bridge
 * between the two, via CodeAPI's internal-only /internal/workspace/quota
 * endpoint (gated on a distinct `admin: true` signed claim, never
 * client-controlled).
 */
const { logger } = require('@librechat/data-schemas');
const { PrincipalType } = require('librechat-data-provider');
const { getCodeBaseURL } = require('@librechat/agents');
const { createAxiosInstance, logAxiosError, mintInternalAdminToken } = require('@librechat/api');
const db = require('~/models');

const axios = createAxiosInstance();

async function resolvePersonalQuota(userId, role) {
  const principals = await db.getUserPrincipals({ userId, role });
  const groupIds = principals
    .filter((p) => p.principalType === PrincipalType.GROUP)
    .map((p) => String(p.principalId));
  return db.resolveEffectivePersonalQuota({ userId, groupIds });
}

async function resolveProjectQuota(workspaceId) {
  return db.resolveEffectiveProjectQuota(workspaceId);
}

/** Push a resolved quota to the helper via CodeAPI. Best-effort: a sync
 * failure must not break chat/file operations — the helper keeps whatever
 * limit it last had (fails safe toward the LAST KNOWN GOOD hard limit, not
 * toward unlimited). */
async function syncQuotaToHelper(workspaceId, kind, quotaBytes) {
  const baseURL = getCodeBaseURL();
  const token = await mintInternalAdminToken();
  if (!token) {
    return; // Code API JWT auth mode disabled (dev/test) — nothing to sync.
  }
  try {
    await axios.post(
      `${baseURL}/internal/workspace/quota`,
      { workspace_id: workspaceId, kind, quota_bytes: quotaBytes },
      { headers: { Authorization: `Bearer ${token}` }, timeout: 10000 },
    );
  } catch (error) {
    logAxiosError({ error, message: `[quotaSync] failed to sync ${kind}:${workspaceId}` });
    logger.warn(`[quotaSync] helper hard limit may be stale for ${kind}:${workspaceId}`);
  }
}

async function syncPersonalQuota(userId, role) {
  const { quotaBytes } = await resolvePersonalQuota(userId, role);
  await syncQuotaToHelper(userId, 'personal', quotaBytes);
  return quotaBytes;
}

async function syncProjectQuota(workspaceId) {
  const { quotaBytes } = await resolveProjectQuota(workspaceId);
  await syncQuotaToHelper(workspaceId, 'project', quotaBytes);
  return quotaBytes;
}

module.exports = {
  resolvePersonalQuota,
  resolveProjectQuota,
  syncPersonalQuota,
  syncProjectQuota,
  syncQuotaToHelper,
};
