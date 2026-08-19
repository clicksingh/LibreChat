/**
 * 8S3D.1 — quota policy admin surface (issue #16). No user may set their
 * own quota; every write here requires SystemCapabilities.ACCESS_ADMIN,
 * the SAME gate as the rest of the admin API family (admin/config.js,
 * admin/groups.js, ...). Deliberately does NOT touch cbhr-admin or the
 * workspace-quota-helper directly — this is pure Mongo policy CRUD;
 * quotaSync.js is what actually pushes the resolved number to the helper.
 */
const express = require('express');
const { SystemCapabilities } = require('@librechat/data-schemas');
const { requireCapability } = require('~/server/middleware/roles/capabilities');
const { requireJwtAuth } = require('~/server/middleware');
const { syncPersonalQuota, syncProjectQuota } = require('~/server/services/Workspace/quotaSync');
const db = require('~/models');

const router = express.Router();
const requireAdminAccess = requireCapability(SystemCapabilities.ACCESS_ADMIN);
router.use(requireJwtAuth, requireAdminAccess);

const VALID_SCOPES = ['platformPersonal', 'platformProject', 'group', 'user', 'project'];

router.get('/', async (_req, res) => {
  res.json(await db.listQuotaPolicies());
});

router.put('/:scope/:scopeId?', async (req, res) => {
  const { scope, scopeId } = req.params;
  const quotaBytes = Number(req.body?.quotaBytes);
  if (!VALID_SCOPES.includes(scope)) {
    return res.status(400).json({ error: `invalid scope: ${scope}` });
  }
  if (!Number.isFinite(quotaBytes) || quotaBytes < 0) {
    return res.status(400).json({ error: 'quotaBytes must be a non-negative number' });
  }
  const normalizedScopeId =
    scope === 'platformPersonal' || scope === 'platformProject' ? null : scopeId || null;
  if (!normalizedScopeId && scope !== 'platformPersonal' && scope !== 'platformProject') {
    return res.status(400).json({ error: `scopeId is required for scope: ${scope}` });
  }
  const policy = await db.upsertQuotaPolicy(scope, normalizedScopeId, quotaBytes);

  // Re-sync affected live workspaces immediately so an admin's change takes
  // effect without waiting for the next lazy per-request sync.
  if (scope === 'project') {
    await syncProjectQuota(normalizedScopeId).catch(() => {});
  } else if (scope === 'user') {
    await syncPersonalQuota(normalizedScopeId, undefined).catch(() => {});
  }
  // group/platform-scope changes affect potentially many workspaces; those
  // re-sync lazily on each affected user's next request (initialize.js) —
  // intentionally not fanned out eagerly here to avoid an admin edit
  // triggering an unbounded burst of helper calls.

  res.json(policy);
});

router.delete('/:scope/:scopeId?', async (req, res) => {
  const { scope, scopeId } = req.params;
  if (!VALID_SCOPES.includes(scope)) {
    return res.status(400).json({ error: `invalid scope: ${scope}` });
  }
  const normalizedScopeId =
    scope === 'platformPersonal' || scope === 'platformProject' ? null : scopeId || null;
  const deleted = await db.deleteQuotaPolicy(scope, normalizedScopeId);
  res.json({ deleted });
});

module.exports = router;
