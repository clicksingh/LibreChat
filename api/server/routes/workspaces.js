/**
 * 8S3D.1 — Workspace routes (issues #15, #16).
 *
 * Personal workspace: implicit, one per user (workspace_id === userId at
 * the CodeAPI layer). No Mongo document, no membership — every
 * authenticated user always has exactly one, reachable at the /personal/*
 * paths below.
 *
 * Project workspace: a real Mongo `Workspace` document (name/owner/state)
 * whose MEMBERSHIP/ACL rides entirely on the existing generic AclEntry
 * permission system (ResourceType.WORKSPACE) — see
 * PermissionService.grantPermission/checkPermission/findAccessibleResources.
 * This route file never re-implements authorization; it only calls that
 * service and CodeAPI's already-hardened /workspace/* endpoints.
 */
const express = require('express');
const mongoose = require('mongoose');
const { logger } = require('@librechat/data-schemas');
const { ResourceType, PrincipalType, AccessRoleIds } = require('librechat-data-provider');
const { requireJwtAuth } = require('~/server/middleware');
const {
  grantPermission,
  checkPermission,
  findAccessibleResources,
} = require('~/server/services/PermissionService');
const {
  resolveWorkspaceContextExplicit,
} = require('~/server/services/Endpoints/agents/authorization');
const { syncProjectQuota } = require('~/server/services/Workspace/quotaSync');
const proxy = require('~/server/services/Workspace/proxy');
const db = require('~/models');

const router = express.Router();
router.use(requireJwtAuth);

/* ------------------------------------------------------------------ *
 * Project workspace CRUD (issue #15)
 * ------------------------------------------------------------------ */

router.post('/', async (req, res) => {
  try {
    const name = String(req.body?.name || '').trim();
    if (!name || name.length > 100) {
      return res.status(400).json({ error: 'name is required (max 100 chars)' });
    }
    const workspace = await db.createWorkspace({
      name,
      description: req.body?.description,
      ownerId: req.user.id,
    });
    await grantPermission({
      principalType: PrincipalType.USER,
      principalId: req.user.id,
      resourceType: ResourceType.WORKSPACE,
      resourceId: workspace._id,
      accessRoleId: AccessRoleIds.WORKSPACE_OWNER,
      grantedBy: req.user.id,
    });
    // Provision the quota-enforced storage boundary + resolve/sync its
    // effective quota (project default unless overridden) immediately, so
    // the workspace is fully usable the moment it's created.
    await syncProjectQuota(String(workspace._id));
    res.status(201).json(workspace);
  } catch (error) {
    logger.error('[Workspace] create failed', error);
    res.status(500).json({ error: 'failed to create workspace' });
  }
});

router.get('/', async (req, res) => {
  try {
    const accessibleIds = await findAccessibleResources({
      userId: req.user.id,
      role: req.user.role,
      resourceType: ResourceType.WORKSPACE,
      requiredPermissions: 1 /* VIEW */,
    });
    const workspaces = await db.listWorkspacesByIds(accessibleIds);
    res.json({
      personal: { kind: 'personal', workspace_id: req.user.id },
      projects: workspaces.filter((w) => w.state === 'active'),
    });
  } catch (error) {
    logger.error('[Workspace] list failed', error);
    res.status(500).json({ error: 'failed to list workspaces' });
  }
});

router.patch('/:id', async (req, res) => {
  try {
    const allowed = await checkPermission({
      userId: req.user.id,
      role: req.user.role,
      resourceType: ResourceType.WORKSPACE,
      resourceId: req.params.id,
      requiredPermission: 2 /* EDIT */,
    });
    if (!allowed) return res.status(403).json({ error: 'not authorized' });

    let workspace;
    if (req.body?.name) {
      workspace = await db.renameWorkspace(req.params.id, String(req.body.name).trim().slice(0, 100));
    }
    if (req.body?.archive === true) {
      workspace = await db.archiveWorkspace(req.params.id);
    }
    if (!workspace) return res.status(404).json({ error: 'workspace not found' });
    res.json(workspace);
  } catch (error) {
    logger.error('[Workspace] update failed', error);
    res.status(500).json({ error: 'failed to update workspace' });
  }
});

router.post('/:id/members', async (req, res) => {
  try {
    // SHARE bit required to manage membership — an EDITOR may write files
    // but must not be able to grant others access unless also an owner.
    const allowed = await checkPermission({
      userId: req.user.id,
      role: req.user.role,
      resourceType: ResourceType.WORKSPACE,
      resourceId: req.params.id,
      requiredPermission: 8 /* SHARE */,
    });
    if (!allowed) return res.status(403).json({ error: 'not authorized to manage members' });

    const { principalType, principalId, accessRoleId } = req.body || {};
    if (
      ![PrincipalType.USER, PrincipalType.GROUP].includes(principalType) ||
      !mongoose.Types.ObjectId.isValid(principalId) ||
      ![AccessRoleIds.WORKSPACE_VIEWER, AccessRoleIds.WORKSPACE_EDITOR, AccessRoleIds.WORKSPACE_OWNER].includes(
        accessRoleId,
      )
    ) {
      return res.status(400).json({ error: 'invalid principalType/principalId/accessRoleId' });
    }
    const entry = await grantPermission({
      principalType,
      principalId,
      resourceType: ResourceType.WORKSPACE,
      resourceId: req.params.id,
      accessRoleId,
      grantedBy: req.user.id,
    });
    res.status(201).json(entry);
  } catch (error) {
    logger.error('[Workspace] add member failed', error);
    res.status(500).json({ error: 'failed to add member' });
  }
});

router.delete('/:id/members/:principalType/:principalId', async (req, res) => {
  try {
    const allowed = await checkPermission({
      userId: req.user.id,
      role: req.user.role,
      resourceType: ResourceType.WORKSPACE,
      resourceId: req.params.id,
      requiredPermission: 8 /* SHARE */,
    });
    if (!allowed) return res.status(403).json({ error: 'not authorized to manage members' });

    await db.revokePermission(
      req.params.principalType,
      req.params.principalId,
      ResourceType.WORKSPACE,
      req.params.id,
    );
    // Membership revocation takes effect immediately: the NEXT request for
    // this workspace re-checks via resolveWorkspaceContext(Explicit) — there
    // is no separate cache to invalidate.
    res.json({ removed: true });
  } catch (error) {
    logger.error('[Workspace] remove member failed', error);
    res.status(500).json({ error: 'failed to remove member' });
  }
});

/* ------------------------------------------------------------------ *
 * Personal workspace: usage / file browser / trash (issue #16)
 * ------------------------------------------------------------------ */

router.get('/personal/usage', async (req, res) => {
  try {
    res.json(await proxy.getUsage(req, 'user'));
  } catch (error) {
    proxy.handleProxyError(res, error, 'personal usage lookup failed');
  }
});

router.get('/personal/files', async (req, res) => {
  try {
    res.json(await proxy.listFiles(req, 'user', undefined, req.query.cursor, req.query.limit));
  } catch (error) {
    proxy.handleProxyError(res, error, 'personal file listing failed');
  }
});

router.get('/personal/trash', async (req, res) => {
  try {
    res.json(await proxy.listTrash(req, 'user', undefined, req.query.cursor, req.query.limit));
  } catch (error) {
    proxy.handleProxyError(res, error, 'personal trash listing failed');
  }
});

router.post('/personal/trash', async (req, res) => {
  try {
    res.json(await proxy.trashFile(req, 'user', undefined, req.body.session_id, req.body.file_id));
  } catch (error) {
    proxy.handleProxyError(res, error, 'personal trash-file failed');
  }
});

router.post('/personal/restore', async (req, res) => {
  try {
    res.json(await proxy.restoreFile(req, 'user', undefined, req.body.trash_id, req.body.newName));
  } catch (error) {
    proxy.handleProxyError(res, error, 'personal restore failed');
  }
});

router.post('/personal/purge', async (req, res) => {
  try {
    res.json(await proxy.purgeFile(req, 'user', undefined, req.body.trash_id));
  } catch (error) {
    proxy.handleProxyError(res, error, 'personal purge failed');
  }
});

/* ------------------------------------------------------------------ *
 * Project workspace: usage / file browser / trash (issue #16)
 *
 * Every one of these re-checks membership THIS request via
 * resolveWorkspaceContextExplicit (fail-closed, 403/404 on denial) before
 * setting req.workspaceContext, which is what getCodeApiAuthHeaders() reads
 * to mint the signed project claim CodeAPI actually trusts.
 * ------------------------------------------------------------------ */

router.get('/:id/usage', async (req, res) => {
  try {
    req.workspaceContext = await resolveWorkspaceContextExplicit(req, req.params.id);
    res.json(await proxy.getUsage(req, 'project', req.params.id));
  } catch (error) {
    if (error.status) return res.status(error.status).json({ error: error.message });
    proxy.handleProxyError(res, error, 'project usage lookup failed');
  }
});

router.get('/:id/files', async (req, res) => {
  try {
    req.workspaceContext = await resolveWorkspaceContextExplicit(req, req.params.id);
    res.json(await proxy.listFiles(req, 'project', req.params.id, req.query.cursor, req.query.limit));
  } catch (error) {
    if (error.status) return res.status(error.status).json({ error: error.message });
    proxy.handleProxyError(res, error, 'project file listing failed');
  }
});

router.get('/:id/trash', async (req, res) => {
  try {
    req.workspaceContext = await resolveWorkspaceContextExplicit(req, req.params.id);
    res.json(await proxy.listTrash(req, 'project', req.params.id, req.query.cursor, req.query.limit));
  } catch (error) {
    if (error.status) return res.status(error.status).json({ error: error.message });
    proxy.handleProxyError(res, error, 'project trash listing failed');
  }
});

router.post('/:id/trash', async (req, res) => {
  try {
    req.workspaceContext = await resolveWorkspaceContextExplicit(req, req.params.id);
    res.json(await proxy.trashFile(req, 'project', req.params.id, req.body.session_id, req.body.file_id));
  } catch (error) {
    if (error.status) return res.status(error.status).json({ error: error.message });
    proxy.handleProxyError(res, error, 'project trash-file failed');
  }
});

router.post('/:id/restore', async (req, res) => {
  try {
    req.workspaceContext = await resolveWorkspaceContextExplicit(req, req.params.id);
    res.json(await proxy.restoreFile(req, 'project', req.params.id, req.body.trash_id, req.body.newName));
  } catch (error) {
    if (error.status) return res.status(error.status).json({ error: error.message });
    proxy.handleProxyError(res, error, 'project restore failed');
  }
});

/**
 * PURGE — irreversible, frees quota. Explicit human confirmation is
 * enforced client-side (the UI requires a typed/clicked confirmation before
 * this request is ever sent); server-side this endpoint enforces only
 * authorization, matching CodeAPI's own contract. No agent/model tool calls
 * this route (ADR 005) — it exists solely for the authenticated human user.
 */
router.post('/:id/purge', async (req, res) => {
  try {
    req.workspaceContext = await resolveWorkspaceContextExplicit(req, req.params.id);
    res.json(await proxy.purgeFile(req, 'project', req.params.id, req.body.trash_id));
  } catch (error) {
    if (error.status) return res.status(error.status).json({ error: error.message });
    proxy.handleProxyError(res, error, 'project purge failed');
  }
});

module.exports = router;
