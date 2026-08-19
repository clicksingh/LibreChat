/**
 * 8S3C.2 — request-scoped RUN_CODE authorization (Blocker 1 fix).
 *
 * RUN_CODE.USE is the authority ceiling for the document workstation in this
 * phase. Every path that previously derived `codeEnvAvailable` from the GLOBAL
 * `endpoints.agents.capabilities` set alone — the agent-chat init path
 * (initialize.js), the ToolService capability resolver, the remote v1 agent
 * controllers, the memory-agent path, and the exported SDK — must AND in the
 * requesting user's RUN_CODE.USE permission using the canonical `checkAccess`
 * semantics already used by the direct execute_code endpoint
 * (api/server/controllers/tools.js:callTool → 403 for denied users).
 *
 * `checkAccessWithRequestCache` caches the resolution on the request object
 * keyed by `[permissionType, permissions, user.id, user.role]`, so the check
 * is computed at most once per request no matter how many call sites consult
 * it. This satisfies the "one request-scoped effective authorization
 * resolution" requirement WITHOUT creating a second permission family — the
 * global platform capability and the user's effective permission AND together
 * gate model tool exposure:
 *
 *     effectiveCodeEnvAvailable = globalCodeCapability && userRunCodeAllowed
 *
 * This is the effective-run-code authorization resolution. No client-supplied
 * flag (e.g. `ephemeralAgent.execute_code`) is ever treated as authorization.
 */
const { PermissionTypes, Permissions, ResourceType, PermissionBits } = require('librechat-data-provider');
const { checkAccessWithRequestCache } = require('@librechat/api');
const { getRoleByName } = require('~/models');

/**
 * Canonical RUN_CODE.USE resolution for a request user (fail-closed).
 *
 * Mirrors the direct execute_code endpoint's check exactly:
 *   checkAccess({ user, permissionType: RUN_CODE, permissions: [USE] }).
 * Returns false when the user, role, or permission cannot be established, so
 * an anonymous/partial request can never obtain code execution.
 *
 * @param {Express.Request} req
 * @returns {Promise<boolean>}
 */
async function isRunCodeUseAllowed(req) {
  const user = req?.user;
  if (!user?.id || !user?.role) {
    return false;
  }
  return checkAccessWithRequestCache({
    req,
    user,
    permissionType: PermissionTypes.RUN_CODE,
    permissions: [Permissions.USE],
    getRoleByName,
  });
}

/**
 * Effective code-environment availability for a request:
 *   globalCodeCapability && userRunCodeAllowed(req).
 *
 * @param {Express.Request} req
 * @param {boolean} globalCodeCapability - resolved global
 *   `endpoints.agents.capabilities` execute_code flag.
 * @returns {Promise<boolean>}
 */
async function resolveEffectiveCodeEnv(req, globalCodeCapability) {
  if (!globalCodeCapability) {
    return false;
  }
  return isRunCodeUseAllowed(req);
}

/**
 * 8S3D.1 — request-scoped PROJECT WORKSPACE authorization.
 *
 * Resolves which workspace (if any) this request's code execution/file
 * operations should be scoped to, and re-checks the requesting user's
 * membership EVERY request — never trusts a conversation's stored
 * `workspaceId` as proof of current access, since membership can be revoked
 * after the conversation was created ("Project member access must be
 * checked on every operation, not only when the page initially loads").
 *
 * Precedence for the desired workspace id:
 *   1. An existing conversation's own (immutable) `workspaceId`.
 *   2. An explicit `workspaceId` on the request body, for a brand-new
 *      conversation that hasn't been persisted yet.
 *   3. Neither present -> no workspace context; callers fall back to the
 *      personal workspace (unchanged default behavior, zero claim added).
 *
 * FAILS CLOSED: if the user explicitly asked for a workspace (case 1 or 2)
 * and no longer has EDIT access (removed member, archived, forged id, never
 * had access), this throws rather than silently downgrading to personal —
 * silently redirecting a user's writes to a different storage boundary than
 * the one they asked for is its own kind of data-safety bug.
 *
 * Cached on `req` (request-scoped only) so repeated call sites within one
 * HTTP request do not re-query Mongo.
 *
 * @param {Express.Request} req
 * @returns {Promise<{kind: 'project', workspaceId: string} | undefined>}
 */
async function resolveWorkspaceContext(req) {
  if (req._workspaceContextResolved) {
    return req.workspaceContext;
  }
  req._workspaceContextResolved = true;

  const user = req?.user;
  if (!user?.id) {
    return undefined;
  }

  const db = require('~/models');
  let desiredWorkspaceId;

  const conversationId = req.body?.conversationId;
  if (conversationId && conversationId !== 'new') {
    const convo = await db.getConvo(user.id, conversationId);
    if (convo?.workspaceId) {
      desiredWorkspaceId = convo.workspaceId;
    }
  }
  if (!desiredWorkspaceId && req.body?.workspaceId) {
    desiredWorkspaceId = req.body.workspaceId;
  }
  if (!desiredWorkspaceId) {
    return undefined;
  }

  const workspace = await db.getWorkspace(desiredWorkspaceId);
  if (!workspace || workspace.state !== 'active') {
    const err = new Error('Workspace not found or archived');
    err.status = 404;
    throw err;
  }
  const allowed = await checkPermissionForWorkspace(user, desiredWorkspaceId);
  if (!allowed) {
    const err = new Error('Not authorized for this workspace');
    err.status = 403;
    throw err;
  }

  req.workspaceContext = { kind: 'project', workspaceId: String(desiredWorkspaceId) };
  syncProjectQuotaFireAndForget(req.workspaceContext.workspaceId);
  return req.workspaceContext;
}

/** Fire-and-forget: keep the helper's hard limit in sync with resolved
 * quota policy on every project-context resolution. Never blocks/fails the
 * request — if the workspace hasn't been ensure()'d yet (first-ever write
 * still pending), the sync 404s harmlessly and the eventual first `ensure()`
 * call falls back to CodeAPI's own project default until the NEXT
 * resolution succeeds in syncing the real policy number. */
function syncProjectQuotaFireAndForget(workspaceId) {
  try {
    const { syncProjectQuota } = require('~/server/services/Workspace/quotaSync');
    syncProjectQuota(workspaceId).catch(() => {});
  } catch {
    /* never let quota-sync plumbing affect request handling */
  }
}

/**
 * 8S3D.1 — same fail-closed re-check as resolveWorkspaceContext(), for
 * REST callers (workspace file-browser routes) that address a workspace
 * explicitly by id rather than via a conversation. Does NOT read/cache
 * req.body — safe to call multiple times with different ids in one request
 * (e.g. an admin listing several workspaces) since browsing multiple
 * workspaces in one request is a legitimate admin/multi-tab scenario, unlike
 * the single conversation-scoped code-exec claim.
 *
 * @param {Express.Request} req
 * @param {string} workspaceId
 * @returns {Promise<{kind: 'project', workspaceId: string}>}
 */
async function resolveWorkspaceContextExplicit(req, workspaceId) {
  const user = req?.user;
  if (!user?.id) {
    const err = new Error('Authentication required');
    err.status = 401;
    throw err;
  }
  const db = require('~/models');
  const workspace = await db.getWorkspace(workspaceId);
  if (!workspace || workspace.state !== 'active') {
    const err = new Error('Workspace not found or archived');
    err.status = 404;
    throw err;
  }
  const allowed = await checkPermissionForWorkspace(user, workspaceId);
  if (!allowed) {
    const err = new Error('Not authorized for this workspace');
    err.status = 403;
    throw err;
  }
  syncProjectQuotaFireAndForget(String(workspaceId));
  return { kind: 'project', workspaceId: String(workspaceId) };
}

async function checkPermissionForWorkspace(user, workspaceId) {
  const { checkPermission } = require('~/server/services/PermissionService');
  return checkPermission({
    userId: user.id,
    role: user.role,
    resourceType: ResourceType.WORKSPACE,
    resourceId: workspaceId,
    requiredPermission: PermissionBits.EDIT,
  });
}

module.exports = {
  isRunCodeUseAllowed,
  resolveEffectiveCodeEnv,
  resolveWorkspaceContext,
  resolveWorkspaceContextExplicit,
};
