'use strict';

/**
 * 8S5 — `agent_management` runtime tool (conversational Agent CRUD).
 *
 * Wraps the EXISTING Agent substrate (versioning, ACL/sharing, lifecycle)
 * directly — no parallel Agent system, no generic Mongo CRUD, no raw query
 * objects from the model. Every operation:
 *
 *   1. derives the actor EXCLUSIVELY from `req.user` (never from a model-
 *      supplied field — there is no `owner_id`/`user_id` input anywhere in
 *      this tool's schema);
 *   2. independently re-checks the SAME ACL primitives the REST routes use
 *      (`PermissionService.checkPermission` / `findAccessibleResources` /
 *      `checkAccessWithRequestCache` against `PermissionTypes.AGENTS`) —
 *      never trusts that the model "should" be allowed just because it
 *      asked;
 *   3. reuses the exact same underlying functions the REST controllers use
 *      for the actual mutation (`db.createAgent`, `db.updateAgent`,
 *      `filterAuthorizedTools`, `assertToolCapabilityCeiling`,
 *      `db.archiveAgent`, `db.diffAgentVersions`, `bulkUpdateResourcePermissions`)
 *      — not a duplicate reimplementation.
 *
 * Fixed action allowlist (exhaustive): list, get, create, update, versions,
 * diff, archive, restore, share, unshare. No generic exec/write/query op.
 * Destructive hard-delete is intentionally NOT exposed here — archive is
 * the model-reachable "remove" action (ADR 005; irreversible delete stays
 * a direct UI/API action only, matching "Do not give a conversational
 * model unrestricted destructive deletion").
 */

const { DynamicStructuredTool } = require('@librechat/agents/langchain/tools');
const {
  Tools,
  Permissions,
  ResourceType,
  AccessRoleIds,
  PrincipalType,
  PermissionBits,
  PermissionTypes,
} = require('librechat-data-provider');
const { checkAccessWithRequestCache } = require('@librechat/api');
const {
  checkPermission,
  grantPermission,
  findAccessibleResources,
  bulkUpdateResourcePermissions,
} = require('~/server/services/PermissionService');
const { getRoleByName, findUser } = require('~/models');
const db = require('~/models');
const v1 = require('~/server/controllers/agents/v1');
const { assertToolCapabilityCeiling } = require('~/server/services/Tools/agentCapabilityCeiling');
const { getCachedTools } = require('~/server/services/Config');
const { nanoid } = require('nanoid');

const TOOL_NAME = Tools.agent_management;

const TOOL_DESCRIPTION = `Manage your Agents (reusable, versioned assistant configurations) without leaving chat.

Actions (exact "action" values):
- list: your accessible agents. Optional: include_archived (bool), search (string).
- get: one agent's current configuration. Requires agent_id.
- create: a new agent. Requires name. Optional: description, instructions, model, tools (array of tool names — only tools you are personally authorized to use are accepted).
- update: edit an existing agent (creates a new immutable version automatically unless nothing behavioral changed). Requires agent_id. Optional: name, description, instructions, model, tools, expected_version (reject if the agent changed since you last saw it).
- versions: list an agent's version history (index, when, who). Requires agent_id.
- diff: what changed between two versions. Requires agent_id, from (version index). Optional: to (version index or "current", default current).
- archive: hide an agent from new-conversation selection WITHOUT deleting it or any conversation history. Requires agent_id.
- restore: bring an archived agent back to active. Requires agent_id.
- share: grant another user access. Requires agent_id, recipient_email. Optional: access ("use" or "edit", default "use").
- unshare: remove another user's access. Requires agent_id, recipient_email.

An agent you create only gets tools/capabilities YOU are personally authorized to use — sharing an agent never grants the recipient authority they don't already have themselves.`;

const TOOL_SCHEMA = {
  type: 'object',
  properties: {
    action: {
      type: 'string',
      enum: [
        'list',
        'get',
        'create',
        'update',
        'versions',
        'diff',
        'archive',
        'restore',
        'share',
        'unshare',
      ],
    },
    agent_id: { type: 'string' },
    name: { type: 'string' },
    description: { type: 'string' },
    instructions: { type: 'string' },
    model: { type: 'string' },
    tools: { type: 'array', items: { type: 'string' } },
    expected_version: { type: 'number' },
    from: { type: 'number' },
    to: { type: 'string' },
    include_archived: { type: 'boolean' },
    search: { type: 'string' },
    recipient_email: { type: 'string' },
    access: { type: 'string', enum: ['use', 'edit'] },
  },
  required: ['action'],
};

const AGENT_VIEWER_ROLES = { use: AccessRoleIds.AGENT_VIEWER, edit: AccessRoleIds.AGENT_EDITOR };

function coded(message, code, status = 400) {
  const err = new Error(message);
  err.code = code;
  err.status = status;
  return err;
}

async function requireGlobalAgentAccess(req, permissions) {
  const allowed = await checkAccessWithRequestCache({
    req,
    user: req.user,
    permissionType: PermissionTypes.AGENTS,
    permissions,
    getRoleByName,
  });
  if (!allowed) {
    throw coded('You do not have permission to manage agents.', 'AGENT_ACCESS_DENIED', 403);
  }
}

async function requireResourcePermission(req, agentDbId, requiredPermission) {
  const allowed = await checkPermission({
    userId: req.user.id,
    role: req.user.role,
    resourceType: ResourceType.AGENT,
    resourceId: agentDbId,
    requiredPermission,
  });
  if (!allowed) {
    throw coded('You do not have access to this agent.', 'AGENT_ACCESS_DENIED', 403);
  }
}

async function loadAgentOrThrow(agentId) {
  const agent = await db.getAgent({ id: agentId });
  if (!agent) {
    throw coded(`Agent "${agentId}" not found.`, 'AGENT_NOT_FOUND', 404);
  }
  return agent;
}

function summarizeAgent(agent) {
  return {
    agent_id: agent.id,
    name: agent.name,
    description: agent.description,
    model: agent.model,
    tools: agent.tools || [],
    lifecycle_state: agent.lifecycle_state || 'active',
    version: agent.versions ? agent.versions.length : 1,
    updated_at: agent.updatedAt,
  };
}

async function actionList(args, req) {
  await requireGlobalAgentAccess(req, [Permissions.USE]);
  const accessibleIds = await findAccessibleResources({
    userId: req.user.id,
    role: req.user.role,
    resourceType: ResourceType.AGENT,
    requiredPermissions: PermissionBits.VIEW,
  });
  const filter = {};
  if (args.include_archived !== true) {
    filter.lifecycle_state = { $ne: 'archived' };
  }
  if (args.search) {
    const safe = String(args.search).slice(0, 100).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    filter.$or = [{ name: new RegExp(safe, 'i') }, { description: new RegExp(safe, 'i') }];
  }
  const result = await db.getListAgentsByAccess({
    accessibleIds,
    otherParams: filter,
    limit: 50,
    after: null,
  });
  return { agents: (result.data || []).map(summarizeAgent) };
}

async function actionGet(args, req) {
  await requireGlobalAgentAccess(req, [Permissions.USE]);
  if (!args.agent_id) throw coded('agent_id is required.', 'AGENT_ID_REQUIRED');
  const agent = await loadAgentOrThrow(args.agent_id);
  await requireResourcePermission(req, agent._id, PermissionBits.VIEW);
  return summarizeAgent(agent);
}

async function actionCreate(args, req) {
  await requireGlobalAgentAccess(req, [Permissions.USE, Permissions.CREATE]);
  if (!args.name) throw coded('name is required.', 'AGENT_NAME_REQUIRED');

  const provider = process.env.AGENT_PROVIDER || 'CBHR AI';
  const model = args.model || process.env.AGENT_DEFAULT_MODEL || 'glm-5.1';

  const availableTools = (await getCachedTools()) ?? {};
  const filteredTools = await v1.filterAuthorizedTools({
    tools: Array.isArray(args.tools) ? args.tools : [],
    userId: req.user.id,
    role: req.user.role,
    user: req.user,
    availableTools,
  });
  await assertToolCapabilityCeiling(filteredTools, req);

  const agentData = {
    id: `agent_${nanoid()}`,
    name: args.name,
    description: args.description,
    instructions: args.instructions,
    provider,
    model,
    tools: filteredTools,
    author: req.user.id,
  };
  const agent = await db.createAgent(agentData);
  await grantPermission({
    principalType: PrincipalType.USER,
    principalId: req.user.id,
    resourceType: ResourceType.AGENT,
    resourceId: agent._id,
    accessRoleId: AccessRoleIds.AGENT_OWNER,
    grantedBy: req.user.id,
  });
  return summarizeAgent(agent);
}

async function actionUpdate(args, req) {
  if (!args.agent_id) throw coded('agent_id is required.', 'AGENT_ID_REQUIRED');
  const existing = await loadAgentOrThrow(args.agent_id);
  await requireResourcePermission(req, existing._id, PermissionBits.EDIT);

  const currentVersion = existing.versions ? existing.versions.length : 0;
  if (args.expected_version !== undefined && args.expected_version !== currentVersion) {
    throw coded(
      `This agent changed since you last saw it (you expected version ${args.expected_version}, it is now version ${currentVersion}). Fetch it again before editing.`,
      'AGENT_VERSION_CONFLICT',
      409,
    );
  }

  const updateData = {};
  if (args.name !== undefined) updateData.name = args.name;
  if (args.description !== undefined) updateData.description = args.description;
  if (args.instructions !== undefined) updateData.instructions = args.instructions;
  if (args.model !== undefined) updateData.model = args.model;
  if (args.tools !== undefined) {
    const availableTools = (await getCachedTools()) ?? {};
    updateData.tools = await v1.filterAuthorizedTools({
      tools: args.tools,
      userId: req.user.id,
      role: req.user.role,
      user: req.user,
      availableTools,
      existingTools: existing.tools,
    });
  }
  // Revalidate the FULL resulting tool set, not just the changed field.
  await assertToolCapabilityCeiling(updateData.tools ?? existing.tools, req);

  const updated = await db.updateAgent({ id: args.agent_id }, updateData, {
    updatingUserId: req.user.id,
  });
  return summarizeAgent(updated);
}

async function actionVersions(args, req) {
  if (!args.agent_id) throw coded('agent_id is required.', 'AGENT_ID_REQUIRED');
  const agent = await loadAgentOrThrow(args.agent_id);
  await requireResourcePermission(req, agent._id, PermissionBits.VIEW);
  const versions = agent.versions || [];
  return {
    agent_id: agent.id,
    current_version: versions.length,
    versions: versions.map((v, i) => ({
      index: i,
      updated_at: v.updatedAt,
      updated_by: v.updatedBy ? String(v.updatedBy) : null,
      name: v.name,
      model: v.model,
    })),
  };
}

async function actionDiff(args, req) {
  if (!args.agent_id) throw coded('agent_id is required.', 'AGENT_ID_REQUIRED');
  if (args.from === undefined) throw coded('from (version index) is required.', 'AGENT_DIFF_FROM_REQUIRED');
  const agent = await loadAgentOrThrow(args.agent_id);
  await requireResourcePermission(req, agent._id, PermissionBits.VIEW);
  const versions = agent.versions || [];
  const fromSnap = versions[args.from];
  if (!fromSnap) throw coded(`Version ${args.from} not found.`, 'AGENT_VERSION_NOT_FOUND', 404);
  let toSnap = agent;
  let toLabel = 'current';
  if (args.to !== undefined && args.to !== 'current') {
    const toIndex = parseInt(args.to, 10);
    toSnap = versions[toIndex];
    toLabel = toIndex;
    if (!toSnap) throw coded(`Version ${args.to} not found.`, 'AGENT_VERSION_NOT_FOUND', 404);
  }
  const changes = db.diffAgentVersions(fromSnap, toSnap);
  return { agent_id: agent.id, from: args.from, to: toLabel, changes };
}

async function actionArchive(args, req) {
  if (!args.agent_id) throw coded('agent_id is required.', 'AGENT_ID_REQUIRED');
  const agent = await loadAgentOrThrow(args.agent_id);
  await requireResourcePermission(req, agent._id, PermissionBits.EDIT);
  const updated = await db.archiveAgent({ id: args.agent_id }, req.user.id);
  return summarizeAgent(updated);
}

async function actionRestore(args, req) {
  if (!args.agent_id) throw coded('agent_id is required.', 'AGENT_ID_REQUIRED');
  const agent = await loadAgentOrThrow(args.agent_id);
  await requireResourcePermission(req, agent._id, PermissionBits.EDIT);
  const updated = await db.restoreAgent({ id: args.agent_id }, req.user.id);
  return summarizeAgent(updated);
}

async function resolveRecipient(email) {
  if (!email || typeof email !== 'string') {
    throw coded('recipient_email is required.', 'AGENT_RECIPIENT_REQUIRED');
  }
  const user = await findUser({ email: email.toLowerCase().trim() }, ['_id', 'email']);
  if (!user) {
    throw coded(`No platform user found with email "${email}".`, 'AGENT_RECIPIENT_NOT_FOUND', 404);
  }
  return user;
}

async function actionShare(args, req) {
  if (!args.agent_id) throw coded('agent_id is required.', 'AGENT_ID_REQUIRED');
  const agent = await loadAgentOrThrow(args.agent_id);
  await requireResourcePermission(req, agent._id, PermissionBits.SHARE);
  const recipient = await resolveRecipient(args.recipient_email);
  const accessRoleId = AGENT_VIEWER_ROLES[args.access || 'use'] || AccessRoleIds.AGENT_VIEWER;
  await bulkUpdateResourcePermissions({
    resourceType: ResourceType.AGENT,
    resourceId: agent._id,
    updatedPrincipals: [{ type: PrincipalType.USER, id: String(recipient._id), accessRoleId }],
    revokedPrincipals: [],
    grantedBy: req.user.id,
  });
  return { agent_id: agent.id, shared_with: recipient.email, access: args.access || 'use' };
}

async function actionUnshare(args, req) {
  if (!args.agent_id) throw coded('agent_id is required.', 'AGENT_ID_REQUIRED');
  const agent = await loadAgentOrThrow(args.agent_id);
  await requireResourcePermission(req, agent._id, PermissionBits.SHARE);
  const recipient = await resolveRecipient(args.recipient_email);
  await bulkUpdateResourcePermissions({
    resourceType: ResourceType.AGENT,
    resourceId: agent._id,
    updatedPrincipals: [],
    revokedPrincipals: [{ type: PrincipalType.USER, id: String(recipient._id) }],
    grantedBy: req.user.id,
  });
  return { agent_id: agent.id, unshared: recipient.email };
}

const ACTIONS = {
  list: actionList,
  get: actionGet,
  create: actionCreate,
  update: actionUpdate,
  versions: actionVersions,
  diff: actionDiff,
  archive: actionArchive,
  restore: actionRestore,
  share: actionShare,
  unshare: actionUnshare,
};

/**
 * @param {{ req: Express.Request }} params
 */
function createAgentManagementTool({ req }) {
  return new DynamicStructuredTool({
    name: TOOL_NAME,
    description: TOOL_DESCRIPTION,
    schema: TOOL_SCHEMA,
    responseFormat: 'content',
    func: async (args) => {
      const handler = ACTIONS[args?.action];
      if (!handler) {
        return `[AGENT_ACTION_UNKNOWN] "${args?.action}" is not a supported action.`;
      }
      if (!req?.user?.id || !req?.user?.role) {
        return '[AGENT_ACCESS_DENIED] Authentication required.';
      }
      try {
        const result = await handler(args || {}, req);
        return JSON.stringify(result);
      } catch (error) {
        if (error.code) {
          return `[${error.code}] ${error.message}`;
        }
        return `[AGENT_MANAGEMENT_ERROR] ${error.message}`;
      }
    },
  });
}

module.exports = {
  createAgentManagementTool,
  summarizeAgent,
};
