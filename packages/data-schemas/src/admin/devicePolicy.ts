/**
 * W10 — admin device-policy: DATA SHAPES (GM-76, GM-79).
 *
 * `docs/GM-PLAN-ROLE-SCOPED-POLICY-AND-INTEGRATION-20261023.md` §2, §3 (W10) and
 * `docs/GM-RULING-ADMIN-ADMINISTERED-PERMISSIONS-20261023.md` §3 (GM-76), §6 (GM-79).
 *
 * WHAT THIS FILE IS
 * The shape of the data an admin edits, and nothing else. It holds no resolution logic, no
 * request handling, no database access and no tool list: the resolution order lives in
 * `packages/api/src/admin/devicePolicy/`, the HTTP surface in
 * `api/server/routes/admin/devicePolicy.js`, and the tool catalog remains where it already is —
 * `api/server/services/Device/deviceCapabilityPolicy` (`TOOL_CATALOG`), which is the single
 * source of truth for which tools exist and at which stage each becomes admissible.
 *
 * GM-76's "no hardcoding" requirement, discharged structurally:
 *   1. The tool CATALOG is data, owned by the device capability policy — this file does not
 *      restate it, so it cannot drift from it.
 *   2. A TOOL SCOPE is data in the database. Adding, editing or retiring a scope is an admin
 *      action through the admin API, not a deploy. Nothing here is a literal scope.
 *   3. The TENANT DEFAULT is data (`defaultToolScopeId`), so changing what a new employee gets
 *      is an admin action.
 *   4. The resolution path reads the catalog and the resolved scope; it contains no literal tool
 *      list. A tool name that is not in the catalog can never be enabled, because the catalog is
 *      the only vocabulary the enforcement path understands.
 *
 * THE SHAPES (plan §2, "Shape of the assignment")
 *
 *   toolScope:  { id, name, description, tools: [catalog names], stage, ...presentation }
 *   role:       { ...existing role..., toolScopeId }      <- attached by W10b, not by W10
 *   group:      { ...existing group..., toolScopeId }     <- overrides role
 *   user:       { ...existing user..., toolScopeId }      <- overrides group
 *   tenant:     { defaultToolScopeId }
 *
 * Why an assignment is its own record rather than a field on the role/group/user document: W10's
 * write scope is **new files only** (plan §4 rule 1 — `roles.js`, `groups.js` and `users.js` are
 * HIGH-risk hot files with live branches in them). A separate assignment record lets every level
 * of the resolution order be administered and tested now, and W10b can attach `toolScopeId` to
 * the existing surfaces later without this record changing meaning: the resolver reads an
 * identity + a policy document, so it does not care which storage produced them.
 *
 * TWO VALUES THAT ARE NOT DATA
 * `lawDeniedToolNames` and the approval gate are deliberately absent from this file. They are
 * law, not policy: the scope layer may only ever NARROW them (see
 * `api/server/services/Device/deviceCapabilityPolicy`, which owns `ALWAYS_DENIED`, `PILOT_DENIED`
 * and `OWNER_APPROVAL_TOOLS`). A scope cannot name its way out of either.
 */

/** Record-format version of a stored tool scope, so a future migration can read old rows. */
export const DEVICE_TOOL_SCOPE_SCHEMA_VERSION = 1;

/** Document id used by the admin API and the resolver. Kept identical to `capabilities.ts` style. */
export const DEVICE_TOOL_SCOPE_SCHEMA = 'cbhr.rdc.device-tool-scope/1';

/** The tenant-default document id (`tenant: { defaultToolScopeId }`). */
export const DEVICE_TENANT_DEFAULT_SCHEMA = 'cbhr.rdc.device-tenant-default/1';

/**
 * The four levels of the resolution order (GM-76 rule 3), most specific first:
 *
 *     user override -> group -> role -> tenant default -> FAIL CLOSED (nothing enabled)
 *
 * Declared as data so the resolver, the API and the tests all read one list instead of three
 * restatements of the same order.
 */
export const DEVICE_POLICY_LEVELS = ['user', 'group', 'role', 'tenant'] as const;

export type DevicePolicyLevel = (typeof DEVICE_POLICY_LEVELS)[number];

/** The principal types that can appear in an assignment or in an identity. */
export const DEVICE_POLICY_PRINCIPAL_TYPES = ['user', 'group', 'role'] as const;

export type DevicePolicyPrincipalType = (typeof DEVICE_POLICY_PRINCIPAL_TYPES)[number];

/**
 * The capability stages, mirroring `CAPABILITY_STAGES` in the device capability policy.
 *
 * `full` is the widest of the four and is a REAL step of the ladder (see that module's "STAGE
 * INTERPRETATION"). A scope may declare a narrower stage than the server's current one; it may
 * never declare a wider one, which the resolver enforces by taking the stricter of the two.
 */
export const DEVICE_POLICY_STAGES = ['A', 'B', 'C', 'full'] as const;

export type DevicePolicyStage = (typeof DEVICE_POLICY_STAGES)[number];

/**
 * A named set of tools, as an admin edits it. Stored data — never a literal in code.
 *
 * `tools` is a list of catalog names with no wildcard semantics whatsoever: there is no `*`, no
 * `all`, and an unknown name can never enable anything (the enforcement path only understands
 * catalog tools). A scope is therefore a subset of the catalog by construction, and `stage` can
 * only narrow the server's own stage.
 */
export type IDeviceToolScope = {
  /** Stable slug: lowercase, digits and single hyphens. The resolver keys off this. */
  id: string;
  /** Human label for the admin panel. */
  name: string;
  /** Human explanation of who this scope is for. */
  description?: string;
  /** Catalog tool names this scope enables. Approval-gated members stay approval-gated. */
  tools: string[];
  /** The stage this scope narrows to; the resolved stage is the stricter of this and the server's. */
  stage: DevicePolicyStage;
  /** Retired scopes keep their history and their assignments but enable nothing. */
  isActive: boolean;
  /**
   * Bumped by the admin API on every content change. Together with `updatedAt` it feeds the
   * resolved policy version a device pins, so a device holding an older policy is detectable
   * (GM-78 rule 4).
   */
  version: number;
  tenantId?: string;
  createdAt?: Date;
  updatedAt?: Date;
};

/** A stored tool scope, as the admin API returns it (no Mongoose internals). */
export type AdminDeviceToolScope = {
  id: string;
  name: string;
  description: string;
  tools: string[];
  stage: DevicePolicyStage;
  isActive: boolean;
  version: number;
  tenantId?: string;
  createdAt?: string;
  updatedAt?: string;
};

/** `POST/PATCH /api/admin/device-policy/scopes` request body. */
export type DeviceToolScopeInput = {
  name?: unknown;
  description?: unknown;
  tools?: unknown;
  stage?: unknown;
  isActive?: unknown;
};

/**
 * An assignment of a scope to a principal.
 *
 *   principalType 'role'  -> role-level assignment (plan §2: `role.toolScopeId`)
 *   principalType 'group' -> group-level assignment (overrides role)
 *   principalType 'user'  -> user-level assignment (overrides group)
 *
 * `priority` resolves the one case the plan's prose does not: a user in two groups, or holding two
 * assigned roles. Higher `priority` wins; ties break on the lexicographically smallest `toolScopeId`,
 * so resolution is deterministic and two administrators reading the same data get the same answer.
 */
export type IDevicePolicyAssignment = {
  principalType: DevicePolicyPrincipalType;
  /** The role NAME, the group id, or the user id — matching the existing admin surfaces. */
  principalId: string;
  /** The scope this principal resolves to. */
  toolScopeId: string;
  /** Higher wins when a principal matches more than one assignment at the same level. */
  priority: number;
  isActive: boolean;
  tenantId?: string;
  createdAt?: Date;
  updatedAt?: Date;
};

/** An assignment as the admin API returns it. */
export type AdminDevicePolicyAssignment = {
  principalType: DevicePolicyPrincipalType;
  principalId: string;
  toolScopeId: string;
  priority: number;
  isActive: boolean;
  tenantId?: string;
  createdAt?: string;
  updatedAt?: string;
};

/** `PUT /api/admin/device-policy/assignments` request body. */
export type DevicePolicyAssignmentInput = {
  principalType?: unknown;
  principalId?: unknown;
  toolScopeId?: unknown;
  priority?: unknown;
  isActive?: unknown;
};

/**
 * The tenant default (plan §2: `tenant: { defaultToolScopeId }`).
 *
 * A tenant with no default resolves to nothing, which is GM-74/GM-76's fail-closed floor: an
 * absent value at every level enables nothing.
 */
export type IDeviceTenantPolicyDefault = {
  /** Tenant the default applies to; absent means the platform-wide default. */
  tenantId?: string;
  /** The scope a principal resolves to when no user, group or role assignment applies. */
  defaultToolScopeId: string;
  version: number;
  updatedAt?: Date;
};

/** The tenant default as the admin API returns it. */
export type AdminDeviceTenantDefault = {
  tenantId?: string;
  defaultToolScopeId: string;
  version: number;
  updatedAt?: string;
};

/** `PUT /api/admin/device-policy/tenant-default` request body. */
export type DeviceTenantDefaultInput = {
  defaultToolScopeId?: unknown;
};

/** The identity the resolver is given. Everything here is server-resolved, never request-supplied. */
export type DevicePolicyPrincipal = {
  userId: string;
  /** The user's role NAME, as the existing role surface stores it. */
  role: string;
  /** Group ids the user belongs to. */
  groupIds: string[];
  tenantId?: string;
};

/** Why a resolution level was or was not the winner. */
export type DevicePolicyLevelOutcome =
  | 'selected'
  | 'no-assignment'
  | 'not-requested'
  | 'scope-missing'
  | 'scope-inactive'
  /**
   * A scope that exists but does not satisfy its own shape. The resolver has always emitted this
   * (it is how a malformed narrow scope STOPS the walk instead of falling through to a wider level),
   * but the member was missing from this union — so a consumer switching on the published type would
   * silently mishandle the single most security-relevant outcome. Added to make the type match
   * runtime.
   */
  | 'scope-malformed';

/** One row of the resolution trace: which level was consulted, and what it decided. */
export type DevicePolicyLevelTrace = {
  level: DevicePolicyLevel;
  outcome: DevicePolicyLevelOutcome;
  /** The scope this level pointed at, when it had one (even if it lost or was unusable). */
  toolScopeId: string | null;
  /** The principal whose assignment supplied it (`null` at the tenant level). */
  principalId: string | null;
  priority: number | null;
};

/** One provenance row: the scope value that answered "why is this tool on?" */
export type DevicePolicyProvenance = {
  tool: string;
  level: DevicePolicyLevel;
  toolScopeId: string;
  toolScopeName: string;
  decision: 'scope' | 'law';
  requiresApproval: boolean;
  reasonCode: string | null;
};

/**
 * Validation result for a scope or assignment body.
 *
 * `ok` discriminates the union, so a caller that ignores the checks cannot reach `.errors`
 * without narrowing first.
 */
export type DevicePolicyValidation =
  | { ok: true; errors: [] }
  | { ok: false; errors: string[] };

/** Bounds that keep a stored scope within what the enforcement path can honour. */
export const DEVICE_POLICY_MAX_SCOPE_ID_LENGTH = 128;
export const DEVICE_POLICY_MAX_NAME_LENGTH = 500;
export const DEVICE_POLICY_MAX_DESCRIPTION_LENGTH = 2000;
export const DEVICE_POLICY_MAX_TOOLS = 256;
export const DEVICE_POLICY_MAX_PRIORITY = 10000;

/** Control characters never belong in an id, a name or a tool name. */
const CONTROL_CHAR_RE = /\p{Cc}/u;

/**
 * Reserved path segment guard, mirroring `RESERVED_ROLE_NAMES` in `packages/api/src/admin/roles.ts`:
 * a scope id becomes a URL segment, so an id that collides with a sub-path would make the API
 * ambiguous for its consumers.
 */
const RESERVED_SCOPE_IDS = new Set(['assignments', 'tenant-default', 'resolve', 'effective']);

/** The canonical scope-id spelling: `lower-kebab`, no leading/trailing/double hyphen. */
const SCOPE_ID_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

const OK: DevicePolicyValidation = { ok: true, errors: [] };

const fail = (errors: string[]): DevicePolicyValidation => ({ ok: false, errors });

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/**
 * Validates a tool-scope ID: required, canonical spelling, bounded, not a reserved path segment,
 * no control characters.
 *
 * @returns an error string, or `null` when the id is usable
 */
export function validateDeviceToolScopeId(value: unknown): string | null {
  if (typeof value !== 'string' || value.trim().length === 0) {
    return 'id must be a non-empty string';
  }
  const id = value.trim();
  if (id.length > DEVICE_POLICY_MAX_SCOPE_ID_LENGTH) {
    return `id must not exceed ${DEVICE_POLICY_MAX_SCOPE_ID_LENGTH} characters`;
  }
  if (CONTROL_CHAR_RE.test(id)) {
    return 'id contains invalid characters';
  }
  if (!SCOPE_ID_RE.test(id)) {
    return 'id must be lower-kebab-case (letters, digits and single hyphens)';
  }
  if (RESERVED_SCOPE_IDS.has(id)) {
    return 'id is a reserved path segment';
  }
  return null;
}

/** Validates a human label. Required on create, bounded, no control characters. */
export function validateDeviceToolScopeName(value: unknown, required: boolean): string | null {
  if (value === undefined) {
    return required ? 'name is required' : null;
  }
  if (typeof value !== 'string' || value.trim().length === 0) {
    return required ? 'name is required' : 'name must be a non-empty string';
  }
  const name = value.trim();
  if (name.length > DEVICE_POLICY_MAX_NAME_LENGTH) {
    return `name must not exceed ${DEVICE_POLICY_MAX_NAME_LENGTH} characters`;
  }
  if (CONTROL_CHAR_RE.test(name)) {
    return 'name contains invalid characters';
  }
  return null;
}

/** Validates a description. Optional, bounded. */
export function validateDeviceToolScopeDescription(value: unknown): string | null {
  if (value === undefined) {
    return null;
  }
  if (typeof value !== 'string') {
    return 'description must be a string';
  }
  if (value.length > DEVICE_POLICY_MAX_DESCRIPTION_LENGTH) {
    return `description must not exceed ${DEVICE_POLICY_MAX_DESCRIPTION_LENGTH} characters`;
  }
  return null;
}

/** True when the value is one of the four declared stages. */
export function isDevicePolicyStage(value: unknown): value is DevicePolicyStage {
  return typeof value === 'string' && (DEVICE_POLICY_STAGES as readonly string[]).includes(value);
}

/**
 * Validates a scope's `tools` list.
 *
 * The list must be an array of unique, non-empty, bounded strings. There is deliberately NO
 * wildcard sentinel: `*`, `all` and friends are ordinary (unknown) names that enable nothing,
 * exactly as in the device-floor parser, so no spelling of "everything" can widen a scope.
 * Membership in the catalog is NOT checked here — the catalog belongs to the device capability
 * policy, and an unknown name is refused by the enforcement path with a reason rather than
 * rejected at write time, so a catalog that later gains a tool does not require a data migration.
 */
export function validateDeviceToolScopeTools(value: unknown): string | null {
  if (value === undefined) {
    return 'tools is required';
  }
  if (!Array.isArray(value)) {
    return 'tools must be an array of catalog tool names';
  }
  if (value.length > DEVICE_POLICY_MAX_TOOLS) {
    return `tools must not list more than ${DEVICE_POLICY_MAX_TOOLS} entries`;
  }
  const seen = new Set<string>();
  for (const entry of value) {
    if (typeof entry !== 'string' || entry.trim().length === 0) {
      return 'tools must contain only non-empty strings';
    }
    const tool = entry.trim();
    if (tool.length > DEVICE_POLICY_MAX_SCOPE_ID_LENGTH) {
      return 'tools contains an over-long tool name';
    }
    if (CONTROL_CHAR_RE.test(tool)) {
      return 'tools contains invalid characters';
    }
    if (seen.has(tool)) {
      return `tools lists "${tool}" more than once`;
    }
    seen.add(tool);
  }
  return null;
}

/**
 * Validates a full scope write body. Collects every problem rather than stopping at the first, so
 * an admin fixing a form sees all of them.
 */
export function validateDeviceToolScopeBody(
  body: unknown,
  { requireId = true, requireName = true }: { requireId?: boolean; requireName?: boolean } = {},
): DevicePolicyValidation {
  if (!isPlainRecord(body)) {
    return fail(['request body must be an object']);
  }

  const errors: string[] = [];

  if (requireId) {
    const idError = validateDeviceToolScopeId(body.id);
    if (idError !== null) {
      errors.push(idError);
    }
  }

  const nameError = validateDeviceToolScopeName(body.name, requireName);
  if (nameError !== null) {
    errors.push(nameError);
  }

  const descriptionError = validateDeviceToolScopeDescription(body.description);
  if (descriptionError !== null) {
    errors.push(descriptionError);
  }

  const toolsError = validateDeviceToolScopeTools(body.tools);
  if (toolsError !== null) {
    errors.push(toolsError);
  }

  if (!isDevicePolicyStage(body.stage)) {
    errors.push(`stage must be one of ${DEVICE_POLICY_STAGES.join(', ')}`);
  }

  if (body.isActive !== undefined && typeof body.isActive !== 'boolean') {
    errors.push('isActive must be a boolean');
  }

  return errors.length === 0 ? OK : fail(errors);
}

/**
 * Validates an assignment write body. `principalId` is intentionally only shape-checked: the role
 * name, group id and user id spaces belong to the existing admin surfaces, and the route asks the
 * database whether the principal exists rather than re-implementing those rules here.
 */
export function validateDevicePolicyAssignmentBody(body: unknown): DevicePolicyValidation {
  if (!isPlainRecord(body)) {
    return fail(['request body must be an object']);
  }

  const errors: string[] = [];

  if (
    typeof body.principalType !== 'string' ||
    !(DEVICE_POLICY_PRINCIPAL_TYPES as readonly string[]).includes(body.principalType)
  ) {
    errors.push(`principalType must be one of ${DEVICE_POLICY_PRINCIPAL_TYPES.join(', ')}`);
  }

  if (typeof body.principalId !== 'string' || body.principalId.trim().length === 0) {
    errors.push('principalId is required');
  } else if (CONTROL_CHAR_RE.test(body.principalId)) {
    errors.push('principalId contains invalid characters');
  }

  const scopeIdError = validateDeviceToolScopeId(body.toolScopeId);
  if (scopeIdError !== null) {
    errors.push(`toolScopeId: ${scopeIdError}`);
  }

  if (
    body.priority !== undefined &&
    (typeof body.priority !== 'number' ||
      !Number.isInteger(body.priority) ||
      body.priority < 0 ||
      body.priority > DEVICE_POLICY_MAX_PRIORITY)
  ) {
    errors.push(`priority must be an integer between 0 and ${DEVICE_POLICY_MAX_PRIORITY}`);
  }

  if (body.isActive !== undefined && typeof body.isActive !== 'boolean') {
    errors.push('isActive must be a boolean');
  }

  return errors.length === 0 ? OK : fail(errors);
}

/** Validates a tenant-default write body. */
export function validateDeviceTenantDefaultBody(body: unknown): DevicePolicyValidation {
  if (!isPlainRecord(body)) {
    return fail(['request body must be an object']);
  }
  const scopeIdError = validateDeviceToolScopeId(body.defaultToolScopeId);
  return scopeIdError === null ? OK : fail([`defaultToolScopeId: ${scopeIdError}`]);
}

/**
 * The assistant text a tool name must be, to be handed to the resolver. Deliberately trivial: it
 * exists so the resolver's entry point cannot be fed a non-string by a caller that skipped
 * validation, not so that it can guess at aliases.
 */
export function isDevicePolicyToolName(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}