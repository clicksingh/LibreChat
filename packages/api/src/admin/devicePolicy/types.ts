/**
 * W10 — device-policy types: the resolution order and its report (GM-76 rule 3, GM-79).
 *
 * The resolution order, exactly as `docs/GM-RULING-ADMIN-ADMINISTERED-PERMISSIONS-20261023.md`
 * §3.3 states it and `docs/GM-PLAN-ROLE-SCOPED-POLICY-AND-INTEGRATION-20261023.md` §2 fixes it:
 *
 *     user override  ->  group  ->  role  ->  tenant default  ->  FAIL CLOSED (nothing enabled)
 *
 * Every type here exists to make one of those steps auditable rather than implicit: which level
 * answered, which scope it named, and — for every tool that is NOT enabled — why not and whose
 * decision that was.
 */

import type {
  AdminDevicePolicyAssignment,
  AdminDeviceTenantDefault,
  AdminDeviceToolScope,
  DevicePolicyLevel,
  DevicePolicyLevelTrace,
  DevicePolicyProvenance,
  DevicePolicyStage,
  DevicePolicyValidation,
  IDevicePolicyAssignment,
  IDeviceTenantPolicyDefault,
  IDeviceToolScope,
} from '@librechat/data-schemas';

export type {
  AdminDevicePolicyAssignment,
  AdminDeviceTenantDefault,
  AdminDeviceToolScope,
  DevicePolicyLevel,
  DevicePolicyLevelOutcome,
  DevicePolicyLevelTrace,
  DevicePolicyPrincipal,
  DevicePolicyProvenance,
  DevicePolicyStage,
  DevicePolicyValidation,
  IDevicePolicyAssignment,
  IDeviceTenantPolicyDefault,
  IDeviceToolScope,
} from '@librechat/data-schemas';

/** The report schema id (what the panel and a device's policy document consume). */
export const DEVICE_POLICY_RESOLUTION_SCHEMA = 'cbhr.rdc.device-policy-resolution/1';

/**
 * The audit action names for device-policy changes (GM-79 rule 2).
 *
 * Namespaced `<domain>.<verb>` under the `config` audit category. Upstream's `AUDIT_ACTIONS`
 * registry currently knows only `grant.assigned` and `grant.removed` and the action is a Mongoose
 * enum, so the rebase adds these six names in the same commit that wires the recorder — see
 * `audit.ts` for why the write paths are closed until then.
 *
 * The explicit annotation is required by this package's declaration build
 * (`isolatedDeclarations`, enforced by tsdown's dts pass): the W10 barrel export puts this module
 * in the package's declaration graph, so every exported value here must carry its own type. The
 * literal keys are kept so the rebase's registry edit is key-checked.
 */
export const DEVICE_POLICY_AUDIT_ACTIONS: Readonly<{
  SCOPE_CREATED: 'device_policy.scope_created';
  SCOPE_UPDATED: 'device_policy.scope_updated';
  SCOPE_DELETED: 'device_policy.scope_deleted';
  ASSIGNMENT_SET: 'device_policy.assignment_set';
  ASSIGNMENT_REMOVED: 'device_policy.assignment_removed';
  TENANT_DEFAULT_SET: 'device_policy.tenant_default_set';
}> = Object.freeze({
  SCOPE_CREATED: 'device_policy.scope_created',
  SCOPE_UPDATED: 'device_policy.scope_updated',
  SCOPE_DELETED: 'device_policy.scope_deleted',
  ASSIGNMENT_SET: 'device_policy.assignment_set',
  ASSIGNMENT_REMOVED: 'device_policy.assignment_removed',
  TENANT_DEFAULT_SET: 'device_policy.tenant_default_set',
});

/**
 * The refusal/decision vocabulary of the SCOPE layer.
 *
 * The registry's own codes are preserved untouched and are reused verbatim wherever the registry
 * is what refused (`TOOL_NOT_PERMITTED`, `TOOL_NOT_ENABLED_AT_STAGE`, `OWNER_APPROVAL_REQUIRED`, …).
 * The codes below are the ones only the scope layer can emit:
 *
 *   DEVICE_POLICY_SCOPE_NOT_GRANTED   — the winning scope does not list the tool
 *   DEVICE_POLICY_NOT_CONFIGURED      — no level answered; fail closed (GM-74/GM-76)
 *   DEVICE_POLICY_SCOPE_INACTIVE      — an explicitly disabled scope: nothing enabled
 *   DEVICE_POLICY_SCOPE_UNKNOWN       — the scope a level named is not in the data
 *   DEVICE_POLICY_SCOPE_MALFORMED     — the stored scope could not be read as a scope
 *   DEVICE_POLICY_TOOL_NOT_IN_CATALOG — a scope listed a name that is not a tool
 */
export const DEVICE_POLICY_CODES: Readonly<{
  SCOPE_NOT_GRANTED: 'DEVICE_POLICY_SCOPE_NOT_GRANTED';
  NOT_CONFIGURED: 'DEVICE_POLICY_NOT_CONFIGURED';
  SCOPE_INACTIVE: 'DEVICE_POLICY_SCOPE_INACTIVE';
  SCOPE_UNKNOWN: 'DEVICE_POLICY_SCOPE_UNKNOWN';
  SCOPE_MALFORMED: 'DEVICE_POLICY_SCOPE_MALFORMED';
  TOOL_NOT_IN_CATALOG: 'DEVICE_POLICY_TOOL_NOT_IN_CATALOG';
}> = Object.freeze({
  SCOPE_NOT_GRANTED: 'DEVICE_POLICY_SCOPE_NOT_GRANTED',
  NOT_CONFIGURED: 'DEVICE_POLICY_NOT_CONFIGURED',
  SCOPE_INACTIVE: 'DEVICE_POLICY_SCOPE_INACTIVE',
  SCOPE_UNKNOWN: 'DEVICE_POLICY_SCOPE_UNKNOWN',
  SCOPE_MALFORMED: 'DEVICE_POLICY_SCOPE_MALFORMED',
  TOOL_NOT_IN_CATALOG: 'DEVICE_POLICY_TOOL_NOT_IN_CATALOG',
});

/** Who answered "why is this tool off?" — the four levels, plus law and the absence of data. */
export const DEVICE_POLICY_DENIED_BY: Readonly<{
  USER: 'user';
  GROUP: 'group';
  ROLE: 'role';
  TENANT: 'tenant';
  /** Server law: the stage ladder, the always/pilot hard denies, the approval tier. */
  LAW: 'law';
  /** No level answered at all: fail closed. */
  NONE: 'none';
}> = Object.freeze({
  USER: 'user',
  GROUP: 'group',
  ROLE: 'role',
  TENANT: 'tenant',
  /** Server law: the stage ladder, the always/pilot hard denies, the approval tier. */
  LAW: 'law',
  /** No level answered at all: fail closed. */
  NONE: 'none',
});

/** Fixed explanation per scope-layer code. No payload, no caller-supplied text. */
export const DEVICE_POLICY_DETAILS: Readonly<Record<string, string>> = Object.freeze({
  [DEVICE_POLICY_CODES.SCOPE_NOT_GRANTED]:
    'Not granted by the tool scope that resolves for this principal. A scope only ever narrows what the server permits, so adding a tool here is an admin action, not a user one.',
  [DEVICE_POLICY_CODES.NOT_CONFIGURED]:
    'No user, group, role or tenant policy resolved for this principal, so nothing is enabled (fail closed). An admin must assign a tool scope.',
  [DEVICE_POLICY_CODES.SCOPE_INACTIVE]:
    'The tool scope that resolves for this principal is retired, so it enables nothing. Re-activate it or assign a different scope.',
  [DEVICE_POLICY_CODES.SCOPE_UNKNOWN]:
    'The policy names a tool scope that does not exist, so this level enabled nothing. Assign an existing scope.',
  [DEVICE_POLICY_CODES.SCOPE_MALFORMED]:
    'The stored tool scope could not be read as a scope, so it enabled nothing rather than being guessed at.',
  [DEVICE_POLICY_CODES.TOOL_NOT_IN_CATALOG]:
    'The tool scope lists a name that is not one of the supported Desktop Commander tools, so it cannot be enabled.',
});

/** One tool row in the resolution report. */
export type DevicePolicyToolDecision = {
  tool: string;
  enabled: boolean;
  requiresApproval: boolean;
  /** The registry's reason code, or a scope-layer code; `null` when the tool is plainly enabled. */
  reasonCode: string | null;
  /** The level whose policy decided this row (`user`|`group`|`role`|`tenant`|`law`|`none`). */
  deniedBy: string;
  /** The scope that decided it, when a scope did. */
  toolScopeId: string | null;
  detail: string | null;
};

/** The resolver's input. Every field is server-resolved; none of it comes from the request. */
export type DevicePolicyResolutionInput = {
  /** The principal to resolve for. */
  principal: {
    userId: string;
    role: string;
    groupIds?: readonly string[];
    tenantId?: string;
  };
  /** The tenant-default record, when the tenant has one (`tenant: { defaultToolScopeId }`). */
  tenantDefault?: IDeviceTenantPolicyDefault | AdminDeviceTenantDefault | null;
  /** Every assignment that could apply. Non-matching principals are filtered by the resolver. */
  assignments?: readonly (IDevicePolicyAssignment | AdminDevicePolicyAssignment)[];
  /** Resolves a scope id to its stored record. Returning undefined means "not in the data". */
  getScope: (toolScopeId: string) => IDeviceToolScope | AdminDeviceToolScope | undefined;
  /**
   * The stage the SERVER is currently at (`deviceCapabilityPolicy.CAPABILITY_STAGES`). A scope may
   * narrow it; it can never widen it.
   */
  serverStage: string;
  /** Apply the pilot deny-list overlay. Defaults to true, like the registry's own default. */
  pilot?: boolean;
  /**
   * The enforcement primitives: the real `deviceCapabilityPolicy` + `deviceToolRegistry` on the
   * server. Injected so this module reuses the law instead of restating it.
   */
  primitives: unknown;
};

/** The resolver's output: the effective tool set, the trace, and a reason for everything excluded. */
export type DevicePolicyResolution = {
  schema: string;
  /** The resolved stage: the stricter of the server's stage and the winning scope's stage. */
  stage: DevicePolicyStage | string;
  /** True when no level answered (or the winning scope enables nothing): nothing is enabled. */
  failClosed: boolean;
  /** Which level answered. `null` when none did. */
  governingLevel: DevicePolicyLevel | null;
  /** The scope that answered. `null` when none did, or when it was unknown/malformed/inactive. */
  resolvedToolScopeId: string | null;
  resolvedToolScopeName: string | null;
  /** A content-derived version the device pins (GM-78 rule 4). Changes whenever the answer changes. */
  policyVersion: string;
  /** The effective tool set, catalog order. */
  tools: readonly string[];
  /** The subset of `tools` that stays approval-gated (tier 3) — never a plain allow. */
  approvalRequired: readonly string[];
  /** Every tool the resolver considered, with its reason and its decision-maker. */
  decisions: readonly DevicePolicyToolDecision[];
  /** Scope value provenance: "why is this tool on?" answered per enabled tool. */
  provenance: readonly DevicePolicyProvenance[];
  /** What each level did, in resolution order. Always length 4. */
  trace: readonly DevicePolicyLevelTrace[];
  counts: {
    enabled: number;
    approvalRequired: number;
    denied: number;
    /** Tools the winning scope listed that are not in the catalog. */
    notInCatalog: number;
  };
};

/** A tool floor as the registry accepts it (`{ schema, enabled }`). */
export type DeviceToolFloor = {
  schema?: string;
  enabled: readonly string[];
};

/** One exclusion row as `deviceToolRegistry.effectiveTools` reports it. */
export type ToolExclusion = {
  tool: string;
  reason: string;
  deniedBy: string;
  code: string;
  httpStatus: number;
  detail: string;
};

/** The report `deviceToolRegistry.effectiveTools` returns (the slice the resolver reads). */
export type ToolEffectiveReport = {
  schema: string;
  ceiling: {
    stage: string;
    pilot: boolean;
    toolCount: number;
    hardDenied: readonly { tool: string; code: string; httpStatus: number; reason: string; scope: string }[];
    withheldByTier1Law: readonly string[];
  };
  deviceFloor: { shape: string };
  enabled: readonly string[];
  approvalRequired: readonly string[];
  excluded: readonly ToolExclusion[];
  counts: Record<string, number>;
  failClosed: boolean;
};

/** The registry functions the resolver (and the guards) consume. */
export interface ToolRegistryPrimitives {
  authorizeDispatch: (
    toolName: string,
    params: { ceiling: unknown; deviceFloor: unknown },
  ) => {
    tool: string | null;
    decision: string;
    allowed: boolean;
    requiresApproval: boolean;
    code: string | null;
    httpStatus: number | null;
    reason: string | null;
    reasonCode: string | null;
    deniedBy: string;
    tier: number | null;
  };
  effectiveTools: (params: { ceiling: unknown; deviceFloor: unknown }) => ToolEffectiveReport;
  assertDispatchAllowed?: (toolName: string, params: unknown) => unknown;
}

/** Admin-handler dependency shapes (structural, so the route injects real DB functions). */
export type AdminDevicePolicyDeps = {
  listScopes: (options?: {
    limit?: number;
    offset?: number;
    tenantId?: string;
  }) => Promise<unknown[]>;
  countScopes: (options?: { tenantId?: string }) => Promise<number>;
  getToolScope: (id: string, options?: { tenantId?: string }) => Promise<unknown | null>;
  upsertToolScope: (scope: unknown, options?: { tenantId?: string }) => Promise<unknown | null>;
  deleteToolScope: (id: string, options?: { tenantId?: string }) => Promise<unknown | null>;
  listAssignments: (options?: {
    tenantId?: string;
    principalType?: string;
    principalId?: string;
  }) => Promise<unknown[]>;
  getAssignment: (
    principalType: string,
    principalId: string,
    options?: { tenantId?: string },
  ) => Promise<unknown | null>;
  upsertAssignment: (assignment: unknown, options?: { tenantId?: string }) => Promise<unknown | null>;
  deleteAssignment: (
    principalType: string,
    principalId: string,
    options?: { tenantId?: string },
  ) => Promise<unknown | null>;
  getTenantDefault: (options?: { tenantId?: string }) => Promise<unknown | null>;
  upsertTenantDefault: (
    input: { defaultToolScopeId: string },
    options?: { tenantId?: string },
  ) => Promise<unknown | null>;
  getRoleByName?: (name: string) => Promise<unknown | null>;
  findGroupById?: (id: string) => Promise<unknown | null>;
  findUser?: (criteria: Record<string, unknown>) => Promise<unknown | null>;
  recordAuditEntry?: (input: unknown, options?: { failClosed?: boolean }) => Promise<unknown>;
  primitives?: unknown;
};

export type { DevicePolicyValidation };