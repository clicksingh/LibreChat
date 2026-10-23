/**
 * W10b — THE ADMIN AUDIT-LOG CONTRACT: action registry, vocabulary, and the recorder's input shape.
 *
 * `docs/GM-RULING-ABSOLUTE-ADMIN-POLICY-AND-AUDIT-SEAM-20261023.md` §2 (GM-81),
 * `docs/GM-RULING-ADMIN-ADMINISTERED-PERMISSIONS-20261023.md` §6.2 (GM-79 rule 2).
 *
 * WHY THIS FILE EXISTS SEPARATELY FROM THE SCHEMA
 * `~/schema/auditLog` owns the STORE (fields, indexes, append-only guards). This file owns the
 * VOCABULARY the store and the recorder must agree on — which actions exist, which outcomes and
 * severities are meaningful, and what a caller may hand to `recordAuditEntry`. Splitting them means
 * the registry is importable by the method layer, the admin barrel and a spec without dragging a
 * Mongoose schema in, which is the same split `~/admin/devicePolicy` already uses for the
 * device-policy vocabulary.
 *
 * WHY THE SIX NAMES ARE SPELLED OUT HERE (and how the duplication is prevented from drifting)
 * `packages/api/src/admin/devicePolicy/types.ts` already exports the six `device_policy.*` action
 * names as a frozen list. This package CANNOT import it: `@librechat/api` depends on
 * `@librechat/data-schemas`, so that import would be a dependency cycle — and GM-81 rule 1 forbids
 * reaching for an absent module. The names are therefore registered here, and the W10b spec closes
 * the loop in the only way that is actually checkable: it imports `DEVICE_POLICY_AUDIT_ACTION_NAMES`
 * from `@librechat/api` and asserts this registry contains EXACTLY those six. If either list moves,
 * the test fails rather than the audit path quietly rejecting a real action.
 *
 * `grant.assigned` / `grant.removed` are upstream's existing `AUDIT_ACTIONS` entries (origin/main
 * `6a63531eb`). They are carried so this collection can accept the events upstream already emits —
 * the rebase then MERGES the registries instead of forking them.
 */

/** Record-format version, so a future migration can read older rows. */
export const AUDIT_LOG_SCHEMA_VERSION = 1;

/** The counter document id: the single chain head for the whole log. */
export const AUDIT_LOG_COUNTER_ID = 'adminAudit';

/** Actions upstream's `AUDIT_ACTIONS` registry already knows. */
export const AUDIT_LOG_UPSTREAM_ACTIONS = ['grant.assigned', 'grant.removed'] as const;

/** The six `device_policy.*` action names (GM-79 rule 2), kept verbatim from W10's frozen list. */
export const AUDIT_LOG_DEVICE_POLICY_ACTIONS = [
  'device_policy.scope_created',
  'device_policy.scope_updated',
  'device_policy.scope_deleted',
  'device_policy.assignment_set',
  'device_policy.assignment_removed',
  'device_policy.tenant_default_set',
] as const;

/**
 * The action registry. `action` is a schema enum, so an unregistered action cannot be stored.
 *
 * The type is declared BEFORE the value and the value carries an explicit annotation because this
 * package's declaration build runs with `isolatedDeclarations`: an exported array built with SPREAD
 * elements cannot be inferred during declaration emit (TS9018), so the shape is stated instead of
 * inferred. Declaring the union separately also gives callers the precise literal type.
 */
export type AuditLogAction =
  | (typeof AUDIT_LOG_UPSTREAM_ACTIONS)[number]
  | (typeof AUDIT_LOG_DEVICE_POLICY_ACTIONS)[number];

export const AUDIT_LOG_ACTIONS: readonly AuditLogAction[] = [
  ...AUDIT_LOG_UPSTREAM_ACTIONS,
  ...AUDIT_LOG_DEVICE_POLICY_ACTIONS,
];

/** Outcomes and severities, mirroring the upstream contract's own vocabulary. */
export const AUDIT_LOG_OUTCOMES = ['success', 'failure'] as const;
export const AUDIT_LOG_SEVERITIES = ['info', 'warning', 'critical'] as const;

export type AuditLogOutcome = (typeof AUDIT_LOG_OUTCOMES)[number];
export type AuditLogSeverity = (typeof AUDIT_LOG_SEVERITIES)[number];

/**
 * Actor / target / input, structurally identical to the types in
 * `packages/api/src/admin/devicePolicy/audit.ts` (`AuditActorInput`, `AuditTargetInput`,
 * `RecordAuditEntryInput`). They are restated rather than imported for the dependency-direction
 * reason above; the shapes are the contract GM-81 binds to, and they are asserted field-by-field in
 * the W10b spec against the entry the W10 writer actually produces.
 */
export interface AuditLogActorInput {
  type: string;
  id?: string | null;
  name: string;
}

export interface AuditLogTargetInput {
  type: string;
  id?: string | null;
  name?: string | null;
}

/** What `recordAuditEntry` accepts. Mirrors `RecordAuditEntryInput` upstream. */
export interface RecordAuditEntryInput {
  action: string;
  category?: string;
  outcome?: string;
  severity?: string;
  actor: AuditLogActorInput;
  target: AuditLogTargetInput;
  metadata?: Record<string, unknown> | null;
  context?: Record<string, unknown> | null;
  tenantId?: string | null;
}

/** Options `recordAuditEntry` accepts. Mirrors `{ failClosed?: boolean }` upstream. */
export interface RecordAuditEntryOptions {
  /**
   * When true (and by default — see `~/methods/auditLog`), an entry that cannot be durably written
   * is an ERROR rather than a warning. GM-81 rule 4 makes this the load-bearing behaviour: the
   * device-policy write handlers pass `failClosed: true`, so a store that cannot audit cannot be
   * changed either.
   */
  failClosed?: boolean;
}