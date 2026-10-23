/**
 * W10 — THE RESOLVER: identity in, effective tool set out, with a reason and an owner for
 * everything excluded (GM-76 rule 3, GM-79 rules 3 and 6).
 *
 * `docs/GM-PLAN-ROLE-SCOPED-POLICY-AND-INTEGRATION-20261023.md` §2 and
 * `docs/GM-RULING-ADMIN-ADMINISTERED-PERMISSIONS-20261023.md` §3.
 *
 * THE ORDER, AND WHY IT IS FIRST-MATCH-WINS
 *
 *     user override  ->  group  ->  role  ->  tenant default  ->  FAIL CLOSED (nothing enabled)
 *
 * The first level that yields a usable scope wins outright; the levels below it are not consulted
 * and cannot add a tool back. That is what makes "a group overrides a role" a real statement rather
 * than a union: a user whose group hands them a narrow scope gets that scope even if their role's
 * scope is wider. A union would silently re-widen exactly the case the owner asked for narrow — a
 * non-technical group inside a technical role.
 *
 * Within one level, a principal may match more than one assignment (two groups; two roles). One
 * still wins: highest `priority`, then the lexicographically smallest `toolScopeId`. Deterministic
 * and explainable, and never a union.
 *
 * MAXIMAL NARROWING, NEVER WIDENING — four independent locks, all of them reusing existing law:
 *
 *   1. STAGE. The resolved stage is the STRICTER of the server's stage and the winning scope's
 *      stage. A scope that declares `full` while the server is at `A` resolves to `A`.
 *   2. CATALOG. A tool name is enabled only if it is one of the catalog tools
 *      (`deviceCapabilityPolicy.TOOL_CATALOG`). There are no aliases and no wildcards, so
 *      `*`, `all`, `everything` and misspellings are all just unknown names that enable nothing.
 *   3. TIER-1 LAW. The effective set is computed by `deviceToolRegistry.effectiveTools()` against
 *      the real `ceilingForStage()` document, which is where `track_ui_event` and
 *      `give_feedback_to_desktop_commander` are denied and where the four approval-gated tools stay
 *      gated. A scope that names them changes nothing: they are reported as excluded, with the law's
 *      own reason, and never appear in `tools` or in `approvalRequired`'s plain-allow sense.
 *   4. FAIL CLOSED. No usable scope at any level resolves to `tools: []` — never to "everything".
 *
 * WHAT THIS MODULE DOES NOT DO
 * It does not read a database, a request, a session, a token or a device claim. It is handed an
 * identity and the policy documents and returns a decision. Where those documents come from is the
 * handler's problem; that separation is what makes GM-79 rule 3 provable — there is no parameter
 * through which a request or a device could raise the answer, because the answer is a function of
 * server-loaded data only.
 */

import { createHash } from 'node:crypto';
import {
  DEVICE_POLICY_LEVELS,
  type DevicePolicyLevel,
  type DevicePolicyLevelOutcome,
  type DevicePolicyLevelTrace,
  type DevicePolicyProvenance,
  type DevicePolicyStage,
  type IDevicePolicyAssignment,
  type IDeviceTenantPolicyDefault,
  type IDeviceToolScope,
} from '@librechat/data-schemas';
import type {
  DevicePolicyDeniedBy,
  DevicePolicyPrimitivesLike,
  DevicePolicyResolution,
  DevicePolicyResolutionInput,
  DevicePolicyToolDecision,
  NormalizedToolScope,
} from './internal';
import {
  DEVICE_POLICY_CODES,
  DEVICE_POLICY_DENIED_BY,
  DEVICE_POLICY_DETAILS,
  DEVICE_POLICY_RESOLUTION_SCHEMA,
} from './types';

/** Typed failure for an unusable primitive port — a server-side wiring error, never a policy one. */
export class DevicePolicyError extends Error {
  code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'DevicePolicyError';
    this.code = code;
  }
}

const MAX_TOOL_LIST_ENTRIES = 256;
const MAX_SCOPE_ID_LENGTH = 128;

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/** `false` is meaningful data (an explicit opt-out); absent is not the same thing. */
function boolOr(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

function intOr(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isInteger(value) ? value : fallback;
}

/** Reads the injected primitives, or throws a wiring error naming what is missing. */
function readPrimitives(primitives: unknown): DevicePolicyPrimitivesLike {
  if (!isPlainRecord(primitives)) {
    throw new DevicePolicyError(
      'DEVICE_POLICY_PRIMITIVES_MISSING',
      'the resolver requires the device capability policy and tool registry primitives',
    );
  }
  const capabilityPolicy = primitives.capabilityPolicy as DevicePolicyPrimitivesLike['capabilityPolicy'];
  const toolRegistry = primitives.toolRegistry as DevicePolicyPrimitivesLike['toolRegistry'];

  if (!isPlainRecord(capabilityPolicy) || !isPlainRecord(toolRegistry)) {
    throw new DevicePolicyError(
      'DEVICE_POLICY_PRIMITIVES_MISSING',
      'the resolver requires both capabilityPolicy and toolRegistry primitives',
    );
  }
  if (
    typeof capabilityPolicy.capabilityCeiling !== 'function' ||
    typeof capabilityPolicy.getToolDefinition !== 'function' ||
    !Array.isArray(capabilityPolicy.catalogToolNames)
  ) {
    throw new DevicePolicyError(
      'DEVICE_POLICY_PRIMITIVES_INVALID',
      'capabilityPolicy primitives must expose catalogToolNames, getToolDefinition and capabilityCeiling',
    );
  }
  if (typeof toolRegistry.effectiveTools !== 'function') {
    throw new DevicePolicyError(
      'DEVICE_POLICY_PRIMITIVES_INVALID',
      'toolRegistry primitives must expose effectiveTools',
    );
  }
  return { capabilityPolicy, toolRegistry };
}

/**
 * Reads a stored scope defensively. Never throws, never repairs, never guesses.
 *
 * A record that cannot yield an id is `malformed` and enables nothing. A well-formed record with
 * an unusable `tools` value yields an EMPTY tool list rather than a failure, because "this scope
 * grants nothing" is the safe reading of a bad list and the tool list is the only field that can
 * grant anything.
 */
function normalizeToolScope(raw: unknown): NormalizedToolScope {
  if (!isPlainRecord(raw)) {
    return {
      shape: 'malformed',
      id: null,
      name: null,
      stage: null,
      isActive: false,
      tools: [],
      version: 0,
      updatedAt: null,
      listedCount: 0,
    };
  }

  const id = typeof raw.id === 'string' && raw.id.trim().length > 0 ? raw.id.trim() : null;
  if (id === null || id.length > MAX_SCOPE_ID_LENGTH) {
    return {
      shape: 'malformed',
      id: null,
      name: null,
      stage: null,
      isActive: false,
      tools: [],
      version: 0,
      updatedAt: null,
      listedCount: 0,
    };
  }

  const rawTools = Array.isArray(raw.tools) ? raw.tools : [];
  const seen = new Set<string>();
  const tools: string[] = [];
  for (const entry of rawTools) {
    if (tools.length >= MAX_TOOL_LIST_ENTRIES) {
      break;
    }
    if (typeof entry !== 'string') {
      continue;
    }
    const tool = entry.trim();
    if (tool.length === 0 || tool.length > MAX_SCOPE_ID_LENGTH || seen.has(tool)) {
      continue;
    }
    seen.add(tool);
    tools.push(tool);
  }

  return {
    shape: 'valid',
    id,
    name: typeof raw.name === 'string' ? raw.name : null,
    stage: typeof raw.stage === 'string' ? raw.stage : null,
    isActive: boolOr(raw.isActive, true),
    tools,
    version: intOr(raw.version, 0),
    updatedAt:
      raw.updatedAt instanceof Date && Number.isFinite(raw.updatedAt.getTime())
        ? raw.updatedAt
        : null,
    listedCount: rawTools.length,
  };
}

/** The binding of one level: which assignment matched, and where it points. */
type LevelBinding = {
  level: DevicePolicyLevel;
  toolScopeId: string;
  principalId: string | null;
  priority: number | null;
};

/**
 * The one assignment that wins at a level. Highest `priority` first; ties break on the smallest
 * `toolScopeId`, so the answer never depends on array order or on which request arrived first.
 */
function selectAssignment(
  candidates: readonly IDevicePolicyAssignment[],
): LevelBinding | null {
  const usable = candidates.filter(
    (entry) =>
      isPlainRecord(entry) &&
      boolOr(entry.isActive, true) &&
      typeof entry.toolScopeId === 'string' &&
      entry.toolScopeId.trim().length > 0,
  );
  if (usable.length === 0) {
    return null;
  }
  const sorted = [...usable].sort((a, b) => {
    const priorityDelta = intOr(b.priority, 0) - intOr(a.priority, 0);
    if (priorityDelta !== 0) {
      return priorityDelta;
    }
    return a.toolScopeId.trim() < b.toolScopeId.trim() ? -1 : 1;
  });
  const winner = sorted[0];
  return {
    level: 'user',
    toolScopeId: winner.toolScopeId.trim(),
    principalId: typeof winner.principalId === 'string' ? winner.principalId : null,
    priority: intOr(winner.priority, 0),
  };
}

/** Which level answered for one candidate assignment, given the identity. */
function assignmentsAtLevel(
  level: DevicePolicyLevel,
  assignments: readonly IDevicePolicyAssignment[],
  principal: DevicePolicyResolutionInput['principal'],
): IDevicePolicyAssignment[] {
  const groupIds = new Set(
    (principal.groupIds ?? []).filter((id): id is string => typeof id === 'string'),
  );
  return assignments.filter((entry) => {
    if (!isPlainRecord(entry) || entry.principalType !== level) {
      return false;
    }
    if (level === 'user') {
      return entry.principalId === principal.userId;
    }
    if (level === 'group') {
      return typeof entry.principalId === 'string' && groupIds.has(entry.principalId);
    }
    return entry.principalId === principal.role;
  });
}

/** The stricter of two stages — the lock that stops a scope widening the server's stage. */
function stricterStage(
  serverStage: string,
  scopeStage: string | null,
  stageRank: Readonly<Record<string, number>>,
): string {
  if (scopeStage === null) {
    return serverStage;
  }
  const serverRank = stageRank[serverStage];
  const scopeRank = stageRank[scopeStage];
  if (typeof scopeRank !== 'number') {
    // An unrecognised stage on the scope is not trusted to be narrow: the server's stage stands.
    return serverStage;
  }
  if (typeof serverRank !== 'number') {
    return scopeStage;
  }
  return scopeRank < serverRank ? scopeStage : serverStage;
}

/**
 * The content-derived policy version a device pins (GM-78 rule 4).
 *
 * Derived from the ANSWER, not from a counter: the winning level, the scope id, the scope's own
 * `version` and `updatedAt`, the resolved stage and the resolved tool set. Two consequences the
 * stale-policy test relies on: a change anywhere in the policy produces a new version without any
 * extra bookkeeping, and the same policy always yields the same version, so a device holding an
 * older document is detectable by comparison rather than by trust.
 */
function policyVersionOf(parts: {
  level: DevicePolicyLevel | null;
  toolScopeId: string | null;
  scopeVersion: number;
  scopeUpdatedAt: Date | null;
  stage: string;
  tools: readonly string[];
  pilot: boolean;
}): string {
  const canonical = JSON.stringify({
    schema: DEVICE_POLICY_RESOLUTION_SCHEMA,
    level: parts.level,
    toolScopeId: parts.toolScopeId,
    scopeVersion: parts.scopeVersion,
    scopeUpdatedAt: parts.scopeUpdatedAt === null ? null : parts.scopeUpdatedAt.toISOString(),
    stage: parts.stage,
    pilot: parts.pilot,
    tools: [...parts.tools],
  });
  return createHash('sha256').update(canonical).digest('hex');
}

/** A trace row for a level that had nothing to offer. */
function levelRow(
  level: DevicePolicyLevel,
  outcome: DevicePolicyLevelOutcome,
  binding: { toolScopeId: string | null; principalId: string | null; priority: number | null } = {
    toolScopeId: null,
    principalId: null,
    priority: null,
  },
): DevicePolicyLevelTrace {
  return {
    level,
    outcome,
    toolScopeId: binding.toolScopeId,
    principalId: binding.principalId,
    priority: binding.priority,
  };
}

/**
 * THE RESOLUTION. Pure: same input, same output, no I/O.
 *
 * @throws {DevicePolicyError} only for an unusable primitive port (a server wiring defect). No
 *   policy condition throws: every refusal is a value, because a refusal must be explainable.
 */
export function resolveDevicePolicy(input: DevicePolicyResolutionInput): DevicePolicyResolution {
  const primitives = readPrimitives(input.primitives);
  const { capabilityPolicy, toolRegistry } = primitives;
  const stageRank = capabilityPolicy.stageRank ?? {};
  const pilot = input.pilot !== false;
  const catalogNames = capabilityPolicy.catalogToolNames;

  const assignments = Array.isArray(input.assignments) ? input.assignments : [];
  const trace: DevicePolicyLevelTrace[] = [];

  // ── Walk the order, most specific first, stopping at the first usable level ────────────────
  let binding: LevelBinding | null = null;
  let selected: NormalizedToolScope | null = null;
  let selectedRaw: IDeviceToolScope | null = null;
  let unavailableOutcome: DevicePolicyLevelOutcome | null = null;
  let unavailableBinding: LevelBinding | null = null;
  let unavailableScopeId: string | null = null;

  for (const level of DEVICE_POLICY_LEVELS) {
    // A level already decided the answer; the rest are reported as not consulted, so the trace
    // never implies a lower level had a say.
    if (binding !== null || unavailableOutcome !== null) {
      trace.push(levelRow(level, 'not-requested'));
      continue;
    }

    const candidate =
      level === 'tenant'
        ? tenantBinding(input.tenantDefault)
        : selectAssignment(assignmentsAtLevel(level, assignments, input.principal));

    if (candidate === null) {
      trace.push(levelRow(level, 'no-assignment'));
      continue;
    }

    const bound: LevelBinding = { ...candidate, level };
    const raw = input.getScope(candidate.toolScopeId);
    const scope = raw === undefined || raw === null ? null : normalizeToolScope(raw);

    if (scope === null) {
      // A dangling reference must not silently fall through to a WIDER level: the level that was
      // configured answers, and its answer is "nothing". Reported as its own outcome so the admin
      // sees a configuration fault rather than an unexplained empty policy.
      unavailableOutcome = 'scope-missing';
      unavailableBinding = bound;
      unavailableScopeId = candidate.toolScopeId;
      trace.push(levelRow(level, 'scope-missing', bound));
      continue;
    }

    if (scope.shape === 'malformed') {
      unavailableOutcome = 'scope-malformed';
      unavailableBinding = bound;
      unavailableScopeId = candidate.toolScopeId;
      trace.push(levelRow(level, 'scope-malformed', bound));
      continue;
    }

    if (!scope.isActive) {
      // An explicitly retired scope is a decision, not an absence: it stops the walk and enables
      // nothing, exactly like a deny rule. Failing through to a broader level would resurrect
      // access an admin deliberately removed.
      unavailableOutcome = 'scope-inactive';
      unavailableBinding = bound;
      unavailableScopeId = scope.id;
      trace.push(levelRow(level, 'scope-inactive', bound));
      continue;
    }

    binding = bound;
    selected = scope;
    selectedRaw = raw as IDeviceToolScope;
    trace.push(levelRow(level, 'selected', bound));
  }

  // ── FAIL CLOSED: nothing usable anywhere ──────────────────────────────────────────────────
  if (binding === null || selected === null) {
    const stage = stricterStage(input.serverStage, null, stageRank);
    const decisions = buildFailClosedDecisions({
      code:
        unavailableOutcome === 'scope-inactive'
          ? DEVICE_POLICY_CODES.SCOPE_INACTIVE
          : unavailableOutcome === 'scope-missing'
            ? DEVICE_POLICY_CODES.SCOPE_UNKNOWN
            : unavailableOutcome === 'scope-malformed'
              ? DEVICE_POLICY_CODES.SCOPE_MALFORMED
              : DEVICE_POLICY_CODES.NOT_CONFIGURED,
      deniedBy:
        unavailableBinding === null
          ? DEVICE_POLICY_DENIED_BY.NONE
          : (unavailableBinding.level as DevicePolicyDeniedBy),
      catalogNames,
    });

    return Object.freeze({
      schema: DEVICE_POLICY_RESOLUTION_SCHEMA,
      stage,
      failClosed: true,
      governingLevel: null,
      resolvedToolScopeId: unavailableScopeId,
      resolvedToolScopeName: null,
      policyVersion: policyVersionOf({
        level: null,
        toolScopeId: unavailableScopeId,
        scopeVersion: 0,
        scopeUpdatedAt: null,
        stage,
        tools: [],
        pilot,
      }),
      tools: Object.freeze([]),
      approvalRequired: Object.freeze([]),
      decisions: Object.freeze(decisions),
      provenance: Object.freeze([]),
      trace: Object.freeze(trace),
      counts: Object.freeze({
        enabled: 0,
        approvalRequired: 0,
        denied: decisions.length,
        notInCatalog: 0,
      }),
    });
  }

  // ── Intersect the scope with the server ceiling, through the existing law ─────────────────
  const stage = stricterStage(input.serverStage, selected.stage, stageRank);
  const ceiling = capabilityPolicy.capabilityCeiling(stage);

  const catalogSet = new Set(catalogNames);
  const grantedInCatalog = selected.tools.filter((tool) => catalogSet.has(tool));
  const notInCatalog = selected.tools.filter((tool) => !catalogSet.has(tool));

  const admitted = new Set(ceiling.tools);
  // The device floor names exactly what the scope grants AND the ceiling admits. A name outside
  // the ceiling is left unclaimed on purpose: it is not a widening attempt by anyone, and calling
  // it one would misattribute a stage refusal to the device.
  const floorTools = grantedInCatalog.filter((tool) => admitted.has(tool));

  const report = toolRegistry.effectiveTools({
    ceiling,
    deviceFloor: { enabled: floorTools },
  });

  const excludedByTool = new Map(report.excluded.map((row) => [row.tool, row]));
  const enabled = new Set(report.enabled);
  const approvalRequired = new Set(report.approvalRequired);
  const deniedBy: DevicePolicyDeniedBy = binding.level as DevicePolicyDeniedBy;

  const decisions: DevicePolicyToolDecision[] = [];
  const provenance: DevicePolicyProvenance[] = [];

  for (const tool of grantedInCatalog) {
    const exclusion = excludedByTool.get(tool);

    if (enabled.has(tool)) {
      const gated = approvalRequired.has(tool);
      decisions.push({
        tool,
        enabled: true,
        requiresApproval: gated,
        // An approval-gated tool that is enabled still reports its gate: it is never a plain allow.
        reasonCode: gated ? (gatedCodeFor(capabilityPolicy, tool) ?? null) : null,
        deniedBy,
        toolScopeId: selected.id,
        detail: gated ? gatedDetail() : null,
      });
      provenance.push({
        tool,
        level: binding.level,
        toolScopeId: selected.id,
        toolScopeName: selected.name ?? selected.id,
        decision: 'scope',
        requiresApproval: gated,
        reasonCode: gated ? (gatedCodeFor(capabilityPolicy, tool) ?? null) : null,
      });
      continue;
    }

    // Not enabled. The cause is either server law (hard deny or stage) or the scope itself.
    if (exclusion !== undefined) {
      decisions.push({
        tool,
        enabled: false,
        requiresApproval: false,
        reasonCode: exclusion.code,
        deniedBy: DEVICE_POLICY_DENIED_BY.LAW,
        toolScopeId: null,
        detail: exclusion.detail,
      });
      continue;
    }

    decisions.push(scopeNotGrantedDecision(tool, selected, deniedBy));
  }

  // A name the scope lists that is not a tool at all. It enables nothing, and saying so is the
  // difference between "the admin typo'd" and a mystery.
  for (const tool of notInCatalog) {
    decisions.push({
      tool,
      enabled: false,
      requiresApproval: false,
      reasonCode: DEVICE_POLICY_CODES.TOOL_NOT_IN_CATALOG,
      deniedBy: DEVICE_POLICY_DENIED_BY.LAW,
      toolScopeId: null,
      detail: DEVICE_POLICY_DETAILS[DEVICE_POLICY_CODES.TOOL_NOT_IN_CATALOG],
    });
  }

  const tools = Object.freeze([...report.enabled]);

  return Object.freeze({
    schema: DEVICE_POLICY_RESOLUTION_SCHEMA,
    stage,
    failClosed: tools.length === 0,
    governingLevel: binding.level,
    resolvedToolScopeId: selected.id,
    resolvedToolScopeName: selected.name ?? selected.id,
    policyVersion: policyVersionOf({
      level: binding.level,
      toolScopeId: selected.id,
      scopeVersion: selected.version,
      scopeUpdatedAt: selected.updatedAt,
      stage,
      tools,
      pilot,
    }),
    tools,
    approvalRequired: Object.freeze([...report.approvalRequired]),
    decisions: Object.freeze(decisions),
    provenance: Object.freeze(provenance),
    trace: Object.freeze(trace),
    counts: Object.freeze({
      enabled: tools.length,
      approvalRequired: report.approvalRequired.length,
      denied: decisions.filter((row) => !row.enabled).length,
      notInCatalog: notInCatalog.length,
    }),
  });
}

/** The tenant level's binding, from the tenant-default record. */
function tenantBinding(
  tenantDefault: IDeviceTenantPolicyDefault | null | undefined,
): { toolScopeId: string; principalId: null; priority: null } | null {
  if (!isPlainRecord(tenantDefault)) {
    return null;
  }
  const id = tenantDefault.defaultToolScopeId;
  if (typeof id !== 'string' || id.trim().length === 0) {
    return null;
  }
  return { toolScopeId: id.trim(), principalId: null, priority: null };
}

/** The "the scope does not list this tool" row. Only emitted for catalog tools. */
function scopeNotGrantedDecision(
  tool: string,
  scope: NormalizedToolScope,
  deniedBy: DevicePolicyDeniedBy,
): DevicePolicyToolDecision {
  return {
    tool,
    enabled: false,
    requiresApproval: false,
    reasonCode: DEVICE_POLICY_CODES.SCOPE_NOT_GRANTED,
    deniedBy,
    toolScopeId: scope.id,
    detail: DEVICE_POLICY_DETAILS[DEVICE_POLICY_CODES.SCOPE_NOT_GRANTED],
  };
}

/**
 * The fail-closed report: every catalog tool off, with the single reason that explains the whole
 * resolution. A caller reading `decisions` sees the complete picture rather than an empty list
 * that could be mistaken for "no tools exist".
 */
function buildFailClosedDecisions(parts: {
  code: string;
  deniedBy: DevicePolicyDeniedBy;
  catalogNames: readonly string[];
}): DevicePolicyToolDecision[] {
  return parts.catalogNames.map((tool) => ({
    tool,
    enabled: false,
    requiresApproval: false,
    reasonCode: parts.code,
    deniedBy: parts.deniedBy,
    toolScopeId: null,
    detail: DEVICE_POLICY_DETAILS[parts.code] ?? null,
  }));
}

/**
 * The registry's own code for "enabled, but approval-gated". Read from the primitives' ceiling
 * rather than restated, so the scope layer cannot invent its own approval vocabulary.
 */
function gatedCodeFor(
  capabilityPolicy: DevicePolicyPrimitivesLike['capabilityPolicy'],
  tool: string,
): string | undefined {
  const definition = capabilityPolicy.getToolDefinition(tool);
  if (definition === undefined || definition.consent !== 'owner-approval') {
    return undefined;
  }
  return 'OWNER_APPROVAL_REQUIRED';
}

function gatedDetail(): string {
  return 'Enabled by the scope, but every execution still requires explicit owner approval (tier 3). A scope can grant a tool; it can never drop the approval gate.';
}

/**
 * THE DISPATCH GATE for a resolved policy. Reuses `deviceToolRegistry.authorizeDispatch` so the
 * tier vocabulary a refusal carries is the same one the dispatch path already emits.
 *
 * Note what a scope CANNOT do here: it cannot make `track_ui_event` or the feedback tool
 * admissible, because the ceiling the gate consults is the real stage ceiling and the registry
 * checks tier-1 law before it ever looks at the tool list.
 */
export function authorizeResolvedTool(
  toolName: string,
  resolution: DevicePolicyResolution,
  primitives: unknown,
): ReturnType<DevicePolicyPrimitivesLike['toolRegistry']['authorizeDispatch']> {
  const { capabilityPolicy, toolRegistry } = readPrimitives(primitives);
  const ceiling = capabilityPolicy.capabilityCeiling(String(resolution.stage));
  const admitted = new Set(ceiling.tools);
  const floorTools = [...resolution.tools].filter((tool) => admitted.has(tool));

  return toolRegistry.authorizeDispatch(toolName, {
    ceiling,
    deviceFloor: { enabled: floorTools },
  });
}

/** A frozen, JSON-serializable view for the admin panel and the device policy document. */
export function describeResolution(resolution: DevicePolicyResolution): Record<string, unknown> {
  return {
    schema: resolution.schema,
    stage: resolution.stage,
    failClosed: resolution.failClosed,
    governingLevel: resolution.governingLevel,
    resolvedToolScopeId: resolution.resolvedToolScopeId,
    resolvedToolScopeName: resolution.resolvedToolScopeName,
    policyVersion: resolution.policyVersion,
    tools: [...resolution.tools],
    approvalRequired: [...resolution.approvalRequired],
    counts: { ...resolution.counts },
    trace: resolution.trace.map((row) => ({ ...row })),
    provenance: resolution.provenance.map((row) => ({ ...row })),
  };
}

export type { DevicePolicyLevel, DevicePolicyStage, DevicePolicyResolution };