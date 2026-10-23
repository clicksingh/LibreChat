/**
 * W10 — device-policy PRIMITIVES PORT (GM-76 "reuse, do not fork").
 *
 * `docs/GM-PLAN-ROLE-SCOPED-POLICY-AND-INTEGRATION-20261023.md` §3 (W10) requires the resolution
 * order to be built ON the enforcement primitives that already exist and are tested:
 *
 *   - `api/server/services/Device/deviceCapabilityPolicy` — the server ceiling by stage, plus the
 *     hard denies (`ALWAYS_DENIED`, `PILOT_DENIED`) and the four approval-gated tools.
 *   - `api/server/services/Device/deviceToolRegistry` — `effectiveTools`, `authorizeDispatch`,
 *     `assertDispatchAllowed` and the refusal codes.
 *
 * This module is the SEAM, not a copy. It declares the narrow slice of those two modules the
 * resolver consumes, so that:
 *
 *   1. `@librechat/api` never imports from `api/server/**` (which would invert the package layering
 *      and drag server internals into the bundle);
 *   2. there is exactly ONE implementation of the law — the two Device modules — and the resolver
 *      cannot drift from it, because it is handed the real functions at the route boundary:
 *
 *        const primitives = requireDevicePolicyPrimitives();   // route file, server side
 *        createAdminDevicePolicyHandlers({ ...deps, primitives });
 *
 *   3. the resolver stays pure and directly unit-testable: a test can hand it the REAL modules
 *      (`requireDevicePolicyPrimitives()` under jest) or a hand-built port to prove that a
 *      defective port still cannot widen anything.
 *
 * WHY THE PORT IS SHAPED THIS WAY
 * `effectiveTools` is the only function that knows the intersection law, the hard denies and the
 * "why was this excluded, and whose decision was that" vocabulary, so the resolver calls it rather
 * than re-deriving any of the three. `getToolDefinition`, `catalogToolNames`, `minStageByName` and
 * `capabilityCeiling` are the reads the resolver needs to answer "is this name a real tool", "is
 * this tool admissible at the resolved stage" and "which stage is the stricter of two".
 */

import type {
  DeviceToolFloor,
  ToolEffectiveReport,
  ToolExclusion,
  ToolRegistryPrimitives,
} from './types';

/**
 * The slice of `deviceCapabilityPolicy` the resolver consumes.
 *
 * `capabilityCeiling(stage)` returns the governor ceiling document for a stage
 * (`ceilingForStage`), whose `tools` are the permitted names with the hard denies already
 * removed — the resolver intersects a scope against it rather than restating the deny-list.
 */
export interface DeviceCapabilityPolicyPrimitives {
  /** The four stages, in order (`CAPABILITY_STAGES`). */
  capabilityStages: readonly string[];
  /** Stage rank (`STAGE_RANK`), so "stricter of two stages" is a comparison and not a guess. */
  stageRank: Readonly<Record<string, number>>;
  /** Every catalog tool name, in catalog order (`TOOL_CATALOG`). */
  catalogToolNames: readonly string[];
  /** The catalog entry for a name, or undefined (`getToolDefinition`). */
  getToolDefinition: (name: string) => { name: string; stage: string; consent: string } | undefined;
  /** The governor ceiling document for a stage (`ceilingForStage`). */
  capabilityCeiling: (stage: string) => {
    schema?: string;
    stage: string;
    pilot: boolean;
    tools: readonly string[];
    approvalRequired: readonly string[];
  };
}

/** The slice of `deviceToolRegistry` the resolver consumes. */
export interface DeviceToolRegistryPrimitives extends ToolRegistryPrimitives {
  /** The intersection law, with a reason and an owner for everything excluded (`effectiveTools`). */
  effectiveTools: (params: {
    ceiling: unknown;
    deviceFloor: unknown;
  }) => ToolEffectiveReport;
}

/** What `requireDevicePolicyPrimitives()` returns on the server side. */
export interface DevicePolicyPrimitives {
  capabilityPolicy: DeviceCapabilityPolicyPrimitives;
  toolRegistry: DeviceToolRegistryPrimitives;
}

/** A tool floor naming exactly these tools (`DEVICE_TOOL_FLOOR_SCHEMA`). */
export interface DeviceToolFloorEnvelope extends DeviceToolFloor {
  schema?: string;
}

/** Re-exported for callers that only need the exclusion row shape. */
export type { ToolExclusion };