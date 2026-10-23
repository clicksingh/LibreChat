'use strict';

/**
 * Device capability policy — GM-14 / R7 staged rollout, W4 pilot hardening.
 *
 * OWNER-AUTHORIZED SCOPE (2026-10-23, LOCAL LAB ONLY; production G0 remains BLOCKED).
 *
 * WHAT THIS FILE IS
 * A *data-driven* policy module: the 26 supported Desktop Commander tools, the stage at which each
 * one becomes admissible, the per-tool deny-list, and the consent class of each tool. It contains no
 * transport, no database access and no request handling — it answers one question, deterministically:
 *
 *     given a stage and a tool name, is the tool allowed, allowed-with-owner-approval, or denied?
 *
 * and one CI question:
 *
 *     is the relay's `clientInfo.name` safe, and does the engine therefore advertise 26 tools?
 *
 * THE RULING (GM-14, `docs/GM-RELAY-FIRST-PILOT-PLAN-20261023.md` §2)
 * Three stages, then full 26, enforced through the same per-tool deny-list mechanism that already
 * proves the `track_ui_event` 403:
 *
 * | Stage | Enabled capability class                                        | Purpose                                    |
 * |-------|-----------------------------------------------------------------|--------------------------------------------|
 * | A     | Read-only: directory listing, file read, search, file metadata   | Prove transport, authority, audit, no writes |
 * | B     | Files: create, write, edit, move/rename, directory create        | Prove the write path and the audit trail    |
 * | C     | Process/terminal/PDF                                             | Highest consequence last, approvals live    |
 * | full  | All 26 advertised tools                                          | The defined end state                       |
 *
 * STAGE INTERPRETATION (deliberate, disclosed)
 * GM-14's stage-C cell reads "Process/terminal/PDF … remaining tools". Read literally, "remaining
 * tools" would make C equal to `full` and the fourth rung of the ladder a no-op — a staged rollout
 * that never actually stages anything, which is the silent-downgrade failure this policy exists to
 * prevent. The ladder is therefore built as A (read-only) -> B (files) -> C (process/terminal/PDF)
 * -> full (the administrative, telemetry and prompt tools that remain), so each promotion adds a
 * real, reviewable capability class and `full` is a genuine step. Every tool still lands in exactly
 * one first stage; nothing is dropped.
 *
 * Hard rules encoded below, not left to prose:
 * - `track_ui_event` is an internal dispatch handler, never advertised, **always** relay-denied 403,
 *   and never counted as an agent-reachable tool (F-H02-2). It is not in the 26-tool catalog.
 * - `give_feedback_to_desktop_commander` is denied for the pilot: it opens an external browser form
 *   and pre-sends `client_id` plus usage counters to a third party, contradicting the isolation
 *   posture (C05-1, closed on the restrictive side). It stays in the catalog — it is a real
 *   advertised tool — but the pilot deny-list removes it from every stage.
 * - The four owner-approval tools (`set_config_value`, `start_process`, `kill_process`,
 *   `give_feedback_to_desktop_commander`) are never plain `allowed` at any stage. Where a stage
 *   enables one, the decision is `approval-required`; where it does not, the decision is `denied`
 *   by stage. Approval never silently becomes permission.
 * - The end state is explicit: stage `full` enables all 26 catalog tools. Under the pilot deny-list
 *   that is 25 *effective* tools plus one explicitly denied — the difference is a declared value
 *   (`pilotEndState()`), not an omission, because a silently missing capability is the failure
 *   `FAILURE-MODES.md` line 10 punishes.
 *
 * WHY THE ADVERTISEMENT CHECK IS A CODE PATH AND NOT A COMMENT
 * `shouldIncludeTool` in the engine hides `give_feedback_to_desktop_commander` and `get_prompts`
 * when `clientInfo.name === 'desktop-commander-app'`, which makes the engine advertise 24 tools
 * instead of 26 while the "all tools" promise reads as true. `assertRelayClientInfo` /
 * `assertRelayToolAdvertisement` turn that into a CI failure instead of a silent downgrade.
 *
 * TIER 1 — THE SERVER CEILING (GM-72, W8; `api/server/services/Device/deviceToolRegistry.js` owns
 * tiers 2 and 3). The ceiling is the governor-set server decision: the stage ladder above plus the
 * always/pilot hard denies, as data (`ceilingForStage`). It is NOT device-settable — the device
 * reports its own floor and the server intersects (ceiling ∩ floor) at dispatch time, so a device
 * that hand-edits its config to claim everything reaches only its ceiling. A dispatch for a tool
 * outside the ceiling is refused with `CEILING_REFUSAL_CODE`, even when the device claims the tool
 * is enabled. The per-call approval tools stay approval-gated at every stage.
 */

/** The policy document schema id. */
const CAPABILITY_POLICY_SCHEMA = 'cbhr.rdc.capability-policy/1';

/** The capability contract the pilot's manifest is written against. */
const CAPABILITY_CONTRACT_SCHEMA = 'cbhr.rdc.capabilities/2';

/** Ordered stages. `full` is the defined end state and is a superset of C by construction. */
const CAPABILITY_STAGES = Object.freeze(['A', 'B', 'C', 'full']);

/** Stage rank: a tool is admissible at stage S when its rank is <= rank(S). */
const STAGE_RANK = Object.freeze({ A: 0, B: 1, C: 2, full: 3 });

/**
 * Exported because a consumer OUTSIDE this module needs the authoritative rank to decide
 * "the stricter of two stages" (the admin device-policy resolver narrows a server stage by a
 * scope's declared stage). Previously it had to infer the rank from `CAPABILITY_STAGES` order,
 * which happens to agree today but is an assumption rather than the source of truth — and when
 * that inference was absent entirely, stage narrowing silently did nothing and a scope declaring
 * stage A could still enable stage B/C tools it named. Exporting the map removes the assumption.
 */

/** The four tools that require explicit owner approval. Constant at every stage. */
const OWNER_APPROVAL_TOOLS = Object.freeze([
  'set_config_value',
  'start_process',
  'kill_process',
  'give_feedback_to_desktop_commander',
]);

/** Consent classes (the CBHR platform's own gating proposal, not an engine feature). */
const CONSENT_CLASSES = Object.freeze({
  AUTO: 'auto',
  PER_CALL_NOTIFY: 'per-call-notify',
  OWNER_APPROVAL: 'owner-approval',
});

/** Denial codes emitted by `evaluateTool`. */
const DECISION_CODES = Object.freeze({
  ALLOWED: 'TOOL_ALLOWED',
  APPROVAL_REQUIRED: 'OWNER_APPROVAL_REQUIRED',
  NOT_PERMITTED: 'TOOL_NOT_PERMITTED',
  NOT_ENABLED_AT_STAGE: 'TOOL_NOT_ENABLED_AT_STAGE',
  UNKNOWN: 'TOOL_UNKNOWN',
  INVALID_NAME: 'TOOL_NAME_INVALID',
});

/**
 * The 26 advertised tools, in the engine's registration order
 * (`reports/GATE-CLOSURE-002-26-TOOLS.md` §1, engine HEAD 7bad545f). `stage` is the first stage at
 * which the tool becomes admissible. No aliases, no invented names.
 *
 * Stage census: A 8 (read-only) · B 4 (files) · C 8 (process/terminal/PDF) · full 6 (config,
 * telemetry, prompts) = 26.
 */
const TOOL_CATALOG = Object.freeze(
  [
    { name: 'get_config', effectClass: 'config-read', consent: 'auto', stage: 'full' },
    {
      name: 'set_config_value',
      effectClass: 'config-write',
      consent: 'owner-approval',
      stage: 'full',
    },
    {
      name: 'read_file',
      effectClass: 'fs-read',
      consent: 'per-call-notify',
      stage: 'A',
      networkEgress: true,
    },
    {
      name: 'read_multiple_files',
      effectClass: 'fs-read',
      consent: 'per-call-notify',
      stage: 'A',
    },
    { name: 'write_file', effectClass: 'fs-write', consent: 'per-call-notify', stage: 'B' },
    { name: 'write_pdf', effectClass: 'fs-write', consent: 'per-call-notify', stage: 'C' },
    { name: 'create_directory', effectClass: 'fs-write', consent: 'per-call-notify', stage: 'B' },
    { name: 'list_directory', effectClass: 'fs-read', consent: 'auto', stage: 'A' },
    { name: 'move_file', effectClass: 'fs-move', consent: 'per-call-notify', stage: 'B' },
    { name: 'start_search', effectClass: 'search', consent: 'per-call-notify', stage: 'A' },
    { name: 'get_more_search_results', effectClass: 'search', consent: 'auto', stage: 'A' },
    { name: 'stop_search', effectClass: 'search', consent: 'auto', stage: 'A' },
    { name: 'list_searches', effectClass: 'search', consent: 'auto', stage: 'A' },
    { name: 'get_file_info', effectClass: 'fs-read', consent: 'auto', stage: 'A' },
    { name: 'edit_block', effectClass: 'fs-write', consent: 'per-call-notify', stage: 'B' },
    {
      name: 'start_process',
      effectClass: 'process-spawn',
      consent: 'owner-approval',
      stage: 'C',
    },
    { name: 'read_process_output', effectClass: 'process-io', consent: 'per-call-notify', stage: 'C' },
    {
      name: 'interact_with_process',
      effectClass: 'process-io',
      consent: 'per-call-notify',
      stage: 'C',
    },
    { name: 'force_terminate', effectClass: 'process-kill', consent: 'per-call-notify', stage: 'C' },
    { name: 'list_sessions', effectClass: 'process-list', consent: 'auto', stage: 'C' },
    { name: 'list_processes', effectClass: 'process-list', consent: 'auto', stage: 'C' },
    { name: 'kill_process', effectClass: 'process-kill', consent: 'owner-approval', stage: 'C' },
    { name: 'get_usage_stats', effectClass: 'telemetry-read', consent: 'auto', stage: 'full' },
    { name: 'get_recent_tool_calls', effectClass: 'telemetry-read', consent: 'auto', stage: 'full' },
    {
      name: 'give_feedback_to_desktop_commander',
      effectClass: 'telemetry-egress',
      consent: 'owner-approval',
      stage: 'full',
    },
    { name: 'get_prompts', effectClass: 'prompts', consent: 'auto', stage: 'full' },
  ].map((entry) =>
    Object.freeze({
      networkEgress: false,
      ...entry,
    }),
  ),
);

/** The catalog indexed by name. Built once; never mutated. */
const TOOL_BY_NAME = new Map(TOOL_CATALOG.map((tool) => [tool.name, tool]));

/** The advertised tool count the "all tools" promise depends on. */
const ADVERTISED_TOOL_COUNT = TOOL_CATALOG.length;

/**
 * Internal dispatch handlers that are NOT tools. They are never advertised and never counted.
 * `track_ui_event` is dispatch-reachable in the engine (F-H02-2), so the relay must deny it.
 */
const INTERNAL_HANDLERS = Object.freeze(['track_ui_event']);

/**
 * Always-denied handlers, at every stage, in and after the pilot. `track_ui_event` is telemetry
 * transport for the bundled UI widgets; it is not a capability and must never execute for an agent.
 */
const ALWAYS_DENIED = Object.freeze({
  track_ui_event: Object.freeze({
    code: DECISION_CODES.NOT_PERMITTED,
    httpStatus: 403,
    reason:
      'Internal UI-telemetry handler, not an advertised tool; relay-denied 403 (F-H02-2, GM-14)',
  }),
});

/**
 * Denied for the pilot only. `give_feedback_to_desktop_commander` opens an external browser form
 * and pre-sends `client_id` and usage counters to a third party (C05-1, restrictive side).
 *
 * GM-72: this is a TIER-1 (server ceiling) deny. It is not in the ceiling of any pilot stage and no
 * device config can restore it; it is not a device-settable preference.
 */
const PILOT_DENIED = Object.freeze({
  give_feedback_to_desktop_commander: Object.freeze({
    code: DECISION_CODES.NOT_PERMITTED,
    httpStatus: 403,
    reason:
      'Denied for the pilot: opens an external browser form and pre-sends client_id and usage counters (GM-14, C05-1)',
  }),
});

/**
 * The GM-72 tier-1 ceiling document id. `ceilingForStage` emits this schema; the registry
 * (`./deviceToolRegistry`) consumes it as the server ceiling and refuses to treat a ceiling as
 * device data.
 */
const CAPABILITY_CEILING_SCHEMA = 'cbhr.rdc.capability-ceiling/1';

/** The only permitted originator of a ceiling document: the server (governor policy). */
const CEILING_SOURCE = 'server';

/**
 * GM-72's distinct refusal code for a dispatch that names a tool OUTSIDE the server ceiling — the
 * load-bearing signal that a device tried to widen. It is deliberately NOT the same code as a
 * tool the device itself disabled (`TOOL_DISABLED_ON_DEVICE`, tier 2, in the registry), and not
 * the stage-gate code `TOOL_NOT_ENABLED_AT_STAGE` used by `evaluateTool`, so a refusal can always
 * be attributed to the tier that caused it.
 *
 * The `TOOL_CEILING_` namespace is reserved for tier-1 (ceiling) refusals so the prefix alone
 * identifies the tier. `assertPolicyIntegrity()` enforces that no per-tool decision code claims it.
 */
const CEILING_REFUSAL_CODE = 'TOOL_CEILING_OUTSIDE_SERVER_CEILING';

/**
 * Scope labels on a tier-1 hard deny. `always` denies at every stage and after the pilot (a
 * non-tool internal handler); `pilot` denies while the pilot deny-list is in force and is a
 * declared, reversible overlay — never a silent downgrade.
 */
const CEILING_DENY_SCOPES = Object.freeze({ ALWAYS: 'always', PILOT: 'pilot' });

/** The relay must never identify itself as the engine's own UI client. */
const FORBIDDEN_RELAY_CLIENT_NAMES = Object.freeze(['desktop-commander-app']);

/**
 * The client name the CBHR relay pins. Any name other than the forbidden one makes the engine
 * advertise all 26 tools; this value is the deliberate, reviewed choice (open question Q2).
 */
const RELAY_CLIENT_NAME = 'cbhr-rdc-relay';

/** The tools the engine hides for the forbidden client name — the 26 -> 24 silent downgrade. */
const HIDDEN_FOR_FORBIDDEN_CLIENT = Object.freeze([
  'give_feedback_to_desktop_commander',
  'get_prompts',
]);

/** Typed policy failure, so CI callers can branch on `code` instead of parsing messages. */
class CapabilityPolicyError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'CapabilityPolicyError';
    this.code = code;
  }
}

/** Throws unless `stage` is one of the four declared stages. */
function assertStage(stage) {
  if (!CAPABILITY_STAGES.includes(stage)) {
    throw new CapabilityPolicyError(
      'CAPABILITY_STAGE_UNKNOWN',
      `Unknown capability stage "${stage}"; expected one of ${CAPABILITY_STAGES.join(', ')}`,
    );
  }
  return stage;
}

/** True when a tool whose first admissible stage is `toolStage` is admissible at `stage`. */
function isStageAtLeast(stage, toolStage) {
  return STAGE_RANK[toolStage] <= STAGE_RANK[stage];
}

/** The catalog entry for a tool name, or `undefined`. Never a guess or an alias. */
function getToolDefinition(toolName) {
  return TOOL_BY_NAME.get(toolName);
}

/** True when the name is one of the 26 advertised tools. */
function isAdvertisedTool(toolName) {
  return TOOL_BY_NAME.has(toolName);
}

/** Names of the tools a stage enables (approval-gated ones included; they are still admissible). */
function stageToolNames(stage) {
  assertStage(stage);
  return TOOL_CATALOG.filter((tool) => isStageAtLeast(stage, tool.stage)).map((tool) => tool.name);
}

/** How many tools a stage enables, before the pilot deny-list is applied. */
function stageToolCount(stage) {
  return stageToolNames(stage).length;
}

/** The four owner-approval tools, constant at every stage. */
function ownerApprovalTools() {
  return [...OWNER_APPROVAL_TOOLS];
}

/** Names denied at a stage: always-denied handlers plus (during the pilot) the pilot deny-list. */
function deniedToolNames({ stage = 'full', pilot = true } = {}) {
  assertStage(stage);
  const denied = Object.keys(ALWAYS_DENIED);
  if (pilot) {
    denied.push(...Object.keys(PILOT_DENIED));
  }
  return denied.sort();
}

/**
 * GM-72 TIER 1 — the server ceiling at a stage, as DATA.
 *
 * The ceiling is what the server will permit for this device, before the device's own floor narrows
 * it. It is the stage ladder (`stageToolNames`) with the hard denies removed, plus the deny list
 * itself so a refusal can be explained rather than appearing as a silent absence:
 *
 *   tools            — the permitted set (catalog order). Approval-gated tools ARE members: they are
 *                      admissible, but every execution still needs owner approval (tier 3).
 *   approvalRequired — the subset of `tools` that stays approval-gated when enabled (GM-72).
 *   hardDenied       — tier-1 denies that no stage and no device config can lift, with their code,
 *                      HTTP status and scope (`always` | `pilot`).
 *   deviceSettable   — always false. This document is server-owned; the registry refuses a ceiling
 *                      that declares otherwise.
 *
 * Counts cross-check against the pre-existing decision engine: `counts.tools` always equals
 * `agentReachableToolCount({ stage, pilot })` (8 / 12 / 20 / 25 during the pilot; 26 at `full`
 * after it), which `assertPolicyIntegrity()` asserts for every stage.
 *
 * @param {'A'|'B'|'C'|'full'} stage
 * @param {object} [options]
 * @param {boolean} [options.pilot=true] apply the pilot deny-list overlay
 * @returns {Readonly<object>} frozen, JSON-serializable ceiling document
 */
function ceilingForStage(stage, { pilot = true } = {}) {
  assertStage(stage);

  const stageTools = stageToolNames(stage);
  const deniedNames = new Set(deniedToolNames({ stage, pilot }));
  const tools = stageTools.filter((name) => !deniedNames.has(name));

  const hardDenied = [
    ...Object.entries(ALWAYS_DENIED).map(([name, deny]) => ({
      tool: name,
      code: deny.code,
      httpStatus: deny.httpStatus,
      reason: deny.reason,
      scope: CEILING_DENY_SCOPES.ALWAYS,
    })),
    ...(pilot
      ? Object.entries(PILOT_DENIED).map(([name, deny]) => ({
          tool: name,
          code: deny.code,
          httpStatus: deny.httpStatus,
          reason: deny.reason,
          scope: CEILING_DENY_SCOPES.PILOT,
        }))
      : []),
  ].map((deny) => Object.freeze(deny));

  const approvalRequired = tools.filter(
    (name) => TOOL_BY_NAME.get(name).consent === CONSENT_CLASSES.OWNER_APPROVAL,
  );

  return Object.freeze({
    schema: CAPABILITY_CEILING_SCHEMA,
    tier: 1,
    source: CEILING_SOURCE,
    deviceSettable: false,
    stage,
    pilot,
    tools: Object.freeze(tools),
    approvalRequired: Object.freeze(approvalRequired),
    hardDenied: Object.freeze(hardDenied),
    counts: Object.freeze({
      stage: stageTools.length,
      tools: tools.length,
      approvalRequired: approvalRequired.length,
      hardDenied: hardDenied.length,
    }),
  });
}

/** The tool names the server ceiling permits at a stage (tier 1, denies already applied). */
function ceilingToolNames(stage, options = {}) {
  return [...ceilingForStage(stage, options).tools];
}

/** How many tools the server ceiling permits at a stage. */
function ceilingToolCount(stage, options = {}) {
  return ceilingForStage(stage, options).tools.length;
}

/**
 * The single decision function of this module.
 *
 * @param {string} toolName the tool the agent asked the relay to execute
 * @param {object} [options]
 * @param {'A'|'B'|'C'|'full'} [options.stage='A'] the pilot's current stage
 * @param {boolean} [options.pilot=true] apply the pilot deny-list
 * @returns {{tool: string|null, stage: string, decision: string, allowed: boolean,
 *            requiresApproval: boolean, agentReachable: boolean, code: string|null,
 *            httpStatus: number|null, reason: string|null}}
 */
function evaluateTool(toolName, { stage = 'A', pilot = true } = {}) {
  assertStage(stage);

  const base = {
    tool: typeof toolName === 'string' ? toolName : null,
    stage,
    decision: 'denied',
    allowed: false,
    requiresApproval: false,
    agentReachable: false,
    code: null,
    httpStatus: null,
    reason: null,
  };

  if (typeof toolName !== 'string' || toolName.length === 0) {
    return {
      ...base,
      code: DECISION_CODES.INVALID_NAME,
      httpStatus: 400,
      reason: 'The relay was asked to evaluate a non-string or empty tool name',
    };
  }

  const alwaysDenied = ALWAYS_DENIED[toolName];
  if (alwaysDenied !== undefined) {
    return {
      ...base,
      code: alwaysDenied.code,
      httpStatus: alwaysDenied.httpStatus,
      reason: alwaysDenied.reason,
    };
  }

  if (pilot) {
    const pilotDenied = PILOT_DENIED[toolName];
    if (pilotDenied !== undefined) {
      return {
        ...base,
        code: pilotDenied.code,
        httpStatus: pilotDenied.httpStatus,
        reason: pilotDenied.reason,
      };
    }
  }

  const tool = TOOL_BY_NAME.get(toolName);
  if (tool === undefined) {
    return {
      ...base,
      code: DECISION_CODES.UNKNOWN,
      httpStatus: 400,
      reason: 'Not one of the 26 supported Desktop Commander tools',
    };
  }

  if (!isStageAtLeast(stage, tool.stage)) {
    return {
      ...base,
      code: DECISION_CODES.NOT_ENABLED_AT_STAGE,
      httpStatus: 403,
      reason: `Enabled from stage ${tool.stage}; the pilot is at stage ${stage}`,
    };
  }

  if (tool.consent === CONSENT_CLASSES.OWNER_APPROVAL) {
    return {
      ...base,
      decision: 'approval-required',
      allowed: true,
      requiresApproval: true,
      agentReachable: true,
      code: DECISION_CODES.APPROVAL_REQUIRED,
      reason: 'Admissible at this stage, but every execution requires explicit owner approval',
    };
  }

  return {
    ...base,
    decision: 'allowed',
    allowed: true,
    agentReachable: true,
    code: DECISION_CODES.ALLOWED,
    reason: null,
  };
}

/**
 * True when the agent can reach the tool at this stage: allowed outright, or allowed behind an
 * approval gate. A denied tool — and always `track_ui_event` — is not agent-reachable.
 */
function isAgentReachable(toolName, options = {}) {
  return evaluateTool(toolName, options).agentReachable;
}

/** How many tools the agent can reach at a stage, under the current deny-list policy. */
function agentReachableToolCount(options = {}) {
  const { stage = 'A', pilot = true } = options;
  assertStage(stage);
  const names = new Set([...TOOL_CATALOG.map((tool) => tool.name), ...Object.keys(ALWAYS_DENIED)]);
  let count = 0;
  for (const name of names) {
    if (isAgentReachable(name, { stage, pilot })) {
      count += 1;
    }
  }
  return count;
}

/**
 * The declared end state, as data. `advertised` is the catalog (26). `effective` is what the agent
 * can actually reach at `full` under the deny-list (25 during the pilot). `denied` names the
 * difference, so "all tools" can never be quietly false.
 */
function pilotEndState({ pilot = true } = {}) {
  return {
    stage: 'full',
    advertised: ADVERTISED_TOOL_COUNT,
    enabledByStage: stageToolCount('full'),
    effective: agentReachableToolCount({ stage: 'full', pilot }),
    denied: deniedToolNames({ stage: 'full', pilot }),
    internalHandlers: [...INTERNAL_HANDLERS],
  };
}

/** A printable stage table for the report and for CI logs. */
function describeStageTable() {
  return CAPABILITY_STAGES.map((stage) => ({
    stage,
    count: stageToolCount(stage),
    tools: stageToolNames(stage),
  }));
}

/**
 * CI ASSERTION 1 — the relay's `clientInfo.name` must not be the engine's own UI client name.
 *
 * Rationale: the engine's `shouldIncludeTool` hides `give_feedback_to_desktop_commander` and
 * `get_prompts` for `desktop-commander-app`, so the engine advertises 24 tools instead of 26 while
 * the "all tools" promise still reads as true. This throws instead.
 *
 * @param {{name?: unknown}} clientInfo the `clientInfo` the relay sends on `initialize`
 * @returns {true}
 * @throws {CapabilityPolicyError}
 */
function assertRelayClientInfo(clientInfo) {
  const name = clientInfo === null || clientInfo === undefined ? undefined : clientInfo.name;
  if (typeof name !== 'string' || name.trim().length === 0) {
    throw new CapabilityPolicyError(
      'RELAY_CLIENT_NAME_MISSING',
      'The relay must send a non-empty clientInfo.name; an unnamed client is unverifiable',
    );
  }
  if (FORBIDDEN_RELAY_CLIENT_NAMES.includes(name)) {
    throw new CapabilityPolicyError(
      'RELAY_CLIENT_NAME_FORBIDDEN',
      `clientInfo.name "${name}" makes the engine hide ${HIDDEN_FOR_FORBIDDEN_CLIENT.join(
        ', ',
      )} and advertise 24 tools instead of 26`,
    );
  }
  return true;
}

/**
 * CI ASSERTION 2 — the relay must actually see all 26 advertised tools.
 *
 * Asserts the client name is safe, then that the advertisement is exactly the 26-tool catalog: no
 * silent downgrade (24), no invented tool, no dropped tool, no duplicate.
 *
 * @param {Array<string|{name?: unknown}>} tools the tool list the engine returned
 * @param {{name?: unknown}} clientInfo the `clientInfo` the relay sent
 * @returns {true}
 * @throws {CapabilityPolicyError}
 */
function assertRelayToolAdvertisement(tools, clientInfo) {
  assertRelayClientInfo(clientInfo);

  if (!Array.isArray(tools)) {
    throw new CapabilityPolicyError(
      'RELAY_TOOL_LIST_INVALID',
      'The engine tool advertisement must be an array',
    );
  }

  const names = tools.map((tool) =>
    typeof tool === 'string' ? tool : tool === null || tool === undefined ? null : tool.name,
  );

  if (names.some((name) => typeof name !== 'string')) {
    throw new CapabilityPolicyError(
      'RELAY_TOOL_LIST_INVALID',
      'Every advertised tool must carry a string name',
    );
  }

  const seen = new Set();
  for (const name of names) {
    if (seen.has(name)) {
      throw new CapabilityPolicyError(
        'RELAY_TOOL_DUPLICATE',
        `The engine advertised "${name}" more than once`,
      );
    }
    seen.add(name);
  }

  if (names.length !== ADVERTISED_TOOL_COUNT) {
    throw new CapabilityPolicyError(
      'RELAY_TOOL_COUNT_MISMATCH',
      `The engine advertised ${names.length} tools; the pilot law requires ${ADVERTISED_TOOL_COUNT}`,
    );
  }

  // Checked before "missing" so a swapped-in unknown tool is named for what it is, while the count
  // check above still reports the 26 -> 24 downgrade as the headline symptom.
  const unexpected = [...seen].filter((name) => !TOOL_BY_NAME.has(name));
  if (unexpected.length > 0) {
    throw new CapabilityPolicyError(
      'RELAY_TOOL_UNEXPECTED',
      `The engine advertised tools outside the frozen catalog: ${unexpected.join(', ')}`,
    );
  }

  const missing = TOOL_CATALOG.map((tool) => tool.name).filter((name) => !seen.has(name));
  if (missing.length > 0) {
    throw new CapabilityPolicyError(
      'RELAY_TOOL_MISSING',
      `The engine did not advertise: ${missing.join(', ')}`,
    );
  }

  return true;
}

/**
 * CI ASSERTION 3 — the policy data itself is coherent.
 *
 * Proves the invariants the stage table depends on: 26 unique tools, every tool assigned a real
 * stage, monotonic stage growth, `full` covering the catalog, the four owner-approval tools being
 * exactly the four, `track_ui_event` absent from the catalog, and every deny-listed name accounted
 * for (as a catalog tool or as an internal handler).
 *
 * @returns {true}
 * @throws {CapabilityPolicyError}
 */
function assertPolicyIntegrity() {
  if (TOOL_CATALOG.length !== 26) {
    throw new CapabilityPolicyError(
      'POLICY_TOOL_COUNT',
      `The catalog must contain exactly 26 tools, found ${TOOL_CATALOG.length}`,
    );
  }

  if (TOOL_BY_NAME.size !== TOOL_CATALOG.length) {
    throw new CapabilityPolicyError('POLICY_DUPLICATE_TOOL', 'The catalog contains duplicate names');
  }

  for (const tool of TOOL_CATALOG) {
    if (!CAPABILITY_STAGES.includes(tool.stage)) {
      throw new CapabilityPolicyError(
        'POLICY_TOOL_STAGE',
        `Tool "${tool.name}" has an unknown stage "${tool.stage}"`,
      );
    }
    if (!Object.values(CONSENT_CLASSES).includes(tool.consent)) {
      throw new CapabilityPolicyError(
        'POLICY_TOOL_CONSENT',
        `Tool "${tool.name}" has an unknown consent class "${tool.consent}"`,
      );
    }
  }

  if (TOOL_BY_NAME.has('track_ui_event')) {
    throw new CapabilityPolicyError(
      'POLICY_INTERNAL_HANDLER_ADVERTISED',
      'track_ui_event must never appear in the advertised 26-tool catalog',
    );
  }

  const declaredApproval = TOOL_CATALOG.filter(
    (tool) => tool.consent === CONSENT_CLASSES.OWNER_APPROVAL,
  ).map((tool) => tool.name);
  if (
    declaredApproval.length !== OWNER_APPROVAL_TOOLS.length ||
    !OWNER_APPROVAL_TOOLS.every((name) => declaredApproval.includes(name))
  ) {
    throw new CapabilityPolicyError(
      'POLICY_APPROVAL_SET',
      `The owner-approval set must be exactly ${OWNER_APPROVAL_TOOLS.join(', ')}`,
    );
  }

  // Monotonic growth: A <= B <= C <= full, and `full` is the whole catalog.
  const sets = CAPABILITY_STAGES.map((stage) => new Set(stageToolNames(stage)));
  for (let index = 1; index < sets.length; index += 1) {
    for (const name of sets[index - 1]) {
      if (!sets[index].has(name)) {
        throw new CapabilityPolicyError(
          'POLICY_STAGE_NOT_MONOTONIC',
          `Stage ${CAPABILITY_STAGES[index]} drops "${name}" which stage ${
            CAPABILITY_STAGES[index - 1]
          } enabled`,
        );
      }
    }
  }
  if (sets[sets.length - 1].size !== TOOL_CATALOG.length) {
    throw new CapabilityPolicyError(
      'POLICY_END_STATE_INCOMPLETE',
      'Stage "full" must enable all 26 advertised tools',
    );
  }

  for (const name of Object.keys(ALWAYS_DENIED)) {
    if (TOOL_BY_NAME.has(name)) {
      throw new CapabilityPolicyError(
        'POLICY_DENY_LIST_COLLISION',
        `"${name}" is both a catalog tool and an always-denied internal handler`,
      );
    }
  }
  for (const name of Object.keys(PILOT_DENIED)) {
    if (!TOOL_BY_NAME.has(name)) {
      throw new CapabilityPolicyError(
        'POLICY_DENY_LIST_UNKNOWN',
        `Pilot-denied "${name}" is not one of the 26 advertised tools`,
      );
    }
  }

  // The four owner-approval tools never become plain-allowed at any stage.
  for (const stage of CAPABILITY_STAGES) {
    for (const name of OWNER_APPROVAL_TOOLS) {
      const decision = evaluateTool(name, { stage, pilot: false });
      if (decision.decision === 'allowed') {
        throw new CapabilityPolicyError(
          'POLICY_APPROVAL_BYPASS',
          `"${name}" evaluates to plain "allowed" at stage ${stage}`,
        );
      }
    }
  }

  // GM-72 tier-1 ceiling invariants: the ceiling is exactly the agent-reachable set (so the report
  // the panel consumes cannot drift from the decision engine), it is never device-settable, it
  // never contains a hard-denied name, and the reserved tier-1 refusal code is not redeclared as a
  // per-tool decision code.
  for (const stage of CAPABILITY_STAGES) {
    for (const pilot of [true, false]) {
      const ceiling = ceilingForStage(stage, { pilot });
      const reachable = agentReachableToolCount({ stage, pilot });
      if (ceiling.tools.length !== reachable) {
        throw new CapabilityPolicyError(
          'POLICY_CEILING_COUNT',
          `The ceiling at stage ${stage} (pilot ${pilot}) permits ${ceiling.tools.length} tools but ${reachable} are agent-reachable`,
        );
      }
      if (ceiling.deviceSettable !== false || ceiling.source !== CEILING_SOURCE) {
        throw new CapabilityPolicyError(
          'POLICY_CEILING_NOT_SERVER_OWNED',
          'The ceiling must be server-owned data and never device-settable',
        );
      }
      const denied = new Set(ceiling.hardDenied.map((entry) => entry.tool));
      for (const name of ceiling.tools) {
        if (denied.has(name)) {
          throw new CapabilityPolicyError(
            'POLICY_CEILING_DENY_LEAK',
            `The ceiling at stage ${stage} permits "${name}" which tier 1 denies`,
          );
        }
      }
      for (const name of ceiling.approvalRequired) {
        if (!OWNER_APPROVAL_TOOLS.includes(name)) {
          throw new CapabilityPolicyError(
            'POLICY_CEILING_APPROVAL_SET',
            `The ceiling marks "${name}" approval-required, which is not an owner-approval tool`,
          );
        }
      }
    }
  }

  if (Object.values(DECISION_CODES).includes(CEILING_REFUSAL_CODE)) {
    throw new CapabilityPolicyError(
      'POLICY_CEILING_CODE_COLLISION',
      `"${CEILING_REFUSAL_CODE}" is a tier-1 ceiling refusal code and must not be a per-tool decision code`,
    );
  }

  return true;
}

module.exports = {
  CAPABILITY_POLICY_SCHEMA,
  CAPABILITY_CONTRACT_SCHEMA,
  CAPABILITY_CEILING_SCHEMA,
  CEILING_SOURCE,
  CEILING_REFUSAL_CODE,
  CEILING_DENY_SCOPES,
  CAPABILITY_STAGES,
  STAGE_RANK,
  CONSENT_CLASSES,
  DECISION_CODES,
  TOOL_CATALOG,
  ADVERTISED_TOOL_COUNT,
  INTERNAL_HANDLERS,
  ALWAYS_DENIED,
  PILOT_DENIED,
  OWNER_APPROVAL_TOOLS,
  FORBIDDEN_RELAY_CLIENT_NAMES,
  RELAY_CLIENT_NAME,
  HIDDEN_FOR_FORBIDDEN_CLIENT,
  CapabilityPolicyError,
  assertStage,
  getToolDefinition,
  isAdvertisedTool,
  stageToolNames,
  stageToolCount,
  ownerApprovalTools,
  deniedToolNames,
  ceilingForStage,
  ceilingToolNames,
  ceilingToolCount,
  evaluateTool,
  isAgentReachable,
  agentReachableToolCount,
  pilotEndState,
  describeStageTable,
  assertRelayClientInfo,
  assertRelayToolAdvertisement,
  assertPolicyIntegrity,
};
