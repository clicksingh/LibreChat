'use strict';

/**
 * Device tool registry — GM-72 / W8: tool policy as SERVER CEILING ∩ DEVICE FLOOR.
 *
 * LOCAL LAB ONLY. Production G0 remains BLOCKED. Nothing here is mounted on a production host.
 *
 * THE RULING (GM-72, `docs/GM-RULING-TOOL-CONFIG-AND-USER-TRY-20261023.md` §1)
 * Tools are user-configurable in the desktop app, WITH ONE ABSOLUTE CONSTRAINT: the device may
 * NARROW the server's permission, never WIDEN it. Tool permission is enforced server-side
 * (`./deviceCapabilityPolicy` plus the relay's per-tool deny-list), so a device that owned the
 * decision would be granting itself permission — the exact inversion this project exists to
 * prevent. Hence three tiers, strictly ordered:
 *
 *   | Tier | Owner of the decision                    | Changeable by                     |
 *   |------|------------------------------------------|-----------------------------------|
 *   | 1    | Server ceiling: stage A/B/C/full + hard  | Governor only, never the device   |
 *   |      | denies (tier-1 data: `ceilingForStage`)  |                                   |
 *   | 2    | Device floor: the employee's local config| The employee, on the PC — but only|
 *   |      |                                          | to a SUBSET of tier 1              |
 *   | 3    | Per-call approval: the four owner-       | Always required, at every stage    |
 *   |      | approval tools                           |                                   |
 *
 * EFFECTIVE SET = CEILING ∩ FLOOR, computed here, enforced server-side. `effectiveTools()` returns
 * the permitted set AND, for everything excluded, WHY (outside the ceiling vs switched off on the
 * device) so the panel can explain a refusal instead of failing mysteriously. `authorizeDispatch()`
 * is the load-bearing dispatch gate: a tool outside the ceiling is refused with the distinct code
 * `CEILING_REFUSAL_CODE` (`TOOL_CEILING_OUTSIDE_SERVER_CEILING`) EVEN WHEN the device claims it is
 * enabled. Nothing in this module reads a request, a session or a database: the ceiling is server
 * data supplied by the caller, the floor is device-supplied data parsed defensively, and the
 * decision is deterministic.
 *
 * DENIED REGARDLESS OF ANY DEVICE CONFIG (tier 1 hard denies, never selectable in the UI)
 * - `track_ui_event` — an internal dispatch handler, not a tool; relay-denied 403 (F-H02-2).
 * - `give_feedback_to_desktop_commander` — denied for the pilot (third-party egress, C05-1).
 * Both are reported as excluded with their own reason (`always-denied` / `pilot-denied`) wherever a
 * device claims them, and both are refused at dispatch with `TOOL_NOT_PERMITTED`.
 *
 * THE FOUR APPROVAL TOOLS STAY APPROVAL-GATED when `enabled`: they are members of the effective set
 * and appear in `approvalRequired`, and dispatch returns `decision: 'approval-required'` — never a
 * plain `allowed`. Approval never silently becomes permission.
 *
 * DEVICE FLOOR — FAIL CLOSED (no floor value means "everything enabled")
 * `parseDeviceFloor` accepts exactly one canonical shape, `{ schema?, enabled: string[] }`, and
 * nothing else. Malformed or unknown-shaped input is NOT repaired and NOT interpreted:
 *   - shape `absent`  (nothing reported) → nothing is enabled locally; every ceiling tool is
 *     excluded with `device-floor-absent` (the device has not positively enabled it).
 *   - shape `malformed` (garbage) → nothing is enabled; every ceiling tool is excluded with
 *     `device-floor-malformed`, and dispatch refuses with `TOOL_DEVICE_FLOOR_MALFORMED`.
 * The distinction matters for the panel: "you switched it off / have not switched it on" is not the
 * same message as "your local config is invalid". Shape-level garbage (a non-object, an array, a
 * missing or non-array `enabled`, a non-string or empty entry, a wildcard sentinel like `*` / `all`,
 * an absurdly long list) fails the WHOLE floor closed. A well-formed NAME that is not one of the 26
 * tools keeps the floor valid but cannot be honoured: that claim is reported per-tool as
 * `outside-server-ceiling`.
 *
 * WHAT THIS MODULE DELIBERATELY DOES NOT DO
 * - It does not read or write a device document, an HTTP request or the database. Where the floor
 *   is persisted and authenticated is the endpoint agent's and the route's problem (W7), not a
 *   policy question.
 * - It does not mint or send frames. `./relay/relayDispatchClient` does that; the intended wiring is
 *   to call `assertDispatchAllowed()` before `dispatchCommand()`.
 * - It does not decide the stage. The ceiling is passed in from governor policy.
 */

const policy = require('./deviceCapabilityPolicy');

/** The registry report schema id (what the panel consumes). */
const TOOL_REGISTRY_SCHEMA = 'cbhr.rdc.tool-registry/1';

/** The canonical device-floor schema id. */
const DEVICE_TOOL_FLOOR_SCHEMA = 'cbhr.rdc.device-tool-floor/1';

/** The three tiers, as data, in strict order. Tier 1 is never device-settable. */
const TOOL_POLICY_TIERS = Object.freeze([
  Object.freeze({
    tier: 1,
    name: 'server-ceiling',
    owner: 'governor',
    source: policy.CEILING_SOURCE,
    deviceSettable: false,
    changeableBy: 'Governor only',
    expressedBy: 'ceilingForStage',
    scope: 'capability stage A/B/C/full plus the always and pilot hard denies',
  }),
  Object.freeze({
    tier: 2,
    name: 'device-floor',
    owner: 'device',
    source: 'device',
    deviceSettable: true,
    changeableBy: 'the employee, on the PC',
    expressedBy: 'parseDeviceFloor',
    scope: 'may only NARROW tier 1; it can never add a tool the ceiling does not permit',
  }),
  Object.freeze({
    tier: 3,
    name: 'per-call-approval',
    owner: 'owner',
    source: 'server',
    deviceSettable: false,
    changeableBy: 'nobody',
    expressedBy: 'authorizeDispatch',
    scope: 'the four owner-approval tools stay approval-gated at every stage, when enabled',
    tools: policy.OWNER_APPROVAL_TOOLS,
  }),
]);

/** The effective-set law, as data, so a witness can assert it without reading prose. */
const EFFECTIVE_SET_LAW = Object.freeze({
  expression: 'ceiling ∩ floor',
  enforcedBy: 'server',
  deviceMayOnlyNarrow: true,
  deviceMayWiden: false,
});

/** Shapes `parseDeviceFloor` reports. Only `valid` can enable anything. */
const FLOOR_SHAPES = Object.freeze({
  VALID: 'valid',
  ABSENT: 'absent',
  MALFORMED: 'malformed',
});

/** Why a tool is not in the effective set — and whose choice that was. */
const EXCLUSION_REASONS = Object.freeze({
  /** Tier 2: the tool is inside the ceiling, the device did not enable it. */
  DISABLED_ON_DEVICE: 'disabled-on-device',
  /** Tier 1: the device claimed a tool the ceiling does not permit. */
  OUTSIDE_SERVER_CEILING: 'outside-server-ceiling',
  /** Tier 1: an internal handler that is denied at every stage (track_ui_event). */
  ALWAYS_DENIED: 'always-denied',
  /** Tier 1: denied for the pilot by the pilot deny-list (the feedback tool). */
  PILOT_DENIED: 'pilot-denied',
  /** Tier 2 degraded: no floor was reported, so nothing was positively enabled. */
  DEVICE_FLOOR_ABSENT: 'device-floor-absent',
  /** Tier 2 degraded: the floor was garbage; fail closed rather than interpret it. */
  DEVICE_FLOOR_MALFORMED: 'device-floor-malformed',
});

/** Which tier refused a tool: `server` (tiers 1/3) or `device` (tier 2). */
const DENIED_BY = Object.freeze({ SERVER: 'server', DEVICE: 'device' });

/**
 * The dispatch decision codes. The shared names are the pre-existing policy codes so a caller can
 * branch on one vocabulary; the tier-1 ceiling code is the distinct, load-bearing refusal for a
 * device claiming beyond the ceiling, and the two floor codes are tier-2 diagnostics.
 */
const DISPATCH_CODES = Object.freeze({
  ...policy.DECISION_CODES,
  OUTSIDE_SERVER_CEILING: policy.CEILING_REFUSAL_CODE,
  DISABLED_ON_DEVICE: 'TOOL_DISABLED_ON_DEVICE',
  DEVICE_FLOOR_MALFORMED: 'TOOL_DEVICE_FLOOR_MALFORMED',
  DEVICE_FLOOR_ABSENT: 'TOOL_DEVICE_FLOOR_ABSENT',
});

/** HTTP status per dispatch code; 403 for a refusal whose cause is a tier, never a 500. */
const DISPATCH_HTTP_STATUS = Object.freeze({
  [policy.DECISION_CODES.INVALID_NAME]: 400,
  [policy.DECISION_CODES.UNKNOWN]: 400,
  [policy.DECISION_CODES.NOT_PERMITTED]: 403,
  [policy.CEILING_REFUSAL_CODE]: 403,
  [DISPATCH_CODES.DISABLED_ON_DEVICE]: 403,
  [DISPATCH_CODES.DEVICE_FLOOR_MALFORMED]: 403,
  [DISPATCH_CODES.DEVICE_FLOOR_ABSENT]: 403,
});

/** Reason text per exclusion reason. Fixed strings; no payload, no device-supplied text. */
const EXCLUSION_DETAILS = Object.freeze({
  [EXCLUSION_REASONS.DISABLED_ON_DEVICE]:
    'Enabled by the server ceiling, but not enabled in this PC’s local tool configuration (tier 2). Turn it back on on the PC.',
  [EXCLUSION_REASONS.OUTSIDE_SERVER_CEILING]:
    'Requested by the device, but outside the server ceiling (tier 1). The device may only narrow the ceiling, never widen it.',
  [EXCLUSION_REASONS.ALWAYS_DENIED]:
    'Denied at every stage by server policy (tier 1); no device configuration can enable it.',
  [EXCLUSION_REASONS.PILOT_DENIED]:
    'Denied for the pilot by server policy (tier 1); no device configuration can enable it.',
  [EXCLUSION_REASONS.DEVICE_FLOOR_ABSENT]:
    'No local tool configuration was received from this device, so nothing is enabled on it (tier 2, fail closed).',
  [EXCLUSION_REASONS.DEVICE_FLOOR_MALFORMED]:
    'The device’s local tool configuration is not in a recognised shape, so the server refuses to interpret it and nothing is enabled (tier 2, fail closed).',
});

/**
 * Wildcard-looking values a device might use to mean "everything". There is no such value: a
 * sentinel is treated as malformed and fails the whole floor closed, so it can never be read as
 * "all tools enabled". Compared case-insensitively.
 */
const FLOOR_WILDCARD_SENTINELS = Object.freeze([
  '*',
  '**',
  'all',
  'any',
  'everything',
  'true',
  'null',
  'undefined',
]);

/** Bounds that make an absurd floor malformed rather than merely unhelpful. */
const FLOOR_MAX_ENTRIES = 256;
const FLOOR_MAX_NAME_LENGTH = 128;

/** Typed registry failure for an unusable CEILING (server-side programming/data error). */
class DeviceToolRegistryError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'DeviceToolRegistryError';
    this.code = code;
  }
}

/**
 * Typed refusal thrown by `assertDispatchAllowed`. Never thrown for a tier-2/tier-1 policy
 * refusal returned by `authorizeDispatch`; this is the throwing form a dispatch path uses so a
 * refusal cannot be silently ignored.
 */
class DeviceToolRefusalError extends Error {
  constructor(code, message, options = {}) {
    super(message);
    this.name = 'DeviceToolRefusalError';
    this.code = code;
    this.httpStatus = options.httpStatus ?? null;
    this.tool = options.tool ?? null;
    this.reason = options.reason ?? null;
    this.reasonCode = options.reasonCode ?? null;
    this.deniedBy = options.deniedBy ?? null;
  }

  toJSON() {
    return {
      name: this.name,
      code: this.code,
      httpStatus: this.httpStatus,
      tool: this.tool,
      message: this.message,
      reason: this.reason,
      reasonCode: this.reasonCode,
      deniedBy: this.deniedBy,
    };
  }
}

/** A plain record (not an array, not a class instance carrying request-ish state). */
function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/**
 * Own-property lookup for the policy's deny maps. `ALWAYS_DENIED['constructor']` would otherwise
 * return an inherited function from `Object.prototype` and be mistaken for a deny entry; a name is
 * only ever a deny-list hit when the map itself declares it.
 */
function ownEntry(map, name) {
  return Object.prototype.hasOwnProperty.call(map, name) ? map[name] : undefined;
}

/**
 * The tier-1 hard deny for a name, or `undefined`. This is LAW, not ceiling data: it is consulted
 * from the policy on every path, so neither a device claim nor a mistaken ceiling document can
 * place an always-denied handler or the pilot-denied feedback tool into an effective set.
 */
function tier1DenyFor(name, pilot) {
  const always = ownEntry(policy.ALWAYS_DENIED, name);
  if (always !== undefined) {
    return { ...always, scope: policy.CEILING_DENY_SCOPES.ALWAYS };
  }
  if (pilot) {
    const pilotDeny = ownEntry(policy.PILOT_DENIED, name);
    if (pilotDeny !== undefined) {
      return { ...pilotDeny, scope: policy.CEILING_DENY_SCOPES.PILOT };
    }
  }
  return undefined;
}

function malformedFloor(problem, extras = {}) {
  return Object.freeze({
    schema: DEVICE_TOOL_FLOOR_SCHEMA,
    source: 'device',
    present: extras.present === true,
    shape: FLOOR_SHAPES.MALFORMED,
    declaredSchema: extras.declaredSchema ?? null,
    enabled: Object.freeze([]),
    claimed: Object.freeze([]),
    unknownKeys: Object.freeze(extras.unknownKeys ?? []),
    problem,
  });
}

/**
 * The human explanation for a device claim the ceiling does not permit. One function, used by both
 * the panel report and the dispatch refusal, so the two can never describe the same event
 * differently.
 */
function outsideCeilingDetail(name, ceilingStage) {
  const definition = policy.getToolDefinition(name);
  if (definition === undefined) {
    return 'Not one of the 26 supported Desktop Commander tools, so it is outside the server ceiling.';
  }
  return `Enabled from stage ${definition.stage}; the server ceiling is stage ${ceilingStage}. The device may only narrow the ceiling, never widen it (GM-72).`;
}

/** The explanation for a floor-level failure (absent or malformed), including the parse problem. */
function floorFailureDetail(reason, floor) {
  const base = EXCLUSION_DETAILS[reason];
  return floor.shape === FLOOR_SHAPES.MALFORMED && floor.problem !== null
    ? `${base} (${floor.problem})`
    : base;
}

/**
 * The tier-2 refusal for a floor that cannot enable anything, or `null` when the floor is usable.
 * One function, so the report row and the dispatch refusal always agree on the reason and the code.
 */
function floorRefusal(floor) {
  if (floor.shape === FLOOR_SHAPES.MALFORMED) {
    return {
      reason: EXCLUSION_REASONS.DEVICE_FLOOR_MALFORMED,
      code: DISPATCH_CODES.DEVICE_FLOOR_MALFORMED,
    };
  }
  if (floor.shape === FLOOR_SHAPES.ABSENT) {
    return {
      reason: EXCLUSION_REASONS.DEVICE_FLOOR_ABSENT,
      code: DISPATCH_CODES.DEVICE_FLOOR_ABSENT,
    };
  }
  return null;
}

/**
 * Parses a device floor defensively. Never throws, never repairs, never guesses.
 *
 * Accepted canonical shape (the only one):
 *   { "schema": "cbhr.rdc.device-tool-floor/1", "enabled": ["read_file", "list_directory"] }
 * `schema` may be omitted (an older agent); if present it must match exactly. `enabled` is REQUIRED
 * and must be an array of unique, non-empty, non-wildcard strings. Unknown top-level keys are
 * ignored and reported (`unknownKeys`), because they cannot enable anything.
 *
 * @param {unknown} deviceFloor the device-reported local configuration
 * @returns {Readonly<object>} `{ schema, source, present, shape, declaredSchema, enabled, claimed,
 *   unknownKeys, problem }` — `enabled` is empty for every shape other than `valid`
 */
function parseDeviceFloor(deviceFloor) {
  if (deviceFloor === undefined || deviceFloor === null) {
    return Object.freeze({
      schema: DEVICE_TOOL_FLOOR_SCHEMA,
      source: 'device',
      present: false,
      shape: FLOOR_SHAPES.ABSENT,
      declaredSchema: null,
      enabled: Object.freeze([]),
      claimed: Object.freeze([]),
      unknownKeys: Object.freeze([]),
      problem: 'no device tool floor was received',
    });
  }

  if (!isPlainRecord(deviceFloor)) {
    return malformedFloor(
      `a device tool floor must be an object of shape { enabled: string[] }; received ${
        Array.isArray(deviceFloor) ? 'an array' : typeof deviceFloor
      }`,
      { present: true },
    );
  }

  const declaredSchema = deviceFloor.schema ?? null;
  if (
    declaredSchema !== null &&
    (typeof declaredSchema !== 'string' || declaredSchema !== DEVICE_TOOL_FLOOR_SCHEMA)
  ) {
    return malformedFloor(
      `the device tool floor declares an unrecognised schema; expected ${DEVICE_TOOL_FLOOR_SCHEMA}`,
      { present: true, declaredSchema },
    );
  }

  if (!Array.isArray(deviceFloor.enabled)) {
    return malformedFloor(
      'the device tool floor must carry an "enabled" array of tool names; a missing or non-array value is never read as "everything enabled"',
      { present: true, declaredSchema },
    );
  }

  if (deviceFloor.enabled.length > FLOOR_MAX_ENTRIES) {
    return malformedFloor(`the device tool floor lists more than ${FLOOR_MAX_ENTRIES} tools`, {
      present: true,
      declaredSchema,
    });
  }

  const unknownKeys = Object.keys(deviceFloor)
    .filter((key) => key !== 'schema' && key !== 'enabled')
    .sort();

  const claimed = [];
  for (const entry of deviceFloor.enabled) {
    if (typeof entry !== 'string' || entry.trim().length === 0) {
      return malformedFloor('the device tool floor contains a non-string or empty tool name', {
        present: true,
        declaredSchema,
        unknownKeys,
      });
    }
    const name = entry.trim();
    if (name.length > FLOOR_MAX_NAME_LENGTH) {
      return malformedFloor('the device tool floor contains an over-long tool name', {
        present: true,
        declaredSchema,
        unknownKeys,
      });
    }
    if (FLOOR_WILDCARD_SENTINELS.includes(name.toLowerCase())) {
      return malformedFloor(
        `the device tool floor uses the wildcard sentinel "${name}"; no floor value means "everything enabled"`,
        { present: true, declaredSchema, unknownKeys },
      );
    }
    if (claimed.includes(name)) {
      return malformedFloor('the device tool floor lists the same tool name more than once', {
        present: true,
        declaredSchema,
        unknownKeys,
      });
    }
    claimed.push(name);
  }

  return Object.freeze({
    schema: DEVICE_TOOL_FLOOR_SCHEMA,
    source: 'device',
    present: true,
    shape: FLOOR_SHAPES.VALID,
    declaredSchema,
    enabled: Object.freeze([...claimed]),
    claimed: Object.freeze([...claimed]),
    unknownKeys: Object.freeze(unknownKeys),
    problem: null,
  });
}

/**
 * Normalises the SERVER ceiling. Accepts a stage name, a governor ceiling document from
 * `policy.ceilingForStage`, or a hand-built `{ stage, tools }` document (which is how CI proves the
 * hard denies hold even if the ceiling data itself were wrong). A ceiling that declares itself
 * device-settable, or claims a non-server source, is REFUSED — tier 1 is never device data.
 *
 * @param {string|object} ceiling
 * @returns {Readonly<object>} `{ stage, pilot, tools, approvalRequired, hardDenied, source,
 *   deviceSettable, provided }`
 * @throws {DeviceToolRegistryError}
 */
function normalizeCeiling(ceiling) {
  if (typeof ceiling === 'string') {
    return fromPolicyCeiling(policy.ceilingForStage(ceiling), 'stage-name');
  }
  if (!isPlainRecord(ceiling)) {
    throw new DeviceToolRegistryError(
      'TOOL_CEILING_INVALID',
      'the server ceiling must be a stage name or a ceiling document; a device never supplies it',
    );
  }
  if (ceiling.deviceSettable === true) {
    throw new DeviceToolRegistryError(
      'TOOL_CEILING_NOT_SERVER_OWNED',
      'the ceiling is server-owned and not device-settable; refusing a ceiling that claims otherwise',
    );
  }
  if (ceiling.source !== undefined && ceiling.source !== policy.CEILING_SOURCE) {
    throw new DeviceToolRegistryError(
      'TOOL_CEILING_NOT_SERVER_OWNED',
      `the ceiling source must be "${policy.CEILING_SOURCE}"; refusing a ceiling that claims otherwise`,
    );
  }
  if (typeof ceiling.stage !== 'string' || !policy.CAPABILITY_STAGES.includes(ceiling.stage)) {
    throw new DeviceToolRegistryError(
      'TOOL_CEILING_INVALID',
      `the server ceiling must declare a capability stage (${policy.CAPABILITY_STAGES.join(', ')})`,
    );
  }
  if (ceiling.tools === undefined) {
    // A stage-only document is resolved from policy, so the stage ladder can never be bypassed.
    return fromPolicyCeiling(
      policy.ceilingForStage(ceiling.stage, { pilot: ceiling.pilot !== false }),
      'stage-only',
    );
  }
  if (!Array.isArray(ceiling.tools) || ceiling.tools.some((name) => typeof name !== 'string')) {
    throw new DeviceToolRegistryError(
      'TOOL_CEILING_INVALID',
      'the server ceiling tools must be an array of tool names',
    );
  }
  return fromPolicyCeiling(ceiling, 'explicit');
}

/** Projects a ceiling (policy document or explicit data) into the frozen shape the registry uses. */
function fromPolicyCeiling(ceiling, provided) {
  const pilot = ceiling.pilot !== false;
  const tools = [...ceiling.tools];
  const approvalRequired =
    Array.isArray(ceiling.approvalRequired) && provided !== 'explicit'
      ? [...ceiling.approvalRequired]
      : tools.filter((name) => policy.OWNER_APPROVAL_TOOLS.includes(name));
  const hardDenied = Array.isArray(ceiling.hardDenied)
    ? ceiling.hardDenied.map((entry) => Object.freeze({ ...entry }))
    : [];
  return Object.freeze({
    schema: ceiling.schema ?? policy.CAPABILITY_CEILING_SCHEMA,
    tier: 1,
    source: policy.CEILING_SOURCE,
    deviceSettable: false,
    stage: ceiling.stage,
    pilot,
    tools: Object.freeze(tools),
    approvalRequired: Object.freeze(approvalRequired),
    hardDenied: Object.freeze(hardDenied),
    provided,
  });
}

/**
 * THE INTERSECTION — GM-72's effective set, with a reason for everything excluded.
 *
 * `enabled` is exactly `ceiling.tools ∩ floor.enabled` (a Set intersection, in catalog order).
 * Whatever the floor claims, nothing outside the ceiling can appear: the ceiling is the authority
 * and the floor is a filter over it. `excluded` explains every tool that is off and WHOSE choice
 * that was (`deniedBy`), so the panel can say "off on this PC, by your local config" versus
 * "refused by server policy" instead of failing mysteriously.
 *
 * Never throws for a floor problem: an absent or malformed floor fails closed — nothing is enabled
 * — with the failure named in `deviceFloor.shape` and in every exclusion reason.
 *
 * @param {object} params
 * @param {string|object} params.ceiling server ceiling (stage name or `ceilingForStage` document)
 * @param {unknown} params.deviceFloor device-reported floor
 * @returns {Readonly<object>} JSON-serializable report (see the header and the spec)
 */
function effectiveTools({ ceiling, deviceFloor } = {}) {
  const serverCeiling = normalizeCeiling(ceiling);
  const floor = parseDeviceFloor(deviceFloor);

  const floorSet = new Set(floor.enabled);
  const deniedByTool = new Map(serverCeiling.hardDenied.map((entry) => [entry.tool, entry]));

  // Tier-1 law outranks ceiling data: a name the ceiling lists but the hard deny-list forbids can
  // never reach the effective set. It is recorded rather than silently dropped, because a ceiling
  // that lists one is a defect someone must see.
  const withheldByTier1Law = serverCeiling.tools.filter(
    (name) => tier1DenyFor(name, serverCeiling.pilot) !== undefined,
  );
  const permitted = serverCeiling.tools.filter((name) => !withheldByTier1Law.includes(name));

  const refusal = floorRefusal(floor);

  const enabled = [];
  const excluded = [];

  for (const name of permitted) {
    if (refusal === null && floorSet.has(name)) {
      enabled.push(name);
      continue;
    }
    excluded.push(
      Object.freeze({
        tool: name,
        reason: refusal === null ? EXCLUSION_REASONS.DISABLED_ON_DEVICE : refusal.reason,
        deniedBy: refusal === null ? DENIED_BY.DEVICE : DENIED_BY.SERVER,
        code: refusal === null ? DISPATCH_CODES.DISABLED_ON_DEVICE : refusal.code,
        httpStatus: 403,
        detail:
          refusal === null
            ? EXCLUSION_DETAILS[EXCLUSION_REASONS.DISABLED_ON_DEVICE]
            : floorFailureDetail(refusal.reason, floor),
      }),
    );
  }

  // Claims the device made that are NOT in the effective set must also be explained: either the
  // ceiling already denied the name outright (hard deny) or the device asked for something the
  // ceiling does not permit (widening).
  if (floor.shape === FLOOR_SHAPES.VALID) {
    for (const name of floor.claimed) {
      if (enabled.includes(name) || excluded.some((entry) => entry.tool === name)) {
        continue;
      }
      // Hard denies are tier-1 LAW, not ceiling data: they are consulted from the policy even when
      // a ceiling document does not declare them, so a claim is never explained as merely "outside
      // the ceiling" when it is actually always denied.
      const deny = deniedByTool.get(name) ?? tier1DenyFor(name, serverCeiling.pilot);
      if (deny !== undefined) {
        excluded.push(
          Object.freeze({
            tool: name,
            reason:
              deny.scope === policy.CEILING_DENY_SCOPES.PILOT
                ? EXCLUSION_REASONS.PILOT_DENIED
                : EXCLUSION_REASONS.ALWAYS_DENIED,
            deniedBy: DENIED_BY.SERVER,
            code: deny.code,
            httpStatus: deny.httpStatus,
            detail: deny.reason,
          }),
        );
        continue;
      }
      excluded.push(
        Object.freeze({
          tool: name,
          reason: EXCLUSION_REASONS.OUTSIDE_SERVER_CEILING,
          deniedBy: DENIED_BY.SERVER,
          code: DISPATCH_CODES.OUTSIDE_SERVER_CEILING,
          httpStatus: DISPATCH_HTTP_STATUS[DISPATCH_CODES.OUTSIDE_SERVER_CEILING],
          detail: outsideCeilingDetail(name, serverCeiling.stage),
        }),
      );
    }
  }

  const approvalRequired = enabled.filter((name) => serverCeiling.approvalRequired.includes(name));

  return Object.freeze({
    schema: TOOL_REGISTRY_SCHEMA,
    tierLaw: EFFECTIVE_SET_LAW,
    ceiling: Object.freeze({
      schema: serverCeiling.schema,
      tier: 1,
      source: serverCeiling.source,
      deviceSettable: false,
      stage: serverCeiling.stage,
      pilot: serverCeiling.pilot,
      toolCount: serverCeiling.tools.length,
      approvalRequiredCount: serverCeiling.approvalRequired.length,
      hardDenied: serverCeiling.hardDenied,
      withheldByTier1Law: Object.freeze([...withheldByTier1Law]),
    }),
    deviceFloor: Object.freeze({
      schema: floor.schema,
      tier: 2,
      source: 'device',
      present: floor.present,
      shape: floor.shape,
      declaredSchema: floor.declaredSchema,
      claimedCount: floor.claimed.length,
      claimed: floor.claimed,
      enabledCount: floor.enabled.length,
      unknownKeys: floor.unknownKeys,
      problem: floor.problem,
    }),
    enabled: Object.freeze(enabled),
    approvalRequired: Object.freeze(approvalRequired),
    excluded: Object.freeze(excluded),
    counts: Object.freeze({
      ceiling: serverCeiling.tools.length,
      deviceClaimed: floor.claimed.length,
      effective: enabled.length,
      approvalRequired: approvalRequired.length,
      excluded: excluded.length,
      disabledOnDevice: excluded.filter(
        (entry) => entry.reason === EXCLUSION_REASONS.DISABLED_ON_DEVICE,
      ).length,
      outsideCeiling: excluded.filter(
        (entry) => entry.reason === EXCLUSION_REASONS.OUTSIDE_SERVER_CEILING,
      ).length,
    }),
    failClosed: floor.shape !== FLOOR_SHAPES.VALID,
  });
}

/**
 * THE DISPATCH GATE — server-side, ceiling first. `allowed` is true only for a tool inside the
 * ceiling AND enabled by the device; approval-gated tools are admissible but carry
 * `requiresApproval: true`.
 *
 * Order of decision (each step is a distinct, attributable code):
 *   1. non-string / empty name                  → TOOL_NAME_INVALID (400)
 *   2. tier-1 hard deny: `track_ui_event` at any stage, and the pilot-denied feedback tool while
 *      the pilot overlay is in force             → TOOL_NOT_PERMITTED (403)
 *   3. not one of the 26 advertised tools        → TOOL_UNKNOWN (400)
 *   4. outside the server ceiling                → TOOL_CEILING_OUTSIDE_SERVER_CEILING (403) — THE
 *      DISTINCT WIDENING REFUSAL. The device floor is not consulted: a device claim cannot widen.
 *   5. floor malformed / absent                  → TOOL_DEVICE_FLOOR_MALFORMED / _ABSENT (403, fail
 *      closed)
 *   6. inside the ceiling, not enabled on the PC → TOOL_DISABLED_ON_DEVICE (403, tier 2)
 *   7. owner-approval tool                       → OWNER_APPROVAL_REQUIRED (approval-required)
 *   8. otherwise                                 → TOOL_ALLOWED
 *
 * Never throws for a policy refusal; `assertDispatchAllowed` is the throwing form.
 *
 * @param {string} toolName
 * @param {object} params
 * @param {string|object} params.ceiling server ceiling
 * @param {unknown} params.deviceFloor device floor
 * @returns {Readonly<object>} decision
 */
function authorizeDispatch(toolName, { ceiling, deviceFloor } = {}) {
  const serverCeiling = normalizeCeiling(ceiling);
  const floor = parseDeviceFloor(deviceFloor);

  const base = {
    tool: typeof toolName === 'string' ? toolName : null,
    stage: serverCeiling.stage,
    tier: null,
    decision: 'denied',
    allowed: false,
    requiresApproval: false,
    code: null,
    httpStatus: null,
    reason: null,
    reasonCode: null,
    deniedBy: DENIED_BY.SERVER,
    ceiling: Object.freeze({ stage: serverCeiling.stage, pilot: serverCeiling.pilot }),
    deviceFloor: Object.freeze({ shape: floor.shape, present: floor.present }),
  };
  const deny = (fields) => Object.freeze({ ...base, ...fields });

  if (typeof toolName !== 'string' || toolName.length === 0) {
    return deny({
      code: DISPATCH_CODES.INVALID_NAME,
      httpStatus: DISPATCH_HTTP_STATUS[DISPATCH_CODES.INVALID_NAME],
      reason: 'The dispatch named a non-string or empty tool',
    });
  }

  const hardDeny = tier1DenyFor(toolName, serverCeiling.pilot);
  if (hardDeny !== undefined) {
    return deny({
      tier: 1,
      code: hardDeny.code,
      httpStatus: hardDeny.httpStatus,
      reason: hardDeny.reason,
      reasonCode:
        hardDeny.scope === policy.CEILING_DENY_SCOPES.PILOT
          ? EXCLUSION_REASONS.PILOT_DENIED
          : EXCLUSION_REASONS.ALWAYS_DENIED,
    });
  }

  const definition = policy.getToolDefinition(toolName);
  if (definition === undefined) {
    return deny({
      code: DISPATCH_CODES.UNKNOWN,
      httpStatus: DISPATCH_HTTP_STATUS[DISPATCH_CODES.UNKNOWN],
      reason: 'Not one of the 26 supported Desktop Commander tools',
    });
  }

  if (!serverCeiling.tools.includes(toolName)) {
    return deny({
      tier: 1,
      code: DISPATCH_CODES.OUTSIDE_SERVER_CEILING,
      httpStatus: DISPATCH_HTTP_STATUS[DISPATCH_CODES.OUTSIDE_SERVER_CEILING],
      reasonCode: EXCLUSION_REASONS.OUTSIDE_SERVER_CEILING,
      reason: outsideCeilingDetail(toolName, serverCeiling.stage),
    });
  }

  const refusal = floorRefusal(floor);
  if (refusal !== null) {
    return deny({
      tier: 2,
      code: refusal.code,
      httpStatus: DISPATCH_HTTP_STATUS[refusal.code],
      reasonCode: refusal.reason,
      reason: floorFailureDetail(refusal.reason, floor),
    });
  }

  if (!floor.enabled.includes(toolName)) {
    return deny({
      tier: 2,
      deniedBy: DENIED_BY.DEVICE,
      code: DISPATCH_CODES.DISABLED_ON_DEVICE,
      httpStatus: DISPATCH_HTTP_STATUS[DISPATCH_CODES.DISABLED_ON_DEVICE],
      reasonCode: EXCLUSION_REASONS.DISABLED_ON_DEVICE,
      reason: EXCLUSION_DETAILS[EXCLUSION_REASONS.DISABLED_ON_DEVICE],
    });
  }

  if (serverCeiling.approvalRequired.includes(toolName)) {
    return deny({
      tier: 3,
      decision: 'approval-required',
      allowed: true,
      requiresApproval: true,
      code: DISPATCH_CODES.APPROVAL_REQUIRED,
      httpStatus: null,
      reason:
        'Admissible at this stage and enabled on this device, but every execution requires explicit owner approval (tier 3)',
    });
  }

  return Object.freeze({
    ...base,
    decision: 'allowed',
    allowed: true,
    requiresApproval: false,
    code: DISPATCH_CODES.ALLOWED,
    httpStatus: null,
    reason: null,
  });
}

/**
 * The throwing form of `authorizeDispatch`: returns the decision when the dispatch may proceed
 * (including an approval-required one, which is admissible but must be approved per call), and
 * throws a `DeviceToolRefusalError` carrying the code and tier otherwise.
 *
 * @param {string} toolName
 * @param {object} params see `authorizeDispatch`
 * @returns {Readonly<object>} the decision, when allowed or approval-required
 * @throws {DeviceToolRefusalError}
 */
function assertDispatchAllowed(toolName, options = {}) {
  const decision = authorizeDispatch(toolName, options);
  if (decision.allowed !== true) {
    throw new DeviceToolRefusalError(
      decision.code,
      decision.reason ?? `dispatch refused: ${decision.code}`,
      {
        httpStatus: decision.httpStatus,
        tool: decision.tool,
        reason: decision.reason,
        reasonCode: decision.reasonCode,
        deniedBy: decision.deniedBy,
      },
    );
  }
  return decision;
}

/**
 * One tool's row for the panel: enabled or not, approval-gated or not, and — when it is off — the
 * reason and whose choice it was.
 *
 * @param {string} toolName
 * @param {object} params see `authorizeDispatch`
 * @returns {Readonly<object>}
 */
function explainTool(toolName, options = {}) {
  const decision = authorizeDispatch(toolName, options);
  return Object.freeze({
    tool: decision.tool,
    enabled: decision.allowed,
    requiresApproval: decision.requiresApproval,
    reason: decision.reasonCode,
    deniedBy: decision.allowed ? null : decision.deniedBy,
    detail: decision.reason,
    code: decision.code,
    httpStatus: decision.httpStatus,
  });
}

/** CI ASSERTION — the registry's three tiers, floor parser and intersection are coherent. */
function assertRegistryIntegrity() {
  const tiers = TOOL_POLICY_TIERS.map((entry) => entry.tier);
  if (tiers.join(',') !== '1,2,3') {
    throw new DeviceToolRegistryError(
      'REGISTRY_TIER_ORDER',
      'the tiers must be declared in strict order 1,2,3',
    );
  }
  if (TOOL_POLICY_TIERS[0].deviceSettable !== false) {
    throw new DeviceToolRegistryError(
      'REGISTRY_CEILING_DEVICE_SETTABLE',
      'tier 1 (the server ceiling) must never be device-settable',
    );
  }
  if (TOOL_POLICY_TIERS[1].deviceSettable !== true) {
    throw new DeviceToolRegistryError(
      'REGISTRY_FLOOR_NOT_DEVICE_SETTABLE',
      'tier 2 (the device floor) is the employee-settable tier',
    );
  }
  if (
    EFFECTIVE_SET_LAW.deviceMayWiden !== false ||
    EFFECTIVE_SET_LAW.deviceMayOnlyNarrow !== true
  ) {
    throw new DeviceToolRegistryError(
      'REGISTRY_WIDENING_ALLOWED',
      'the effective-set law must forbid widening',
    );
  }
  if (DISPATCH_CODES.OUTSIDE_SERVER_CEILING !== policy.CEILING_REFUSAL_CODE) {
    throw new DeviceToolRegistryError(
      'REGISTRY_REFUSAL_CODE_DRIFT',
      'the widening refusal code must be the one the ceiling policy declares',
    );
  }
  const widening = Object.values(DISPATCH_CODES).filter(
    (code) => typeof code === 'string' && code.startsWith('TOOL_CEILING_'),
  );
  if (widening.length !== 1 || widening[0] !== policy.CEILING_REFUSAL_CODE) {
    throw new DeviceToolRegistryError(
      'REGISTRY_REFUSAL_CODE_UNCLEAR',
      'exactly one ceiling-scoped refusal code may exist, so a widening refusal is unambiguous',
    );
  }

  for (const stage of policy.CAPABILITY_STAGES) {
    const ceiling = policy.ceilingForStage(stage);
    const floor = {
      schema: DEVICE_TOOL_FLOOR_SCHEMA,
      enabled: [...policy.ceilingToolNames(stage)],
    };
    const report = effectiveTools({ ceiling, deviceFloor: floor });
    if (
      report.enabled.length !== ceiling.tools.length ||
      report.excluded.some((entry) => entry.reason !== EXCLUSION_REASONS.DISABLED_ON_DEVICE)
    ) {
      throw new DeviceToolRegistryError(
        'REGISTRY_INTERSECTION_BROKEN',
        `a floor claiming exactly the ceiling must reproduce it at stage ${stage}`,
      );
    }
  }

  const maxFloor = {
    schema: DEVICE_TOOL_FLOOR_SCHEMA,
    enabled: policy.TOOL_CATALOG.map((tool) => tool.name),
  };
  for (const stage of policy.CAPABILITY_STAGES) {
    const report = effectiveTools({ ceiling: stage, deviceFloor: maxFloor });
    if (
      report.enabled.length !== policy.ceilingToolCount(stage) ||
      report.counts.effective !== policy.ceilingToolCount(stage)
    ) {
      throw new DeviceToolRegistryError(
        'REGISTRY_WIDENING_DETECTED',
        `a floor claiming every tool exceeds the ceiling at stage ${stage}`,
      );
    }
  }

  for (const garbage of [
    null,
    undefined,
    42,
    'read_file',
    [],
    {},
    { enabled: 'read_file' },
    { enabled: ['*'] },
  ]) {
    const report = effectiveTools({ ceiling: 'full', deviceFloor: garbage });
    if (report.enabled.length !== 0 || report.failClosed !== true) {
      throw new DeviceToolRegistryError(
        'REGISTRY_FLOOR_FAIL_OPEN',
        'an absent or malformed device floor must enable nothing',
      );
    }
  }

  return true;
}

module.exports = {
  TOOL_REGISTRY_SCHEMA,
  DEVICE_TOOL_FLOOR_SCHEMA,
  TOOL_POLICY_TIERS,
  EFFECTIVE_SET_LAW,
  FLOOR_SHAPES,
  EXCLUSION_REASONS,
  EXCLUSION_DETAILS,
  DENIED_BY,
  DISPATCH_CODES,
  DISPATCH_HTTP_STATUS,
  FLOOR_WILDCARD_SENTINELS,
  FLOOR_MAX_ENTRIES,
  FLOOR_MAX_NAME_LENGTH,
  DeviceToolRegistryError,
  DeviceToolRefusalError,
  isPlainRecord,
  parseDeviceFloor,
  normalizeCeiling,
  effectiveTools,
  authorizeDispatch,
  assertDispatchAllowed,
  explainTool,
  assertRegistryIntegrity,
};
