'use strict';

/**
 * GM-72 / W8 — tool policy as SERVER CEILING ∩ DEVICE FLOOR.
 *
 * `docs/GM-RULING-TOOL-CONFIG-AND-USER-TRY-20261023.md` §1 (GM-72) and the W8 acceptance criteria:
 * the owner may configure tools through the desktop app, but the device may only NARROW the
 * server's permission, never widen it. Enforcement is server-side; the effective set is the
 * intersection, reported to the panel with a reason for every exclusion.
 *
 * This spec exercises the two REAL modules only (`deviceCapabilityPolicy` = tier 1 ceiling,
 * `deviceToolRegistry` = tiers 2/3, intersection, dispatch gate). It stubs nothing, reads no
 * request, opens no database, and does not touch the pre-existing device suites: the frozen stage
 * ladder is asserted through the same public functions those suites use, so a change that broke the
 * ceiling would fail here too rather than only there.
 *
 * W8 acceptance, mapped to the `describe` blocks below:
 *  - ceiling authoritative and not device-settable ......... 'tier 1 — the server ceiling'
 *  - device floor can only narrow .......................... 'tier 2 — the device floor'
 *  - effective set = intersection, reported to the panel ... 'the effective set is the exact
 *                                                            intersection' / 'the panel report'
 *  - track_ui_event and the feedback tool denied regardless . 'tier 1 hard denies'
 *  - four approval tools stay approval-gated ............... 'tier 3 — per-call approval'
 *  - device claiming outside the ceiling refused with a
 *    distinct code, and that refusal is tested ............. 'a device cannot widen'
 */

const policy = require('~/server/services/Device/deviceCapabilityPolicy');
const registry = require('~/server/services/Device/deviceToolRegistry');

/** The 26 advertised tools, in catalog order. */
const CATALOG = policy.TOOL_CATALOG.map((tool) => tool.name);

/** The four owner-approval (tier 3) tools. */
const APPROVAL_TOOLS = [...policy.OWNER_APPROVAL_TOOLS];

/** The stage ladder, read from policy so this spec cannot drift from it. */
const STAGES = [...policy.CAPABILITY_STAGES];

const { FLOOR_SHAPES, EXCLUSION_REASONS, EXCLUSION_DETAILS, DENIED_BY, DISPATCH_CODES } = registry;

/** A canonical device floor. */
const floorOf = (enabled) => ({ schema: registry.DEVICE_TOOL_FLOOR_SCHEMA, enabled });

/** A floor claiming every one of the 26 tools — the widest claim a hand-edited config can make. */
const floorClaimingEverything = () => floorOf([...CATALOG]);

const ceilingOf = (stage, options) => policy.ceilingForStage(stage, options ?? {});

/** Every exclusion row for a tool (there should be at most one). */
const exclusionsFor = (report, tool) => report.excluded.filter((entry) => entry.tool === tool);

/** The single exclusion row for a tool, failing the test when it is missing or duplicated. */
function exclusionFor(report, tool) {
  const rows = exclusionsFor(report, tool);
  expect(rows).toHaveLength(1);
  return rows[0];
}

describe('GM-72 tier 1 — the server ceiling is governor data, not device data', () => {
  it('declares the three tiers in strict order, with tier 1 not device-settable', () => {
    expect(registry.TOOL_POLICY_TIERS.map((tier) => tier.tier)).toEqual([1, 2, 3]);

    const [ceiling, floor, approval] = registry.TOOL_POLICY_TIERS;
    expect(ceiling.name).toBe('server-ceiling');
    expect(ceiling.deviceSettable).toBe(false);
    expect(ceiling.changeableBy).toMatch(/Governor only/);
    expect(floor.name).toBe('device-floor');
    expect(floor.deviceSettable).toBe(true);
    expect(approval.name).toBe('per-call-approval');
    expect(approval.deviceSettable).toBe(false);
    expect([...approval.tools].sort()).toEqual([...APPROVAL_TOOLS].sort());

    expect(registry.EFFECTIVE_SET_LAW.expression).toBe('ceiling ∩ floor');
    expect(registry.EFFECTIVE_SET_LAW.enforcedBy).toBe('server');
    expect(registry.EFFECTIVE_SET_LAW.deviceMayOnlyNarrow).toBe(true);
    expect(registry.EFFECTIVE_SET_LAW.deviceMayWiden).toBe(false);
  });

  it('expresses the ceiling as data that preserves the existing stages and deny-list', () => {
    const pilotCounts = [];
    const postPilotCounts = [];

    for (const stage of STAGES) {
      for (const pilot of [true, false]) {
        const ceiling = ceilingOf(stage, { pilot });
        const denied = new Set(policy.deniedToolNames({ stage, pilot }));
        const expected = policy.stageToolNames(stage).filter((name) => !denied.has(name));

        expect(ceiling.tools).toEqual(expected);
        expect(ceiling.tools.length).toBe(policy.agentReachableToolCount({ stage, pilot }));
        expect(ceiling.deviceSettable).toBe(false);
        expect(ceiling.source).toBe(policy.CEILING_SOURCE);
        expect(ceiling.schema).toBe(policy.CAPABILITY_CEILING_SCHEMA);
        expect(ceiling.stage).toBe(stage);
        expect([...ceiling.tools]).not.toContain('track_ui_event');
      }
      pilotCounts.push(ceilingOf(stage).tools.length);
      postPilotCounts.push(ceilingOf(stage, { pilot: false }).tools.length);
    }

    // A (read-only) 8 · B (files) 12 · C (process/terminal/PDF) 20 · full 25 in the pilot (26 after).
    expect(pilotCounts).toEqual([8, 12, 20, 25]);
    expect(postPilotCounts).toEqual([8, 12, 20, 26]);
    expect(policy.ceilingToolNames('C')).toEqual([...ceilingOf('C').tools]);
    expect(policy.ceilingToolCount('C')).toBe(20);
  });

  it('refuses a ceiling that presents itself as device-settable', () => {
    const notServerOwned = [
      { ...ceilingOf('full'), deviceSettable: true },
      { stage: 'full', source: 'device', tools: [] },
    ];

    for (const bogus of notServerOwned) {
      expect(() => registry.normalizeCeiling(bogus)).toThrow(registry.DeviceToolRegistryError);
      let code = null;
      try {
        registry.normalizeCeiling(bogus);
      } catch (error) {
        code = error.code;
      }
      expect(code).toBe('TOOL_CEILING_NOT_SERVER_OWNED');
    }

    expect(() => registry.effectiveTools({ ceiling: 42, deviceFloor: floorOf([]) })).toThrow(
      registry.DeviceToolRegistryError,
    );
    expect(() => registry.normalizeCeiling({ stage: 'Z', tools: [] })).toThrow(
      registry.DeviceToolRegistryError,
    );
  });

  it('passes its own registry integrity assertion', () => {
    expect(registry.assertRegistryIntegrity()).toBe(true);
    expect(policy.assertPolicyIntegrity()).toBe(true);
  });
});

describe('GM-72 tier 2 — the device floor can only narrow, and a device cannot widen', () => {
  it('excludes a ceiling tool the device did not enable, and explains whose choice that was', () => {
    const report = registry.effectiveTools({
      ceiling: 'A',
      deviceFloor: floorOf(['read_file', 'get_file_info']),
    });

    // The same tool is enabled when the floor says so, so the exclusion below is caused by the
    // floor and nothing else.
    expect(report.enabled).toEqual(['read_file', 'get_file_info']);

    const row = exclusionFor(report, 'list_directory');
    expect(row.reason).toBe('disabled-on-device');
    expect(row.reason).toBe(EXCLUSION_REASONS.DISABLED_ON_DEVICE);
    expect(row.deniedBy).toBe('device');
    expect(row.deniedBy).toBe(DENIED_BY.DEVICE);
    expect(row.code).toBe(DISPATCH_CODES.DISABLED_ON_DEVICE);
    expect(row.code).not.toBe(policy.CEILING_REFUSAL_CODE);
    expect(row.httpStatus).toBe(403);
    expect(row.detail).toBe(EXCLUSION_DETAILS[EXCLUSION_REASONS.DISABLED_ON_DEVICE]);

    const decision = registry.authorizeDispatch('list_directory', {
      ceiling: 'A',
      deviceFloor: floorOf(['read_file', 'get_file_info']),
    });
    expect(decision.decision).toBe('denied');
    expect(decision.allowed).toBe(false);
    expect(decision.tier).toBe(2);
    expect(decision.code).toBe(DISPATCH_CODES.DISABLED_ON_DEVICE);
    expect(decision.code).not.toBe(policy.CEILING_REFUSAL_CODE);
    expect(decision.httpStatus).toBe(403);
    expect(decision.deniedBy).toBe(DENIED_BY.DEVICE);

    // And enabling it on the PC makes the very same call admissible (the test can fail both ways).
    expect(
      registry.authorizeDispatch('list_directory', {
        ceiling: 'A',
        deviceFloor: floorOf(['list_directory']),
      }).code,
    ).toBe(DISPATCH_CODES.ALLOWED);
  });

  it('refuses a tool outside the ceiling with the distinct code even when the device claims it', () => {
    // The device's claim is irrelevant to the outcome: claiming exactly the tool, claiming every
    // tool it can name, or claiming nothing all produce the same ceiling refusal.
    const claims = [floorOf(['write_file']), floorClaimingEverything(), floorOf([])];

    for (const deviceFloor of claims) {
      const decision = registry.authorizeDispatch('write_file', { ceiling: 'A', deviceFloor });

      expect(decision.allowed).toBe(false);
      expect(decision.decision).toBe('denied');
      expect(decision.code).toBe('TOOL_CEILING_OUTSIDE_SERVER_CEILING');
      expect(decision.code).toBe(policy.CEILING_REFUSAL_CODE);
      expect(decision.tier).toBe(1);
      expect(decision.deniedBy).toBe(DENIED_BY.SERVER);
      expect(decision.httpStatus).toBe(403);
      expect(decision.reasonCode).toBe(EXCLUSION_REASONS.OUTSIDE_SERVER_CEILING);
      // It is emphatically not the tier-2 code: a widening claim is refused by the ceiling.
      expect(decision.code).not.toBe(DISPATCH_CODES.DISABLED_ON_DEVICE);

      expect(() =>
        registry.assertDispatchAllowed('write_file', { ceiling: 'A', deviceFloor }),
      ).toThrow(registry.DeviceToolRefusalError);

      let thrown = null;
      try {
        registry.assertDispatchAllowed('write_file', { ceiling: 'A', deviceFloor });
      } catch (error) {
        thrown = error;
      }
      expect(thrown.code).toBe('TOOL_CEILING_OUTSIDE_SERVER_CEILING');
      expect(thrown.httpStatus).toBe(403);
      expect(thrown.tool).toBe('write_file');
      expect(thrown).toBeInstanceOf(registry.DeviceToolRefusalError);
    }

    // The claim is reported as a widening attempt, with the server named as the refuser.
    const report = registry.effectiveTools({
      ceiling: 'A',
      deviceFloor: floorOf(['write_file', 'read_file']),
    });
    expect(report.enabled).toEqual(['read_file']);
    const row = exclusionFor(report, 'write_file');
    expect(row.reason).toBe('outside-server-ceiling');
    expect(row.reason).toBe(EXCLUSION_REASONS.OUTSIDE_SERVER_CEILING);
    expect(row.deniedBy).toBe(DENIED_BY.SERVER);
    expect(row.code).toBe(policy.CEILING_REFUSAL_CODE);
    expect(row.detail).toMatch(/outside the server ceiling|may only narrow/);

    // Ceiling first: even a garbage floor cannot turn a widening claim into a tier-2 refusal code.
    expect(
      registry.authorizeDispatch('write_file', {
        ceiling: 'A',
        deviceFloor: { enabled: 'write_file' },
      }).code,
    ).toBe(policy.CEILING_REFUSAL_CODE);
  });

  it('keeps the widening refusal at every stage, for every tool the ceiling does not permit', () => {
    const deviceFloor = floorClaimingEverything();

    for (const stage of STAGES) {
      const ceiling = ceilingOf(stage);
      const report = registry.effectiveTools({ ceiling, deviceFloor });

      // A floor claiming all 26 tools can never exceed the ceiling.
      expect(report.enabled.length).toBe(ceiling.tools.length);
      expect(report.enabled.length).toBe(policy.ceilingToolCount(stage));
      expect([...report.enabled].sort()).toEqual([...ceiling.tools].sort());

      for (const tool of CATALOG) {
        const insideCeiling = ceiling.tools.includes(tool);
        const decision = registry.authorizeDispatch(tool, { ceiling, deviceFloor });

        if (insideCeiling) {
          expect(decision.allowed).toBe(true);
          expect([DISPATCH_CODES.ALLOWED, DISPATCH_CODES.APPROVAL_REQUIRED]).toContain(
            decision.code,
          );
          expect(decision.code).not.toBe(policy.CEILING_REFUSAL_CODE);
        } else {
          expect(decision.allowed).toBe(false);
          // Either the tool is stage-disabled (widening) or tier-1 denies it outright.
          expect([policy.CEILING_REFUSAL_CODE, policy.DECISION_CODES.NOT_PERMITTED]).toContain(
            decision.code,
          );
        }
      }
    }
  });

  it('computes the effective set as the exact intersection for representative pairs', () => {
    const readOnlySubset = ['read_file', 'list_directory', 'get_file_info'];

    const pairs = [
      { stage: 'A', floor: readOnlySubset },
      { stage: 'B', floor: ['read_file', 'write_file', 'edit_block', 'start_process'] },
      {
        stage: 'C',
        floor: ['start_process', 'kill_process', 'write_pdf', 'list_processes', 'get_config'],
      },
      { stage: 'full', floor: [...CATALOG] },
      { stage: 'B', floor: [] },
    ];

    for (const { stage, floor } of pairs) {
      const ceiling = ceilingOf(stage);
      const report = registry.effectiveTools({ ceiling, deviceFloor: floorOf(floor) });

      const expected = ceiling.tools.filter((name) => floor.includes(name));
      expect([...report.enabled].sort()).toEqual([...expected].sort());
      expect(report.counts.effective).toBe(expected.length);
      expect(report.counts.ceiling).toBe(ceiling.tools.length);
      expect(report.deviceFloor.shape).toBe(FLOOR_SHAPES.VALID);
      expect(report.failClosed).toBe(false);

      // Every ceiling tool is accounted for exactly once: enabled or excluded.
      for (const tool of ceiling.tools) {
        const inEnabled = report.enabled.includes(tool);
        const rows = exclusionsFor(report, tool);
        expect(rows).toHaveLength(inEnabled ? 0 : 1);
      }

      // And the intersection can never contain anything the ceiling does not permit.
      for (const name of report.enabled) {
        expect(ceiling.tools).toContain(name);
        expect(floor).toContain(name);
      }
    }

    // The declared end state: the floor may claim all 26, the pilot ceiling still permits 25.
    expect(
      registry.effectiveTools({ ceiling: 'full', deviceFloor: floorClaimingEverything() }).enabled,
    ).toHaveLength(25);
  });
});

describe('GM-72 tier 1 hard denies — not user-configurable at any tier', () => {
  it('denies track_ui_event even when both tiers claim it, and even if a ceiling lists it', () => {
    const ceiling = ceilingOf('full');
    // A ceiling that WRONGLY lists the internal handler: the hard deny is law, not ceiling data.
    const hostileCeiling = { ...ceiling, tools: [...ceiling.tools, 'track_ui_event'] };
    const deviceFloor = floorOf(['track_ui_event', 'read_file']);

    for (const activeCeiling of [ceiling, hostileCeiling]) {
      const decision = registry.authorizeDispatch('track_ui_event', {
        ceiling: activeCeiling,
        deviceFloor,
      });
      expect(decision.allowed).toBe(false);
      expect(decision.decision).toBe('denied');
      expect(decision.code).toBe(policy.DECISION_CODES.NOT_PERMITTED);
      expect(decision.httpStatus).toBe(403);
      expect(decision.tier).toBe(1);
      expect(decision.reasonCode).toBe(EXCLUSION_REASONS.ALWAYS_DENIED);

      const report = registry.effectiveTools({ ceiling: activeCeiling, deviceFloor });
      expect(report.enabled).not.toContain('track_ui_event');
      expect(report.approvalRequired).not.toContain('track_ui_event');
      const row = exclusionFor(report, 'track_ui_event');
      expect(row.reason).toBe('always-denied');
      expect(row.deniedBy).toBe(DENIED_BY.SERVER);
      expect(row.code).toBe(policy.DECISION_CODES.NOT_PERMITTED);
    }

    expect(
      registry.effectiveTools({ ceiling: hostileCeiling, deviceFloor }).ceiling.withheldByTier1Law,
    ).toContain('track_ui_event');
    expect(policy.isAdvertisedTool('track_ui_event')).toBe(false);
    expect(policy.INTERNAL_HANDLERS).toContain('track_ui_event');

    expect(() =>
      registry.assertDispatchAllowed('track_ui_event', { ceiling, deviceFloor }),
    ).toThrow(registry.DeviceToolRefusalError);
  });

  it('denies the feedback tool for the pilot even when both tiers claim it', () => {
    const ceiling = ceilingOf('full');
    const hostileCeiling = {
      ...ceiling,
      tools: [...ceiling.tools, 'give_feedback_to_desktop_commander'],
    };
    const deviceFloor = floorOf(['give_feedback_to_desktop_commander', 'read_file']);

    for (const activeCeiling of [ceiling, hostileCeiling]) {
      const decision = registry.authorizeDispatch('give_feedback_to_desktop_commander', {
        ceiling: activeCeiling,
        deviceFloor,
      });
      expect(decision.allowed).toBe(false);
      expect(decision.code).toBe(policy.DECISION_CODES.NOT_PERMITTED);
      expect(decision.httpStatus).toBe(403);
      expect(decision.reason).toMatch(/client_id/);
      expect(decision.reasonCode).toBe(EXCLUSION_REASONS.PILOT_DENIED);

      const report = registry.effectiveTools({ ceiling: activeCeiling, deviceFloor });
      expect(report.enabled).not.toContain('give_feedback_to_desktop_commander');
      const row = exclusionFor(report, 'give_feedback_to_desktop_commander');
      expect(row.reason).toBe('pilot-denied');
      expect(row.reason).not.toBe(EXCLUSION_REASONS.ALWAYS_DENIED);
      expect(row.deniedBy).toBe(DENIED_BY.SERVER);
    }

    // Only the pilot overlay denies it: after the pilot it is admissible — and STILL approval-gated.
    const postPilot = ceilingOf('full', { pilot: false });
    const postPilotDecision = registry.authorizeDispatch('give_feedback_to_desktop_commander', {
      ceiling: postPilot,
      deviceFloor,
    });
    expect(postPilotDecision.decision).toBe('approval-required');
    expect(postPilotDecision.requiresApproval).toBe(true);
    expect(postPilotDecision.decision).not.toBe('allowed');
    expect(postPilotDecision.code).toBe(policy.DECISION_CODES.APPROVAL_REQUIRED);

    // The default is the pilot ceiling, so forgetting the flag cannot enable it.
    expect(registry.normalizeCeiling(ceilingOf('full')).pilot).toBe(true);
  });
});

describe('GM-72 tier 3 — per-call approval survives enabling', () => {
  it('keeps an enabled approval-gated tool approval-gated, never plain allowed', () => {
    const cases = [
      { stage: 'C', enabled: ['start_process', 'kill_process'] },
      { stage: 'full', enabled: ['start_process', 'kill_process', 'set_config_value'] },
    ];

    for (const { stage, enabled } of cases) {
      const report = registry.effectiveTools({
        ceiling: stage,
        deviceFloor: floorOf(enabled),
      });

      expect([...report.enabled].sort()).toEqual([...enabled].sort());
      expect([...report.approvalRequired].sort()).toEqual([...enabled].sort());
      expect(report.counts.approvalRequired).toBe(enabled.length);

      for (const tool of enabled) {
        const decision = registry.authorizeDispatch(tool, {
          ceiling: stage,
          deviceFloor: floorOf(enabled),
        });
        expect(decision.allowed).toBe(true);
        expect(decision.decision).toBe('approval-required');
        expect(decision.decision).not.toBe('allowed');
        expect(decision.requiresApproval).toBe(true);
        expect(decision.tier).toBe(3);
        expect(decision.code).toBe(policy.DECISION_CODES.APPROVAL_REQUIRED);
        expect(decision.httpStatus).toBeNull();

        // Approved per call, not pre-approved: the gate is still reported to the dispatch path.
        expect(
          registry.assertDispatchAllowed(tool, { ceiling: stage, deviceFloor: floorOf(enabled) })
            .requiresApproval,
        ).toBe(true);
      }
    }

    // Contrast: an ordinary enabled tool is plain allowed, so the gate above is the approval tier
    // and not a blanket refusal.
    expect(
      registry.authorizeDispatch('read_file', {
        ceiling: 'C',
        deviceFloor: floorOf(['read_file']),
      }),
    ).toMatchObject({ decision: 'allowed', requiresApproval: false, code: DISPATCH_CODES.ALLOWED });
  });

  it('never returns plain allowed for any owner-approval tool at any stage', () => {
    expect([...APPROVAL_TOOLS].sort()).toEqual(
      [
        'give_feedback_to_desktop_commander',
        'kill_process',
        'set_config_value',
        'start_process',
      ].sort(),
    );

    for (const stage of STAGES) {
      for (const pilot of [true, false]) {
        for (const tool of APPROVAL_TOOLS) {
          const decision = registry.authorizeDispatch(tool, {
            ceiling: ceilingOf(stage, { pilot }),
            deviceFloor: floorOf([...CATALOG]),
          });
          expect(decision.decision).not.toBe('allowed');
          if (decision.allowed) {
            expect(decision.decision).toBe('approval-required');
            expect(decision.requiresApproval).toBe(true);
          } else {
            expect(decision.decision).toBe('denied');
          }
        }
      }
    }
  });
});

describe('device floor parsing — fail closed on malformed or unknown shapes', () => {
  const garbageFloors = [
    'read_file',
    '{"enabled":["read_file"]}',
    42,
    true,
    [],
    ['read_file'],
    {},
    { tools: ['read_file'] },
    { enabled: 'read_file' },
    { enabled: 42 },
    { enabled: [42] },
    { enabled: [''] },
    { enabled: ['   '] },
    { enabled: null },
    { enabled: ['*'] },
    { enabled: ['all'] },
    { enabled: ['ALL'] },
    { enabled: ['everything'] },
    { enabled: ['*', 'read_file'] },
    { enabled: ['read_file', 'read_file'] },
    { schema: 'cbhr.rdc.device-tool-floor/2', enabled: ['read_file'] },
    { schema: 7, enabled: ['read_file'] },
    { enabled: ['x'.repeat(registry.FLOOR_MAX_NAME_LENGTH + 1)] },
    { enabled: Array.from({ length: registry.FLOOR_MAX_ENTRIES + 1 }, (_, i) => `tool_${i}`) },
  ];

  it('never reads a malformed floor as "everything enabled"', () => {
    for (const deviceFloor of garbageFloors) {
      const parsed = registry.parseDeviceFloor(deviceFloor);
      expect(parsed.shape).toBe(FLOOR_SHAPES.MALFORMED);
      expect(parsed.enabled).toEqual([]);
      expect(parsed.present).toBe(true);

      const report = registry.effectiveTools({ ceiling: 'full', deviceFloor });
      expect(report.deviceFloor.shape).toBe(FLOOR_SHAPES.MALFORMED);
      expect(report.failClosed).toBe(true);
      expect(report.enabled).toEqual([]);
      expect(report.approvalRequired).toEqual([]);
      expect(report.excluded).toHaveLength(policy.ceilingToolCount('full'));
      for (const row of report.excluded) {
        expect(row.reason).toBe(EXCLUSION_REASONS.DEVICE_FLOOR_MALFORMED);
        expect(row.deniedBy).toBe(DENIED_BY.SERVER);
        expect(row.code).toBe(DISPATCH_CODES.DEVICE_FLOOR_MALFORMED);
      }

      // Every tool — even a stage-A read — is refused while the local config is unusable.
      for (const tool of ['read_file', 'list_directory', 'get_file_info']) {
        const decision = registry.authorizeDispatch(tool, { ceiling: 'full', deviceFloor });
        expect(decision.allowed).toBe(false);
        expect(decision.code).toBe(DISPATCH_CODES.DEVICE_FLOOR_MALFORMED);
        expect(decision.httpStatus).toBe(403);
        expect(decision.tier).toBe(2);
      }
    }

    // The whole point of the wildcard entries above: no spelling of "*" enables anything.
    for (const sentinel of registry.FLOOR_WILDCARD_SENTINELS) {
      expect(registry.parseDeviceFloor({ enabled: [sentinel] }).shape).toBe(FLOOR_SHAPES.MALFORMED);
      expect(
        registry.effectiveTools({ ceiling: 'full', deviceFloor: { enabled: [sentinel] } }).enabled,
      ).toEqual([]);
    }
  });

  it('fails closed when no floor was received, distinctly from a valid empty floor', () => {
    for (const absent of [undefined, null]) {
      const report = registry.effectiveTools({ ceiling: 'A', deviceFloor: absent });
      expect(report.deviceFloor.shape).toBe(FLOOR_SHAPES.ABSENT);
      expect(report.deviceFloor.present).toBe(false);
      expect(report.failClosed).toBe(true);
      expect(report.enabled).toEqual([]);
      expect(report.excluded).toHaveLength(8);
      for (const row of report.excluded) {
        expect(row.reason).toBe(EXCLUSION_REASONS.DEVICE_FLOOR_ABSENT);
      }

      const decision = registry.authorizeDispatch('read_file', {
        ceiling: 'A',
        deviceFloor: absent,
      });
      expect(decision.code).toBe(DISPATCH_CODES.DEVICE_FLOOR_ABSENT);
      expect(decision.code).not.toBe(DISPATCH_CODES.DISABLED_ON_DEVICE);
      expect(decision.httpStatus).toBe(403);
    }

    // "Not configured yet" and "configured, nothing ticked" are different panel messages.
    const empty = registry.effectiveTools({ ceiling: 'A', deviceFloor: floorOf([]) });
    expect(empty.deviceFloor.shape).toBe(FLOOR_SHAPES.VALID);
    expect(empty.failClosed).toBe(false);
    expect(empty.enabled).toEqual([]);
    expect(exclusionFor(empty, 'read_file').reason).toBe(EXCLUSION_REASONS.DISABLED_ON_DEVICE);
  });

  it('accepts the canonical shape, ignores unknown keys, and explains unknown tool names', () => {
    const parsed = registry.parseDeviceFloor({
      schema: registry.DEVICE_TOOL_FLOOR_SCHEMA,
      enabled: ['read_file'],
      updatedAt: '2026-10-23T00:00:00.000Z',
    });
    expect(parsed.shape).toBe(FLOOR_SHAPES.VALID);
    expect(parsed.enabled).toEqual(['read_file']);
    expect(parsed.unknownKeys).toEqual(['updatedAt']);
    expect(parsed.problem).toBeNull();

    // A well-formed NAME that is not one of the 26 keeps the floor usable but cannot be honoured.
    const report = registry.effectiveTools({
      ceiling: 'full',
      deviceFloor: floorOf(['fuzzy_search', 'read_file']),
    });
    expect(report.enabled).toEqual(['read_file']);
    const row = exclusionFor(report, 'fuzzy_search');
    expect(row.reason).toBe(EXCLUSION_REASONS.OUTSIDE_SERVER_CEILING);
    expect(row.deniedBy).toBe(DENIED_BY.SERVER);
    expect(row.detail).toMatch(/Not one of the 26/);

    const decision = registry.authorizeDispatch('fuzzy_search', {
      ceiling: 'full',
      deviceFloor: floorOf(['fuzzy_search']),
    });
    expect(decision.allowed).toBe(false);
    expect(decision.code).toBe(policy.DECISION_CODES.UNKNOWN);
    expect(decision.httpStatus).toBe(400);
  });

  it('rejects an invalid or non-string dispatch name with the shared codes', () => {
    for (const name of ['', 42, null, undefined, {}]) {
      const decision = registry.authorizeDispatch(name, {
        ceiling: 'full',
        deviceFloor: floorClaimingEverything(),
      });
      expect(decision.allowed).toBe(false);
      expect(decision.code).toBe(policy.DECISION_CODES.INVALID_NAME);
      expect(decision.httpStatus).toBe(400);
    }

    // `constructor` is an own-property miss, not an inherited deny-map hit.
    expect(
      registry.authorizeDispatch('constructor', {
        ceiling: 'full',
        deviceFloor: floorClaimingEverything(),
      }).code,
    ).toBe(policy.DECISION_CODES.UNKNOWN);
  });
});

describe('the effective-set report the panel consumes', () => {
  it('is JSON-serializable and explains every exclusion by reason and by whose choice', () => {
    const report = registry.effectiveTools({
      ceiling: 'C',
      deviceFloor: floorOf([
        'read_file',
        'start_process',
        'track_ui_event',
        'fuzzy_search',
        'write_file',
      ]),
    });

    expect(Object.isFrozen(report)).toBe(true);
    expect(JSON.parse(JSON.stringify(report))).toEqual(report);

    expect(report.schema).toBe(registry.TOOL_REGISTRY_SCHEMA);
    expect(report.ceiling).toMatchObject({
      stage: 'C',
      source: 'server',
      deviceSettable: false,
      tier: 1,
    });
    expect(report.deviceFloor).toMatchObject({
      shape: FLOOR_SHAPES.VALID,
      tier: 2,
      source: 'device',
    });
    expect(report.tierLaw).toEqual(registry.EFFECTIVE_SET_LAW);

    // write_file is admitted from stage B, so it IS inside the C ceiling and, because the device
    // claims it too, it is part of the effective set.
    expect([...report.enabled].sort()).toEqual(['read_file', 'start_process', 'write_file'].sort());
    expect(report.approvalRequired).toEqual(['start_process']);
    expect(report.counts).toMatchObject({
      ceiling: policy.ceilingToolCount('C'),
      effective: 3,
      approvalRequired: 1,
    });

    const reasons = new Set(report.excluded.map((row) => row.reason));
    expect(reasons).toEqual(
      new Set([
        EXCLUSION_REASONS.DISABLED_ON_DEVICE,
        EXCLUSION_REASONS.ALWAYS_DENIED,
        EXCLUSION_REASONS.OUTSIDE_SERVER_CEILING,
      ]),
    );

    for (const row of report.excluded) {
      expect(Object.values(EXCLUSION_REASONS)).toContain(row.reason);
      expect([DENIED_BY.SERVER, DENIED_BY.DEVICE]).toContain(row.deniedBy);
      expect(typeof row.code).toBe('string');
      expect([403, 400]).toContain(row.httpStatus);
      expect(typeof row.detail).toBe('string');
      expect(row.detail.length).toBeGreaterThan(0);
    }

    // The panel's two questions per capability: is it on, and if not, whose choice was that?
    expect(exclusionFor(report, 'list_sessions')).toMatchObject({
      reason: EXCLUSION_REASONS.DISABLED_ON_DEVICE,
      deniedBy: DENIED_BY.DEVICE,
    });
    expect(exclusionFor(report, 'write_pdf')).toMatchObject({
      reason: EXCLUSION_REASONS.DISABLED_ON_DEVICE,
      deniedBy: DENIED_BY.DEVICE,
    });
    expect(exclusionFor(report, 'track_ui_event')).toMatchObject({
      reason: EXCLUSION_REASONS.ALWAYS_DENIED,
      deniedBy: DENIED_BY.SERVER,
    });
    expect(exclusionFor(report, 'fuzzy_search')).toMatchObject({
      reason: EXCLUSION_REASONS.OUTSIDE_SERVER_CEILING,
      deniedBy: DENIED_BY.SERVER,
    });
  });

  it('survives the device→server JSON round trip and refuses a JSON string', () => {
    const wire = JSON.stringify(floorOf(['read_file', 'list_directory']));
    expect(registry.parseDeviceFloor(JSON.parse(wire)).shape).toBe(FLOOR_SHAPES.VALID);
    expect(
      registry.effectiveTools({ ceiling: 'A', deviceFloor: JSON.parse(wire) }).enabled,
    ).toEqual(['read_file', 'list_directory']);

    // The server refuses to parse a string itself: an unparsed body is not a floor.
    const unparsed = registry.effectiveTools({ ceiling: 'A', deviceFloor: wire });
    expect(unparsed.deviceFloor.shape).toBe(FLOOR_SHAPES.MALFORMED);
    expect(unparsed.enabled).toEqual([]);

    // `schema` may be omitted by an older agent; `undefined` keys vanish in transport.
    expect(registry.parseDeviceFloor({ enabled: ['read_file'], updatedAt: undefined }).shape).toBe(
      FLOOR_SHAPES.VALID,
    );
  });

  it('explains one tool through explainTool()', () => {
    expect(
      registry.explainTool('list_sessions', { ceiling: 'C', deviceFloor: floorOf(['read_file']) }),
    ).toEqual({
      tool: 'list_sessions',
      enabled: false,
      requiresApproval: false,
      reason: EXCLUSION_REASONS.DISABLED_ON_DEVICE,
      deniedBy: DENIED_BY.DEVICE,
      detail: EXCLUSION_DETAILS[EXCLUSION_REASONS.DISABLED_ON_DEVICE],
      code: DISPATCH_CODES.DISABLED_ON_DEVICE,
      httpStatus: 403,
    });

    expect(
      registry.explainTool('read_file', { ceiling: 'C', deviceFloor: floorOf(['read_file']) }),
    ).toMatchObject({
      enabled: true,
      requiresApproval: false,
      reason: null,
      deniedBy: null,
      code: DISPATCH_CODES.ALLOWED,
      httpStatus: null,
    });

    expect(
      registry.explainTool('start_process', {
        ceiling: 'C',
        deviceFloor: floorOf(['start_process']),
      }),
    ).toMatchObject({
      enabled: true,
      requiresApproval: true,
      code: policy.DECISION_CODES.APPROVAL_REQUIRED,
    });

    expect(
      registry.explainTool('start_process', {
        ceiling: 'A',
        deviceFloor: floorOf(['start_process']),
      }),
    ).toMatchObject({
      enabled: false,
      deniedBy: DENIED_BY.SERVER,
      reason: EXCLUSION_REASONS.OUTSIDE_SERVER_CEILING,
      code: policy.CEILING_REFUSAL_CODE,
    });

    // The per-tool row and the bulk report describe the same event with the same words, so the
    // panel cannot show one explanation in the list and a contradictory one in a detail view.
    const deviceFloor = floorOf(['read_file', 'start_process', 'track_ui_event', 'fuzzy_search']);
    const report = registry.effectiveTools({ ceiling: 'C', deviceFloor });

    for (const tool of ['list_sessions', 'write_pdf', 'track_ui_event']) {
      const row = exclusionFor(report, tool);
      expect(registry.explainTool(tool, { ceiling: 'C', deviceFloor })).toMatchObject({
        enabled: false,
        reason: row.reason,
        deniedBy: row.deniedBy,
        code: row.code,
        httpStatus: row.httpStatus,
        detail: row.detail,
      });
    }

    // A well-formed name that is not one of the 26 tools is reported as outside the ceiling (it is
    // outside every ceiling) and refused at dispatch with the more specific frozen-catalog code.
    const nonCatalogRow = exclusionFor(report, 'fuzzy_search');
    expect(nonCatalogRow).toMatchObject({
      reason: EXCLUSION_REASONS.OUTSIDE_SERVER_CEILING,
      deniedBy: DENIED_BY.SERVER,
      code: policy.CEILING_REFUSAL_CODE,
    });
    expect(registry.explainTool('fuzzy_search', { ceiling: 'C', deviceFloor })).toMatchObject({
      enabled: false,
      deniedBy: DENIED_BY.SERVER,
      code: policy.DECISION_CODES.UNKNOWN,
      httpStatus: 400,
    });

    // An enabled tool has no exclusion row at all, and still explains itself.
    expect(exclusionsFor(report, 'start_process')).toHaveLength(0);
    expect(registry.explainTool('start_process', { ceiling: 'C', deviceFloor })).toMatchObject({
      enabled: true,
      requiresApproval: true,
      deniedBy: null,
    });
  });
});
