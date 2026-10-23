'use strict';

/**
 * CBHR ENDPOINT AGENT — dispatch (workstream W7 / ruling GM-72 three tiers).
 *
 * The step between "the frame verified" and "the tool ran". It answers exactly one question per
 * frame: is this tool inside BOTH the server ceiling (tier 1) and this PC's own configuration
 * (tier 2), and does this agent actually implement it?
 *
 * ORDER OF REFUSALS (each distinct, each tested)
 *   1. the server ceiling   -> ENDPOINT_TOOL_OUTSIDE_CEILING     (GM-72: the device may never widen)
 *   2. the device floor      -> ENDPOINT_TOOL_NOT_ENABLED_ON_DEVICE (GM-72: the employee may narrow)
 *   3. local implementation  -> ENDPOINT_TOOL_NOT_IMPLEMENTED
 *   4. argument shape        -> ENDPOINT_TOOL_ARGS_INVALID
 *
 * Ceiling before floor is deliberate. A tool outside the ceiling is refused on tier-1 grounds EVEN IF
 * the device enabled it, so the refusal says "the server does not permit this", not "you turned it
 * off" — which is the difference between a policy statement and a configuration hint. The reverse
 * order would let a hand-edited config masquerade as a permission decision.
 *
 * Tier 3 (per-call owner approval for the four approval-gated tools) is reported, never assumed: the
 * ceiling marks those tools `owner-approval`, and this module refuses them for the lab agent with
 * `ENDPOINT_TOOL_NOT_IMPLEMENTED` — approval-gated execution belongs to a build that can actually
 * present the approval UI, and until then claiming to have asked the owner would be a lie.
 */

const { refusal } = require('./errors');
const { executeTool, IMPLEMENTED_TOOLS, describeTools } = require('./tools');

/**
 * The effective-set computation for this PC, materialized once at startup so a frame cannot change
 * which policies apply to it mid-flight.
 *
 * @param {object} params
 * @param {object} params.ceiling
 * @param {object} params.deviceConfig `deviceConfig.loadDeviceToolConfig(...)`
 * @param {string} [params.workspaceRoot]
 * @returns {Readonly<object>}
 */
function createDispatcher(params = {}) {
  const { ceiling, deviceConfig } = params;
  if (ceiling === null || typeof ceiling !== 'object' || typeof ceiling.allows !== 'function') {
    throw refusal('ENDPOINT_CEILING_SNAPSHOT_INVALID', 'the dispatcher needs a server ceiling');
  }
  if (deviceConfig === null || typeof deviceConfig !== 'object' || !Array.isArray(deviceConfig.enabled)) {
    throw refusal('ENDPOINT_DEVICE_CONFIG_INVALID', 'the dispatcher needs the device tool configuration');
  }
  const enabledOnDevice = new Set(deviceConfig.enabled);
  const workspaceRoot = params.workspaceRoot;

  /**
   * Decides one tool call. Never executes.
   * @param {string} toolName
   * @returns {{allowed: boolean, reason: string|null, refusalCode: string|null,
   *   withinCeiling: boolean, enabledOnDevice: boolean, implemented: boolean, requiresApproval: boolean}}
   */
  function decide(toolName) {
    const inCeiling = ceiling.allows(toolName);
    const approved =
      inCeiling.allowed === true &&
      typeof inCeiling.reason === 'string' &&
      inCeiling.reason.includes('owner approval');
    const isEnabled = enabledOnDevice.has(toolName);
    const isImplemented = IMPLEMENTED_TOOLS.includes(toolName);
    const base = {
      allowed: false,
      reason: null,
      refusalCode: null,
      withinCeiling: inCeiling.allowed === true,
      enabledOnDevice: isEnabled,
      implemented: isImplemented,
      requiresApproval: approved,
    };
    if (inCeiling.allowed !== true) {
      return { ...base, reason: inCeiling.reason, refusalCode: 'ENDPOINT_TOOL_OUTSIDE_CEILING' };
    }
    if (!isEnabled) {
      return {
        ...base,
        reason: 'the tool is switched off in this PC\'s local configuration (the employee narrowed it)',
        refusalCode: 'ENDPOINT_TOOL_NOT_ENABLED_ON_DEVICE',
      };
    }
    if (approved) {
      return {
        ...base,
        reason:
          'the tool is approval-gated and this lab agent has no approval UI, so it refuses rather than claiming consent',
        refusalCode: 'ENDPOINT_TOOL_NOT_IMPLEMENTED',
      };
    }
    if (!isImplemented) {
      return {
        ...base,
        reason: 'the tool is permitted and enabled, but this agent has no local implementation for it yet',
        refusalCode: 'ENDPOINT_TOOL_NOT_IMPLEMENTED',
      };
    }
    return { ...base, allowed: true };
  }

  return Object.freeze({
    /** The effective set: server ceiling ∩ device floor, in that order of authority. */
    effectiveTools: () => Object.freeze(ceiling.ceilingNames().filter((name) => enabledOnDevice.has(name))),
    /** What the ceiling permits but this PC has switched off: the panel's "off by your choice" list. */
    narrowedByDevice: () => Object.freeze(ceiling.ceilingNames().filter((name) => !enabledOnDevice.has(name))),
    /** Device-floor entries the ceiling refuses: configuration errors, surfaced loudly. */
    outsideCeiling: () => Object.freeze([...enabledOnDevice].filter((name) => ceiling.allows(name).allowed !== true).sort()),
    decide,
    /**
     * Decides AND executes. Throws an `EndpointRefusal` for any refused step; returns the tool's
     * result object otherwise. The caller wraps this so a throw becomes `outcome:'uncertain'` rather
     * than a fabricated success.
     * @param {object} call
     * @param {string} call.toolName
     * @param {Buffer} call.argsBytes verified argument bytes
     * @returns {{toolName: string, executedAtMs: number, result: object}}
     */
    execute: (call) => {
      const decision = decide(call.toolName);
      if (decision.allowed !== true) {
        throw refusal(decision.refusalCode ?? 'ENDPOINT_TOOL_NOT_IMPLEMENTED', decision.reason ?? 'the tool call was refused', {
          field: 'toolName',
        });
      }
      return executeTool({ toolName: call.toolName, argsBytes: call.argsBytes, workspaceRoot });
    },
    describe: () => ({
      ceiling: ceiling.describe(),
      deviceEnabled: [...enabledOnDevice].sort(),
      deviceConfigFile: deviceConfig.file ?? null,
      effective: ceiling.ceilingNames().filter((name) => enabledOnDevice.has(name)),
      narrowedByDevice: ceiling.ceilingNames().filter((name) => !enabledOnDevice.has(name)),
      outsideCeiling: [...enabledOnDevice].filter((name) => ceiling.allows(name).allowed !== true).sort(),
      implemented: [...IMPLEMENTED_TOOLS],
      tools: describeTools(workspaceRoot),
      workspaceRoot: describeTools(workspaceRoot).workspaceRoot,
    }),
  });
}

module.exports = { createDispatcher };