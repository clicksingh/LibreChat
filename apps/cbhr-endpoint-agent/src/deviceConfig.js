'use strict';

/**
 * CBHR ENDPOINT AGENT — the device floor (workstream W7 / ruling GM-72 tier 2).
 *
 * This is the file the owner edits: a plain JSON list of the tools that are ON for this PC. Under
 * GM-72 the device may only NARROW, and this module is where that constraint is enforced locally —
 * for every enabled entry it asks the server ceiling whether the tool is inside tier 1 at all, and a
 * name outside the ceiling makes the WHOLE configuration invalid (`ENDPOINT_DEVICE_CONFIG_INVALID`).
 *
 * WHY A WHOLE-CONFIG REFUSAL RATHER THAN A SILENT FILTER
 * Silently dropping the unknown entries would produce exactly the failure GM-72's UX clause forbids:
 * the employee sees a tool listed as enabled while the platform refuses to dispatch it, and nobody can
 * say which side said no. Refusing the configuration means the discrepancy is loud and local, and the
 * operator fixes it on the PC (never in the browser), which is the same principle as renewal
 * (GM-12/R5).
 *
 * The dispatch-time check is separate and ALSO present: a frame naming a tool outside the ceiling is
 * refused with `ENDPOINT_TOOL_OUTSIDE_CEILING` even when the config enables it (`narrow()` is a
 * convenience, not the guard). Both are tested.
 *
 * ON-DISK FORMAT (`tools.json` in the agent root, outside the repo)
 *   { "version": 1, "enabled": ["list_directory", "read_file", "get_file_info"] }
 */

const fs = require('node:fs');
const path = require('node:path');

const { refusal } = require('./errors');
const { resolveRootDir } = require('./keystore');
const { writeOwnerOnlyFile } = require('./permissions');

/** The tools the shipped default enables: stage A, read-only, all three actually implemented. */
const DEFAULT_ENABLED_TOOLS = Object.freeze(['get_file_info', 'list_directory', 'read_file']);

function configRefusal(detail, cause) {
  return refusal('ENDPOINT_DEVICE_CONFIG_INVALID', detail, { field: 'toolsConfig', cause });
}

function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function defaultToolsConfigFile(rootDir) {
  return path.join(rootDir ?? resolveRootDir(), 'tools.json');
}

/**
 * Reads and validates the device's local tool configuration.
 *
 * @param {object} params
 * @param {object} params.ceiling the server ceiling (`ceiling.loadCeilingSnapshot(...)`)
 * @param {string} [params.rootDir]
 * @param {string} [params.toolsConfigFile]
 * @param {boolean} [params.createIfMissing] write the safe default when the file does not exist
 * @returns {{enabled: string[], file: string, created: boolean, refused: string[]}}
 *   `refused` lists names that were dropped because the ceiling does not permit them — only ever
 *   populated by `narrow()`, never by this loader (which throws instead).
 */
function loadDeviceToolConfig(params = {}) {
  const { ceiling, createIfMissing = true } = params;
  if (ceiling === null || typeof ceiling !== 'object' || typeof ceiling.allows !== 'function') {
    throw configRefusal('the device tool configuration needs a server ceiling to check against');
  }
  const file = params.toolsConfigFile ?? defaultToolsConfigFile(params.rootDir);
  let created = false;
  if (!fs.existsSync(file)) {
    if (!createIfMissing) {
      throw configRefusal('no local tool configuration exists');
    }
    const written = writeOwnerOnlyFile(
      file,
      `${JSON.stringify({ version: 1, enabled: [...DEFAULT_ENABLED_TOOLS] }, null, 2)}\n`,
    );
    created = written !== null && typeof written === 'object';
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    throw configRefusal('the local tool configuration is not valid JSON', err);
  }
  if (!isPlainRecord(parsed)) {
    throw configRefusal('the local tool configuration must be a JSON object');
  }
  if (parsed.version !== 1) {
    throw configRefusal('the local tool configuration declares an unsupported version');
  }
  if (!Array.isArray(parsed.enabled)) {
    throw configRefusal('the local tool configuration must carry an "enabled" array');
  }
  const enabled = [];
  for (const name of parsed.enabled) {
    if (typeof name !== 'string' || name.length === 0) {
      throw configRefusal('the local tool configuration contains a non-string or empty tool name');
    }
    if (enabled.includes(name)) {
      throw configRefusal('the local tool configuration lists one tool name twice');
    }
    const verdict = ceiling.allows(name);
    if (verdict.allowed !== true) {
      // Loud, local, and specific to the side that said no. Never a silent drop.
      throw configRefusal('the local tool configuration enables a tool the server ceiling does not permit');
    }
    enabled.push(name);
  }
  return { enabled: enabled.sort(), file, created, refused: [] };
}

/**
 * Computes the effective set for this PC: **server ceiling ∩ device floor** (GM-72), in that order of
 * authority. Returns the intersection plus the names narrowed away on each side, so the panel can
 * later explain a refusal ("off on this PC, by the employee's choice") instead of leaving it
 * mysterious.
 *
 * @param {object} params
 * @param {object} params.ceiling
 * @param {string[]} params.enabled the device floor
 * @returns {{effective: string[], outsideCeiling: string[], notEnabledOnDevice: string[]}}
 */
function narrow(params = {}) {
  const { ceiling, enabled } = params;
  if (ceiling === null || typeof ceiling !== 'object' || typeof ceiling.allows !== 'function') {
    throw configRefusal('narrow() needs a server ceiling');
  }
  if (!Array.isArray(enabled)) {
    throw configRefusal('narrow() needs the device floor as an array of tool names');
  }
  const ceilingNames = ceiling.ceilingNames();
  const outsideCeiling = enabled.filter((name) => !ceilingNames.includes(name));
  const notEnabledOnDevice = ceilingNames.filter((name) => !enabled.includes(name));
  const effective = ceilingNames.filter((name) => enabled.includes(name)).sort();
  return { effective, outsideCeiling: outsideCeiling.sort(), notEnabledOnDevice: notEnabledOnDevice.sort() };
}

/** Writes a device configuration file (owner-editable). Refuses anything outside the ceiling. */
function writeDeviceToolConfig(params = {}) {
  const { ceiling, rootDir, toolsConfigFile } = params;
  const enabled = Array.isArray(params.enabled) ? params.enabled : [...DEFAULT_ENABLED_TOOLS];
  if (ceiling === null || typeof ceiling !== 'object' || typeof ceiling.allows !== 'function') {
    throw configRefusal('writing a device tool configuration needs a server ceiling');
  }
  for (const name of enabled) {
    if (ceiling.allows(name).allowed !== true) {
      throw configRefusal('refusing to write a configuration that enables a tool outside the server ceiling');
    }
  }
  const file = toolsConfigFile ?? defaultToolsConfigFile(rootDir);
  const written = writeOwnerOnlyFile(file, `${JSON.stringify({ version: 1, enabled }, null, 2)}\n`);
  return { file, enabled: [...enabled].sort(), mode: written.mode, acl: written.acl };
}

module.exports = {
  DEFAULT_ENABLED_TOOLS,
  defaultToolsConfigFile,
  loadDeviceToolConfig,
  narrow,
  writeDeviceToolConfig,
};