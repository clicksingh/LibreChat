'use strict';

/**
 * CBHR ENDPOINT AGENT — implemented local tools (workstream W7).
 *
 * DELIBERATELY SMALL. GM-73 builds the agent's LOGIC first; the 26 Desktop Commander tools are
 * Phase 3 wiring, and no graphical control is claimed anywhere in this repository. This module
 * implements exactly three REAL, read-only tools — the ones the ceiling's stage A describes — so the
 * loop (verify → dispatch → execute → result) is proven against genuine filesystem work and against
 * a tool-call surface an owner can reason about:
 *
 *   list_directory   read a directory's entries               (stage A, fs-read)
 *   read_file        read a bounded byte range of a file       (stage A, fs-read)
 *   get_file_info    stat a path, plus directory counts        (stage A, fs-read)
 *
 * NOT IMPLEMENTED — ON PURPOSE, AND REFUSED WITH A DISTINCT CODE
 * Every other name in the ceiling (search tools, stage B writes, the process tools) is refused with
 * `ENDPOINT_TOOL_NOT_IMPLEMENTED`. "Inside the ceiling" is not "implemented here", and the difference
 * must be observable rather than silent: a platform that dispatches `edit_block` to this agent gets a
 * typed refusal, not a hang and not a success.
 *
 * CONTAINMENT
 * Paths are resolved against a configured workspace root and any path that escapes it (absolute path
 * outside, `..` traversal, a drive change on Windows, a symlink pointing outside) is refused with
 * `ENDPOINT_TOOL_ARGS_INVALID`. The root defaults to `~/.cbhr/endpoint-agent/workspace`, created on
 * first use. This is not presented as a containment boundary the pilot relies on long-term — the
 * Tauri build will pin the real policy — but it does mean this lab agent cannot be talked into reading
 * an arbitrary file by a frame, which is the minimum an owner running it on their own PC should get.
 *
 * NO WRITES. Nothing in this module creates, modifies, moves or deletes anything except the workspace
 * root directory itself, and no tool reads or writes outside it.
 */

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const nodeCrypto = require('node:crypto');

const { refusal } = require('./errors');

/** Bounds. A read-only tool that can exhaust memory is a denial-of-service, not a capability. */
const MAX_READ_BYTES = 1048576; // 1 MiB hard cap per read_file call
const DEFAULT_READ_BYTES = 262144; // 256 KiB default
const MAX_DIRECTORY_ENTRIES = 2000; // entries per list_directory page
const DEFAULT_DIRECTORY_ENTRIES = 500;

/** Tool names this module actually implements. Nothing else may execute, whatever the ceiling says. */
const IMPLEMENTED_TOOLS = Object.freeze(['get_file_info', 'list_directory', 'read_file']);

/** Argument schemas, checked strictly: unknown keys are refused, never ignored. */
const TOOL_SCHEMAS = Object.freeze({
  list_directory: Object.freeze({
    required: Object.freeze(['path']),
    optional: Object.freeze(['limit', 'cursor']),
  }),
  read_file: Object.freeze({
    required: Object.freeze(['path']),
    optional: Object.freeze(['maxBytes', 'encoding']),
  }),
  get_file_info: Object.freeze({
    required: Object.freeze(['path']),
    optional: Object.freeze([]),
  }),
});

function defaultWorkspaceRoot() {
  const home = process.env.USERPROFILE ?? process.env.HOME ?? os.homedir();
  return path.join(home, '.cbhr', 'endpoint-agent', 'workspace');
}

function resolveWorkspaceRoot(explicit) {
  if (typeof explicit === 'string' && explicit.length > 0) {
    return path.resolve(explicit);
  }
  if (typeof process.env.CBHR_ENDPOINT_AGENT_WORKSPACE === 'string' && process.env.CBHR_ENDPOINT_AGENT_WORKSPACE.length > 0) {
    return path.resolve(process.env.CBHR_ENDPOINT_AGENT_WORKSPACE);
  }
  return defaultWorkspaceRoot();
}

function argsRefusal(detail) {
  return refusal('ENDPOINT_TOOL_ARGS_INVALID', detail, { field: 'args' });
}

/**
 * Parses the loose JSON object a frame carries as its args payload.
 *
 * The payload is OPAQUE BYTES at the protocol layer (GM-29) — this is the first and only place those
 * bytes are interpreted, and interpretation happens after verification, never before.
 * @param {Buffer} bytes
 * @returns {object} the parsed plain object (empty object for empty bytes)
 */
function parseArgsBytes(bytes) {
  if (!Buffer.isBuffer(bytes)) {
    throw argsRefusal('tool arguments must be supplied as raw bytes');
  }
  if (bytes.length === 0) {
    return {};
  }
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString('utf8'));
  } catch (err) {
    throw refusal('ENDPOINT_TOOL_ARGS_INVALID', 'tool arguments are not valid UTF-8 JSON', {
      field: 'args',
      cause: err,
    });
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw argsRefusal('tool arguments must be a JSON object');
  }
  return parsed;
}

/**
 * Strict schema check: required keys present and string-typed where required, no unknown keys.
 * @param {string} toolName
 * @param {object} args
 * @returns {object} the same args
 */
function assertArgsShape(toolName, args) {
  const schema = TOOL_SCHEMAS[toolName];
  if (schema === undefined) {
    throw refusal('ENDPOINT_TOOL_NOT_IMPLEMENTED', 'this tool has no local implementation or schema', {
      field: 'toolName',
    });
  }
  for (const key of Object.keys(args)) {
    if (!schema.required.includes(key) && !schema.optional.includes(key)) {
      throw argsRefusal(`tool arguments contain an unknown key for this tool`);
    }
  }
  for (const key of schema.required) {
    if (!Object.prototype.hasOwnProperty.call(args, key)) {
      throw argsRefusal('tool arguments are missing a required key');
    }
  }
  if (typeof args.path !== 'string' || args.path.length === 0) {
    throw argsRefusal('the "path" argument must be a non-empty string');
  }
  if (args.limit !== undefined && (!Number.isSafeInteger(args.limit) || args.limit < 1 || args.limit > MAX_DIRECTORY_ENTRIES)) {
    throw argsRefusal(`the "limit" argument must be an integer between 1 and ${MAX_DIRECTORY_ENTRIES}`);
  }
  if (args.maxBytes !== undefined && (!Number.isSafeInteger(args.maxBytes) || args.maxBytes < 1 || args.maxBytes > MAX_READ_BYTES)) {
    throw argsRefusal(`the "maxBytes" argument must be an integer between 1 and ${MAX_READ_BYTES}`);
  }
  if (args.cursor !== undefined && typeof args.cursor !== 'string') {
    throw argsRefusal('the "cursor" argument must be a string');
  }
  if (args.encoding !== undefined && args.encoding !== 'utf8' && args.encoding !== 'base64') {
    throw argsRefusal('the "encoding" argument must be "utf8" or "base64"');
  }
  return args;
}

/**
 * Resolves a tool path INSIDE the workspace root, refusing anything that escapes it.
 *
 * Order matters: the candidate is resolved first (`path.resolve` normalises `..`), then compared
 * against the resolved root with a separator-aware prefix test, then re-checked through `realpath`
 * when the target exists so a symlink pointing outside the root is refused too.
 *
 * @param {object} params
 * @param {string} params.root the resolved workspace root
 * @param {string} params.requested the caller's path (absolute or root-relative)
 * @returns {{absolute: string, relative: string}}
 */
function resolveInsideRoot(params) {
  const { root, requested } = params;
  if (typeof requested !== 'string' || requested.length === 0) {
    throw argsRefusal('the "path" argument must be a non-empty string');
  }
  const rootResolved = path.resolve(root);
  const candidate = path.resolve(rootResolved, requested);
  const withSeparator = rootResolved.endsWith(path.sep) ? rootResolved : `${rootResolved}${path.sep}`;
  const inside = candidate === rootResolved || candidate.startsWith(withSeparator);
  if (!inside) {
    throw argsRefusal('the requested path resolves outside the agent workspace root');
  }
  let realCandidate = candidate;
  try {
    realCandidate = fs.realpathSync.native(candidate);
  } catch {
    // The target may not exist; the lexical check above already holds. A later stat will report it.
    realCandidate = candidate;
  }
  let realRoot = null;
  try {
    realRoot = fs.realpathSync.native(rootResolved);
  } catch {
    // An unresolvable root is not a containment failure; the lexical check above stands.
    realRoot = null;
  }
  if (realRoot !== null) {
    const realWithSeparator = realRoot.endsWith(path.sep) ? realRoot : `${realRoot}${path.sep}`;
    if (realCandidate !== realRoot && !realCandidate.startsWith(realWithSeparator)) {
      throw argsRefusal('the requested path resolves outside the agent workspace root through a link');
    }
  }
  return { absolute: candidate, relative: path.relative(rootResolved, candidate) || '.' };
}

/** Ensures the workspace root exists (the only write this module performs). */
function ensureWorkspaceRoot(root) {
  fs.mkdirSync(path.resolve(root), { recursive: true });
  return path.resolve(root);
}

function utf8OrBinary(bytes) {
  const text = bytes.toString('utf8');
  // Round-tripping detects replacement characters without a manual decoder.
  return Buffer.from(text, 'utf8').equals(bytes) ? { text, binary: false } : { text: null, binary: true };
}

/** `list_directory` — a bounded, sorted, pageable directory listing. */
function listDirectory(params) {
  const { root, args } = params;
  const resolved = resolveInsideRoot({ root, requested: args.path });
  let stat;
  try {
    stat = fs.statSync(resolved.absolute);
  } catch (err) {
    throw refusal('ENDPOINT_TOOL_ARGS_INVALID', 'the requested path does not exist or is not readable', {
      field: 'path',
      cause: err,
    });
  }
  if (!stat.isDirectory()) {
    throw argsRefusal('the requested path is not a directory');
  }
  const limit = args.limit ?? DEFAULT_DIRECTORY_ENTRIES;
  const all = fs.readdirSync(resolved.absolute, { withFileTypes: true });
  const names = all.map((entry) => entry.name).sort((left, right) => left.localeCompare(right));
  let startIndex = 0;
  if (typeof args.cursor === 'string' && args.cursor.length > 0) {
    const found = names.findIndex((name) => name > args.cursor);
    startIndex = found === -1 ? names.length : found;
  }
  const page = names.slice(startIndex, startIndex + limit);
  const entries = page.map((name) => {
    const absolute = path.join(resolved.absolute, name);
    let entryStat;
    try {
      entryStat = fs.lstatSync(absolute);
    } catch {
      return { name, kind: 'unreadable' };
    }
    return {
      name,
      kind: entryStat.isDirectory() ? 'directory' : entryStat.isFile() ? 'file' : entryStat.isSymbolicLink() ? 'symlink' : 'other',
      size: entryStat.isFile() ? entryStat.size : null,
      modifiedMs: Math.trunc(entryStat.mtimeMs),
    };
  });
  const nextIndex = startIndex + page.length;
  return {
    path: resolved.relative,
    entries,
    returned: entries.length,
    total: names.length,
    truncated: nextIndex < names.length,
    nextCursor: nextIndex < names.length ? page[page.length - 1] : null,
    limit,
  };
}

/** `read_file` — a bounded read, UTF-8 by default with a lossless base64 path for binary files. */
function readFile(params) {
  const { root, args } = params;
  const resolved = resolveInsideRoot({ root, requested: args.path });
  let stat;
  try {
    stat = fs.statSync(resolved.absolute);
  } catch (err) {
    throw refusal('ENDPOINT_TOOL_ARGS_INVALID', 'the requested path does not exist or is not readable', {
      field: 'path',
      cause: err,
    });
  }
  if (!stat.isFile()) {
    throw argsRefusal('the requested path is not a regular file');
  }
  const maxBytes = args.maxBytes ?? DEFAULT_READ_BYTES;
  const bytesToRead = Math.min(stat.size, maxBytes);
  const buffer = Buffer.alloc(bytesToRead);
  const fd = fs.openSync(resolved.absolute, 'r');
  let read = 0;
  try {
    read = fs.readSync(fd, buffer, 0, bytesToRead, 0);
  } finally {
    fs.closeSync(fd);
  }
  const bytes = buffer.subarray(0, read);
  const requestedEncoding = args.encoding ?? 'utf8';
  const classified = utf8OrBinary(bytes);
  const encoding = requestedEncoding === 'base64' || classified.binary ? 'base64' : 'utf8';
  return {
    path: resolved.relative,
    size: stat.size,
    bytesRead: read,
    truncated: read < stat.size,
    encoding,
    content: encoding === 'base64' ? bytes.toString('base64') : classified.text,
    sha256Hex: nodeCrypto.createHash('sha256').update(bytes).digest('hex'),
  };
}

/** `get_file_info` — metadata only; for a directory, counts are capped and reported as truncated. */
function getFileInfo(params) {
  const { root, args } = params;
  const resolved = resolveInsideRoot({ root, requested: args.path });
  let stat;
  try {
    stat = fs.lstatSync(resolved.absolute);
  } catch (err) {
    throw refusal('ENDPOINT_TOOL_ARGS_INVALID', 'the requested path does not exist or is not readable', {
      field: 'path',
      cause: err,
    });
  }
  const info = {
    path: resolved.relative,
    absoluteIsWithinRoot: true,
    kind: stat.isDirectory() ? 'directory' : stat.isFile() ? 'file' : stat.isSymbolicLink() ? 'symlink' : 'other',
    size: stat.size,
    createdMs: Math.trunc(stat.birthtimeMs),
    modifiedMs: Math.trunc(stat.mtimeMs),
    accessedMs: Math.trunc(stat.atimeMs),
    mode: stat.mode & 0o777,
    entryCount: null,
    entryCountTruncated: false,
  };
  if (stat.isDirectory()) {
    const names = fs.readdirSync(resolved.absolute);
    info.entryCount = Math.min(names.length, MAX_DIRECTORY_ENTRIES);
    info.entryCountTruncated = names.length > MAX_DIRECTORY_ENTRIES;
  }
  return info;
}

const IMPLEMENTATIONS = Object.freeze({
  list_directory: listDirectory,
  read_file: readFile,
  get_file_info: getFileInfo,
});

/**
 * Executes an implemented tool. Returns a plain JSON-serializable result object, or throws an
 * `EndpointRefusal`. It never reports success for work it did not do.
 *
 * @param {object} params
 * @param {string} params.toolName
 * @param {Buffer} params.argsBytes the verified args bytes
 * @param {string} [params.workspaceRoot]
 * @returns {{toolName: string, executedAtMs: number, result: object}}
 */
function executeTool(params) {
  const { toolName, argsBytes } = params;
  const implementation = IMPLEMENTATIONS[toolName];
  if (implementation === undefined) {
    throw refusal('ENDPOINT_TOOL_NOT_IMPLEMENTED', 'this agent has no local implementation for that tool', {
      field: 'toolName',
    });
  }
  const root = ensureWorkspaceRoot(resolveWorkspaceRoot(params.workspaceRoot));
  const args = assertArgsShape(toolName, parseArgsBytes(argsBytes));
  const result = implementation({ root, args });
  return { toolName, executedAtMs: Date.now(), result };
}

/** Serializable description of the local tool surface, for `describe()` and for the panel later. */
function describeTools(workspaceRoot) {
  return {
    implemented: [...IMPLEMENTED_TOOLS],
    workspaceRoot: resolveWorkspaceRoot(workspaceRoot),
    limits: {
      maxReadBytes: MAX_READ_BYTES,
      defaultReadBytes: DEFAULT_READ_BYTES,
      maxDirectoryEntries: MAX_DIRECTORY_ENTRIES,
      defaultDirectoryEntries: DEFAULT_DIRECTORY_ENTRIES,
    },
    schemas: Object.fromEntries(
      Object.entries(TOOL_SCHEMAS).map(([name, schema]) => [
        name,
        { required: [...schema.required], optional: [...schema.optional] },
      ]),
    ),
  };
}

module.exports = {
  IMPLEMENTED_TOOLS,
  TOOL_SCHEMAS,
  MAX_READ_BYTES,
  DEFAULT_READ_BYTES,
  MAX_DIRECTORY_ENTRIES,
  DEFAULT_DIRECTORY_ENTRIES,
  defaultWorkspaceRoot,
  resolveWorkspaceRoot,
  parseArgsBytes,
  assertArgsShape,
  resolveInsideRoot,
  ensureWorkspaceRoot,
  executeTool,
  describeTools,
};