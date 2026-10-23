'use strict';

/**
 * CBHR ENDPOINT AGENT — the server ceiling (workstream W7 / ruling GM-72 tier 1).
 *
 * GM-72's constraint is absolute: the effective tool set is **server ceiling ∩ device floor**, and
 * the device may only NARROW. This module holds the endpoint's local copy of tier 1 — the server's
 * ceiling — and answers one question: may this tool be dispatched at all?
 *
 * WHY A SNAPSHOT AND NOT A LIVE FETCH
 * The ceiling is authoritative server-side (`api/server/services/Device/deviceCapabilityPolicy.js`,
 * `ceilingForStage()`). The endpoint does not, and must not, re-derive it: an endpoint that could
 * compute its own ceiling would be granting itself permission, which is the inversion GM-72 exists to
 * forbid. So the endpoint reads a snapshot the server publishes, and treats a missing or malformed
 * snapshot as "no tool is permitted" — fail closed, never "no constraints".
 *
 * THE CONTENT OF THE SNAPSHOT IS THE SERVER'S CEILING DOCUMENT, UNCHANGED
 * `config/server-ceiling.json` embeds the server's own `ceilingForStage(stage, {pilot})` document
 * verbatim under `ceiling` (`schema: cbhr.rdc.capability-ceiling/1`, `tier: 1`, `source: 'server'`,
 * `deviceSettable: false`, the permitted `tools`, the `approvalRequired` subset, `hardDenied`, and
 * `counts`). The endpoint does not recompute the stage gate: it reads `ceiling.tools` as the set the
 * server permits. Regenerating the snapshot after a server policy change is a one-command operation
 * (`tools/generate-ceiling-snapshot.cjs`), and the test suite compares the committed snapshot against
 * a fresh call into the server module, so the two cannot silently drift.
 *
 * The snapshot additionally carries `stageIndex` — the first-admissible stage of every tool in the
 * full catalog. It is used ONLY to produce a precise diagnosis ("enabled from stage B, this endpoint
 * is at stage A") and never to widen `ceiling.tools`.
 *
 * The endpoint additionally refuses two names under GM-72 even if a snapshot was edited to permit
 * them (`track_ui_event`, `give_feedback_to_desktop_commander`). That is not a second authority; it
 * is a refusal to act on a snapshot that contradicts the ruling the endpoint was built under.
 */

const fs = require('node:fs');
const path = require('node:path');

const { refusal } = require('./errors');

/** Ordered stages; rank decides admissibility when the snapshot's stageIndex is consulted. */
const STAGE_RANK = Object.freeze({ A: 0, B: 1, C: 2, full: 3 });

/** The server's ceiling-document schema this endpoint knows how to read. */
const EXPECTED_CEILING_SCHEMA = 'cbhr.rdc.capability-ceiling/1';

/** Under GM-72 these two are never user-configurable and never dispatchable, at any tier. */
const ABSOLUTE_DENIES = Object.freeze(['track_ui_event', 'give_feedback_to_desktop_commander']);

/** The tier-1 refusal code the server's own policy module publishes for an out-of-ceiling claim. */
const CEILING_REFUSAL_CODE = 'TOOL_CEILING_OUTSIDE_SERVER_CEILING';

function ceilingRefusal(detail, cause) {
  return refusal('ENDPOINT_CEILING_SNAPSHOT_INVALID', detail, { field: 'serverCeiling', cause });
}

function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Validates a snapshot's shape and returns a frozen ceiling object.
 *
 * A malformed snapshot throws: "I could not read my ceiling" must never degrade to "everything is
 * permitted" (the same failure mode GM-23 names for a relay with an empty heap).
 *
 * @param {object} snapshot
 * @returns {Readonly<object>}
 */
function ceilingFromSnapshot(snapshot) {
  if (!isPlainRecord(snapshot)) {
    throw ceilingRefusal('the server ceiling snapshot must be a JSON object');
  }
  const document = snapshot.ceiling;
  if (!isPlainRecord(document)) {
    throw ceilingRefusal('the server ceiling snapshot does not embed a ceiling document');
  }
  if (document.schema !== EXPECTED_CEILING_SCHEMA) {
    throw ceilingRefusal('the embedded ceiling document declares an unsupported schema');
  }
  if (document.tier !== 1 || document.source !== 'server') {
    throw ceilingRefusal('the embedded ceiling document is not the tier-1 server ceiling');
  }
  if (document.deviceSettable !== false) {
    throw ceilingRefusal('the embedded ceiling document claims to be device-settable, which GM-72 forbids');
  }
  const stage = document.stage;
  if (!Object.prototype.hasOwnProperty.call(STAGE_RANK, stage)) {
    throw ceilingRefusal('the embedded ceiling document declares an unknown pilot stage');
  }
  if (!Array.isArray(document.tools) || document.tools.length === 0) {
    throw ceilingRefusal('the embedded ceiling document does not permit any tools');
  }
  const permitted = [];
  for (const name of document.tools) {
    if (typeof name !== 'string' || name.length === 0) {
      throw ceilingRefusal('the embedded ceiling document contains an unusable tool name');
    }
    if (permitted.includes(name)) {
      throw ceilingRefusal('the embedded ceiling document lists one tool name twice');
    }
    permitted.push(name);
  }
  const approvalRequired = Array.isArray(document.approvalRequired)
    ? document.approvalRequired.filter((name) => typeof name === 'string')
    : [];
  for (const name of approvalRequired) {
    if (!permitted.includes(name)) {
      throw ceilingRefusal('the embedded ceiling document requires approval for a tool it does not permit');
    }
  }
  const hardDenied = Array.isArray(document.hardDenied)
    ? document.hardDenied
        .filter((entry) => isPlainRecord(entry) && typeof entry.tool === 'string')
        .map((entry) => entry.tool)
    : [];
  for (const name of hardDenied) {
    if (permitted.includes(name)) {
      throw ceilingRefusal('the embedded ceiling document permits a tool it also hard-denies');
    }
  }

  const stageIndex = new Map();
  if (snapshot.stageIndex !== undefined) {
    if (!isPlainRecord(snapshot.stageIndex)) {
      throw ceilingRefusal('the snapshot stage index must be an object of tool name to stage');
    }
    for (const [name, toolStage] of Object.entries(snapshot.stageIndex)) {
      if (!Object.prototype.hasOwnProperty.call(STAGE_RANK, toolStage)) {
        throw ceilingRefusal('the snapshot stage index declares an unknown stage for a tool');
      }
      stageIndex.set(name, toolStage);
    }
    for (const name of permitted) {
      if (!stageIndex.has(name)) {
        throw ceilingRefusal('the snapshot stage index does not describe a tool the ceiling permits');
      }
    }
  }

  const rulingDenies = Array.isArray(snapshot.rulingAbsoluteDenies)
    ? snapshot.rulingAbsoluteDenies.filter((name) => typeof name === 'string')
    : [];

  // `track_ui_event` is an internal dispatch handler rather than one of the 26 advertised tools, so
  // it appears in `rulingAbsoluteDenies` and NOT in the stage index. It must still be refused, and
  // the refusal has to be attributable to tier 1 (the server ceiling) rather than to an unknown name,
  // so the ruling denies join the deny set here.
  const denied = new Set([...ABSOLUTE_DENIES, ...rulingDenies, ...hardDenied]);

  return Object.freeze({
    stage: () => stage,
    stageRank: () => STAGE_RANK[stage],
    pilot: () => document.pilot === true,
    /** Tier 1 for this endpoint, right now — exactly the server document's `tools`, minus nothing. */
    ceilingNames: () => Object.freeze([...permitted].sort()),
    deniedNames: () => Object.freeze([...denied].sort()),
    ownerApprovalTools: () => Object.freeze([...approvalRequired].sort()),
    /** Every tool the snapshot's stage index describes (the full catalog, for diagnosis only). */
    knownToolNames: () => Object.freeze([...stageIndex.keys()].sort()),
    definitionOf: (toolName) =>
      stageIndex.has(toolName)
        ? Object.freeze({ name: toolName, stage: stageIndex.get(toolName) })
        : null,
    /**
     * Is `toolName` inside the server ceiling?
     * @param {string} toolName
     * @returns {{allowed: boolean, reason: string|null, refusalCode: string|null}}
     */
    allows: (toolName) => {
      if (typeof toolName !== 'string' || toolName.length === 0) {
        return { allowed: false, reason: 'the tool name is not a non-empty string', refusalCode: CEILING_REFUSAL_CODE };
      }
      if (denied.has(toolName)) {
        return {
          allowed: false,
          reason: 'the tool is hard-denied at every stage (GM-72)',
          refusalCode: CEILING_REFUSAL_CODE,
        };
      }
      if (!permitted.includes(toolName)) {
        const known = stageIndex.get(toolName);
        return {
          allowed: false,
          reason:
            known === undefined
              ? 'the tool is not described by the server ceiling snapshot'
              : `the tool is enabled from stage ${known} and the server ceiling is at stage ${stage}`,
          refusalCode: CEILING_REFUSAL_CODE,
        };
      }
      if (approvalRequired.includes(toolName)) {
        // Inside the ceiling, but tier 3 applies: the endpoint never treats this as plain permission.
        return {
          allowed: true,
          reason: 'admissible, but every execution requires per-call owner approval',
          refusalCode: null,
        };
      }
      return { allowed: true, reason: null, refusalCode: null };
    },
    /** Serializable description for logs and for `describe()`. Tool names only: no secrets. */
    describe: () => ({
      schema: document.schema,
      stage,
      pilot: document.pilot === true,
      ceilingTools: permitted.length,
      approvalRequired: [...approvalRequired].sort(),
      hardDenied: [...denied].sort(),
      stageIndexTools: stageIndex.size,
    }),
  });
}

/** Loads a snapshot from disk, failing closed on absence or malformation. */
function loadCeilingSnapshot(snapshotPath) {
  if (typeof snapshotPath !== 'string' || snapshotPath.length === 0) {
    throw ceilingRefusal('no server ceiling snapshot path was supplied');
  }
  if (!fs.existsSync(snapshotPath)) {
    throw ceilingRefusal('the server ceiling snapshot file does not exist');
  }
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(snapshotPath, 'utf8'));
  } catch (err) {
    throw ceilingRefusal('the server ceiling snapshot is not valid JSON', err);
  }
  return ceilingFromSnapshot(parsed);
}

/** The snapshot shipped with the agent (a deployment may point elsewhere via config). */
function defaultSnapshotPath() {
  return path.resolve(__dirname, '..', 'config', 'server-ceiling.json');
}

module.exports = {
  STAGE_RANK,
  EXPECTED_CEILING_SCHEMA,
  ABSOLUTE_DENIES,
  CEILING_REFUSAL_CODE,
  ceilingFromSnapshot,
  loadCeilingSnapshot,
  defaultSnapshotPath,
};