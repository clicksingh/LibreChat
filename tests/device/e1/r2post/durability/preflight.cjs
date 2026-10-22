'use strict';

/**
 * W3-B R2 S4T frozen-input hash gate (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Verifies the six authorized source bytes by SHA-256 before any test write and again after the run.
 * A mismatch, a missing file, or an uncomputable hash is a hard BLOCK: no row may run, and no test
 * file may be written.
 */

const fs = require('node:fs');
const path = require('node:path');
const nodeCrypto = require('node:crypto');

/** durability -> r2post -> e1 -> device -> tests -> worktree */
const WORKTREE = path.resolve(__dirname, '..', '..', '..', '..', '..');

/** Authorization order: [worktree-relative path, authorized SHA-256 (uppercase)]. */
const FROZEN_INPUTS = Object.freeze([
  [
    'api/server/services/Device/registrationService.js',
    '9DB81E9ACDB79DCE45456E6C38EC463A80B9911A24AFB54C690D5CD1C8157EA9',
  ],
  [
    'api/server/services/Device/pairingSessionService.js',
    'D1644F00C1B67CC9712D540B04D2FF39D3118D40FAA0BB091C0DF0C424046D6F',
  ],
  [
    'api/server/services/Device/authorityService.js',
    'B51B3CEC5A02935A0CC7486F0A91B0883F33C7C0FE0F3A58C35E659AD9E9C0CF',
  ],
  [
    'api/server/services/Device/auditSink.js',
    '3F39D0102040A6FC510AC3AC8BADFE10E87B36784CD3DBEABF0C771F2F39CC37',
  ],
  [
    'packages/data-schemas/src/schema/auditEvent.ts',
    'AD4820FE7D4CDBB1B734D35BD1DEBCDB266058F362BA4400246AF0D54757BF0B',
  ],
  [
    'api/server/services/Device/errors.js',
    '7C084A33BF392CF0FC0FBCC8B8E1280382073FEC839860EC0DD51F2AEC727039',
  ],
]);

/**
 * Supplementary dependency-surface integrity set (S4T-08): the six bound bytes plus the four
 * device model/schema pairs this lane composes. Read-only hashing; nothing here is written.
 */
const DEPENDENCY_SURFACE = Object.freeze([
  ...FROZEN_INPUTS.map(([rel]) => rel),
  'packages/data-schemas/src/models/challenge.ts',
  'packages/data-schemas/src/schema/challenge.ts',
  'packages/data-schemas/src/models/pairingSession.ts',
  'packages/data-schemas/src/schema/pairingSession.ts',
  'packages/data-schemas/src/models/deviceAuthority.ts',
  'packages/data-schemas/src/schema/deviceAuthority.ts',
  'packages/data-schemas/src/models/auditEvent.ts',
  'packages/data-schemas/src/models/index.ts',
  'packages/data-schemas/src/schema/index.ts',
]);

function sha256File(absolute) {
  return nodeCrypto.createHash('sha256').update(fs.readFileSync(absolute)).digest('hex');
}

function sha256HexUpper(absolute) {
  return sha256File(absolute).toUpperCase();
}

function runPreflight() {
  const entries = [];
  const problems = [];
  const hashes = {};
  for (const [rel, authorized] of FROZEN_INPUTS) {
    const absolute = path.join(WORKTREE, rel);
    const entry = {
      path: rel,
      absolute,
      present: fs.existsSync(absolute),
      observed: null,
      authorized,
      match: false,
      error: null,
    };
    if (!entry.present) {
      entry.error = 'FILE_NOT_FOUND';
      problems.push(`${rel}: file not found at ${absolute}`);
    } else {
      try {
        entry.observed = sha256HexUpper(absolute);
        hashes[rel] = entry.observed;
        entry.match = entry.observed === authorized;
        if (!entry.match) {
          problems.push(`${rel}: observed ${entry.observed} != authorized ${authorized}`);
        }
      } catch (err) {
        entry.error = `${err.name}: ${err.message}`;
        problems.push(`${rel}: hash could not be computed (${entry.error})`);
      }
    }
    entries.push(entry);
  }
  return { ok: problems.length === 0, entries, hashes, problems };
}

/** Lowercase-hex hash manifest for a bounded list of worktree-relative paths. */
function hashManifest(paths) {
  const files = {};
  const problems = [];
  for (const rel of paths) {
    const absolute = path.join(WORKTREE, rel);
    if (!fs.existsSync(absolute)) {
      problems.push(`${rel}: MISSING`);
      files[rel] = null;
      continue;
    }
    try {
      files[rel] = sha256File(absolute);
    } catch (err) {
      problems.push(`${rel}: ${err.name}: ${err.message}`);
      files[rel] = null;
    }
  }
  return { files, problems, count: paths.length };
}

/** Compares two manifests produced by `hashManifest` over the same path list. */
function compareManifests(before, after) {
  const changed = [];
  const missingAfter = [];
  const added = [];
  for (const [rel, hash] of Object.entries(before.files)) {
    if (!(rel in after.files)) {
      missingAfter.push(rel);
      continue;
    }
    if (after.files[rel] !== hash) {
      changed.push({ path: rel, before: hash, after: after.files[rel] });
    }
  }
  for (const rel of Object.keys(after.files)) {
    if (!(rel in before.files)) {
      added.push(rel);
    }
  }
  return {
    unchanged: changed.length === 0 && missingAfter.length === 0 && added.length === 0,
    changed,
    missingAfter,
    added,
  };
}

module.exports = {
  WORKTREE,
  FROZEN_INPUTS,
  DEPENDENCY_SURFACE,
  sha256File,
  sha256HexUpper,
  runPreflight,
  hashManifest,
  compareManifests,
};

if (require.main === module) {
  const result = runPreflight();
  process.stdout.write(
    `${JSON.stringify(
      {
        ok: result.ok,
        verdict: result.ok ? 'PASS' : 'BLOCKED',
        entries: result.entries.map((entry) => ({
          path: entry.path,
          observed: entry.observed,
          authorized: entry.authorized,
          match: entry.match,
          error: entry.error,
        })),
        problems: result.problems,
      },
      null,
      2,
    )}\n`,
  );
  process.exitCode = result.ok ? 0 : 2;
}
