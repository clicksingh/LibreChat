'use strict';

/**
 * W3-B R2 S2-T frozen-input hash preflight (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * Verifies the six authorized input bytes by SHA-256 (lowercase hex) BEFORE any test write.
 * A mismatch, a missing file, or an uncomputable hash is a hard BLOCK: no row may run.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

/** s2t -> e1 -> device -> tests -> worktree */
const WORKTREE = path.resolve(__dirname, '..', '..', '..', '..');

/** Authorization order: [worktree-relative path, authorized SHA-256]. */
const FROZEN_INPUTS = [
  [
    'api/server/services/Device/authorityService.js',
    '99ecd5b9134dadca9130200a546a2f6ac968a7c574f42a54ac576dcbf55778c2',
  ],
  [
    'api/server/services/Device/registrationService.js',
    '9db81e9acdb79dce45456e6c38ec463a80b9911a24afb54c690d5cd1c8157ea9',
  ],
  [
    'api/server/services/Device/pairingSessionService.js',
    'd1644f00c1b67cc9712d540b04d2ff39d3118d40faa0bb091c0df0c424046d6f',
  ],
  ['api/server/services/Device/errors.js', '1ba26da2fdb05d69f155b5bca1ccdd942daf83ab2f182727e76859955019645c'],
  [
    'packages/data-schemas/src/schema/challenge.ts',
    'a1569f7795a2d7366865bc3c8efa4116ebb4e34bf9d776a881650879f9312c2c',
  ],
  [
    'packages/data-schemas/src/schema/pairingSession.ts',
    '785c95f48e0df258baaa187785ec87f57ce6fa45d432b331055f046f323f4c9b',
  ],
];

function sha256File(absolute) {
  return crypto.createHash('sha256').update(fs.readFileSync(absolute)).digest('hex');
}

/**
 * @returns {{ok: boolean, entries: Array<{path: string, absolute: string, present: boolean,
 *   observed: string|null, authorized: string, match: boolean, error: string|null}>,
 *   hashes: Record<string, string>, problems: string[]}}
 */
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
        entry.observed = sha256File(absolute);
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

module.exports = { WORKTREE, FROZEN_INPUTS, sha256File, runPreflight };

if (require.main === module) {
  const result = runPreflight();
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  process.exitCode = result.ok ? 0 : 2;
}