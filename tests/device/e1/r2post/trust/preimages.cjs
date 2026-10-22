'use strict';

/**
 * W3-B R2 T2-F4 controlling-preimage hash gate and integrity manifests
 * (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * The six expected SHA-256 values below are transcribed VERBATIM from
 * `cbhr-rdc/docs/GOVERNOR-W3B-R2-T2-F4-TRUST-TEST-AUTHORIZATION-20261015.md`
 * ("Binding current source preimages"). The algorithm is SHA-256 over the raw file bytes, rendered
 * as uppercase hexadecimal — the same algorithm and rendering this lane's writer report already
 * attested. A mismatch BLOCKS the run before any row executes.
 */

const fs = require('node:fs');
const path = require('node:path');

const GOVERNANCE_ROOT = 'C:\\Users\\Aryan\\Desktop\\codellm\\cbhr-rdc';

const GOVERNANCE_DOCS = Object.freeze([
  path.join(GOVERNANCE_ROOT, 'docs', 'GOVERNOR-W3B-R2-T2-F4R-RECOVERY-20261015.md'),
  path.join(GOVERNANCE_ROOT, 'docs', 'GOVERNOR-W3B-R2-T2-F4-TRUST-TEST-AUTHORIZATION-20261015.md'),
]);

/** The six protected sources, in the authorization's own order. */
const PREIMAGES = Object.freeze([
  Object.freeze({
    id: 'authorityService.js',
    path: 'api/server/services/Device/authorityService.js',
    expected: 'B51B3CEC5A02935A0CC7486F0A91B0883F33C7C0FE0F3A58C35E659AD9E9C0CF',
  }),
  Object.freeze({
    id: 'registrationService.js',
    path: 'api/server/services/Device/registrationService.js',
    expected: '492D140B2BD6925DFECB0E54B7621316807B986BA9392E927E48E17EE88A8320',
  }),
  Object.freeze({
    id: 'pairingSessionService.js',
    path: 'api/server/services/Device/pairingSessionService.js',
    expected: 'C1B5D83B98191C345725988BC407E5460752937DBB64C1B1549438B8EBF4749F',
  }),
  Object.freeze({
    id: 'errors.js',
    path: 'api/server/services/Device/errors.js',
    expected: '7C084A33BF392CF0FC0FBCC8B8E1280382073FEC839860EC0DD51F2AEC727039',
  }),
  Object.freeze({
    id: 'tenantContext.ts',
    path: 'packages/data-schemas/src/config/tenantContext.ts',
    expected: '456989A4270290A6A2C52E0CE62E66646419BF464C17DC958DEBC0D015E625BD',
  }),
  Object.freeze({
    id: 'tenantIsolation.ts',
    path: 'packages/data-schemas/src/models/plugins/tenantIsolation.ts',
    expected: 'BFDED81714C2C36D0D23C2BB33E8EE8AB75112F5DD4AA1BBFC3B11FE5E028137',
  }),
]);

const PRIOR_EVIDENCE_REL_DIR = 'tests/device/_phase1_evidence/w3b-r2/t2-f4-trust';

const RUNTIME_PACKAGES = Object.freeze([
  'tests/device/_phase1_evidence/w2-runtime/node_modules/mongoose/package.json',
  'tests/device/_phase1_evidence/w2-runtime/node_modules/mongodb/package.json',
  'tests/device/_phase1_evidence/w2-runtime/node_modules/typescript/package.json',
]);

function sha256FileUpper(absolute) {
  return require('node:crypto')
    .createHash('sha256')
    .update(fs.readFileSync(absolute))
    .digest('hex')
    .toUpperCase();
}

/** Runs the six-preimage gate. Never throws: every problem is reported per entry. */
function runHashGate(worktree) {
  const entries = PREIMAGES.map((preimage) => {
    const absolute = path.join(worktree, preimage.path);
    try {
      const observed = sha256FileUpper(absolute);
      return {
        id: preimage.id,
        path: preimage.path,
        absolute,
        expected: preimage.expected,
        observed,
        match: observed === preimage.expected,
        error: null,
      };
    } catch (err) {
      return {
        id: preimage.id,
        path: preimage.path,
        absolute,
        expected: preimage.expected,
        observed: null,
        match: false,
        error: `${err.name}: ${err.message}`,
      };
    }
  });
  const problems = entries
    .filter((entry) => entry.match !== true)
    .map(
      (entry) =>
        `${entry.path}: expected ${entry.expected}, observed ${entry.observed ?? `(unreadable: ${entry.error})`}`,
    );
  return {
    algorithm: 'sha256(raw file bytes) rendered as uppercase hex',
    source: 'GOVERNOR-W3B-R2-T2-F4-TRUST-TEST-AUTHORIZATION-20261015.md',
    entries,
    hashes: Object.fromEntries(entries.map((entry) => [entry.path, entry.observed])),
    problems,
    ok: entries.length === PREIMAGES.length && problems.length === 0,
  };
}

/** Read-only digest manifest for a bounded list of repo-relative files. */
function hashManifest(worktree, relativePaths) {
  const files = {};
  for (const relative of relativePaths) {
    const absolute = path.join(worktree, relative);
    try {
      files[relative] = sha256FileUpper(absolute);
    } catch (err) {
      files[relative] = `UNREADABLE: ${err.name}: ${err.message}`;
    }
  }
  return { count: relativePaths.length, files };
}

function compareManifests(before, after) {
  const changed = [];
  const missing = [];
  for (const [relative, digest] of Object.entries(before.files)) {
    if (!Object.prototype.hasOwnProperty.call(after.files, relative)) {
      missing.push(relative);
      continue;
    }
    if (after.files[relative] !== digest) {
      changed.push({ path: relative, before: digest, after: after.files[relative] });
    }
  }
  const added = Object.keys(after.files).filter(
    (relative) => !Object.prototype.hasOwnProperty.call(before.files, relative),
  );
  return {
    unchanged: changed.length === 0 && missing.length === 0 && added.length === 0,
    changed,
    missing,
    added,
  };
}

/** Direct files (not directories) of the T2-F4 writer report folder: hashed so none can drift. */
function listPriorEvidenceFiles(worktree) {
  const dir = path.join(worktree, PRIOR_EVIDENCE_REL_DIR);
  if (!fs.existsSync(dir)) {
    return [];
  }
  return fs
    .readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => `${PRIOR_EVIDENCE_REL_DIR}/${entry.name}`)
    .sort();
}

/** Pinned scoped-runtime versions, read from the lab runtime manifests (read-only). */
function runtimeVersions(worktree) {
  const out = {};
  for (const relative of RUNTIME_PACKAGES) {
    try {
      const manifest = JSON.parse(fs.readFileSync(path.join(worktree, relative), 'utf8'));
      out[manifest.name] = manifest.version;
    } catch (err) {
      out[relative] = `UNREADABLE: ${err.name}: ${err.message}`;
    }
  }
  return out;
}

/** Governance document inventory: existence only; the authorization does not require hashing them. */
function governanceInventory() {
  return GOVERNANCE_DOCS.map((absolute) => ({
    path: absolute,
    exists: fs.existsSync(absolute),
    hashRequiredByAuthorization: false,
  }));
}

module.exports = {
  GOVERNANCE_ROOT,
  GOVERNANCE_DOCS,
  PREIMAGES,
  PRIOR_EVIDENCE_REL_DIR,
  RUNTIME_PACKAGES,
  sha256FileUpper,
  runHashGate,
  hashManifest,
  compareManifests,
  listPriorEvidenceFiles,
  runtimeVersions,
  governanceInventory,
};