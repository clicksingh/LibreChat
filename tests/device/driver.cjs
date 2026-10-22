'use strict';

const fs = require('node:fs');
const path = require('node:path');

const PINNED_DRIVER_VERSION = '6.21.0';
const EVIDENCE_ROOT = path.resolve(__dirname, '_phase1_evidence');
const FORBIDDEN_TRAVERSAL_ROOT = path.join(EVIDENCE_ROOT, 'runtime', 'node_modules', 'LibreChat');

const CANDIDATE_MODULE_ROOTS = [
  path.join(EVIDENCE_ROOT, 'w2-runtime', 'node_modules'),
  path.join(EVIDENCE_ROOT, 'runtime', 'node_modules'),
];

function isForbiddenTraversal(target) {
  const resolved = path.resolve(target);
  return resolved === FORBIDDEN_TRAVERSAL_ROOT || resolved.startsWith(`${FORBIDDEN_TRAVERSAL_ROOT}${path.sep}`);
}

function readPackageVersion(modulePath) {
  const manifestPath = path.join(modulePath, 'package.json');
  if (!fs.existsSync(manifestPath)) {
    return null;
  }
  return JSON.parse(fs.readFileSync(manifestPath, 'utf8')).version;
}

function resolveDriver() {
  const probes = [];
  for (const root of CANDIDATE_MODULE_ROOTS) {
    const driverPath = path.join(root, 'mongodb');
    if (isForbiddenTraversal(driverPath)) {
      probes.push(`${driverPath} (refused: forbidden W0 junction traversal)`);
      continue;
    }
    const version = readPackageVersion(driverPath);
    if (version === null) {
      probes.push(`${driverPath} (absent)`);
      continue;
    }
    if (version !== PINNED_DRIVER_VERSION) {
      throw new Error(`DRIVER_VERSION_DRIFT: expected ${PINNED_DRIVER_VERSION} at ${driverPath}, observed ${version}`);
    }
    const bsonPath = path.join(root, 'bson');
    if (readPackageVersion(bsonPath) === null) {
      throw new Error(`BROKEN_PROBE: vendored bson absent at ${bsonPath}`);
    }
    return { driverPath, bsonPath, version };
  }
  throw new Error(`BROKEN_PROBE: vendored mongodb@${PINNED_DRIVER_VERSION} absent; probed ${probes.join(', ')}`);
}

const resolved = resolveDriver();
const { MongoClient } = require(resolved.driverPath);
const bson = require(resolved.bsonPath);

async function main(argv) {
  let runX4;
  try {
    ({ runX4 } = require('./index-assertion.js'));
  } catch (err) {
    process.stdout.write(
      `${JSON.stringify({ check: 'X4', status: 'HARNESS_FAIL', reason: 'index_assertion_require_failed', error: err.message })}\n`,
    );
    process.exitCode = 4;
    return;
  }
  const code = await runX4(argv);
  process.exitCode = code;
}

module.exports = {
  MongoClient,
  bson,
  driverPath: resolved.driverPath,
  version: resolved.version,
};

if (require.main === module) {
  main(process.argv.slice(2)).then(
    () => {},
    (err) => {
      process.stdout.write(
        `${JSON.stringify({ check: 'X4', status: 'HARNESS_FAIL', reason: 'driver_main_failed', error: err.message })}\n`,
      );
      process.exitCode = 4;
    },
  );
}
