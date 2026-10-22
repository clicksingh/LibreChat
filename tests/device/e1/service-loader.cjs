'use strict';

/**
 * Honest product-service probe for the I9 E1/E2 fixtures.
 *
 * The I6 authority service and the I5 pairing/registration services are NOT part of
 * W2-B. This module must therefore never fabricate a working service, never install a
 * fallback stub, and never let a fixture report PASS against a missing dependency.
 *
 * Status values:
 *   AVAILABLE            all three frozen factories loaded from real product files
 *   BLOCKED_PENDING_I6_I5 at least one product service file is absent
 *   BLOCKED_SERVICE_SHAPE a file exists but does not expose its frozen factory
 */

const fs = require('node:fs');
const path = require('node:path');

const DEVICE_DIR = path.resolve(__dirname, '..', '..', '..', 'api', 'server', 'services', 'Device');

const REQUIRED = [
  {
    lane: 'I6',
    file: 'authorityService.js',
    factory: 'createAuthorityService',
    frozenSignature: 'createAuthorityService({ db, clock, crypto, logger, audit, verifyRenewalProof })',
  },
  {
    lane: 'I5',
    file: 'registrationService.js',
    factory: 'createRegistrationService',
    frozenSignature: 'createRegistrationService({ db, clock, crypto, logger, audit, tenantPolicy })',
  },
  {
    lane: 'I5',
    file: 'pairingSessionService.js',
    factory: 'createPairingSessionService',
    frozenSignature:
      'createPairingSessionService({ db, clock, crypto, logger, audit, authorityService, tenantPolicy, verifyLocalConsent })',
  },
];

function probe() {
  const missing = [];
  const shapeProblems = [];
  const loaded = {};

  for (const entry of REQUIRED) {
    const absolute = path.join(DEVICE_DIR, entry.file);
    if (!fs.existsSync(absolute)) {
      missing.push({ lane: entry.lane, file: entry.file, reason: 'file_absent' });
      continue;
    }
    let exported = null;
    try {
      // eslint-disable-next-line global-require, import/no-dynamic-require
      exported = require(absolute);
    } catch (err) {
      shapeProblems.push({ lane: entry.lane, file: entry.file, reason: `require_failed: ${err.message}` });
      continue;
    }
    if (typeof exported[entry.factory] !== 'function') {
      shapeProblems.push({ lane: entry.lane, file: entry.file, reason: `missing_factory_export: ${entry.factory}` });
      continue;
    }
    loaded[entry.lane] = loaded[entry.lane] || [];
    loaded[entry.lane].push({ file: entry.file, factory: entry.factory, module: exported });
  }

  if (missing.length > 0) {
    return {
      status: 'BLOCKED_PENDING_I6_I5',
      exitCode: 2,
      deviceDir: DEVICE_DIR,
      missing,
      shapeProblems,
      loaded: Object.keys(loaded),
      reason: 'I6 authority service and/or I5 pairing/registration service not implemented in W2-B',
      noFallbackInstalled: true,
    };
  }
  if (shapeProblems.length > 0) {
    return {
      status: 'BLOCKED_SERVICE_SHAPE',
      exitCode: 2,
      deviceDir: DEVICE_DIR,
      missing,
      shapeProblems,
      loaded: Object.keys(loaded),
      reason: 'product service files exist but do not expose the frozen factory surface',
      noFallbackInstalled: true,
    };
  }
  return {
    status: 'AVAILABLE',
    exitCode: 0,
    deviceDir: DEVICE_DIR,
    missing: [],
    shapeProblems: [],
    loaded: Object.keys(loaded),
    services: loaded,
    noFallbackInstalled: true,
  };
}

module.exports = { DEVICE_DIR, REQUIRED, probe };

if (require.main === module) {
  process.stdout.write(`${JSON.stringify(probe())}\n`);
}
