'use strict';

/**
 * W3-B R2-T0A read-only source/static probes (test-only, PHASE1-LOCAL-AUTHORITY-001).
 *
 * These helpers NEVER write product bytes. They read the frozen pre-repair source to record,
 * per row, exactly which frozen symbol/filter is absent or present, and to validate that the
 * model recorder used for the tenantless-classifier row can actually detect a tenantless read.
 */

const fs = require('node:fs');
const path = require('node:path');

// eslint-disable-next-line global-require, import/no-dynamic-require
const env = require('./env.cjs');

const PRODUCT_FILES = Object.freeze({
  authorityService: 'api/server/services/Device/authorityService.js',
  registrationService: 'api/server/services/Device/registrationService.js',
  pairingSessionService: 'api/server/services/Device/pairingSessionService.js',
  crypto: 'api/server/services/Device/crypto.js',
  errors: 'api/server/services/Device/errors.js',
  deviceAuthoritySchema: 'packages/data-schemas/src/schema/deviceAuthority.ts',
  challengeSchema: 'packages/data-schemas/src/schema/challenge.ts',
  pairingSessionSchema: 'packages/data-schemas/src/schema/pairingSession.ts',
  auditEventSchema: 'packages/data-schemas/src/schema/auditEvent.ts',
  modelsIndex: 'packages/data-schemas/src/models/index.ts',
});

function resolveProduct(relative) {
  return path.join(env.WORKTREE, ...String(relative).split('/'));
}

function readSource(relative) {
  const absolute = path.isAbsolute(relative)
    ? relative
    : relative.startsWith('api/') || relative.startsWith('packages/') || relative.startsWith('tests/')
      ? resolveProduct(relative)
      : path.join(env.DEVICE_DIR, relative);
  if (!fs.existsSync(absolute)) {
    return { path: path.relative(env.WORKTREE, absolute).replace(/\\/g, '/'), absolute, exists: false, text: null };
  }
  return {
    path: path.relative(env.WORKTREE, absolute).replace(/\\/g, '/'),
    absolute,
    exists: true,
    text: fs.readFileSync(absolute, 'utf8'),
  };
}

/** All matches of `regex` with 1-based line numbers and the trimmed line text. */
function scan(relative, regex, limit = 40) {
  const source = readSource(relative);
  if (!source.exists) {
    return [];
  }
  const out = [];
  const lines = source.text.split('\n');
  for (let i = 0; i < lines.length && out.length < limit; i += 1) {
    if (regex.test(lines[i])) {
      out.push({ file: source.path, line: i + 1, text: lines[i].trim() });
    }
  }
  return out;
}

/** Presence/absence of a symbol across one or more relative files. */
function symbolScan(symbol, relatives) {
  const hits = [];
  for (const relative of relatives) {
    const source = readSource(relative);
    if (!source.exists) {
      continue;
    }
    const lines = source.text.split('\n');
    for (let i = 0; i < lines.length; i += 1) {
      if (lines[i].includes(symbol)) {
        hits.push({ file: source.path, line: i + 1, text: lines[i].trim() });
      }
    }
  }
  return { symbol, searched: relatives.slice(), present: hits.length > 0, hitCount: hits.length, hits };
}

/** Line-numbered excerpt window around the first match of `regex`. */
function excerpt(relative, regex, before = 2, after = 5) {
  const source = readSource(relative);
  if (!source.exists) {
    return { file: relative, found: false, anchors: [], text: null };
  }
  const lines = source.text.split('\n');
  const index = lines.findIndex((line) => regex.test(line));
  if (index === -1) {
    return { file: source.path, found: false, anchors: [], text: null };
  }
  const start = Math.max(0, index - before);
  const end = Math.min(lines.length, index + after + 1);
  return {
    file: source.path,
    found: true,
    anchorLine: index + 1,
    anchors: [{ line: index + 1, text: lines[index].trim() }],
    text: lines.slice(start, end).map((line, offset) => `${start + offset + 1}: ${line}`).join('\n'),
  };
}

/**
 * Forbidden attestation vocabulary, assembled from fragments so this detector's own source does
 * not contain any of the literal phrases it searches for.
 */
function attestationTerms() {
  const j = (...parts) => parts.join(' ');
  return [
    j('hardware', 'attestation'),
    j('attested', 'hardware'),
    j('physical', 'hardware'),
    j('physical', 'machine', 'identity'),
    j('physically', 'unique'),
    j('hardware', 'root', 'of', 'trust'),
    j('TPM', 'measured', 'boot'),
    j('secure', 'enclave', 'identity'),
  ];
}

function walkFiles(dir, predicate) {
  const out = [];
  if (!fs.existsSync(dir)) {
    return out;
  }
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
      out.push(...walkFiles(full, predicate));
    } else if (predicate(full)) {
      out.push(full);
    }
  }
  return out;
}

/** Scans a directory tree for the forbidden attestation vocabulary. */
function scanAttestationVocabulary(roots, options = {}) {
  const terms = attestationTerms();
  const files = [];
  for (const root of roots) {
    for (const file of walkFiles(root, (full) => /\.(js|ts|cjs|md|json)$/.test(full) && !full.endsWith('package-lock.json'))) {
      if (options.exclude && options.exclude.some((suffix) => file.endsWith(suffix))) continue;
      files.push(file);
    }
  }
  const hits = [];
  for (const file of files) {
    const text = fs.readFileSync(file, 'utf8').toLowerCase();
    for (const term of terms) {
      if (text.includes(term.toLowerCase())) {
        hits.push({ file: path.relative(env.WORKTREE, file).replace(/\\/g, '/'), term });
      }
    }
  }
  return {
    terms,
    fileCount: files.length,
    hits,
    clean: hits.length === 0,
  };
}

/**
 * Recording-proxy detector validity control. The proxy delegates every call to the GENUINE
 * Mongoose model (it is not a plain-object facade); it exists only to prove the detector can tell
 * a tenant-scoped Challenge read from a tenantless one.
 */
function makeTenantlessDetector(registry) {
  const recorder = env.w3a.makeRecorder();
  const instrumented = env.w3a.instrumentModels(
    {
      Challenge: registry.Challenge,
      DeviceAuthority: registry.DeviceAuthority,
      PairingSession: registry.PairingSession,
    },
    recorder,
  );
  const tenantlessReads = () =>
    recorder.entries.filter(
      (entry) =>
        entry.model === 'Challenge' &&
        entry.method === 'findOne' &&
        entry.filter !== null &&
        typeof entry.filter === 'object' &&
        entry.filter.challengeHash !== undefined &&
        entry.filter.tenantId === undefined,
    );
  return { instrumented, recorder, tenantlessReads };
}

const DEVICE_SERVICE_FILES = Object.freeze([
  PRODUCT_FILES.authorityService,
  PRODUCT_FILES.registrationService,
  PRODUCT_FILES.pairingSessionService,
]);

/**
 * Extracts the body of a function starting at `startRegex` up to (and including) the first
 * column-2 closing brace that follows it. Used to scope a symbol check to ONE product function
 * instead of the whole file.
 */
function extractFunction(relative, startRegex) {
  const source = readSource(relative);
  if (!source.exists) {
    return { file: relative, found: false, startLine: null, text: null };
  }
  const lines = source.text.split('\n');
  const start = lines.findIndex((line) => startRegex.test(line));
  if (start === -1) {
    return { file: source.path, found: false, startLine: null, text: null };
  }
  let end = start;
  for (let i = start + 1; i < lines.length; i += 1) {
    if (lines[i] === '  }') {
      end = i;
      break;
    }
  }
  return {
    file: source.path,
    found: true,
    startLine: start + 1,
    endLine: end + 1,
    text: lines.slice(start, end + 1).join('\n'),
    lineTexts: lines.slice(start, end + 1).map((line, offset) => ({ line: start + offset + 1, text: line })),
  };
}

module.exports = {
  PRODUCT_FILES,
  DEVICE_SERVICE_FILES,
  resolveProduct,
  readSource,
  scan,
  symbolScan,
  excerpt,
  extractFunction,
  attestationTerms,
  scanAttestationVocabulary,
  makeTenantlessDetector,
  walkFiles,
};