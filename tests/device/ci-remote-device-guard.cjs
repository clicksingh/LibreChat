'use strict';

const fs = require('node:fs');
const path = require('node:path');

const WORKTREE_ROOT = path.resolve(__dirname, '..', '..');
const SCAN_ROOTS = [path.join('api', 'server', 'services', 'Device'), path.join('packages', 'data-schemas', 'src'), path.join('tests', 'device')];
const SKIP_DIR_NAMES = new Set(['node_modules', '.git', 'dist', 'coverage', '.turbo']);
const SKIP_PATH_PREFIXES = [path.join('tests', 'device', '_phase1_evidence')];
const CODE_EXTENSIONS = new Set(['.js', '.cjs', '.mjs', '.ts', '.tsx']);
const DEVICE_ROOT = path.join('api', 'server', 'services', 'Device');
const FORBIDDEN_ARTIFACT_PATHS = [
  path.join('src', 'remote-device'),
  path.join('api', 'src', 'remote-device'),
  path.join('npm-scripts', 'remote.ts'),
  path.join('api', 'npm-scripts', 'remote.ts'),
];

const LITERAL_ENDPOINT = 'mcp.desktop' + 'commander.app';
const LITERAL_VENDOR = 'desktop' + 'commander';
const LITERAL_REMOTE_DEVICE_DIR = 'src/' + 'remote' + '-device';
const LITERAL_REMOTE_SCRIPT = 'npm-scripts/' + 'remote' + '.ts';
const LITERAL_SRV_SCHEME = 'mongodb' + '+srv://';
const LITERAL_RPC_ENVELOPE = 'CBHR-' + 'RPC-V2';
const LITERAL_RENEW_ENVELOPE = 'CBHR-' + 'RENEW-V2';
const NON_LOCAL_MONGO_URI = new RegExp(
  'mongodb' + '://' + '(?!127\\.0\\.0\\.1[:/]|localhost[:/])[A-Za-z0-9_.\\-]+',
);

const GLOBAL_PATTERNS = [
  { id: 'third_party_endpoint', pattern: new RegExp(escapeRegExp(LITERAL_ENDPOINT)), detail: 'third-party remote endpoint literal' },
  { id: 'third_party_vendor', pattern: new RegExp(escapeRegExp(LITERAL_VENDOR)), detail: 'third-party remote vendor literal' },
  { id: 'remote_device_import', pattern: new RegExp(escapeRegExp(LITERAL_REMOTE_DEVICE_DIR)), detail: 'remote device transport import path' },
  { id: 'remote_script_import', pattern: new RegExp(escapeRegExp(LITERAL_REMOTE_SCRIPT)), detail: 'remote npm-script import path' },
  { id: 'srv_scheme', pattern: new RegExp(escapeRegExp(LITERAL_SRV_SCHEME)), detail: 'DNS-SRV remote Mongo discovery' },
  { id: 'non_local_mongo_uri', pattern: NON_LOCAL_MONGO_URI, detail: 'Mongo URI that is not the local 127.0.0.1 lab instance' },
];
const DEVICE_PATTERNS = [
  { id: 'rpc_envelope_literal', pattern: new RegExp(escapeRegExp(LITERAL_RPC_ENVELOPE)), detail: 'remote RPC envelope literal is out of Phase 1 scope' },
  { id: 'renew_envelope_literal', pattern: new RegExp(escapeRegExp(LITERAL_RENEW_ENVELOPE)), detail: 'remote renew envelope literal is out of Phase 1 scope' },
];

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function isSkippedDirectory(relativeDir) {
  return SKIP_PATH_PREFIXES.some((prefix) => relativeDir === prefix || relativeDir.startsWith(`${prefix}${path.sep}`));
}

function listCodeFiles(rootRelative) {
  const absoluteRoot = path.join(WORKTREE_ROOT, rootRelative);
  if (!fs.existsSync(absoluteRoot)) {
    return [];
  }
  const files = [];
  const stack = [absoluteRoot];
  while (stack.length > 0) {
    const current = stack.pop();
    const relativeCurrent = path.relative(WORKTREE_ROOT, current);
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const absolute = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIR_NAMES.has(entry.name) || isSkippedDirectory(path.relative(WORKTREE_ROOT, absolute))) {
          continue;
        }
        stack.push(absolute);
        continue;
      }
      if (!CODE_EXTENSIONS.has(path.extname(entry.name))) {
        continue;
      }
      files.push({ absolute, relative: relativeCurrent === '' ? entry.name : path.join(relativeCurrent, entry.name) });
    }
  }
  return files;
}

function scanFile(file) {
  const violations = [];
  const lines = fs.readFileSync(file.absolute, 'utf8').split(/\r?\n/);
  const deviceScoped = file.relative === DEVICE_ROOT || file.relative.startsWith(`${DEVICE_ROOT}${path.sep}`);
  const patterns = deviceScoped ? [...GLOBAL_PATTERNS, ...DEVICE_PATTERNS] : GLOBAL_PATTERNS;
  for (let index = 0; index < lines.length; index += 1) {
    for (const candidate of patterns) {
      if (!candidate.pattern.test(lines[index])) {
        continue;
      }
      violations.push({
        id: candidate.id,
        detail: candidate.detail,
        file: file.relative.split(path.sep).join('/'),
        line: index + 1,
        snippet: lines[index].trim().slice(0, 160),
      });
    }
  }
  return violations;
}

function presentForbiddenArtifacts() {
  return FORBIDDEN_ARTIFACT_PATHS.filter((relative) => fs.existsSync(path.join(WORKTREE_ROOT, relative))).map((relative) =>
    relative.split(path.sep).join('/'),
  );
}

function run() {
  const startedAt = new Date().toISOString();
  if (!fs.existsSync(WORKTREE_ROOT)) {
    process.stdout.write(
      `${JSON.stringify({ check: 'ci-remote-device-guard', status: 'BLOCKED', reason: 'worktree_root_absent', worktreeRoot: WORKTREE_ROOT })}\n`,
    );
    process.exitCode = 2;
    return;
  }

  const files = SCAN_ROOTS.flatMap((rootRelative) => listCodeFiles(rootRelative));
  const forbiddenArtifacts = presentForbiddenArtifacts();
  const violations = files.flatMap(scanFile);
  const status = violations.length === 0 && forbiddenArtifacts.length === 0 ? 'PASS' : 'VIOLATION';

  process.stdout.write(
    `${JSON.stringify({
      check: 'ci-remote-device-guard',
      guard: 'F-H02-1',
      status,
      startedAt,
      finishedAt: new Date().toISOString(),
      worktreeRoot: WORKTREE_ROOT,
      scanRoots: SCAN_ROOTS.map((root) => root.split(path.sep).join('/')),
      scannedFiles: files.length,
      forbiddenArtifacts,
      violations,
      policy: {
        thirdPartyTransport: 'stdio-only; no remote device transport, no third-party endpoint',
        mongoTargets: 'local lab instance only (127.0.0.1:27027, replicaSet cbhrRdcP1)',
        deviceScope: 'no CBHR RPC/renew envelope literals inside api/server/services/Device',
      },
    })}\n`,
  );
  process.exitCode = status === 'PASS' ? 0 : 5;
}

module.exports = {
  WORKTREE_ROOT,
  SCAN_ROOTS,
  GLOBAL_PATTERNS,
  DEVICE_PATTERNS,
  listCodeFiles,
  scanFile,
  run,
};

if (require.main === module) {
  run();
}
