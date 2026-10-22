'use strict';

const fs = require('node:fs');
const path = require('node:path');

const WORKTREE_ROOT = path.resolve(__dirname, '..', '..');
const EVIDENCE_ROOT = path.join(WORKTREE_ROOT, 'tests', 'device', '_phase1_evidence');
const W2R_RUNTIME_ROOT = path.join(EVIDENCE_ROOT, 'w2-runtime');
const FORBIDDEN_TRAVERSAL_ROOT = path.join(EVIDENCE_ROOT, 'runtime', 'node_modules', 'LibreChat');

const REQUIRED_HOSTS = ['127.0.0.1', 'localhost'];
const REQUIRED_PORT = '27027';
const REQUIRED_REPLICA_SET = 'cbhrRdcP1';
const REQUIRED_SERVER_VERSION = '7.0.43';
const PINNED_DRIVER_VERSION = '6.21.0';
const DB_NAME_PATTERN = /^cbhr_rdc_phase1_w2r_[A-Za-z0-9_]+$/;
const DB_NAME_PREFIX = 'cbhr_rdc_phase1_';
const SYSTEM_DATABASES = new Set(['admin', 'local', 'config']);
const SRV_SCHEME = 'mongodb' + '+srv://';

const FROZEN_URI =
  'mongodb://127.0.0.1:27027/?directConnection=true&replicaSet=cbhrRdcP1&serverSelectionTimeoutMS=5000&retryWrites=false';
const DEFAULT_URI =
  'mongodb://127.0.0.1:27027/?directConnection=true&replicaSet=cbhrRdcP1&serverSelectionTimeoutMS=15000&retryWrites=false';

const OWNED_WRITE_PATHS = [
  'tests/device/driver.cjs',
  'tests/device/index-assertion.js',
  'tests/device/ci-remote-device-guard.cjs',
  'tests/device/scope-guard.cjs',
  'tests/device/_phase1_evidence/.gitignore',
  'tests/device/_phase1_evidence/w2r/I8R-TOOLCHAIN-X4.md',
];
const OWNED_WRITE_PREFIXES = ['tests/device/_phase1_evidence/w2-runtime/'];
const FORBIDDEN_WRITE_PREFIXES = [
  'node_modules/',
  'packages/',
  'api/',
  'tests/device/_phase1_evidence/runtime/',
  'tests/device/_phase1_evidence/w0/',
  'tests/device/_phase1_evidence/w1/',
  'tests/device/_phase1_evidence/w2/',
];

const SKIP_DIR_NAMES = new Set(['node_modules', '.git', 'dist', 'coverage', '.turbo']);
const CODE_EXTENSIONS = new Set(['.js', '.cjs', '.mjs', '.ts', '.tsx']);
const BARE_MONGO_REQUIRE = /(?:require\s*\(\s*['"]mongodb['"]\s*\)|from\s+['"]mongodb['"])/;

function normalize(relativePath) {
  return String(relativePath).split(path.sep).join('/');
}

function localUriProblems(uri) {
  if (typeof uri !== 'string' || uri.length === 0) {
    return ['uri is required'];
  }
  if (uri.startsWith(SRV_SCHEME)) {
    return ['DNS-SRV mongodb scheme is forbidden (no remote discovery)'];
  }
  if (!uri.startsWith('mongodb://')) {
    return ['uri must start with mongodb://'];
  }
  const problems = [];
  const authority = uri.slice('mongodb://'.length).split('/')[0].split('?')[0];
  if (authority.includes('@')) {
    problems.push('credentials in the URI are forbidden');
  }
  if (authority.includes(',')) {
    problems.push('multi-host URIs are forbidden');
  }
  let parsed;
  try {
    parsed = new URL(uri);
  } catch {
    problems.push('uri is not parseable as a single-host mongodb:// URI');
    return problems;
  }
  if (!REQUIRED_HOSTS.includes(parsed.hostname)) {
    problems.push(`host must be one of ${REQUIRED_HOSTS.join('|')} (observed ${parsed.hostname})`);
  }
  const port = parsed.port === '' ? '27017' : parsed.port;
  if (port !== REQUIRED_PORT) {
    problems.push(`port must be ${REQUIRED_PORT} (observed ${port})`);
  }
  const replicaSet = parsed.searchParams.get('replicaSet');
  if (replicaSet !== REQUIRED_REPLICA_SET) {
    problems.push(`replicaSet must be ${REQUIRED_REPLICA_SET} (observed ${replicaSet === null ? 'absent' : replicaSet})`);
  }
  if (parsed.searchParams.get('tls') === 'true' || parsed.searchParams.get('ssl') === 'true') {
    problems.push('tls/ssl is forbidden for the local lab instance');
  }
  if (parsed.searchParams.get('directConnection') !== 'true') {
    problems.push('directConnection=true is required for the local single-node topology');
  }
  return problems;
}

function isolatedDbNameProblems(name) {
  if (typeof name !== 'string' || name.length === 0) {
    return ['db name is required'];
  }
  if (!DB_NAME_PATTERN.test(name)) {
    return [`db name must match ${DB_NAME_PATTERN} (prefix cbhr_rdc_phase1_w2r_ required)`];
  }
  return [];
}

function foreignDatabaseNames(names, ownDbName) {
  return names.filter(
    (name) => !SYSTEM_DATABASES.has(name) && name !== ownDbName && !name.startsWith(DB_NAME_PREFIX),
  );
}

function ownedPathProblems(relativePath) {
  const normalized = normalize(relativePath).replace(/^\.\//, '');
  if (OWNED_WRITE_PATHS.includes(normalized)) {
    return [];
  }
  if (OWNED_WRITE_PREFIXES.some((prefix) => normalized.startsWith(prefix))) {
    return [];
  }
  if (FORBIDDEN_WRITE_PREFIXES.some((prefix) => normalized.startsWith(prefix))) {
    return [`${normalized} is forbidden to lane I8R (shared or another lane's path)`];
  }
  return [`${normalized} is outside lane I8R ownership`];
}

function isForbiddenTraversal(target) {
  const resolved = path.resolve(target);
  return resolved === FORBIDDEN_TRAVERSAL_ROOT || resolved.startsWith(`${FORBIDDEN_TRAVERSAL_ROOT}${path.sep}`);
}

function reparsePoints(root) {
  const found = [];
  if (!fs.existsSync(root)) {
    return found;
  }
  const stack = [root];
  while (stack.length > 0) {
    const current = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (err) {
      found.push({ path: current, reason: `unreadable: ${err.code}` });
      continue;
    }
    for (const entry of entries) {
      const absolute = path.join(current, entry.name);
      let resolved;
      try {
        resolved = fs.realpathSync(absolute);
      } catch {
        resolved = absolute;
      }
      const stat = fs.lstatSync(absolute);
      if (stat.isSymbolicLink() || resolved !== path.resolve(absolute)) {
        found.push({ path: absolute, reason: stat.isSymbolicLink() ? 'symlink_or_junction' : 'realpath_divergence' });
        continue;
      }
      if (entry.isDirectory()) {
        stack.push(absolute);
      }
    }
  }
  return found;
}

function listCodeFiles(root) {
  const files = [];
  if (!fs.existsSync(root)) {
    return files;
  }
  const stack = [root];
  while (stack.length > 0) {
    const current = stack.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const absolute = path.join(current, entry.name);
      if (SKIP_DIR_NAMES.has(entry.name)) {
        continue;
      }
      if (entry.isDirectory()) {
        stack.push(absolute);
        continue;
      }
      if (CODE_EXTENSIONS.has(path.extname(entry.name))) {
        files.push(absolute);
      }
    }
  }
  return files;
}

function bareMongoRequires(root) {
  return listCodeFiles(root)
    .filter((absolute) => BARE_MONGO_REQUIRE.test(fs.readFileSync(absolute, 'utf8')))
    .map((absolute) => normalize(path.relative(WORKTREE_ROOT, absolute)));
}

function auditLocalIsolation() {
  const findings = [];
  const moduleRoot = path.join(W2R_RUNTIME_ROOT, 'node_modules');
  const driverPackage = path.join(moduleRoot, 'mongodb', 'package.json');

  if (!fs.existsSync(W2R_RUNTIME_ROOT)) {
    findings.push({ id: 'w2r_runtime_absent', detail: normalize(path.relative(WORKTREE_ROOT, W2R_RUNTIME_ROOT)) });
  }
  if (!fs.existsSync(driverPackage)) {
    findings.push({ id: 'isolated_driver_absent', detail: normalize(path.relative(WORKTREE_ROOT, driverPackage)) });
  } else {
    const observed = JSON.parse(fs.readFileSync(driverPackage, 'utf8')).version;
    if (observed !== PINNED_DRIVER_VERSION) {
      findings.push({ id: 'driver_version_drift', detail: `expected ${PINNED_DRIVER_VERSION}, observed ${observed}` });
    }
  }

  const reparse = reparsePoints(W2R_RUNTIME_ROOT);
  for (const point of reparse) {
    findings.push({ id: 'reparse_point_in_sandbox', detail: `${normalize(path.relative(WORKTREE_ROOT, point.path))} (${point.reason})` });
  }

  for (const file of bareMongoRequires(path.join(WORKTREE_ROOT, 'tests', 'device'))) {
    findings.push({ id: 'bare_mongodb_require', detail: file });
  }

  if (fs.existsSync(path.join(WORKTREE_ROOT, 'node_modules'))) {
    findings.push({ id: 'root_node_modules_present', detail: 'worktree root node_modules exists' });
  }

  for (const uri of [FROZEN_URI, DEFAULT_URI]) {
    for (const problem of localUriProblems(uri)) {
      findings.push({ id: 'policy_uri_invalid', detail: `${uri} => ${problem}` });
    }
  }

  const junctionSelfCheck =
    isForbiddenTraversal(path.join(FORBIDDEN_TRAVERSAL_ROOT, 'mongodb')) === true &&
    isForbiddenTraversal(path.join(W2R_RUNTIME_ROOT, 'node_modules')) === false;
  if (!junctionSelfCheck) {
    findings.push({ id: 'forbidden_traversal_guard_broken', detail: 'junction classifier did not separate the W0 runtime junction from the I8R sandbox' });
  }

  return {
    check: 'scope-guard',
    mode: 'audit',
    status: findings.length === 0 ? 'PASS' : 'BLOCKED',
    worktreeRoot: WORKTREE_ROOT,
    w2rRuntimeRoot: normalize(path.relative(WORKTREE_ROOT, W2R_RUNTIME_ROOT)),
    pinnedDriverVersion: PINNED_DRIVER_VERSION,
    requiredServerVersion: REQUIRED_SERVER_VERSION,
    frozenUri: FROZEN_URI,
    defaultUri: DEFAULT_URI,
    findings,
  };
}

function parseArgs(argv) {
  const options = { uri: null, db: null, paths: [], audit: false };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const [flag, inlineValue] = arg.includes('=') ? arg.split(/=(.*)/s, 2) : [arg, null];
    const value = inlineValue !== null ? inlineValue : argv[index + 1];
    const consumeNext = inlineValue === null;
    if (flag === '--audit') {
      options.audit = true;
      continue;
    }
    if (flag === '--uri') {
      options.uri = value;
      if (consumeNext) index += 1;
      continue;
    }
    if (flag === '--db') {
      options.db = value;
      if (consumeNext) index += 1;
      continue;
    }
    if (flag === '--path') {
      options.paths.push(value);
      if (consumeNext) index += 1;
    }
  }
  return options;
}

function evaluate(options) {
  const findings = [];
  if (options.uri !== null && options.uri !== undefined) {
    findings.push(...localUriProblems(options.uri));
  }
  if (options.db !== null && options.db !== undefined) {
    findings.push(...isolatedDbNameProblems(options.db));
  }
  for (const target of options.paths) {
    findings.push(...ownedPathProblems(target));
  }
  return findings;
}

function main(argv) {
  const options = parseArgs(argv);
  const auditRequested = options.audit || (options.uri === null && options.db === null && options.paths.length === 0);
  if (auditRequested) {
    const report = auditLocalIsolation();
    process.stdout.write(`${JSON.stringify(report)}\n`);
    process.exitCode = report.status === 'PASS' ? 0 : 2;
    return;
  }
  const findings = evaluate(options);
  const report = {
    check: 'scope-guard',
    mode: 'evaluate',
    status: findings.length === 0 ? 'PASS' : 'BLOCKED',
    uri: options.uri,
    db: options.db,
    paths: options.paths,
    findings,
  };
  process.stdout.write(`${JSON.stringify(report)}\n`);
  process.exitCode = report.status === 'PASS' ? 0 : 2;
}

module.exports = {
  WORKTREE_ROOT,
  EVIDENCE_ROOT,
  W2R_RUNTIME_ROOT,
  FORBIDDEN_TRAVERSAL_ROOT,
  REQUIRED_HOSTS,
  REQUIRED_PORT,
  REQUIRED_REPLICA_SET,
  REQUIRED_SERVER_VERSION,
  PINNED_DRIVER_VERSION,
  DB_NAME_PATTERN,
  DB_NAME_PREFIX,
  FROZEN_URI,
  DEFAULT_URI,
  localUriProblems,
  isolatedDbNameProblems,
  foreignDatabaseNames,
  ownedPathProblems,
  isForbiddenTraversal,
  reparsePoints,
  listCodeFiles,
  bareMongoRequires,
  auditLocalIsolation,
  normalize,
};

if (require.main === module) {
  main(process.argv.slice(2));
}
