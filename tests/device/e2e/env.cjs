'use strict';

/**
 * W9 — the harness's environment: real module resolution, real MongoDB namespace discipline, and a
 * real HTTP server that mounts the REAL `api/server/routes/devices.js` router.
 *
 * FOUR DISCLOSED DECISIONS, all of them outside the product tree:
 *
 * 1. `~/*` ALIAS. `jest.config.cjs` maps `^~/(.*)$` to `<rootDir>/api/$1`. At runtime LibreChat
 *    resolves the same alias through its build tooling. A plain `node` process has no alias, so it is
 *    installed here for requesters that actually live under `api/` — nothing else changes.
 *
 * 2. `~/db/models` ADAPTER. Two accepted facts collide in a plain node process:
 *      - `api/db/models.js` is `createModels(mongoose)` with `{ ...models }`, so its members are
 *        genuine Mongoose Model CONSTRUCTORS (`typeof === 'function'`);
 *      - every accepted `Device/**` factory asserts `typeof db.<Model> === 'object'`
 *        (`pairingSessionService.assertDependencies`, `registrationService`, `authorityService`).
 *    `api/server/routes/devices.js` hands that raw registry to the factories at module load, so the
 *    real router cannot be required in node without the mismatch. `models-adapter.cjs` closes it: a
 *    plain-object surface whose members forward every call to the genuine model and add no logic.
 *    The adapter is substituted for THAT ONE SPECIFIER only, and it is named in the evidence.
 *
 * 3. AUTH IS REAL. The real `requireJwtAuth` middleware stays mounted and the real trusted passport
 *    `jwt` strategy from `api/strategies` is registered exactly as `api/server/index.js` registers it
 *    (`passport.use(jwtLogin())`). The harness mints a real JWT and seeds a real `User` row in
 *    MongoDB, so the device routes are reached through the real authentication chain: an
 *    unauthenticated request is refused by that chain, not by the harness.
 *
 * 4. NO PRODUCT EDIT. Nothing under `api/**`, `apps/**` or `packages/**` is read-modify-written.
 *    The `models-adapter.cjs` code lives in the W9 write scope.
 */

const path = require('node:path');
const http = require('node:http');
const Module = require('node:module');
const nodeCrypto = require('node:crypto');

const REPO = path.resolve(__dirname, '..', '..', '..');
const API_DIR = path.join(REPO, 'api') + path.sep;

/** The frozen local lab database endpoint. Refused at runtime if it does not match (fail closed). */
const REQUIRED_HOST = '127.0.0.1';
const REQUIRED_PORT = '27027';
const REQUIRED_REPLICA_SET = 'cbhrRdcP1';
const REQUIRED_SERVER_VERSION = '7.0.43';
/** Every database this harness may create. The cleanup asserts the namespace returns to its pre-run state. */
const DB_PREFIX = 'cbhr_rdc_phase1_e2e_';
const DB_NAME_PATTERN = /^cbhr_rdc_phase1_e2e_[A-Za-z0-9_]+$/;
const SYSTEM_DATABASES = Object.freeze(['admin', 'local', 'config']);

function stamp() {
  const iso = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
  return `${iso}_${nodeCrypto.randomBytes(3).toString('hex')}`;
}

function makeRunId() {
  return `w9-${stamp()}`;
}

function makeDbName(runId) {
  const safe = String(runId).replace(/[^A-Za-z0-9_]/g, '_');
  const name = `${DB_PREFIX}${safe}`;
  if (!DB_NAME_PATTERN.test(name)) {
    throw new Error(`HARNESS_REFUSAL: generated database name is outside the permitted prefix: ${name}`);
  }
  return name;
}

function uriFor(dbName) {
  if (!DB_NAME_PATTERN.test(dbName)) {
    throw new Error(`HARNESS_REFUSAL: refusing to build a URI for ${dbName}`);
  }
  return `mongodb://${REQUIRED_HOST}:${REQUIRED_PORT}/${dbName}?directConnection=true&replicaSet=${REQUIRED_REPLICA_SET}&serverSelectionTimeoutMS=15000&retryWrites=false`;
}

/**
 * The pre-run namespace, so the post-run comparison is against an OBSERVED value rather than an
 * assumption. System databases are reported separately and excluded from the comparison.
 */
async function listNamespace(adminDb) {
  const listed = await adminDb.admin().listDatabases({ nameOnly: true });
  const all = listed.databases.map((entry) => entry.name).sort();
  return {
    all,
    nonSystem: all.filter((name) => !SYSTEM_DATABASES.includes(name)),
  };
}

function namespaceDelta(before, after) {
  const missing = before.nonSystem.filter((name) => !after.nonSystem.includes(name));
  const added = after.nonSystem.filter((name) => !before.nonSystem.includes(name));
  return { equal: missing.length === 0 && added.length === 0, missing, added, before: before.nonSystem, after: after.nonSystem };
}

/** Installs the api-side `~/*` alias and the two disclosed substitutions. Idempotent. */
function installModuleResolution(state = {}) {
  if (state.installed === true) {
    return state;
  }
  const previous = Module._resolveFilename;
  state.apiRewrites = 0;
  state.adapterHits = 0;
  state.pepperSeamHits = 0;
  state.installed = true;
  Module._resolveFilename = function harnessResolve(request, parent, ...rest) {
    const parentFile = typeof parent === 'string' ? parent : parent?.filename;
    const fromApi = typeof parentFile === 'string' && parentFile.startsWith(API_DIR);
    if (fromApi && typeof request === 'string' && request.startsWith('~/')) {
      state.apiRewrites += 1;
      if (request === '~/db/models') {
        state.adapterHits += 1;
        return previous.call(this, path.join(__dirname, 'models-adapter.cjs'), parent, ...rest);
      }
      // `deviceHttpTrust` is re-exported with ONLY `resolvePepperSeam` wrapped, so the real router gets
      // the server-side pairing pepper the deployment config would supply. See that file's header.
      if (request === '~/server/services/Device/deviceHttpTrust') {
        state.pepperSeamHits += 1;
        return previous.call(this, path.join(__dirname, 'device-http-trust-seam.cjs'), parent, ...rest);
      }
      return previous.call(this, path.join(REPO, 'api', request.slice(2)), parent, ...rest);
    }
    return previous.call(this, request, parent, ...rest);
  };
  return state;
}

/**
 * Installs the server-owned pairing-pepper seam INTO the genuine `deviceHttpTrust` module object.
 *
 * Why not only the `~/*` alias rewrite: `pairingHttpHandler.js` reaches the module by RELATIVE path
 * (`require('./deviceHttpTrust')`), so an alias substitution alone never fires — measured, not
 * assumed: the first run with the alias-only seam recorded `pepperSeamSubstitutions: 0`. The function
 * is therefore replaced on the module's own exports object, which is what a destination module
 * resolves at require time.
 *
 * @param {object} seam the seam module (`device-http-trust-seam.cjs`)
 * @returns {{restore: Function, modulePath: string}}
 */
function installPepperSeam(seam) {
  const modulePath = path.join(REPO, 'api', 'server', 'services', 'Device', 'deviceHttpTrust.js');
  const genuine = require(modulePath);
  const original = genuine.resolvePepperSeam;
  genuine.resolvePepperSeam = seam.resolvePepperSeam;
  return {
    modulePath,
    restore: () => {
      genuine.resolvePepperSeam = original;
    },
  };
}

/**
 * Boots the real device HTTP surface.
 *
 * @param {object} params
 * @param {object} params.models the genuine `createModels(mongoose)` registry (the adapter's source)
 * @returns {Promise<{base: string, server: object, close: Function, provenance: object}>}
 */
async function bootDeviceHttpServer({ models }) {
  const express = require(path.join(REPO, 'node_modules', 'express'));
  const passport = require(path.join(REPO, 'node_modules', 'passport'));
  const { jwtLogin } = require(path.join(REPO, 'api', 'strategies'));
  const requireJwtAuth = require(path.join(REPO, 'api/server/middleware/requireJwtAuth.js'));
  const devicesRouter = require(path.join(REPO, 'api/server/routes/devices.js'));

  passport.use(jwtLogin());

  const app = express();
  app.use(express.json({ limit: '1mb' }));
  app.use(passport.initialize());
  app.use('/api/devices', devicesRouter);

  const server = http.createServer(app);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const base = `http://127.0.0.1:${server.address().port}`;

  return {
    base,
    server,
    requireJwtAuthLoaded: typeof requireJwtAuth === 'function',
    close: () => new Promise((resolve) => server.close(resolve)),
    provenance: {
      router: path.join(REPO, 'api', 'server', 'routes', 'devices.js'),
      routerExports: 'express.Router (mounted at /api/devices)',
      authMiddleware: path.join(REPO, 'api', 'server', 'middleware', 'requireJwtAuth.js'),
      passportStrategy: 'api/strategies jwtLogin(), registered as api/server/index.js does',
      rateLimiters: 'the router\'s own deviceRateLimiters (per-route, unmocked)',
      modelsRegistry: 'genuine createModels(mongoose) from @librechat/data-schemas (built dist)',
      modelsAdapter: path.join(__dirname, 'models-adapter.cjs'),
      modelsAdapterRealModels: Object.keys(models).length,
      productFilesModified: 'none',
    },
  };
}

/** A real bearer JWT for a real seeded user, signed with the process JWT_SECRET. */
function mintAccessToken({ userId, ttlSeconds = 3600 }) {
  const jwt = require(path.join(REPO, 'node_modules', 'jsonwebtoken'));
  const secret = process.env.JWT_SECRET;
  if (typeof secret !== 'string' || secret.length === 0) {
    throw new Error('HARNESS_REFUSAL: JWT_SECRET must be set before minting a token');
  }
  return jwt.sign({ id: userId }, secret, { expiresIn: ttlSeconds });
}

/** A JSON POST helper that never throws for a non-2xx answer. */
async function postJson(fetchImpl, url, body, headers = {}) {
  const res = await fetchImpl(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body ?? {}),
  });
  const text = await res.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = { __nonJson: text.slice(0, 200) };
  }
  return { status: res.status, body: parsed };
}

async function getJson(fetchImpl, url, headers = {}) {
  const res = await fetchImpl(url, { method: 'GET', headers });
  const text = await res.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = { __nonJson: text.slice(0, 200) };
  }
  return { status: res.status, body: parsed };
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(predicate, { timeout = 5000, interval = 25 } = {}) {
  const started = Date.now();
  for (;;) {
    const value = await predicate();
    if (value) {
      return value;
    }
    if (Date.now() - started >= timeout) {
      return null;
    }
    await sleep(interval);
  }
}

module.exports = {
  REPO,
  REQUIRED_HOST,
  REQUIRED_PORT,
  REQUIRED_REPLICA_SET,
  REQUIRED_SERVER_VERSION,
  DB_PREFIX,
  DB_NAME_PATTERN,
  SYSTEM_DATABASES,
  stamp,
  makeRunId,
  makeDbName,
  uriFor,
  listNamespace,
  namespaceDelta,
  installModuleResolution,
  installPepperSeam,
  bootDeviceHttpServer,
  mintAccessToken,
  postJson,
  getJson,
  sleep,
  waitFor,
};