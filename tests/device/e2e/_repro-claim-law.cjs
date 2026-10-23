'use strict';

/**
 * FOCUSED SOURCE-LEVEL REPRODUCTION of the pairing-claim binding law.
 *
 * The accepted `requireLocalConsent` reports ONE message for eight conjuncts, and the service's
 * internals are closure-private, so a caller cannot see WHICH conjunct failed. This probe compiles the
 * GENUINE product file (the exact bytes on disk) with ONE `console.error` line inserted immediately
 * before the rejection, and hands that compiled copy to `createPairingSessionService` by redirecting
 * the module resolution for that ONE specifier. The inserted line only READS and PRINTS; no value, no
 * branch and no outcome is altered, and the repro drives the same direct service calls the W9 harness
 * drives.
 *
 * The product file is never written to. The instrumented bytes live only in memory.
 *
 * Usage: node _repro-claim-law.cjs
 */

const path = require('node:path');
const Module = require('node:module');
const nodeCrypto = require('node:crypto');
const fs = require('node:fs');

const REPO = path.resolve(__dirname, '..', '..', '..');
const DEVICE_DIR = path.join(REPO, 'api', 'server', 'services', 'Device');
const SERVICE_PATH = path.join(DEVICE_DIR, 'pairingSessionService.js');

/** Compiles the genuine file with one read-only log line inserted at the binding law. */
function compileInstrumentedService() {
  const source = fs.readFileSync(SERVICE_PATH, 'utf8');
  const anchor = "    if (!bound) {\n      return reject('Local-endpoint approval is stale or not bound to trusted session truth');\n    }";
  if (!source.includes(anchor)) {
    throw new Error('anchor not found in the accepted service');
  }
  const injected = source.replace(
    anchor,
    `    console.error('[LAW]', JSON.stringify({
      nonceHashOk: isNonEmptyString(verdict.localApprovalNonceHash),
      tenantOk: verdict.boundTenantId === tenantId,
      ownerOk: verdict.boundOwnerId === ownerId,
      deviceOk: verdict.boundDeviceId === session.deviceId,
      sessionOk: verdict.boundPairingSessionId === String(session._id),
      challengeOk: verdict.boundChallengeRef === claim.challengeRef,
      approvedAt,
      openedAt,
      expiresAt,
      now,
      approvedAtType: typeof verdict.approvedAt,
      openedAtType: claim.openedAt === null ? 'null' : (claim.openedAt?.constructor?.name ?? 'undefined'),
      approvedAtCtor: verdict.approvedAt?.constructor?.name ?? null,
      geOpened: approvedAt !== null && openedAt !== null && approvedAt >= openedAt,
      leNow: approvedAt !== null && approvedAt <= now,
      ltExpires: approvedAt !== null && expiresAt !== null && approvedAt < expiresAt,
    }));
    if (!bound) {
      return reject('Local-endpoint approval is stale or not bound to trusted session truth');
    }`,
  );
  const compiled = new Module(SERVICE_PATH, null);
  compiled.filename = SERVICE_PATH;
  compiled.paths = Module._nodeModulePaths(DEVICE_DIR);
  compiled._compile(injected, SERVICE_PATH);
  return compiled.exports;
}

const instrumented = compileInstrumentedService();
const realResolve = Module._resolveFilename;
Module._resolveFilename = function reproResolve(request, parent, ...rest) {
  if (typeof request === 'string' && request.includes('pairingSessionService')) {
    return SERVICE_PATH;
  }
  return realResolve.call(this, request, parent, ...rest);
};
require.cache[SERVICE_PATH] = {
  id: SERVICE_PATH,
  filename: SERVICE_PATH,
  loaded: true,
  exports: instrumented,
  children: [],
  paths: Module._nodeModulePaths(DEVICE_DIR),
};

const dbName = `cbhr_rdc_phase1_e2e_law_${nodeCrypto.randomBytes(4).toString('hex')}`;
process.env.MONGO_URI = `mongodb://127.0.0.1:27027/${dbName}?directConnection=true&replicaSet=cbhrRdcP1`;

const env = require('./env.cjs');
env.installModuleResolution({});

const TENANT = 'tenant-law';
const OWNER = 'principal-law-owner';
const PAIRING_COMPLETE_DOMAIN = 'cbhr:device:pairing-complete:v1';
const PAIRING_OPEN_DOMAIN = 'cbhr:device:pairing-open:v1';
const REGISTRATION_DOMAIN = 'cbhr:device:registration:v1';
const PEPPER = Buffer.from('law-lookup-pepper-0001', 'utf8');

async function main() {
  const out = { dbName, serviceInstrumented: instrumented.createPairingSessionService !== undefined };
  const { connectDb } = require(path.join(REPO, 'api', 'db', 'connect.js'));
  await connectDb();
  const models = require('./models-adapter.cjs');
  const deviceCrypto = require(path.join(DEVICE_DIR, 'crypto.js'));
  const { createAuthorityService } = require(path.join(DEVICE_DIR, 'authorityService.js'));
  const { createRegistrationService } = require(path.join(DEVICE_DIR, 'registrationService.js'));
  const { createPairingSessionService } = require(SERVICE_PATH);
  const { createEndpointSignatureConsent } = require(path.join(DEVICE_DIR, 'pairingCompleteHttpHandler.js'));
  const { createClockSkewGuard } = require(path.join(DEVICE_DIR, 'databaseTime.js'));

  const clock = { now: () => Date.now() };
  const tenantContext = { getActiveTenantId: () => TENANT, alsAbsencePermitted: false };
  const audit = async () => {};

  const registration = createRegistrationService({
    db: models,
    clock,
    crypto: deviceCrypto,
    logger: null,
    audit,
    tenantPolicy: { validateRegistrationTenant: async (tenantId) => tenantId === TENANT },
    tenantContext,
  });
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const begin = await registration.beginRegistration({ tenantId: TENANT, requestSource: 'law' });
  const nonce = nodeCrypto.randomBytes(16).toString('base64url');
  const issuedAt = String(Date.now());
  const regMessage = deviceCrypto.canonicalEncode({
    domainTag: REGISTRATION_DOMAIN,
    fields: [TENANT, begin.challenge, spki, deviceCrypto.thumbprintB64u(spki), 'law', process.platform, '0.0.0', nonce, issuedAt],
  });
  const done = await registration.completeRegistration({
    tenantId: TENANT,
    devicePublicKey: spki,
    deviceName: 'law',
    platform: process.platform,
    agentVersion: '0.0.0',
    domainTag: REGISTRATION_DOMAIN,
    requestSource: 'law',
    proof: { challenge: begin.challenge, nonce, issuedAt, signatureB64u: nodeCrypto.sign(null, regMessage, privateKey).toString('base64url') },
  });

  const makePairing = () => {
    const authorityService = createAuthorityService({
      db: models,
      clock,
      crypto: deviceCrypto,
      logger: null,
      audit,
      tenantContext,
      clockSkewGuard: createClockSkewGuard({ db: models, logger: null }),
      verifyRenewalProof: async () => ({ ok: false }),
    });
    return createPairingSessionService({
      db: models,
      clock,
      crypto: deviceCrypto,
      logger: null,
      audit,
      authorityService,
      tenantContext,
      pepperLookup: PEPPER,
      verifyLocalConsent: createEndpointSignatureConsent({ clock, crypto: deviceCrypto }),
    });
  };

  const opened = await makePairing().mintPairingOpenChallenge({
    tenantId: TENANT,
    deviceId: done.deviceId,
    deviceKeyId: done.deviceKeyId,
  });
  const openRow = await models.Challenge.findOne({ challengeHash: opened.challengeHash }).lean();
  const openMessage = deviceCrypto.canonicalEncode({
    domainTag: PAIRING_OPEN_DOMAIN,
    fields: ['pairing-open', TENANT, done.deviceId, done.deviceKeyId, opened.challengeHash, String(new Date(openRow.issuedAt).getTime())],
  });
  const issued = await makePairing().issuePairingSession({
    tenantId: TENANT,
    deviceId: done.deviceId,
    deviceKeyId: done.deviceKeyId,
    challengeHash: opened.challengeHash,
    domainTag: PAIRING_OPEN_DOMAIN,
    requestSource: 'law',
    proof: { signatureB64u: nodeCrypto.sign(null, openMessage, privateKey).toString('base64url') },
  });
  const redeemed = await makePairing().redeemPairingCode({ tenantId: TENANT, ownerId: OWNER, code: issued.code });
  const armed = await makePairing().mintPairingClaimChallenge({
    pairingSessionId: String(redeemed.pairingSession._id),
    tenantId: TENANT,
    ownerId: OWNER,
  });
  const claimRow = await models.Challenge.findOne({ challengeHash: armed.challengeHash }).lean();
  const claimMessage = deviceCrypto.canonicalEncode({
    domainTag: PAIRING_COMPLETE_DOMAIN,
    fields: ['pairing-claim', TENANT, OWNER, done.deviceId, done.deviceKeyId, armed.challengeHash, String(redeemed.pairingSession._id), String(new Date(claimRow.issuedAt).getTime())],
  });
  const signatureB64u = nodeCrypto.sign(null, claimMessage, privateKey).toString('base64url');

  const claimed = await makePairing().approvePairingClaim({
    pairingSessionId: String(redeemed.pairingSession._id),
    tenantId: TENANT,
    ownerId: OWNER,
    domainTag: PAIRING_COMPLETE_DOMAIN,
    localConsent: null,
    proof: { challengeHash: armed.challengeHash, signatureB64u },
  });
  out.claim = {
    ok: claimed.ok === true,
    error: claimed.error?.code ?? null,
    message: claimed.error?.message ?? null,
  };

  await require(path.join(REPO, 'node_modules', 'mongoose')).disconnect().catch(() => {});
  const driver = require(path.join(REPO, 'tests', 'device', 'driver.cjs'));
  const client = new driver.MongoClient('mongodb://127.0.0.1:27027/?directConnection=true&replicaSet=cbhrRdcP1');
  await client.connect();
  out.dropped = await client.db(dbName).dropDatabase();
  await client.close();
  process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
  process.exit(0);
}

main().catch((err) => {
  process.stdout.write(`${JSON.stringify({ fatal: err.message, stack: err.stack?.split('\n').slice(0, 8) }, null, 2)}\n`);
  process.exit(1);
});