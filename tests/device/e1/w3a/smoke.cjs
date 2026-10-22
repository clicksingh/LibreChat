'use strict';

/**
 * W3-A / I11 smoke probe: proves the environment can execute the real product bytes against a
 * self-owned cbhr_rdc_phase1_w3_* database before any fixture is trusted.
 *
 *   node tests/device/e1/w3a/smoke.cjs
 */

const fence = require('./fence.cjs');
const env = require('./env.cjs');

async function main() {
  const out = {
    check: 'W3A-SMOKE',
    pid: process.pid,
    nodeVersion: process.version,
    productFiles: {},
    bridge: {
      worktree: env.bridge.WORKTREE,
      aliases: env.bridge.describeAliases(),
    },
    fenceSelfTest: {},
    db: null,
    steps: [],
  };

  const fs = require('node:fs');
  const crypto = require('node:crypto');
  for (const [name, file] of Object.entries(env.PRODUCT_FILES)) {
    const bytes = fs.readFileSync(file);
    out.productFiles[name] = {
      file,
      bytes: bytes.length,
      sha256: crypto.createHash('sha256').update(bytes).digest('hex').toUpperCase(),
    };
  }

  out.fenceSelfTest = {
    refused: [
      'cbhr_rdc_phase1_preflight_20261010',
      'cbhr_rdc_phase1_governor_nullgrant_probe_20261010',
      'cbhr_rdc_phase1_w2b_x',
      'cbhr_rdc_phase1_w2c_x',
      'devices_prod',
      'admin',
    ].map((name) => {
      let code = null;
      try {
        fence.assertDbName(name);
      } catch (err) {
        code = err.code;
      }
      return { name, code };
    }),
  };

  const dbName = fence.createDbName('smoke');
  out.db = { dbName, patternOk: fence.checkDbName(dbName).length === 0 };

  const before = await fence.listDatabaseNames();
  out.databasesBefore = before;

  const { client } = await fence.connectGuarded({ dbName, appName: 'cbhr-phase1-w3a-smoke' });
  try {
    const modelInfo = env.loadModels();
    out.steps.push({ step: 'loadModels', registryKeys: modelInfo.keys, barrelPath: modelInfo.barrelPath });

    const connection = await env.connectMongoose({ uri: fence.FROZEN_URI, dbName });
    out.steps.push({ step: 'mongooseConnect', connection });

    const registry = modelInfo.registry;
    const four = {
      DeviceAuthority: registry.DeviceAuthority,
      PairingSession: registry.PairingSession,
      Challenge: registry.Challenge,
      AuditEvent: registry.AuditEvent,
    };
    out.steps.push({
      step: 'schemaIndexes',
      declared: {
        DeviceAuthority: four.DeviceAuthority.schema.indexes().map((entry) => entry[0]),
        PairingSession: four.PairingSession.schema.indexes().map((entry) => entry[0]),
        Challenge: four.Challenge.schema.indexes().map((entry) => entry[0]),
        AuditEvent: four.AuditEvent.schema.indexes().map((entry) => entry[0]),
      },
    });

    out.steps.push({ step: 'syncIndexes', applied: await env.syncDeclaredIndexes(four) });
    out.steps.push({
      step: 'listIndexes',
      live: Object.fromEntries(
        Object.entries(
          await env.listLiveIndexes(client, dbName, [
            'deviceauthorities',
            'pairingsessions',
            'challenges',
            'deviceauthorityevents',
          ]),
        ).map(([k, rows]) => [k, rows.map((row) => ({ name: row.name, key: row.key, unique: row.unique ?? false, partial: row.partialFilterExpression ?? null, ttl: row.expireAfterSeconds ?? null }))]),
      ),
    });

    // real services + one real claim through the real I6 CAS
    const recorder = env.makeRecorder();
    const clock = env.makeClock();
    const cryptoSurface = env.makeCrypto();
    const tenantPolicy = env.makeTenantPolicy();
    const key = env.labKey;

    out.steps.push({
      step: 'rawRegistryFactoryProbe',
      attempts: env.probeFactoryShapeAgainstRawRegistry(four, clock, cryptoSurface),
    });

    const facade = env.makeDbFacade(four, recorder.entries);
    const db = facade.db;
    out.steps.push({ step: 'dbFacade', provenance: facade.provenance, kind: facade.kind });

    const audit = env.makeAuditSink(db, recorder.entries);

    const authorityService = env.product.createAuthorityService({
      db,
      clock,
      crypto: cryptoSurface,
      logger: null,
      audit: audit.audit,
      verifyRenewalProof: async () => ({ ok: false }),
    });

    await db.DeviceAuthority.create({
      _id: 'smoke-device',
      tenantId: env.TENANT,
      deviceKeyId: 'smoke-key',
      devicePublicKey: key.spkiB64u,
      identityState: 'pending',
      leaseState: 'never',
      epoch: 0,
      ownerId: null,
      grantId: null,
      registeredAt: new Date(clock.now()),
    });

    const claim = await authorityService.claimAuthority({
      deviceId: 'smoke-device',
      tenantId: env.TENANT,
      ownerId: env.OWNER_A,
      sessionId: 'smoke-session',
      grantProof: null,
    });
    out.steps.push({
      step: 'claimAuthority',
      ok: claim.ok,
      matched: claim.matched,
      error: claim.error ? claim.error.toJSON() : null,
      authority: claim.authority
        ? {
            leaseState: claim.authority.leaseState,
            identityState: claim.authority.identityState,
            ownerId: claim.authority.ownerId,
            epoch: claim.authority.epoch,
            grantIdLength: claim.authority.grantId ? claim.authority.grantId.length : 0,
            expiresAtMinusActivatedAt:
              claim.authority.expiresAt && claim.authority.activatedAt
                ? new Date(claim.authority.expiresAt).getTime() - new Date(claim.authority.activatedAt).getTime()
                : null,
          }
        : null,
      grantIdEqualsSession: claim.authority ? claim.authority.grantId !== 'smoke-session' : null,
    });

    const reread = await authorityService.readAuthority({ deviceId: 'smoke-device', tenantId: env.TENANT });
    out.steps.push({ step: 'readAuthority', leaseState: reread.leaseState, epoch: reread.epoch });

    out.steps.push({ step: 'auditEvents', count: audit.events.length, kinds: audit.events.map((e) => e.kind) });
    out.steps.push({ step: 'recorderSummary', summary: recorder.summary() });

    // registration service real bytes
    const registration = env.product.createRegistrationService({
      db,
      clock,
      crypto: cryptoSurface,
      logger: null,
      audit: audit.audit,
      tenantPolicy,
    });
    const begin = await registration.beginRegistration({ tenantId: env.TENANT, requestSource: 'w3a-smoke' });
    out.steps.push({
      step: 'beginRegistration',
      ok: begin.ok,
      challengeLength: begin.challenge ? begin.challenge.length : 0,
      challengeHashLength: begin.challengeHash ? begin.challengeHash.length : 0,
      error: begin.error ? begin.error.toJSON() : null,
    });
    if (begin.ok) {
      const message = env.product.crypto.canonicalEncode({
        domainTag: env.constants.REGISTRATION_DOMAIN,
        fields: [
          env.TENANT,
          begin.challenge,
          key.spkiB64u,
          env.product.crypto.thumbprintB64u(key.spkiB64u),
          'smoke-device-name',
          'win32',
          '0.0.1',
          'smoke-nonce',
          String(clock.now()),
        ],
      });
      const complete = await registration.completeRegistration({
        tenantId: env.TENANT,
        devicePublicKey: key.spkiB64u,
        deviceName: 'smoke-device-name',
        platform: 'win32',
        agentVersion: '0.0.1',
        domainTag: env.constants.REGISTRATION_DOMAIN,
        requestSource: 'w3a-smoke',
        proof: {
          challenge: begin.challenge,
          nonce: 'smoke-nonce',
          issuedAt: String(clock.now()),
          signatureB64u: env.sign(key, message),
        },
      });
      out.steps.push({
        step: 'completeRegistration',
        ok: complete.ok,
        deviceId: complete.deviceId ? `${complete.deviceId.slice(0, 8)}…` : null,
        deviceKeyIdLength: complete.deviceKeyId ? complete.deviceKeyId.length : 0,
        error: complete.error ? complete.error.toJSON() : null,
      });
    }

    // pairing service real bytes
    const pairing = env.product.createPairingSessionService({
      db,
      clock,
      crypto: cryptoSurface,
      logger: null,
      audit: audit.audit,
      authorityService,
      tenantPolicy,
      verifyLocalConsent: env.makeLocalConsent().verify,
      pepperLookup: env.LAB_PEPPER,
    });
    const issueMessage = env.product.crypto.canonicalEncode({
      domainTag: env.constants.PAIRING_OPEN_DOMAIN,
      fields: [env.TENANT, 'smoke-device', 'smoke-key', 'open-nonce', String(clock.now())],
    });
    const issue = await pairing.issuePairingSession({
      tenantId: env.TENANT,
      deviceId: 'smoke-device',
      deviceKeyId: 'smoke-key',
      domainTag: env.constants.PAIRING_OPEN_DOMAIN,
      proof: { nonce: 'open-nonce', issuedAt: String(clock.now()), signatureB64u: env.sign(key, issueMessage) },
    });
    out.steps.push({
      step: 'issuePairingSession',
      ok: issue.ok,
      codeShape: issue.code ? /^\d{6}$/.test(issue.code) : null,
      lookupTagLength: issue.pairingSession ? issue.pairingSession.lookupTag.length : 0,
      error: issue.error ? issue.error.toJSON() : null,
    });
  } finally {
    await mongoose_disconnect();
    const dropped = await fence.dropOwnDatabase(client, dbName);
    await client.close().catch(() => {});
    out.cleanup = dropped;
  }

  const after = await fence.listDatabaseNames();
  out.databasesAfter = after;
  out.databaseAudit = fence.auditDatabaseSets(before, after);
  out.status = out.databaseAudit.ok ? 'PASS' : 'HARNESS_FAIL';
  process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
  return out.status === 'PASS' ? 0 : 4;
}

async function mongoose_disconnect() {
  await env.mongoose.disconnect().catch(() => {});
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    process.stderr.write(
      `${JSON.stringify({ check: 'W3A-SMOKE', status: 'HARNESS_FAIL', error: { name: err.name, message: err.message, stack: err.stack } }, null, 2)}\n`,
    );
    process.exitCode = 4;
  },
);