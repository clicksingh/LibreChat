'use strict';

/**
 * W3-A / I11 E1 pairing fixtures (real I5 bytes + real Mongoose models + real MongoDB).
 *
 *   E1-V24T04-CODE-TTL-300S    300000ms bare pairing-code expiry (299999 / 300000 / 300001)
 *   E1-V24T03-CODE-COLLISION   forced same-tenant lookupTag collision + bounded regeneration
 */

const support = require('./support.cjs');
const env = require('./env.cjs');

const { TENANT } = env;

function principal(tag) {
  return `principal-w3a-i11-${tag}`;
}

function baseResult(fixture, dbName, extras = {}) {
  return {
    id: fixture.id,
    tier: fixture.tier,
    kind: fixture.kind,
    runner: fixture.runner,
    requires: fixture.requires,
    title: fixture.title,
    runnerPid: process.pid,
    dbName,
    productClaim: true,
    ...extras,
  };
}

/** E1-V24T04-CODE-TTL-300S */
async function codeTtl300s(fixture) {
  const ctx = await support.makeContext({ tag: fixture.id, point: 'V24-T04' });
  const checks = support.makeChecks();
  try {
    const T = ctx.clock.now();
    const pairing = ctx.pairingService();
    const devices = {};
    for (const tag of ['ttl-ok', 'ttl-eq', 'ttl-plus']) {
      devices[tag] = await support.seedDevice(ctx, tag);
    }
    const issued = {};
    for (const tag of Object.keys(devices)) {
      const device = devices[tag];
      const issue = await pairing.issuePairingSession({
        tenantId: TENANT,
        deviceId: device.deviceId,
        deviceKeyId: device.deviceKeyId,
        domainTag: env.constants.PAIRING_OPEN_DOMAIN,
        requestSource: 'w3a-t04',
        proof: support.pairingOpenProof(ctx, device),
      });
      issued[tag] = issue;
    }

    const offsets = { 'ttl-ok': 299999, 'ttl-eq': 300000, 'ttl-plus': 300001 };
    const redeems = {};
    for (const [tag, offset] of Object.entries(offsets)) {
      ctx.clock.set(T + offset);
      const issue = issued[tag];
      redeems[tag] = {
        offset,
        result: await pairing.redeemPairingCode({ code: issue.code, tenantId: TENANT, ownerId: principal(tag) }),
      };
    }
    const rows = {};
    for (const tag of Object.keys(devices)) {
      rows[tag] = await ctx.models.PairingSession.findOne({ _id: issued[tag].pairingSession._id, tenantId: TENANT }).lean();
    }
    // a second redemption of the already-claimed session far later must still be the uniform miss
    ctx.clock.set(T + 400000);
    const lateRedeem = await pairing.redeemPairingCode({ code: issued['ttl-ok'].code, tenantId: TENANT, ownerId: principal('ttl-ok') });
    const lateRow = await ctx.models.PairingSession.findOne({ _id: issued['ttl-ok'].pairingSession._id, tenantId: TENANT }).lean();

    for (const tag of Object.keys(devices)) {
      const issue = issued[tag];
      checks.ok(`issue ${tag} ok`, issue.ok === true, support.errorView(issue.error));
      checks.eq(`issue ${tag} code is 6 digits`, /^\d{6}$/.test(issue.code), true);
      checks.eq(`issue ${tag} lookupTag length`, issue.pairingSession.lookupTag.length, 43);
      checks.eq(
        `issue ${tag} bare 300000ms TTL`,
        new Date(issue.pairingSession.expiresAt).getTime() - new Date(issue.pairingSession.issuedAt).getTime(),
        300000,
      );
    }
    checks.ok('redeem at T+299999 succeeds', redeems['ttl-ok'].result.ok === true, support.errorView(redeems['ttl-ok'].result.error));
    checks.eq('T+299999 state', rows['ttl-ok'].state, 'claim_pending');
    checks.eq('T+299999 attemptsUsed', rows['ttl-ok'].attemptsUsed, 1);
    checks.eq('T+299999 pendingOwnerId', rows['ttl-ok'].pendingOwnerId, principal('ttl-ok'));

    checks.ok('redeem at T+300000 fails closed', redeems['ttl-eq'].result.ok === false, support.errorView(redeems['ttl-eq'].result.error));
    checks.eq('T+300000 uniform error code', redeems['ttl-eq'].result.error && redeems['ttl-eq'].result.error.code, 'INVALID_OR_EXPIRED_CODE');
    checks.eq('T+300000 uniform http status', redeems['ttl-eq'].result.error && redeems['ttl-eq'].result.error.httpStatus, 400);
    checks.eq('T+300000 no write (state stays open)', { state: rows['ttl-eq'].state, attemptsUsed: rows['ttl-eq'].attemptsUsed }, { state: 'open', attemptsUsed: 0 });
    checks.eq('T+300000 no pendingOwnerId write', rows['ttl-eq'].pendingOwnerId, null);

    checks.ok('redeem at T+300001 fails closed', redeems['ttl-plus'].result.ok === false, support.errorView(redeems['ttl-plus'].result.error));
    checks.eq('T+300001 uniform error code', redeems['ttl-plus'].result.error && redeems['ttl-plus'].result.error.code, 'INVALID_OR_EXPIRED_CODE');
    checks.eq('T+300001 no write (state stays open)', { state: rows['ttl-plus'].state, attemptsUsed: rows['ttl-plus'].attemptsUsed }, { state: 'open', attemptsUsed: 0 });
    checks.ok('late re-redeem of a claimed session is the uniform miss', lateRedeem.ok === false && lateRedeem.error.code === 'INVALID_OR_EXPIRED_CODE', support.errorView(lateRedeem.error));
    checks.eq('late re-redeem did not increment attemptsUsed', lateRow.attemptsUsed, rows['ttl-ok'].attemptsUsed);

    const rawCodes = await support.dumpAllFourCollections(ctx.client, ctx.dbName);
    const persistedCode = Object.values(issued).some((issue) =>
      support.findBySerializedValue(rawCodes, `"${issue.code}"`).length > 0,
    );
    checks.eq('no plaintext six-digit code persisted', persistedCode, false);

    return baseResult(fixture, ctx.dbName, {
      ...support.statusFromChecks(checks.checks),
      checks: checks.checks,
      attempts: { issuePairingSessionCalls: 3, redeemPairingCodeCalls: 4 },
      realReturns: Object.fromEntries(
        Object.entries(redeems).map(([tag, entry]) => [tag, { offset: entry.offset, ok: entry.result.ok, error: support.errorView(entry.result.error) }]),
      ),
      dbReadBack: Object.fromEntries(
        Object.entries(rows).map(([tag, row]) => [
          tag,
          { state: row.state, attemptsUsed: row.attemptsUsed, pendingOwnerId: row.pendingOwnerId, issuedAt: row.issuedAt, expiresAt: row.expiresAt },
        ]),
      ),
      provenance: support.provenance(ctx, {
        clockOffsetsProbed: ['T+299999', 'T+300000', 'T+300001', 'T+400000'],
        barePredicateDisclosure: 'The frozen §10a G rule for pairing-session expiry is the BARE expiresAt > now; a 5000ms margin would make T+300000 succeed, so this fixture discriminates.',
      }),
    });
  } finally {
    await ctx.teardown();
  }
}

/** E1-V24T03-CODE-COLLISION */
async function codeCollision(fixture) {
  const ctx = await support.makeContext({ tag: fixture.id, point: 'V24-T03' });
  const checks = support.makeChecks();
  const FIXED_CODE = '424242';
  const loggerCalls = [];
  const recordingLogger = {
    error: (...args) => loggerCalls.push({ level: 'error', args }),
    warn: (...args) => loggerCalls.push({ level: 'warn', args }),
    info: (...args) => loggerCalls.push({ level: 'info', args }),
    debug: (...args) => loggerCalls.push({ level: 'debug', args }),
    child() {
      return recordingLogger;
    },
  };
  try {
    const fixedCrypto = env.makeCrypto({ generatePairingCode: () => FIXED_CODE });
    const pairing = ctx.pairingService({ crypto: fixedCrypto, logger: recordingLogger });
    const first = await support.seedDevice(ctx, 'collision-1');
    const second = await support.seedDevice(ctx, 'collision-2');

    const issue1 = await pairing.issuePairingSession({
      tenantId: TENANT,
      deviceId: first.deviceId,
      deviceKeyId: first.deviceKeyId,
      domainTag: env.constants.PAIRING_OPEN_DOMAIN,
      requestSource: 'w3a-t03',
      proof: support.pairingOpenProof(ctx, first),
    });
    const createCallsBefore = ctx.recorder.entries.filter((entry) => entry.model === 'PairingSession' && entry.method === 'create').length;
    const issue2 = await pairing.issuePairingSession({
      tenantId: TENANT,
      deviceId: second.deviceId,
      deviceKeyId: second.deviceKeyId,
      domainTag: env.constants.PAIRING_OPEN_DOMAIN,
      requestSource: 'w3a-t03',
      proof: support.pairingOpenProof(ctx, second),
    });
    const createEntries = ctx.recorder.entries.filter((entry) => entry.model === 'PairingSession' && entry.method === 'create');
    const secondIssueCreates = createEntries.slice(createCallsBefore);
    const duplicateEntries = secondIssueCreates.filter((entry) => entry.error && entry.error.code === 11000);
    const lookupTag = issue1.pairingSession.lookupTag;
    const nonTerminalForTag = await ctx.models.PairingSession.countDocuments({
      tenantId: TENANT,
      lookupTag,
      state: { $in: ['open', 'claim_pending'] },
    });
    const allSessions = await ctx.models.PairingSession.find({ tenantId: TENANT }).lean();
    const regenerated = allSessions.filter((row) => row.lookupTag === lookupTag).length;
    const recomputedTag = ctx.crypto.computeLookupTag({ code: FIXED_CODE, tenantId: TENANT, pepperLookup: env.LAB_PEPPER });
    const dump = await support.dumpAllFourCollections(ctx.client, ctx.dbName);
    const codeLeaks = support.findBySerializedValue(dump, FIXED_CODE);
    const loggerLeaks = loggerCalls.filter((call) => JSON.stringify(call.args).includes(FIXED_CODE));

    checks.ok('first issuance ok', issue1.ok === true, support.errorView(issue1.error));
    checks.eq('forced code used', issue1.code, FIXED_CODE);
    checks.eq('lookupTag length', lookupTag.length, 43);
    checks.eq('lookupTag equals the real tenant-bound HMAC', lookupTag, recomputedTag);
    checks.ok('second issuance fails closed', issue2.ok === false, support.errorView(issue2.error));
    checks.eq('second issuance error code', issue2.error && issue2.error.code, 'CODE_ISSUANCE_EXHAUSTED');
    checks.eq('second issuance http status', issue2.error && issue2.error.httpStatus, 409);
    checks.eq('bounded insert attempts on the second issuance', secondIssueCreates.length, 4);
    checks.eq('regenerations after exhaustion', secondIssueCreates.length - 1, env.constants.MAX_CODE_REGENERATIONS);
    checks.eq('every second-issuance insert observed E11000', duplicateEntries.length, secondIssueCreates.length);
    checks.ok(
      'observed keyPattern is exactly {tenantId:1,lookupTag:1}',
      duplicateEntries.every(
        (entry) => entry.error.keyPattern && entry.error.keyPattern.tenantId === 1 && entry.error.keyPattern.lookupTag === 1 && Object.keys(entry.error.keyPattern).length === 2,
      ),
      duplicateEntries.map((entry) => entry.error.keyPattern),
    );
    checks.eq('exactly one non-terminal session for the colliding tag', nonTerminalForTag, 1);
    checks.eq('no partial write: one row per persisted tag', regenerated, 1);
    checks.eq('no plaintext code anywhere in the four collections', codeLeaks, []);
    checks.eq('no plaintext code handed to the injected logger', loggerLeaks, []);

    return baseResult(fixture, ctx.dbName, {
      ...support.statusFromChecks(checks.checks),
      checks: checks.checks,
      attempts: {
        issuePairingSessionCalls: 2,
        pairingSessionInsertAttempts: secondIssueCreates.length,
        codeRegenerations: secondIssueCreates.length - 1,
      },
      realReturns: {
        firstIssue: { ok: issue1.ok, codeShape: /^\d{6}$/.test(issue1.code), error: support.errorView(issue1.error) },
        secondIssue: { ok: issue2.ok, error: support.errorView(issue2.error) },
      },
      dbReadBack: {
        sessions: allSessions.map((row) => ({ state: row.state, attemptsUsed: row.attemptsUsed, lookupTagLength: row.lookupTag.length, deviceId: row.deviceId })),
        nonTerminalForTag,
        duplicateKeyPatterns: duplicateEntries.map((entry) => entry.error.keyPattern),
      },
      provenance: support.provenance(ctx, {
        cryptoOverrides: [
          {
            member: 'generatePairingCode',
            replacement: 'test-controlled constant, disclosed',
            reason: 'the only way to force two issuances in one tenant to compute the same lookupTag; every other crypto member is the real frozen implementation and the tag is independently recomputed with the real computeLookupTag',
          },
        ],
        loggerOverrides: ['injected recording logger with no product behaviour (both services are constructed with logger: null in every other fixture)'],
      }),
    });
  } finally {
    await ctx.teardown();
  }
}

const FIXTURES = [
  {
    id: 'E1-V24T04-CODE-TTL-300S',
    tier: 'E1',
    kind: 'product',
    runner: 'inline',
    requires: ['I5'],
    title: '300s pairing-code timeout boundary (299999 / 300000 / 300001) through real I5 bytes',
    run: codeTtl300s,
  },
  {
    id: 'E1-V24T03-CODE-COLLISION',
    tier: 'E1',
    kind: 'product',
    runner: 'inline',
    requires: ['I5'],
    title: 'forced same-tenant lookupTag collision and bounded regeneration',
    run: codeCollision,
  },
];

module.exports = { FIXTURES, codeCollision, codeTtl300s };