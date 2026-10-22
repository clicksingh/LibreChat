'use strict';

/**
 * Device registration service (lane I5, PHASE1-LOCAL-AUTHORITY-001 / W2-D).
 *
 * Implements the frozen PM-INTERFACE-FREEZE §9 registration surface against injected
 * Mongoose models. Invariants held here:
 *   - the only clock is the injected `clock.now()` (no `Date.now()`, no wall-clock read, no
 *     sleep);
 *   - `tenantPolicy.validateRegistrationTenant(tenantId, requestSource)` is evaluated before
 *     ANY row creation; a missing policy or a non-`true` result fails closed with
 *     `REGISTRATION_TENANT_NOT_PERMITTED` (G-3);
 *   - the app-declared tenant is signed inside the registration PoP and must equal the
 *     challenge row's bound tenant BEFORE the challenge is spent; a mid-ceremony switch is
 *     `TENANT_MISMATCH` with zero writes;
 *   - the request-supplied device public key is the ONE legal request-supplied key: it is
 *     used only to verify the registration PoP and is never trusted as identity;
 *   - every write pins `{ w: 'majority', j: true }` and carries its own explicit `tenantId`;
 *   - model methods only: no `.collection.`, no `bulkWrite`;
 *   - audit is emitted through the injected `audit(event)` sink AFTER the committed insert; a
 *     sink failure surfaces `AUDIT_DELIVERY_UNCERTAIN` and the committed row is NOT rolled
 *     back (G-5);
 *   - no pairing code, pepper, private key or challenge nonce is ever logged or persisted
 *     (only the SHA-256 challenge hash is stored).
 */

const { randomUUID } = require('node:crypto');

const {
  DeviceError,
  DUPLICATE_DISPOSITIONS,
  classifyDuplicateKey,
  classifyWriteOutcome,
  isDuplicateKeyError,
} = require('./errors');

/** Frozen registration-challenge lifetime: exactly 120 seconds (PM-INTERFACE-FREEZE §9). */
const REGISTRATION_CHALLENGE_TTL_MS = 120000;
/** Frozen bound on challenge-hash collision regeneration (freeze §7 `{challengeHash:1}` row). */
const MAX_CHALLENGE_REGENERATIONS = 3;
/** Authority-critical write concern (freeze §8/§9, G-5/G-6). */
const AUTHORITY_WRITE_CONCERN = Object.freeze({ w: 'majority', j: true });
/** Frozen authority-event kind emitted by this lane (G-5 canonical vocabulary). */
const AUDIT_KIND_REGISTER = 'register';
/** Registration challenge purposes admitted by the CAS. */
const REGISTRATION_PURPOSE = 'registration';

/**
 * Raw HTTP request containers. A device service must never receive one: identity would then
 * travel from the request body/query instead of the trusted server context (§9).
 */
const REQUEST_CONTAINER_KEYS = Object.freeze([
  'body',
  'query',
  'params',
  'headers',
  'req',
  'request',
  'res',
]);

function isNonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

function toMillis(value) {
  if (value instanceof Date) {
    return value.getTime();
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === 'string') {
    const parsed = Date.parse(value);
    return Number.isNaN(parsed) ? null : parsed;
  }
  return null;
}

function uniformMiss() {
  return new DeviceError(
    'INVALID_OR_EXPIRED_CODE',
    'The registration ceremony cannot be completed with the supplied values',
  );
}

function rejectRequestSuppliedIdentity(args) {
  if (args === null || typeof args !== 'object') {
    return null;
  }
  for (const key of REQUEST_CONTAINER_KEYS) {
    if (
      Object.prototype.hasOwnProperty.call(args, key) &&
      args[key] !== undefined &&
      args[key] !== null
    ) {
      return new DeviceError(
        'REQUEST_SUPPLIED_IDENTITY_REJECTED',
        `A raw request container (${key}) must never be passed to a device service`,
      );
    }
  }
  return null;
}

function requireTrustedTenant(tenantId) {
  if (!isNonEmptyString(tenantId)) {
    return new DeviceError(
      'TENANT_MISMATCH',
      'tenantId must be supplied by the trusted server context',
    );
  }
  return null;
}

function classifyWriteFailure(err) {
  if (isDuplicateKeyError(err)) {
    return classifyDuplicateKey(err);
  }
  if (classifyWriteOutcome(err) === 'uncertain') {
    return new DeviceError(
      'WRITE_OUTCOME_UNCERTAIN',
      'Ambiguous write outcome after send; re-read before any retry',
      { cause: err },
    );
  }
  return new DeviceError('WRITE_OUTCOME_UNCERTAIN', 'Unclassified write failure; fail closed', {
    cause: err,
  });
}

/** Accepts only a string; `undefined`/`null` normalize to the empty canonical field. */
function canonicalField(value) {
  if (value === undefined || value === null) {
    return '';
  }
  return typeof value === 'string' ? value : null;
}

/**
 * Resolves the caller-injected canonical domain tag. The tag is never a literal in Device/**
 * (freeze §6 / W1-D 1.6): the trusted per-call value wins, otherwise the proof envelope's
 * value is used. Absence fails closed.
 */
function resolveDomainTag(trustedDomainTag, proof) {
  if (isNonEmptyString(trustedDomainTag)) {
    return trustedDomainTag;
  }
  if (proof !== null && typeof proof === 'object' && isNonEmptyString(proof.domainTag)) {
    return proof.domainTag;
  }
  return null;
}

function mintDeviceId(crypto) {
  const minted =
    crypto !== null && typeof crypto === 'object' && typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : randomUUID();
  if (!isNonEmptyString(minted)) {
    throw new DeviceError('WRITE_OUTCOME_UNCERTAIN', 'Device id mint returned no value');
  }
  return minted;
}

function assertDependencies({ db, clock, crypto }) {
  if (db === null || typeof db !== 'object') {
    throw new TypeError('createRegistrationService requires a db object exposing models');
  }
  const challengeModel = db.Challenge;
  if (
    challengeModel === null ||
    (typeof challengeModel !== 'object' && typeof challengeModel !== 'function') ||
    typeof challengeModel.findOne !== 'function' ||
    typeof challengeModel.updateOne !== 'function' ||
    typeof challengeModel.create !== 'function'
  ) {
    throw new TypeError(
      'createRegistrationService requires db.Challenge with findOne/updateOne/create',
    );
  }
  const authorityModel = db.DeviceAuthority;
  if (
    authorityModel === null ||
    (typeof authorityModel !== 'object' && typeof authorityModel !== 'function') ||
    typeof authorityModel.create !== 'function' ||
    typeof authorityModel.findOne !== 'function'
  ) {
    throw new TypeError(
      'createRegistrationService requires db.DeviceAuthority with create/findOne',
    );
  }
  if (clock === null || typeof clock !== 'object' || typeof clock.now !== 'function') {
    throw new TypeError('createRegistrationService requires clock.now()');
  }
  if (!Number.isFinite(clock.now())) {
    throw new TypeError('clock.now() must return a finite epoch-millisecond number');
  }
  if (crypto === null || typeof crypto !== 'object') {
    throw new TypeError('createRegistrationService requires the crypto helper surface');
  }
  for (const required of [
    'newChallengeNonce',
    'challengeHash',
    'canonicalEncode',
    'verifyEd25519',
    'thumbprintB64u',
  ]) {
    if (typeof crypto[required] !== 'function') {
      throw new TypeError(`createRegistrationService requires crypto.${required}()`);
    }
  }
}

/**
 * Builds the frozen registration service.
 *
 * @param {object} deps
 * @param {{DeviceAuthority: object, PairingSession: object, Challenge: object, AuditEvent: object}} deps.db
 *   the `createModels(mongoose)` object; model methods only.
 * @param {{now: () => number}} deps.clock canonical epoch-millisecond clock.
 * @param {object} deps.crypto the I7 `crypto.js` surface.
 * @param {object} [deps.logger] injected logger; never receives codes, keys or HMAC inputs.
 * @param {(event: object) => (void|Promise<void>)} [deps.audit] authority-event sink.
 * @param {{validateRegistrationTenant: (tenantId: string, requestSource: *) => (boolean|Promise<boolean>)}} [deps.tenantPolicy]
 *   server-controlled tenant allowlist seam; absence fails closed (G-3).
 * @returns {{
 *   beginRegistration: Function, completeRegistration: Function,
 * }}
 */
function createRegistrationService(deps = {}) {
  const { db, clock, crypto, logger, audit, tenantPolicy, tenantContext } = deps;

  assertDependencies({ db, clock, crypto });

  function tenantAgreementError(args) {
    const tenantId = args !== null && typeof args === 'object' ? args.tenantId : undefined;
    if (!isNonEmptyString(tenantId) ||
        tenantContext === null || typeof tenantContext !== 'object' ||
        typeof tenantContext.getActiveTenantId !== 'function') {
      return new DeviceError('TENANT_MISMATCH', 'Trusted registration tenant context is required');
    }
    let active;
    try {
      active = tenantContext.getActiveTenantId();
    } catch {
      return new DeviceError('TENANT_MISMATCH', 'Tenant context lookup failed closed');
    }
    if (active === undefined || active === null) {
      return tenantContext.alsAbsencePermitted === true ? null :
        new DeviceError('TENANT_MISMATCH', 'Registration ALS absence is not permitted');
    }
    if (!isNonEmptyString(active) || active === '__SYSTEM__' || active !== tenantId) {
      return new DeviceError('TENANT_MISMATCH', 'Registration ALS tenant differs from trusted tenant');
    }
    return null;
  }

  function currentTime() {
    const now = clock.now();
    if (!Number.isFinite(now)) {
      throw new DeviceError('WRITE_OUTCOME_UNCERTAIN', 'Injected clock returned a non-finite time');
    }
    return now;
  }

  function safeLog(level, message, meta) {
    if (logger === null || typeof logger !== 'object' || typeof logger[level] !== 'function') {
      return;
    }
    try {
      logger[level](message, meta);
    } catch {
      /* a logger failure must never change a registration outcome */
    }
  }

  function beginFailure(error) {
    return { ok: false, challenge: null, challengeHash: null, error };
  }

  function completeFailure(error) {
    return { ok: false, deviceId: null, deviceKeyId: null, authority: null, error };
  }

  /**
   * Unauthenticated tenant provenance gate (G-3). A missing policy, a throwing policy or any
   * non-`true` result fails closed before any row is created.
   */
  async function validateRegistrationTenant(tenantId, requestSource) {
    if (!isNonEmptyString(tenantId)) {
      return new DeviceError(
        'REGISTRATION_TENANT_NOT_PERMITTED',
        'An app-declared tenant is required for the registration ceremony',
      );
    }
    if (
      tenantPolicy === null ||
      typeof tenantPolicy !== 'object' ||
      typeof tenantPolicy.validateRegistrationTenant !== 'function'
    ) {
      return new DeviceError(
        'REGISTRATION_TENANT_NOT_PERMITTED',
        'No registration tenant policy is configured; registration fails closed',
      );
    }
    let verdict;
    try {
      verdict = await tenantPolicy.validateRegistrationTenant(tenantId, requestSource);
    } catch (err) {
      return new DeviceError(
        'REGISTRATION_TENANT_NOT_PERMITTED',
        'Registration tenant policy evaluation failed; registration fails closed',
        { cause: err },
      );
    }
    if (verdict !== true) {
      return new DeviceError(
        'REGISTRATION_TENANT_NOT_PERMITTED',
        'The declared registration tenant is not permitted',
      );
    }
    return null;
  }

  /**
   * Emits one append-only authority event after a committed insert. Returns `null` on delivery
   * and an `AUDIT_DELIVERY_UNCERTAIN` DeviceError otherwise (never a silent pass, G-5).
   */
  async function emitRegistrationAudit({ tenantId, deviceId, deviceKeyId, epoch, now }) {
    const event = {
      tenantId,
      deviceId,
      ownerId: null,
      grantId: null,
      epoch,
      seq: epoch,
      kind: AUDIT_KIND_REGISTER,
      ts: new Date(now),
      actor: null,
      reasonCode: null,
    };
    if (typeof audit !== 'function') {
      return new DeviceError(
        'AUDIT_DELIVERY_UNCERTAIN',
        'Registration committed without a configured audit sink',
      );
    }
    try {
      await audit(event);
      return null;
    } catch (err) {
      safeLog('error', 'registration audit delivery failed after committed insert', {
        deviceId,
        tenantId,
        deviceKeyId,
      });
      return new DeviceError(
        'AUDIT_DELIVERY_UNCERTAIN',
        'Registration committed but audit delivery failed',
        { cause: err },
      );
    }
  }

  /**
   * Mints and stores one single-use 256-bit registration challenge. `{challengeHash:1}` is
   * unique, so a collision is regenerated at most `MAX_CHALLENGE_REGENERATIONS` times.
   */
  async function insertRegistrationChallenge({ tenantId, now }) {
    for (let attempt = 0; attempt <= MAX_CHALLENGE_REGENERATIONS; attempt += 1) {
      const challenge = crypto.newChallengeNonce();
      const challengeHash = crypto.challengeHash(challenge);
      const row = {
        challengeHash,
        purpose: REGISTRATION_PURPOSE,
        deviceId: null,
        deviceKeyId: null,
        tenantId,
        boundPairingSessionId: null,
        boundOwnerId: null,
        boundGrantId: null,
        issuedAt: new Date(now),
        expiresAt: new Date(now + REGISTRATION_CHALLENGE_TTL_MS),
        consumedAt: null,
      };
      try {
        await db.Challenge.create([row], { writeConcern: AUTHORITY_WRITE_CONCERN });
        return { ok: true, challenge, challengeHash, error: null };
      } catch (err) {
        const classified = classifyWriteFailure(err);
        const regenerable =
          classified.disposition === DUPLICATE_DISPOSITIONS.REGENERATE_CHALLENGE &&
          classified.retryable === true;
        if (!regenerable || attempt === MAX_CHALLENGE_REGENERATIONS) {
          if (regenerable) {
            return {
              ok: false,
              challenge: null,
              challengeHash: null,
              error: new DeviceError(
                'WRITE_OUTCOME_UNCERTAIN',
                'Challenge hash collided after the bounded regeneration budget; fail closed',
                { cause: err },
              ),
            };
          }
          return { ok: false, challenge: null, challengeHash: null, error: classified };
        }
      }
    }
    return {
      ok: false,
      challenge: null,
      challengeHash: null,
      error: new DeviceError('WRITE_OUTCOME_UNCERTAIN', 'Challenge insertion exhausted'),
    };
  }

  /** Tenant-scoped registration-challenge read (explicit `tenantId`). */
  async function readRegistrationChallenge({ challengeHash, tenantId }) {
    try {
      const doc = await db.Challenge.findOne({
        challengeHash,
        purpose: REGISTRATION_PURPOSE,
        tenantId,
      }).lean();
      return { doc: doc ?? null, error: null };
    } catch (err) {
      safeLog('warn', 'registration challenge read failed closed', {
        tenantId,
        code: 'READ_FAILED',
      });
      return {
        doc: null,
        error: new DeviceError('WRITE_OUTCOME_UNCERTAIN', 'Challenge read failed; fail closed', {
          cause: err,
        }),
      };
    }
  }

  /** Frozen registration canonical field order (W1-BR §1 / freeze §6). */
  function buildRegistrationMessage({
    tenantId,
    challenge,
    devicePublicKey,
    deviceName,
    platform,
    agentVersion,
    nonce,
    issuedAt,
    domainTag,
  }) {
    if (
      !isNonEmptyString(nonce) ||
      !isNonEmptyString(issuedAt) ||
      !/^\d+$/.test(issuedAt) ||
      !isNonEmptyString(devicePublicKey)
    ) {
      return null;
    }
    const name = canonicalField(deviceName);
    const platformField = canonicalField(platform);
    const versionField = canonicalField(agentVersion);
    if (name === null || platformField === null || versionField === null) {
      return null;
    }
    let thumbprint;
    try {
      thumbprint = crypto.thumbprintB64u(devicePublicKey);
    } catch {
      return null;
    }
    try {
      return crypto.canonicalEncode({
        domainTag,
        fields: [
          tenantId,
          challenge,
          devicePublicKey,
          thumbprint,
          name,
          platformField,
          versionField,
          nonce,
          issuedAt,
        ],
      });
    } catch {
      return null;
    }
  }

  /**
   * `beginRegistration` (freeze §9). The policy gate runs before any row creation; the 256-bit
   * challenge is returned to the caller while only its SHA-256 hash is persisted.
   */
  async function beginRegistrationImpl(args = {}) {
    const requestError = rejectRequestSuppliedIdentity(args);
    if (requestError) {
      return beginFailure(requestError);
    }
    const policyError = await validateRegistrationTenant(args.tenantId, args.requestSource);
    if (policyError) {
      return beginFailure(policyError);
    }
    const now = currentTime();
    return insertRegistrationChallenge({ tenantId: args.tenantId, now });
  }

  /**
   * `completeRegistration` (freeze §9). Order: tenant policy → registration PoP over the frozen
   * canonical form → app-declared tenant verified against the bound challenge tenant → single
   * challenge spend CAS → one authority row insert with `identityState:'pending'`.
   */
  async function completeRegistrationImpl(args = {}) {
    const requestError = rejectRequestSuppliedIdentity(args);
    if (requestError) {
      return completeFailure(requestError);
    }
    const tenantError = requireTrustedTenant(args.tenantId);
    if (tenantError) {
      return completeFailure(tenantError);
    }
    const policyError = await validateRegistrationTenant(args.tenantId, args.requestSource);
    if (policyError) {
      return completeFailure(policyError);
    }

    const tenantId = args.tenantId;
    const proof = args.proof;
    if (!isNonEmptyString(args.devicePublicKey) || proof === null || typeof proof !== 'object') {
      return completeFailure(uniformMiss());
    }
    if (!isNonEmptyString(proof.challenge)) {
      return completeFailure(uniformMiss());
    }

    let challengeHash;
    try {
      challengeHash = crypto.challengeHash(proof.challenge);
    } catch {
      return completeFailure(uniformMiss());
    }

    const domainTag = resolveDomainTag(args.domainTag, proof);
    if (domainTag === null) {
      return completeFailure(uniformMiss());
    }

    const message = buildRegistrationMessage({
      tenantId,
      challenge: proof.challenge,
      devicePublicKey: args.devicePublicKey,
      deviceName: args.deviceName,
      platform: args.platform,
      agentVersion: args.agentVersion,
      nonce: proof.nonce,
      issuedAt: proof.issuedAt,
      domainTag,
    });
    if (message === null) {
      return completeFailure(uniformMiss());
    }

    let proofOk = false;
    try {
      proofOk = crypto.verifyEd25519({
        publicKeySpkiB64u: args.devicePublicKey,
        message,
        signatureB64u: proof.signatureB64u,
      });
    } catch {
      proofOk = false;
    }
    if (proofOk !== true) {
      return completeFailure(uniformMiss());
    }

    const challengeRead = await readRegistrationChallenge({ challengeHash, tenantId });
    if (challengeRead.error) {
      return completeFailure(challengeRead.error);
    }
    if (challengeRead.doc === null) {
      // Foreign-tenant challenge rows are deliberately indistinguishable from invalid/expired.
      // The only lookup above is tenant-scoped; never perform a global challengeHash classifier.
      return completeFailure(uniformMiss());
    }

    const now = currentTime();
    let matched;
    try {
      const result = await db.Challenge.updateOne(
        {
          challengeHash,
          purpose: REGISTRATION_PURPOSE,
          consumedAt: null,
          expiresAt: { $gt: new Date(now) },
          tenantId,
        },
        { $set: { consumedAt: new Date(now) } },
        { writeConcern: AUTHORITY_WRITE_CONCERN },
      );
      if (
        result === null ||
        typeof result !== 'object' ||
        result.acknowledged !== true ||
        typeof result.matchedCount !== 'number'
      ) {
        throw new DeviceError(
          'WRITE_OUTCOME_UNCERTAIN',
          'Challenge spend did not ack a trustworthy matched count',
        );
      }
      matched = result.matchedCount;
    } catch (err) {
      if (err instanceof DeviceError) {
        return completeFailure(err);
      }
      return completeFailure(classifyWriteFailure(err));
    }
    if (matched === 0) {
      return completeFailure(uniformMiss());
    }

    let deviceKeyId;
    try {
      deviceKeyId = crypto.thumbprintB64u(args.devicePublicKey);
    } catch {
      return completeFailure(uniformMiss());
    }
    const deviceId = mintDeviceId(crypto);
    const row = {
      _id: deviceId,
      tenantId,
      deviceKeyId,
      devicePublicKey: args.devicePublicKey,
      identityState: 'pending',
      leaseState: 'never',
      epoch: 0,
      ownerId: null,
      grantId: null,
      registeredAt: new Date(now),
    };
    if (isNonEmptyString(args.deviceName)) {
      row.deviceName = args.deviceName;
    }
    if (isNonEmptyString(args.platform)) {
      row.platform = args.platform;
    }
    if (isNonEmptyString(args.agentVersion)) {
      row.agentVersion = args.agentVersion;
    }

    let committedAuthority = row;
    let committedDeviceId = deviceId;
    try {
      await db.DeviceAuthority.create([row], { writeConcern: AUTHORITY_WRITE_CONCERN });
    } catch (err) {
      const classified = classifyWriteFailure(err);
      if (classified.code !== 'WRITE_OUTCOME_UNCERTAIN') {
        return completeFailure(classified);
      }
      let recovered = null;
      try {
        recovered = await db.DeviceAuthority.findOne({ tenantId, deviceKeyId }).lean();
      } catch {
        recovered = null;
      }
      const recoveredMatches =
        recovered !== null &&
        typeof recovered === 'object' &&
        recovered.tenantId === tenantId &&
        recovered.deviceKeyId === deviceKeyId &&
        recovered.devicePublicKey === args.devicePublicKey &&
        recovered.identityState === 'pending' &&
        recovered.leaseState === 'never' &&
        recovered.epoch === 0 &&
        recovered.ownerId === null &&
        recovered.grantId === null &&
        toMillis(recovered.registeredAt) === now;
      if (!recoveredMatches) {
        return completeFailure(classified);
      }
      committedAuthority = recovered;
      committedDeviceId = String(recovered._id);
    }

    const auditError = await emitRegistrationAudit({
      tenantId,
      deviceId: committedDeviceId,
      deviceKeyId,
      epoch: 0,
      now,
    });
    return {
      ok: auditError === null,
      deviceId: committedDeviceId,
      deviceKeyId,
      authority: committedAuthority,
      error: auditError,
    };
  }

  function guard(handler, toFailure) {
    return async (args) => {
      try {
        const tenantError = tenantAgreementError(args);
        if (tenantError) return toFailure(tenantError);
        return await handler(args);
      } catch (err) {
        if (err instanceof DeviceError) {
          return toFailure(err);
        }
        safeLog('error', 'registration operation failed closed', {
          code: 'WRITE_OUTCOME_UNCERTAIN',
        });
        return toFailure(
          new DeviceError('WRITE_OUTCOME_UNCERTAIN', 'Registration operation failed closed', {
            cause: err,
          }),
        );
      }
    };
  }

  return {
    beginRegistration: guard(beginRegistrationImpl, beginFailure),
    completeRegistration: guard(completeRegistrationImpl, completeFailure),
  };
}

module.exports = {
  createRegistrationService,
  REGISTRATION_CHALLENGE_TTL_MS,
  MAX_CHALLENGE_REGENERATIONS,
  AUTHORITY_WRITE_CONCERN,
};
