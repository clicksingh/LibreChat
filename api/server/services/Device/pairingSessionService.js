'use strict';

/**
 * Device pairing-session service (lane I5, PHASE1-LOCAL-AUTHORITY-001 / W2-D).
 *
 * Implements the frozen PM-INTERFACE-FREEZE §9 issuance / redemption / rejoin / claim / deny
 * surface plus the §10a A–C transcriptions against injected Mongoose models and the accepted
 * I6 authority service. Invariants held here:
 *   - the only clock is the injected `clock.now()` (no `Date.now()`, no wall-clock read, no
 *     sleep);
 *   - the six-digit pairing code is minted by the injected I7 helper, is returned to the
 *     caller, and is NEVER persisted and NEVER logged — only its tenant-bound 43-character
 *     HMAC-SHA-256 lookup tag is stored;
 *   - every write pins `{ w: 'majority', j: true }` and carries its own explicit `tenantId`;
 *   - model methods only (no `.collection.`, no `bulkWrite`, no upsert);
 *   - `tenantId`/`ownerId` are trusted-context arguments; a raw request container handed to a
 *     method is rejected with `REQUEST_SUPPLIED_IDENTITY_REJECTED`;
 *   - pairing-session expiry uses the BARE `expiresAt: { $gt: now }` predicate, never the
 *     5-second skew margin (§10a G);
 *   - claim order is frozen: device PoP against the DB-stored key → local endpoint consent →
 *     challenge spend → session `claim_pending → consumed` → `authorityService.claimAuthority`.
 *     A crash after the session consume leaves `consumed` without a grant, which is
 *     fail-closed and recoverable only by a fresh pairing session;
 *   - audit is emitted through the injected `audit(event)` sink; a sink failure surfaces
 *     `AUDIT_DELIVERY_UNCERTAIN` and never claims a clean success (G-5).
 */

const {
  DeviceError,
  DUPLICATE_DISPOSITIONS,
  classifyDuplicateKey,
  classifyWriteOutcome,
  isDuplicateKeyError,
} = require('./errors');

/** Frozen pairing-code lifetime: exactly 300000 ms (PM-INTERFACE-FREEZE §9). */
const PAIRING_CODE_TTL_MS = 300000;
/** Frozen attempt ceiling for one pairing session. */
const MAX_CODE_ATTEMPTS = 5;
/** Frozen bound on lookup-tag collision regeneration. */
const MAX_CODE_REGENERATIONS = 3;
/** Frozen inter-host skew margin (§10a G); used only to choose the guarded release branch. */
const SKEW_MARGIN_MS = 5000;
/** Authority-critical write concern (freeze §8/§9, G-5/G-6). */
const AUTHORITY_WRITE_CONCERN = Object.freeze({ w: 'majority', j: true });
/** Frozen authority-event kind vocabulary emitted by this lane (G-5). */
const AUDIT_KIND_CLAIM_REFUSED = 'claim-refused';
/** Server-minted pairing challenge lifetimes are exactly 120 seconds. */
const OPEN_CHALLENGE_TTL_MS = 120000;
const CLAIM_CHALLENGE_TTL_MS = 120000;
/** Challenge hash collision regeneration is bounded. */
const MAX_CHALLENGE_REGENERATIONS = 3;
/** Purposes admitted by the injected authority challenge-spend CAS. */
const OPEN_CHALLENGE_PURPOSE = 'pairing-open';
const CLAIM_CHALLENGE_PURPOSE = 'pairing-claim';
/** Non-terminal pairing-session states a new issuance supersedes. */
const NON_TERMINAL_SESSION_STATES = Object.freeze(['open', 'claim_pending']);
/** Bounded total insert attempts: 1 initial code + 3 regenerations, plus supersede retries. */
const MAX_ISSUANCE_ATTEMPTS = 8;

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
    'The supplied pairing code or session cannot be used',
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

function requireTrustedOwner(ownerId) {
  if (!isNonEmptyString(ownerId)) {
    return new DeviceError(
      'NOT_OWNER',
      'ownerId must be supplied by the authenticated server context',
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
function resolveDomainTag(trustedDomainTag) {
  return isNonEmptyString(trustedDomainTag) ? trustedDomainTag : null;
}

function isUsablePepper(value) {
  if (typeof value === 'string') {
    return value.length > 0;
  }
  if (Buffer.isBuffer(value) || ArrayBuffer.isView(value)) {
    return value.byteLength > 0;
  }
  return value !== null && typeof value === 'object' && value.type === 'secret';
}

function assertDependencies({ db, clock, crypto, authorityService }) {
  if (db === null || typeof db !== 'object') {
    throw new TypeError('createPairingSessionService requires a db object exposing models');
  }
  const sessionModel = db.PairingSession;
  if (
    sessionModel === null ||
    (typeof sessionModel !== 'object' && typeof sessionModel !== 'function') ||
    typeof sessionModel.findOne !== 'function' ||
    typeof sessionModel.findOneAndUpdate !== 'function' ||
    typeof sessionModel.updateOne !== 'function' ||
    typeof sessionModel.create !== 'function'
  ) {
    throw new TypeError(
      'createPairingSessionService requires db.PairingSession with findOne/findOneAndUpdate/updateOne/create',
    );
  }
  const challengeModel = db.Challenge;
  if (
    challengeModel === null ||
    (typeof challengeModel !== 'object' && typeof challengeModel !== 'function') ||
    typeof challengeModel.findOne !== 'function' ||
    typeof challengeModel.create !== 'function'
  ) {
    throw new TypeError(
      'createPairingSessionService requires db.Challenge with findOne/create',
    );
  }
  if (clock === null || typeof clock !== 'object' || typeof clock.now !== 'function') {
    throw new TypeError('createPairingSessionService requires clock.now()');
  }
  if (!Number.isFinite(clock.now())) {
    throw new TypeError('clock.now() must return a finite epoch-millisecond number');
  }
  if (crypto === null || typeof crypto !== 'object') {
    throw new TypeError('createPairingSessionService requires the crypto helper surface');
  }
  for (const required of [
    'generatePairingCode',
    'computeLookupTag',
    'newChallengeNonce',
    'challengeHash',
    'canonicalEncode',
    'verifyEd25519',
    'sha256B64u',
  ]) {
    if (typeof crypto[required] !== 'function') {
      throw new TypeError(`createPairingSessionService requires crypto.${required}()`);
    }
  }
  if (authorityService === null || typeof authorityService !== 'object') {
    throw new TypeError('createPairingSessionService requires the I6 authority service');
  }
  for (const required of [
    'readAuthority',
    'releaseLapsedLease',
    'spendChallenge',
    'claimAuthority',
  ]) {
    if (typeof authorityService[required] !== 'function') {
      throw new TypeError(`createPairingSessionService requires authorityService.${required}()`);
    }
  }
}

/**
 * Builds the frozen pairing-session service.
 *
 * @param {object} deps
 * @param {{DeviceAuthority: object, PairingSession: object, Challenge: object, AuditEvent: object}} deps.db
 *   the `createModels(mongoose)` object; model methods only.
 * @param {{now: () => number}} deps.clock canonical epoch-millisecond clock.
 * @param {object} deps.crypto the I7 `crypto.js` surface.
 * @param {object} [deps.logger] injected logger; never receives codes, keys or HMAC inputs.
 * @param {(event: object) => (void|Promise<void>)} [deps.audit] authority-event sink.
 * @param {object} deps.authorityService the accepted I6 authority CAS surface.
 * @param {object} [deps.tenantPolicy] server-controlled tenant policy (freeze §9 seam).
 * @param {(input: object) => (boolean|{ok: boolean}|Promise<*>) } [deps.verifyLocalConsent]
 *   injected local-endpoint consent verifier; absence or a non-`true` verdict fails closed
 *   with `ENDPOINT_CONSENT_REQUIRED`.
 * @param {Buffer|string|object} [deps.pepperLookup] deployment HMAC pepper for the lookup tag.
 *   The frozen §9 signature names no pepper seam; this lane therefore resolves the pepper from
 *   `deps.pepperLookup`, then `crypto.pepperLookup`, then `tenantPolicy.pepperLookup`, and
 *   fails closed when none is configured.
 * @returns {{
 *   issuePairingSession: Function, redeemPairingCode: Function, rejoinPendingPairing: Function,
 *   approvePairingClaim: Function, denyPairingSession: Function,
 * }}
 */
function createPairingSessionService(deps = {}) {
  const {
    db,
    clock,
    crypto,
    logger,
    audit,
    authorityService,
    tenantPolicy,
    verifyLocalConsent,
    tenantContext,
  } = deps;

  assertDependencies({ db, clock, crypto, authorityService });

  function tenantAgreementError(args) {
    const tenantId = args !== null && typeof args === 'object' ? args.tenantId : undefined;
    if (!isNonEmptyString(tenantId) ||
        tenantContext === null || typeof tenantContext !== 'object' ||
        typeof tenantContext.getActiveTenantId !== 'function') {
      return new DeviceError('TENANT_MISMATCH', 'Trusted tenant context is required');
    }
    let active;
    try {
      active = tenantContext.getActiveTenantId();
    } catch {
      return new DeviceError('TENANT_MISMATCH', 'Tenant context lookup failed closed');
    }
    if (!isNonEmptyString(active) || active === '__SYSTEM__' || active !== tenantId) {
      return new DeviceError('TENANT_MISMATCH', 'Authenticated ALS tenant does not match trusted tenant');
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
      /* a logger failure must never change a pairing outcome */
    }
  }

  function issueFailure(error) {
    return { ok: false, code: null, pairingSession: null, error };
  }

  function challengeFailure(error) {
    return {
      ok: false,
      challenge: null,
      challengeHash: null,
      expiresAt: null,
      pairingSession: null,
      error,
    };
  }

  async function mintChallengeRecord({
    purpose,
    tenantId,
    deviceId,
    deviceKeyId,
    boundPairingSessionId = null,
    boundOwnerId = null,
    boundGrantId = null,
    boundEpoch = null,
    boundSessionVersion = null,
    expiresAt,
    now,
  }) {
    for (let attempt = 0; attempt <= MAX_CHALLENGE_REGENERATIONS; attempt += 1) {
      const challenge = crypto.newChallengeNonce();
      let challengeHash;
      try {
        challengeHash = crypto.challengeHash(challenge);
      } catch (err) {
        return challengeFailure(
          new DeviceError('WRITE_OUTCOME_UNCERTAIN', 'Challenge hashing failed', { cause: err }),
        );
      }
      const row = {
        challengeHash,
        purpose,
        deviceId,
        deviceKeyId,
        tenantId,
        boundPairingSessionId,
        boundOwnerId,
        boundGrantId,
        boundEpoch,
        boundSessionVersion,
        issuedAt: new Date(now),
        expiresAt: new Date(expiresAt),
        consumedAt: null,
      };
      try {
        await db.Challenge.create([row], { writeConcern: AUTHORITY_WRITE_CONCERN });
        return {
          ok: true,
          challenge,
          challengeHash,
          expiresAt: new Date(expiresAt),
          pairingSession: null,
          error: null,
        };
      } catch (err) {
        const classified = classifyWriteFailure(err);
        if (
          classified.disposition !== DUPLICATE_DISPOSITIONS.REGENERATE_CHALLENGE ||
          classified.retryable !== true
        ) {
          return challengeFailure(classified);
        }
        if (attempt === MAX_CHALLENGE_REGENERATIONS) {
          return challengeFailure(
            new DeviceError(
              'CODE_ISSUANCE_EXHAUSTED',
              'Challenge generation exhausted its bounded collision budget',
              { cause: err },
            ),
          );
        }
      }
    }
    return challengeFailure(
      new DeviceError('WRITE_OUTCOME_UNCERTAIN', 'Challenge generation exhausted'),
    );
  }

  async function readChallengeRecord({
    challengeHash,
    purpose,
    tenantId,
    deviceId,
    deviceKeyId,
    boundPairingSessionId,
    boundOwnerId,
    boundEpoch,
    boundSessionVersion,
    now,
  }) {
    const filter = {
      challengeHash,
      purpose,
      tenantId,
      deviceId,
      deviceKeyId,
      consumedAt: null,
      expiresAt: { $gt: new Date(now) },
    };
    if (boundPairingSessionId !== undefined) filter.boundPairingSessionId = boundPairingSessionId;
    if (boundOwnerId !== undefined) filter.boundOwnerId = boundOwnerId;
    if (boundEpoch !== undefined) filter.boundEpoch = boundEpoch;
    if (boundSessionVersion !== undefined) filter.boundSessionVersion = boundSessionVersion;
    try {
      const doc = await db.Challenge.findOne(filter).lean();
      return { doc: doc ?? null, error: null };
    } catch (err) {
      return {
        doc: null,
        error: new DeviceError('WRITE_OUTCOME_UNCERTAIN', 'Challenge read failed; fail closed', {
          cause: err,
        }),
      };
    }
  }

  function redeemFailure(error) {
    return { ok: false, pairingSession: null, error };
  }

  function rejoinFailure(error) {
    return { ok: false, pairingSession: null, error };
  }

  function approveFailure(error, pairingSession = null, authority = null) {
    return { ok: false, pairingSession, authority, error };
  }

  function denyFailure(error) {
    return { ok: false, pairingSession: null, error };
  }

  /** Resolves the deployment pepper without ever accepting a request-supplied value. */
  function resolvePepperLookup() {
    if (isUsablePepper(deps.pepperLookup)) {
      return deps.pepperLookup;
    }
    if (crypto.pepperLookup !== undefined && isUsablePepper(crypto.pepperLookup)) {
      return crypto.pepperLookup;
    }
    if (
      tenantPolicy !== null &&
      typeof tenantPolicy === 'object' &&
      isUsablePepper(tenantPolicy.pepperLookup)
    ) {
      return tenantPolicy.pepperLookup;
    }
    return null;
  }

  /** Tenant-bound 43-character base64url lookup tag; the plaintext code never leaves here. */
  function deriveLookupTag({ code, tenantId }) {
    const pepperLookup = resolvePepperLookup();
    if (pepperLookup === null) {
      return {
        lookupTag: null,
        error: new DeviceError(
          'WRITE_OUTCOME_UNCERTAIN',
          'No pairing pepper seam is configured; the operation fails closed',
        ),
      };
    }
    try {
      return {
        lookupTag: crypto.computeLookupTag({ code, tenantId, pepperLookup }),
        error: null,
      };
    } catch (err) {
      return {
        lookupTag: null,
        error: new DeviceError('WRITE_OUTCOME_UNCERTAIN', 'Lookup tag derivation failed', {
          cause: err,
        }),
      };
    }
  }

  async function emitClaimRefused({
    tenantId, deviceId, ownerId, kind, now, reasonCode, authority = null,
  }) {
    const knownEpoch =
      authority !== null && typeof authority === 'object' &&
      Number.isInteger(authority.epoch) && authority.epoch >= 0
        ? authority.epoch
        : null;
    const knownGrantId =
      authority !== null && typeof authority === 'object' && isNonEmptyString(authority.grantId)
        ? authority.grantId
        : null;
    const event = {
      tenantId,
      deviceId: deviceId ?? null,
      ownerId: ownerId ?? null,
      grantId: knownGrantId,
      epoch: knownEpoch,
      seq: knownEpoch,
      kind: AUDIT_KIND_CLAIM_REFUSED,
      ts: new Date(now),
      actor: ownerId ?? null,
      reasonCode: reasonCode ?? null,
    };
    if (typeof audit !== 'function') {
      return new DeviceError(
        'AUDIT_DELIVERY_UNCERTAIN',
        'Claim refusal was not recorded because no audit sink is configured',
      );
    }
    try {
      await audit(event);
      return null;
    } catch (err) {
      safeLog('error', 'claim-refused audit delivery failed', {
        tenantId,
        deviceId: deviceId ?? null,
        kind,
      });
      return new DeviceError(
        'AUDIT_DELIVERY_UNCERTAIN',
        'Claim refusal outcome could not be recorded',
        { cause: err },
      );
    }
  }

  /**
   * Records one failed proof attempt atomically and flips the session to the terminal
   * `exhausted` state on the fifth failure (freeze §9; §10a B keeps the attempt counter on the
   * session row).
   */
  async function registerFailedAttempt({ session, now }) {
    const startedAs = session.state;
    const expectedSessionVersion = observedSessionVersion(session);
    if (expectedSessionVersion === null) {
      return staleSessionError();
    }
    let updated;
    try {
      updated = await db.PairingSession.findOneAndUpdate(
        {
          _id: session._id,
          tenantId: session.tenantId,
          state: { $in: NON_TERMINAL_SESSION_STATES },
          sessionVersion: expectedSessionVersion,
        },
        [
          {
            $set: {
              attemptsUsed: { $add: ['$attemptsUsed', 1] },
              sessionVersion: { $add: ['$sessionVersion', 1] },
              state: {
                $cond: [
                  { $gte: [{ $add: ['$attemptsUsed', 1] }, MAX_CODE_ATTEMPTS] },
                  'exhausted',
                  '$state',
                ],
              },
            },
          },
        ],
        { new: true, writeConcern: AUTHORITY_WRITE_CONCERN },
      );
    } catch (err) {
      return classifyWriteFailure(err);
    }
    if (updated === null || updated === undefined) {
      return staleSessionError();
    }
    if (updated.state === 'exhausted' && startedAs !== 'exhausted') {
      return emitClaimRefused({
        tenantId: updated.tenantId,
        deviceId: updated.deviceId,
        ownerId: updated.pendingOwnerId,
        kind: 'exhausted',
        now,
        reasonCode: 'attempts-exhausted',
      });
    }
    return null;
  }

  /** Tenant-scoped session read (explicit `tenantId`). */
  async function readSession({ pairingSessionId, tenantId }) {
    try {
      const doc = await db.PairingSession.findOne({ _id: pairingSessionId, tenantId }).lean();
      return { doc: doc ?? null, error: null };
    } catch (err) {
      safeLog('warn', 'pairing session read failed closed', { tenantId, code: 'READ_FAILED' });
      return {
        doc: null,
        error: new DeviceError('WRITE_OUTCOME_UNCERTAIN', 'Session read failed; fail closed', {
          cause: err,
        }),
      };
    }
  }

  function observedSessionVersion(session) {
    const version = session !== null && typeof session === 'object' ? session.sessionVersion : null;
    return Number.isInteger(version) && version >= 0 ? version : null;
  }

  async function recoverCommittedClaim({
    tenantId, deviceId, ownerId, pairingSessionId, expectedEpoch, now,
  }) {
    if (!Number.isInteger(expectedEpoch) || expectedEpoch < 0) {
      return null;
    }
    const authority = await authorityService.readAuthority({ deviceId, tenantId });
    if (authority === null || typeof authority !== 'object') {
      return null;
    }
    const expiresAt = toMillis(authority.expiresAt);
    const matches =
      authority.identityState === 'active' &&
      authority.leaseState === 'active' &&
      authority.ownerId === ownerId &&
      authority.grantedByPairingSessionId === pairingSessionId &&
      authority.epoch === expectedEpoch + 1 &&
      isNonEmptyString(authority.grantId) &&
      expiresAt !== null &&
      expiresAt > now;
    return matches ? authority : null;
  }

  function staleSessionError() {
    return new DeviceError(
      'PAIRING_CEREMONY_STALE',
      'Pairing session changed after it was observed; obtain a fresh ceremony',
    );
  }

  async function completeGrantMarker({
    pairingSessionId, tenantId, consumed, grantedGrantId,
  }) {
    const expectedSessionVersion = observedSessionVersion(consumed);
    if (expectedSessionVersion === null || !isNonEmptyString(grantedGrantId)) {
      return {
        session: consumed,
        error: new DeviceError(
          'WRITE_OUTCOME_UNCERTAIN',
          'Committed grant cannot be bound to a trustworthy consumed-session preimage',
        ),
      };
    }

    const readCurrent = async () => {
      const current = await readSession({ pairingSessionId, tenantId });
      return current.error ? { doc: null, error: current.error } : current;
    };

    const exactCommitted = (doc) =>
      doc !== null &&
      typeof doc === 'object' &&
      doc.state === 'consumed' &&
      doc.grantedGrantId === grantedGrantId &&
      Number.isInteger(doc.sessionVersion) &&
      doc.sessionVersion >= expectedSessionVersion + 1;

    const exactRetryable = (doc) =>
      doc !== null &&
      typeof doc === 'object' &&
      doc.state === 'consumed' &&
      (doc.grantedGrantId === null || doc.grantedGrantId === undefined) &&
      doc.sessionVersion === expectedSessionVersion;

    const writeOnce = async () => {
      try {
        const result = await db.PairingSession.updateOne(
          {
            _id: pairingSessionId,
            tenantId,
            state: 'consumed',
            sessionVersion: expectedSessionVersion,
            grantedGrantId: null,
          },
          {
            $set: { grantedGrantId },
            $inc: { sessionVersion: 1 },
          },
          { writeConcern: AUTHORITY_WRITE_CONCERN },
        );
        if (
          result !== null &&
          typeof result === 'object' &&
          result.acknowledged === true &&
          Number.isInteger(result.matchedCount) &&
          result.matchedCount === 1
        ) {
          const after = await readCurrent();
          if (after.error) return { session: consumed, error: after.error };
          return exactCommitted(after.doc)
            ? { session: after.doc, error: null }
            : {
                session: after.doc,
                error: new DeviceError(
                  'WRITE_OUTCOME_UNCERTAIN',
                  'Grant marker write acknowledged but read-back did not match committed truth',
                ),
              };
        }
      } catch {
        /* uncertain marker write is resolved by exact read-back below */
      }
      const reread = await readCurrent();
      if (reread.error) return { session: consumed, error: reread.error };
      if (exactCommitted(reread.doc)) return { session: reread.doc, error: null };
      if (!exactRetryable(reread.doc)) {
        return {
          session: reread.doc,
          error: new DeviceError(
            'WRITE_OUTCOME_UNCERTAIN',
            'Grant marker outcome conflicts with the consumed-session preimage',
          ),
        };
      }
      try {
        const retry = await db.PairingSession.updateOne(
          {
            _id: pairingSessionId,
            tenantId,
            state: 'consumed',
            sessionVersion: expectedSessionVersion,
            grantedGrantId: null,
          },
          {
            $set: { grantedGrantId },
            $inc: { sessionVersion: 1 },
          },
          { writeConcern: AUTHORITY_WRITE_CONCERN },
        );
        if (
          retry === null ||
          typeof retry !== 'object' ||
          retry.acknowledged !== true ||
          !Number.isInteger(retry.matchedCount) ||
          retry.matchedCount !== 1
        ) {
          return {
            session: reread.doc,
            error: new DeviceError(
              'WRITE_OUTCOME_UNCERTAIN',
              'Idempotent grant-marker retry did not commit exactly once',
            ),
          };
        }
      } catch (err) {
        return {
          session: reread.doc,
          error: classifyWriteFailure(err),
        };
      }
      const afterRetry = await readCurrent();
      if (afterRetry.error) return { session: reread.doc, error: afterRetry.error };
      return exactCommitted(afterRetry.doc)
        ? { session: afterRetry.doc, error: null }
        : {
            session: afterRetry.doc,
            error: new DeviceError(
              'WRITE_OUTCOME_UNCERTAIN',
              'Grant-marker retry could not establish committed marker truth',
            ),
          };
    };

    return writeOnce();
  }

  /** Server-challenge pairing-open canonical payload. */
  function buildIssuanceMessage({
    tenantId,
    deviceId,
    deviceKeyId,
    challengeHash,
    issuedAt,
    domainTag,
  }) {
    if (
      !isNonEmptyString(challengeHash) ||
      !isNonEmptyString(issuedAt) ||
      !/^\d+$/.test(issuedAt)
    ) {
      return null;
    }
    try {
      return crypto.canonicalEncode({
        domainTag,
        fields: [
          OPEN_CHALLENGE_PURPOSE,
          tenantId,
          deviceId,
          deviceKeyId,
          challengeHash,
          issuedAt,
        ],
      });
    } catch {
      return null;
    }
  }

  /** Server-challenge pairing-claim canonical payload. */
  function buildClaimChallengeMessage({
    tenantId,
    ownerId,
    deviceId,
    deviceKeyId,
    challengeHash,
    pairingSessionId,
    issuedAt,
    domainTag,
  }) {
    if (
      !isNonEmptyString(challengeHash) ||
      !isNonEmptyString(pairingSessionId) ||
      !isNonEmptyString(issuedAt) ||
      !/^\d+$/.test(issuedAt)
    ) {
      return null;
    }
    try {
      return crypto.canonicalEncode({
        domainTag,
        fields: [
          CLAIM_CHALLENGE_PURPOSE,
          tenantId,
          ownerId,
          deviceId,
          deviceKeyId,
          challengeHash,
          pairingSessionId,
          issuedAt,
        ],
      });
    } catch {
      return null;
    }
  }

  /**
   * Frozen claim canonical field order
   * `tag ‖ tenantId ‖ ownerId ‖ pairingSessionId ‖ deviceId ‖ deviceKeyId ‖ challenge ‖
   * serverIssuedAt ‖ nonce` (W1-BR §1), and the `pairing-deny` order without `deviceKeyId`.
   */
  function buildSessionMessage({ purpose, session, tenantId, ownerId, nonce, issuedAt, domainTag }) {
    if (!isNonEmptyString(nonce) || !isNonEmptyString(issuedAt) || !/^\d+$/.test(issuedAt)) {
      return null;
    }
    let serverIssuedAt;
    try {
      serverIssuedAt = String(toMillis(session.issuedAt));
    } catch {
      return null;
    }
    if (serverIssuedAt === 'null') {
      return null;
    }
    const fields =
      purpose === 'pairing-claim'
        ? [
            tenantId,
            ownerId,
            String(session._id),
            session.deviceId,
            session.deviceKeyId,
            String(session.claimChallenge),
            serverIssuedAt,
            nonce,
          ]
        : [
            tenantId,
            ownerId,
            String(session._id),
            session.deviceId,
            String(session.claimChallenge),
            serverIssuedAt,
            nonce,
          ];
    try {
      return crypto.canonicalEncode({ domainTag, fields });
    } catch {
      return null;
    }
  }

  /**
   * Verifies a device proof against a DB-stored public key. The signed field list is
   * reconstructed server-side from trusted/derived values, so a caller cannot choose which
   * bytes are signed.
   */
  function verifyDeviceProof({
    purpose,
    publicKeySpkiB64u,
    session,
    tenantId,
    ownerId,
    proof,
    trustedDomainTag,
    challenge,
  }) {
    if (!isNonEmptyString(publicKeySpkiB64u) || proof === null || typeof proof !== 'object') {
      return { ok: false, error: uniformMiss() };
    }
    if (!isNonEmptyString(challenge)) {
      return { ok: false, error: uniformMiss() };
    }
    if (proof.ownerId !== undefined && proof.ownerId !== null && proof.ownerId !== ownerId) {
      return { ok: false, error: uniformMiss() };
    }
    const domainTag = resolveDomainTag(trustedDomainTag, proof);
    if (domainTag === null) {
      return { ok: false, error: uniformMiss() };
    }
    const message = buildSessionMessage({
      purpose,
      session: { ...session, claimChallenge: challenge },
      tenantId,
      ownerId,
      nonce: proof.nonce,
      issuedAt: proof.issuedAt,
      domainTag,
    });
    if (message === null) {
      return { ok: false, error: uniformMiss() };
    }
    let verified = false;
    try {
      verified = crypto.verifyEd25519({
        publicKeySpkiB64u,
        message,
        signatureB64u: proof.signatureB64u,
      });
    } catch {
      verified = false;
    }
    if (verified !== true) {
      return { ok: false, error: uniformMiss() };
    }
    let challengeHash;
    try {
      challengeHash = crypto.challengeHash(challenge);
    } catch {
      return { ok: false, error: uniformMiss() };
    }
    return { ok: true, challengeHash, error: null };
  }

  /** Guarded anti-ABA supersede: only an observed open session may be superseded. */
  async function supersedeNonTerminalSessions({ deviceId, tenantId }) {
    let observed;
    try {
      observed = await db.PairingSession.findOne({ deviceId, tenantId, state: 'open' }).lean();
    } catch (err) {
      return classifyWriteFailure(err);
    }
    if (observed === null || observed === undefined) {
      return null;
    }
    const expectedSessionVersion = observedSessionVersion(observed);
    if (expectedSessionVersion === null) {
      return staleSessionError();
    }
    try {
      const result = await db.PairingSession.updateOne(
        {
          _id: observed._id,
          deviceId,
          tenantId,
          state: 'open',
          sessionVersion: expectedSessionVersion,
        },
        {
          $set: { state: 'superseded' },
          $inc: { sessionVersion: 1 },
        },
        { writeConcern: AUTHORITY_WRITE_CONCERN },
      );
      if (
        result === null ||
        typeof result !== 'object' ||
        result.acknowledged !== true ||
        !Number.isInteger(result.matchedCount) ||
        result.matchedCount < 0 ||
        result.matchedCount > 1
      ) {
        return new DeviceError(
          'WRITE_OUTCOME_UNCERTAIN',
          'Supersede write did not ack a trustworthy matched count',
        );
      }
      return result.matchedCount === 1 ? null : staleSessionError();
    } catch (err) {
      return classifyWriteFailure(err);
    }
  }

  function isLiveLease(authority, now) {
    const expiresAt = toMillis(authority.expiresAt);
    return (
      authority.leaseState === 'active' && expiresAt !== null && now < expiresAt
    );
  }

  function isLapsedLease(authority, now) {
    if (authority.leaseState !== 'active') {
      return false;
    }
    const expiresAt = toMillis(authority.expiresAt);
    return expiresAt === null || expiresAt + SKEW_MARGIN_MS <= now;
  }

  /**
   * Mints a single-use server challenge for pairing-open PoP. The endpoint signs only after
   * receiving this server value; this method never creates or supersedes a PairingSession.
   */
  async function mintPairingOpenChallengeImpl(args = {}) {
    const requestError = rejectRequestSuppliedIdentity(args);
    if (requestError) return challengeFailure(requestError);
    const tenantError = requireTrustedTenant(args.tenantId);
    if (tenantError) return challengeFailure(tenantError);
    if (!isNonEmptyString(args.deviceId) || !isNonEmptyString(args.deviceKeyId)) {
      return challengeFailure(
        new DeviceError('UNKNOWN_DEVICE', 'A server-resolved deviceId and deviceKeyId are required'),
      );
    }
    const tenantId = args.tenantId;
    const deviceId = args.deviceId;
    const deviceKeyId = args.deviceKeyId;
    const now = currentTime();
    const authority = await authorityService.readAuthority({ deviceId, tenantId });
    if (
      authority === null ||
      typeof authority !== 'object' ||
      authority.tenantId !== tenantId ||
      authority.deviceKeyId !== deviceKeyId
    ) {
      return challengeFailure(
        new DeviceError('UNKNOWN_DEVICE', 'No matching device identity exists in this tenant'),
      );
    }
    if (authority.identityState === 'retired') {
      return challengeFailure(
        new DeviceError('DEVICE_IDENTITY_REVOKED', 'Device identity is retired'),
      );
    }
    return mintChallengeRecord({
      purpose: OPEN_CHALLENGE_PURPOSE,
      tenantId,
      deviceId,
      deviceKeyId,
      expiresAt: now + OPEN_CHALLENGE_TTL_MS,
      now,
    });
  }

  /**
   * `issuePairingSession` (freeze §9, §10a A). Retired identity and a genuinely live lease
   * refuse; a lapsed lease is released only through the guarded I6 CAS, whose 0-match path is
   * re-read before proceeding. A prior non-terminal session is superseded; lookup-tag
   * collisions regenerate at most three times.
   */
  async function issuePairingSessionImpl(args = {}) {
    const requestError = rejectRequestSuppliedIdentity(args);
    if (requestError) {
      return issueFailure(requestError);
    }
    const tenantError = requireTrustedTenant(args.tenantId);
    if (tenantError) {
      return issueFailure(tenantError);
    }
    if (!isNonEmptyString(args.deviceId) || !isNonEmptyString(args.deviceKeyId)) {
      return issueFailure(
        new DeviceError('UNKNOWN_DEVICE', 'A server-resolved deviceId and deviceKeyId are required'),
      );
    }
    if (
      args.requestSource !== undefined &&
      args.requestSource !== null &&
      typeof args.requestSource !== 'string'
    ) {
      return issueFailure(
        new DeviceError(
          'REQUEST_SUPPLIED_IDENTITY_REJECTED',
          'requestSource must be a server-derived source descriptor string',
        ),
      );
    }

    const tenantId = args.tenantId;
    const deviceId = args.deviceId;
    const deviceKeyId = args.deviceKeyId;
    const now = currentTime();

    const authority = await authorityService.readAuthority({ deviceId, tenantId });
    if (
      authority === null ||
      typeof authority !== 'object' ||
      authority.tenantId !== tenantId
    ) {
      return issueFailure(
        new DeviceError('UNKNOWN_DEVICE', 'No authority row for this device in this tenant'),
      );
    }
    if (authority.identityState === 'retired') {
      return issueFailure(
        new DeviceError('DEVICE_IDENTITY_REVOKED', 'Device identity is retired'),
      );
    }
    if (authority.deviceKeyId !== deviceKeyId) {
      return issueFailure(
        new DeviceError('UNKNOWN_DEVICE', 'The device key does not match the registered identity'),
      );
    }

    const proof = args.proof;
    const domainTag = resolveDomainTag(args.domainTag);
    if (
      !isNonEmptyString(authority.devicePublicKey) ||
      !isNonEmptyString(args.challengeHash) ||
      proof === null ||
      typeof proof !== 'object' ||
      domainTag === null
    ) {
      return issueFailure(uniformMiss());
    }
    const challengeRead = await readChallengeRecord({
      challengeHash: args.challengeHash,
      purpose: OPEN_CHALLENGE_PURPOSE,
      tenantId,
      deviceId,
      deviceKeyId,
      now,
    });
    if (challengeRead.error) {
      return issueFailure(challengeRead.error);
    }
    if (challengeRead.doc === null) {
      return issueFailure(uniformMiss());
    }
    const serverIssuedAtMs = toMillis(challengeRead.doc.issuedAt);
    if (serverIssuedAtMs === null) {
      return issueFailure(uniformMiss());
    }
    const message = buildIssuanceMessage({
      tenantId,
      deviceId,
      deviceKeyId,
      challengeHash: args.challengeHash,
      issuedAt: String(serverIssuedAtMs),
      domainTag,
    });
    if (message === null) {
      return issueFailure(uniformMiss());
    }
    let verified = false;
    try {
      verified = crypto.verifyEd25519({
        publicKeySpkiB64u: authority.devicePublicKey,
        message,
        signatureB64u: proof.signatureB64u,
      });
    } catch {
      verified = false;
    }
    if (verified !== true) {
      return issueFailure(uniformMiss());
    }

    if (isLiveLease(authority, now)) {
      return issueFailure(
        new DeviceError(
          'DEVICE_ALREADY_PAIRED_USE_RENEW',
          'The device already holds a live lease in this tenant',
        ),
      );
    }

    if (isLapsedLease(authority, now)) {
      const release = await authorityService.releaseLapsedLease({ deviceId, tenantId });
      if (release === null || typeof release !== 'object') {
        return issueFailure(
          new DeviceError('WRITE_OUTCOME_UNCERTAIN', 'Lazy lease release returned no envelope'),
        );
      }
      if (release.error) {
        return issueFailure(release.error);
      }
      if (release.matched === 0) {
        const reread = await authorityService.readAuthority({ deviceId, tenantId });
        if (reread === null || typeof reread !== 'object') {
          return issueFailure(
            new DeviceError('UNKNOWN_DEVICE', 'No authority row for this device in this tenant'),
          );
        }
        if (reread.identityState === 'retired') {
          return issueFailure(
            new DeviceError('DEVICE_IDENTITY_REVOKED', 'Device identity is retired'),
          );
        }
        if (isLiveLease(reread, now)) {
          return issueFailure(
            new DeviceError(
              'DEVICE_ALREADY_PAIRED_USE_RENEW',
              'The device already holds a live lease in this tenant',
            ),
          );
        }
      }
    }

    const challengeSpend = await authorityService.spendChallenge({
      challengeHash: args.challengeHash,
      purpose: OPEN_CHALLENGE_PURPOSE,
      tenantId,
      bound: { deviceId, deviceKeyId },
    });
    if (
      challengeSpend === null ||
      typeof challengeSpend !== 'object' ||
      challengeSpend.ok !== true
    ) {
      return issueFailure(
        challengeSpend !== null && typeof challengeSpend === 'object' && challengeSpend.error
          ? challengeSpend.error
          : uniformMiss(),
      );
    }

    const supersedeError = await supersedeNonTerminalSessions({ deviceId, tenantId });
    if (supersedeError) {
      return issueFailure(supersedeError);
    }

    let issuedFromSourceHash = null;
    if (isNonEmptyString(args.requestSource)) {
      try {
        issuedFromSourceHash = crypto.sha256B64u(args.requestSource);
      } catch {
        issuedFromSourceHash = null;
      }
    }

    let supersedeRetries = 0;
    let regenerations = 0;
    for (let attempt = 0; attempt < MAX_ISSUANCE_ATTEMPTS; attempt += 1) {
      const code = crypto.generatePairingCode();
      const tag = deriveLookupTag({ code, tenantId });
      if (tag.error) {
        return issueFailure(tag.error);
      }
      const row = {
        tenantId,
        deviceId,
        deviceKeyId,
        lookupTag: tag.lookupTag,
        state: 'open',
        sessionVersion: 0,
        pendingOwnerId: null,
        attemptsUsed: 0,
        issuedAt: new Date(now),
        expiresAt: new Date(now + PAIRING_CODE_TTL_MS),
        claimedAt: null,
        claim: { challengeRef: null, openedAt: null },
        consumedAt: null,
        grantedGrantId: null,
        issuedFromSourceHash,
        deviceSessionId: isNonEmptyString(args.deviceSessionId) ? args.deviceSessionId : null,
      };
      try {
        const [created] = await db.PairingSession.create([row], { writeConcern: AUTHORITY_WRITE_CONCERN });
        return { ok: true, code, pairingSession: created, error: null };
      } catch (err) {
        const classified = classifyWriteFailure(err);
        if (isDuplicateKeyError(err) === false) {
          return issueFailure(classified);
        }
        if (classified.disposition === DUPLICATE_DISPOSITIONS.REGENERATE_CODE) {
          if (regenerations >= MAX_CODE_REGENERATIONS) {
            return issueFailure(
              new DeviceError(
                'CODE_ISSUANCE_EXHAUSTED',
                'Pairing code generation exhausted its bounded regeneration budget',
                { cause: err },
              ),
            );
          }
          regenerations += 1;
          continue;
        }
        if (classified.disposition === DUPLICATE_DISPOSITIONS.SUPERSEDE_SESSION) {
          if (supersedeRetries >= 1) {
            return issueFailure(
              new DeviceError(
                'WRITE_OUTCOME_UNCERTAIN',
                'Prior non-terminal session survived the single supersede retry; fail closed',
                { cause: err },
              ),
            );
          }
          supersedeRetries += 1;
          const retryError = await supersedeNonTerminalSessions({ deviceId, tenantId });
          if (retryError) {
            return issueFailure(retryError);
          }
          continue;
        }
        return issueFailure(classified);
      }
    }
    return issueFailure(
      new DeviceError('CODE_ISSUANCE_EXHAUSTED', 'Pairing session issuance attempts exhausted'),
    );
  }

  /**
   * `redeemPairingCode` (freeze §9, §10a B). One bare-expiry CAS; any 0-match is the uniform
   * `INVALID_OR_EXPIRED_CODE`.
   */
  async function redeemPairingCodeImpl(args = {}) {
    const requestError = rejectRequestSuppliedIdentity(args);
    if (requestError) {
      return redeemFailure(requestError);
    }
    const tenantError = requireTrustedTenant(args.tenantId);
    if (tenantError) {
      return redeemFailure(tenantError);
    }
    const ownerError = requireTrustedOwner(args.ownerId);
    if (ownerError) {
      return redeemFailure(ownerError);
    }
    if (!isNonEmptyString(args.code)) {
      return redeemFailure(uniformMiss());
    }
    const tenantId = args.tenantId;
    const now = currentTime();
    const tag = deriveLookupTag({ code: args.code, tenantId });
    if (tag.error) {
      return redeemFailure(tag.error);
    }
    let observed;
    try {
      observed = await db.PairingSession.findOne({
        lookupTag: tag.lookupTag,
        tenantId,
        state: 'open',
        expiresAt: { $gt: new Date(now) },
        attemptsUsed: { $lt: MAX_CODE_ATTEMPTS },
      }).lean();
    } catch (err) {
      return redeemFailure(classifyWriteFailure(err));
    }
    if (observed === null || observed === undefined) {
      return redeemFailure(uniformMiss());
    }
    const expectedSessionVersion = observedSessionVersion(observed);
    if (expectedSessionVersion === null) {
      return redeemFailure(staleSessionError());
    }
    let updated;
    try {
      updated = await db.PairingSession.findOneAndUpdate(
        {
          _id: observed._id,
          lookupTag: tag.lookupTag,
          tenantId,
          state: 'open',
          sessionVersion: expectedSessionVersion,
          expiresAt: { $gt: new Date(now) },
          attemptsUsed: { $lt: MAX_CODE_ATTEMPTS },
        },
        {
          $set: {
            state: 'claim_pending',
            pendingOwnerId: args.ownerId,
            claimedAt: new Date(now),
          },
          $inc: { attemptsUsed: 1, sessionVersion: 1 },
        },
        { new: true, writeConcern: AUTHORITY_WRITE_CONCERN },
      );
    } catch (err) {
      return redeemFailure(classifyWriteFailure(err));
    }
    if (updated === null || updated === undefined) {
      return redeemFailure(staleSessionError());
    }
    return { ok: true, pairingSession: updated, error: null };
  }

  /**
   * `rejoinPendingPairing` (freeze §9, §10a B). Same-owner idempotent rejoin: no new challenge,
   * no new prompt, `attemptsUsed` increments only.
   */
  async function rejoinPendingPairingImpl(args = {}) {
    const requestError = rejectRequestSuppliedIdentity(args);
    if (requestError) {
      return rejoinFailure(requestError);
    }
    const tenantError = requireTrustedTenant(args.tenantId);
    if (tenantError) {
      return rejoinFailure(tenantError);
    }
    const ownerError = requireTrustedOwner(args.ownerId);
    if (ownerError) {
      return rejoinFailure(ownerError);
    }
    if (!isNonEmptyString(args.code)) {
      return rejoinFailure(uniformMiss());
    }
    const tenantId = args.tenantId;
    const now = currentTime();
    const tag = deriveLookupTag({ code: args.code, tenantId });
    if (tag.error) {
      return rejoinFailure(tag.error);
    }
    let observed;
    try {
      observed = await db.PairingSession.findOne({
        lookupTag: tag.lookupTag,
        tenantId,
        state: 'claim_pending',
        pendingOwnerId: args.ownerId,
        expiresAt: { $gt: new Date(now) },
      }).lean();
    } catch (err) {
      return rejoinFailure(classifyWriteFailure(err));
    }
    if (observed === null || observed === undefined) {
      return rejoinFailure(uniformMiss());
    }
    const expectedSessionVersion = observedSessionVersion(observed);
    if (expectedSessionVersion === null) {
      return rejoinFailure(staleSessionError());
    }
    let updated;
    try {
      updated = await db.PairingSession.findOneAndUpdate(
        {
          _id: observed._id,
          lookupTag: tag.lookupTag,
          tenantId,
          state: 'claim_pending',
          pendingOwnerId: args.ownerId,
          sessionVersion: expectedSessionVersion,
          expiresAt: { $gt: new Date(now) },
        },
        { $inc: { sessionVersion: 1 } },
        { new: true, writeConcern: AUTHORITY_WRITE_CONCERN },
      );
    } catch (err) {
      return rejoinFailure(classifyWriteFailure(err));
    }
    if (updated === null || updated === undefined) {
      return rejoinFailure(staleSessionError());
    }
    return { ok: true, pairingSession: updated, error: null };
  }

  /**
   * Mints and arms one server challenge for the authenticated pending owner. A session may
   * have only one armed claim challenge; losing it requires a fresh pairing session.
   */
  async function mintPairingClaimChallengeImpl(args = {}) {
    const requestError = rejectRequestSuppliedIdentity(args);
    if (requestError) return challengeFailure(requestError);
    const tenantError = requireTrustedTenant(args.tenantId);
    if (tenantError) return challengeFailure(tenantError);
    const ownerError = requireTrustedOwner(args.ownerId);
    if (ownerError) return challengeFailure(ownerError);
    if (!isNonEmptyString(args.pairingSessionId)) {
      return challengeFailure(uniformMiss());
    }

    const tenantId = args.tenantId;
    const ownerId = args.ownerId;
    const pairingSessionId = args.pairingSessionId;
    const now = currentTime();
    const read = await readSession({ pairingSessionId, tenantId });
    if (read.error) return challengeFailure(read.error);
    const session = read.doc;
    if (
      session === null ||
      session.state !== 'claim_pending' ||
      session.pendingOwnerId !== ownerId
    ) {
      return challengeFailure(
        session !== null && session.pendingOwnerId !== ownerId
          ? new DeviceError('NOT_OWNER', 'The pending claim belongs to another principal')
          : uniformMiss(),
      );
    }
    const sessionExpiresAt = toMillis(session.expiresAt);
    if (sessionExpiresAt === null || sessionExpiresAt <= now) {
      return challengeFailure(uniformMiss());
    }
    const claim =
      session.claim !== null && typeof session.claim === 'object' ? session.claim : {};
    if (
      claim.challengeRef !== null && claim.challengeRef !== undefined ||
      claim.expectedEpoch !== null && claim.expectedEpoch !== undefined ||
      claim.openedAt !== null && claim.openedAt !== undefined
    ) {
      return challengeFailure(staleSessionError());
    }
    const expectedSessionVersion = observedSessionVersion(session);
    if (expectedSessionVersion === null) {
      return challengeFailure(staleSessionError());
    }
    const authority = await authorityService.readAuthority({
      deviceId: session.deviceId,
      tenantId,
    });
    if (authority === null || typeof authority !== 'object') {
      return challengeFailure(
        new DeviceError('UNKNOWN_DEVICE', 'No authority row for this device in this tenant'),
      );
    }
    if (authority.identityState === 'retired') {
      return challengeFailure(
        new DeviceError('DEVICE_IDENTITY_REVOKED', 'Device identity is retired'),
      );
    }
    if (!Number.isInteger(authority.epoch) || authority.epoch < 0) {
      return challengeFailure(
        new DeviceError('WRITE_OUTCOME_UNCERTAIN', 'Authority epoch preimage is invalid'),
      );
    }
    const expectedEpoch = authority.epoch;
    const armedSessionVersion = expectedSessionVersion + 1;
    const challengeExpiresAt = Math.min(
      sessionExpiresAt,
      now + CLAIM_CHALLENGE_TTL_MS,
    );
    if (challengeExpiresAt <= now) {
      return challengeFailure(uniformMiss());
    }
    const minted = await mintChallengeRecord({
      purpose: CLAIM_CHALLENGE_PURPOSE,
      tenantId,
      deviceId: session.deviceId,
      deviceKeyId: session.deviceKeyId,
      boundPairingSessionId: String(session._id),
      boundOwnerId: ownerId,
      boundEpoch: expectedEpoch,
      boundSessionVersion: armedSessionVersion,
      expiresAt: challengeExpiresAt,
      now,
    });
    if (!minted.ok) return minted;

    let armed;
    try {
      armed = await db.PairingSession.findOneAndUpdate(
        {
          _id: pairingSessionId,
          tenantId,
          state: 'claim_pending',
          pendingOwnerId: ownerId,
          sessionVersion: expectedSessionVersion,
          expiresAt: { $gt: new Date(now) },
          'claim.challengeRef': null,
          'claim.expectedEpoch': null,
        },
        {
          $set: {
            'claim.challengeRef': minted.challengeHash,
            'claim.expectedEpoch': expectedEpoch,
            'claim.openedAt': new Date(now),
          },
          $inc: { sessionVersion: 1 },
        },
        { new: true, writeConcern: AUTHORITY_WRITE_CONCERN },
      );
    } catch (err) {
      return challengeFailure(classifyWriteFailure(err));
    }
    if (armed === null || armed === undefined) {
      await authorityService.spendChallenge({
        challengeHash: minted.challengeHash,
        purpose: CLAIM_CHALLENGE_PURPOSE,
        tenantId,
        bound: {
          boundPairingSessionId: String(session._id),
          boundOwnerId: ownerId,
          deviceId: session.deviceId,
          deviceKeyId: session.deviceKeyId,
          boundEpoch: expectedEpoch,
          boundSessionVersion: armedSessionVersion,
        },
      }).catch(() => {});
      return challengeFailure(staleSessionError());
    }
    return { ...minted, pairingSession: armed };
  }

  /**
   * Injected local-endpoint consent seam (freeze §9). Missing verifier or a non-`true` verdict
   * fails closed with `ENDPOINT_CONSENT_REQUIRED`.
   */
  async function requireLocalConsent({ tenantId, ownerId, session, localConsent, proof, now }) {
    const reject = (message, cause) => ({
      error: new DeviceError(
        'ENDPOINT_CONSENT_REQUIRED',
        message,
        cause === undefined ? undefined : { cause },
      ),
      nonceHash: null,
    });
    if (typeof verifyLocalConsent !== 'function') {
      return reject('No local-consent verifier is configured; the claim fails closed');
    }
    const claim = session !== null && typeof session === 'object' &&
      session.claim !== null && typeof session.claim === 'object' ? session.claim : {};
    if (!isNonEmptyString(claim.challengeRef)) {
      return reject('No server-armed pairing-claim challenge is bound to this session');
    }
    let verdict;
    try {
      verdict = await verifyLocalConsent({
        tenantId,
        ownerId,
        pairingSessionId: String(session._id),
        deviceId: session.deviceId,
        deviceKeyId: session.deviceKeyId,
        challengeRef: claim.challengeRef,
        localConsent,
        proof,
      });
    } catch (err) {
      return reject('Local-endpoint consent could not be verified; the claim fails closed', err);
    }
    if (verdict === null || typeof verdict !== 'object' || verdict.approved !== true) {
      return reject('A structured local-endpoint approval verdict is required');
    }
    const approvedAt = toMillis(verdict.approvedAt);
    const openedAt = toMillis(claim.openedAt);
    const expiresAt = toMillis(session.expiresAt);
    const bound =
      isNonEmptyString(verdict.localApprovalNonceHash) &&
      verdict.boundTenantId === tenantId &&
      verdict.boundOwnerId === ownerId &&
      verdict.boundDeviceId === session.deviceId &&
      verdict.boundPairingSessionId === String(session._id) &&
      verdict.boundChallengeRef === claim.challengeRef &&
      approvedAt !== null &&
      openedAt !== null &&
      expiresAt !== null &&
      approvedAt >= openedAt &&
      approvedAt <= now &&
      approvedAt < expiresAt;
    if (!bound) {
      return reject('Local-endpoint approval is stale or not bound to trusted session truth');
    }
    return { error: null, nonceHash: verdict.localApprovalNonceHash };
  }

  /**
   * `approvePairingClaim` (freeze §9, §10a C). Order is law: device PoP against the DB-stored
   * key → local consent → claim-challenge spend → session consume → authority claim.
   */
  async function approvePairingClaimImpl(args = {}) {
    const requestError = rejectRequestSuppliedIdentity(args);
    if (requestError) {
      return approveFailure(requestError);
    }
    const tenantError = requireTrustedTenant(args.tenantId);
    if (tenantError) {
      return approveFailure(tenantError);
    }
    const ownerError = requireTrustedOwner(args.ownerId);
    if (ownerError) {
      return approveFailure(ownerError);
    }
    if (!isNonEmptyString(args.pairingSessionId)) {
      return approveFailure(uniformMiss());
    }
    const tenantId = args.tenantId;
    const ownerId = args.ownerId;
    const pairingSessionId = args.pairingSessionId;
    const now = currentTime();

    const read = await readSession({ pairingSessionId, tenantId });
    if (read.error) {
      return approveFailure(read.error);
    }
    const session = read.doc;
    if (session === null) {
      return approveFailure(uniformMiss());
    }
    if (session.state !== 'claim_pending') {
      return approveFailure(uniformMiss());
    }
    const expiresAt = toMillis(session.expiresAt);
    if (expiresAt === null || expiresAt <= now) {
      return approveFailure(uniformMiss());
    }
    if (session.pendingOwnerId !== ownerId) {
      return approveFailure(
        new DeviceError('NOT_OWNER', 'The pending claim belongs to another principal'),
      );
    }
    const expectedSessionVersion = observedSessionVersion(session);
    if (expectedSessionVersion === null) {
      return approveFailure(staleSessionError());
    }

    const authority = await authorityService.readAuthority({
      deviceId: session.deviceId,
      tenantId,
    });
    if (authority === null || typeof authority !== 'object') {
      return approveFailure(
        new DeviceError('UNKNOWN_DEVICE', 'No authority row for this device in this tenant'),
      );
    }
    if (authority.identityState === 'retired') {
      return approveFailure(
        new DeviceError('DEVICE_IDENTITY_REVOKED', 'Device identity is retired'),
      );
    }

    const proof = args.proof;
    const claimArm =
      session.claim !== null && typeof session.claim === 'object' ? session.claim : {};
    if (
      proof === null ||
      typeof proof !== 'object' ||
      !isNonEmptyString(proof.challengeHash) ||
      !isNonEmptyString(claimArm.challengeRef) ||
      proof.challengeHash !== claimArm.challengeRef ||
      !Number.isInteger(claimArm.expectedEpoch) ||
      claimArm.expectedEpoch < 0
    ) {
      const attemptError = await registerFailedAttempt({ session, now });
      if (attemptError) {
        return approveFailure(attemptError);
      }
      return approveFailure(uniformMiss());
    }
    if (proof.ownerId !== undefined && proof.ownerId !== null && proof.ownerId !== ownerId) {
      const attemptError = await registerFailedAttempt({ session, now });
      if (attemptError) return approveFailure(attemptError);
      return approveFailure(uniformMiss());
    }
    const challengeRead = await readChallengeRecord({
      challengeHash: proof.challengeHash,
      purpose: CLAIM_CHALLENGE_PURPOSE,
      tenantId,
      deviceId: session.deviceId,
      deviceKeyId: session.deviceKeyId,
      boundPairingSessionId: pairingSessionId,
      boundOwnerId: ownerId,
      boundEpoch: claimArm.expectedEpoch,
      boundSessionVersion: expectedSessionVersion,
      now,
    });
    if (challengeRead.error) {
      return approveFailure(challengeRead.error);
    }
    if (challengeRead.doc === null) {
      const attemptError = await registerFailedAttempt({ session, now });
      if (attemptError) return approveFailure(attemptError);
      return approveFailure(uniformMiss());
    }
    const serverIssuedAtMs = toMillis(challengeRead.doc.issuedAt);
    const domainTag = resolveDomainTag(args.domainTag);
    if (serverIssuedAtMs === null || domainTag === null) {
      const attemptError = await registerFailedAttempt({ session, now });
      if (attemptError) return approveFailure(attemptError);
      return approveFailure(uniformMiss());
    }
    const message = buildClaimChallengeMessage({
      tenantId,
      ownerId,
      deviceId: session.deviceId,
      deviceKeyId: session.deviceKeyId,
      challengeHash: proof.challengeHash,
      pairingSessionId,
      issuedAt: String(serverIssuedAtMs),
      domainTag,
    });
    let proofVerified = false;
    if (message !== null && isNonEmptyString(authority.devicePublicKey)) {
      try {
        proofVerified = crypto.verifyEd25519({
          publicKeySpkiB64u: authority.devicePublicKey,
          message,
          signatureB64u: proof.signatureB64u,
        });
      } catch {
        proofVerified = false;
      }
    }
    if (proofVerified !== true) {
      const attemptError = await registerFailedAttempt({ session, now });
      if (attemptError) return approveFailure(attemptError);
      return approveFailure(uniformMiss());
    }
    const proofResult = { ok: true, challengeHash: proof.challengeHash, error: null };

    const consent = await requireLocalConsent({
      tenantId,
      ownerId,
      session,
      localConsent: args.localConsent,
      proof,
      now,
    });
    if (consent.error) {
      const auditError = await emitClaimRefused({
        tenantId,
        deviceId: session.deviceId,
        ownerId,
        kind: 'claim',
        now,
        reasonCode: consent.error.code,
      });
      return approveFailure(auditError ?? consent.error);
    }

    const spend = await authorityService.spendChallenge({
      challengeHash: proofResult.challengeHash,
      purpose: CLAIM_CHALLENGE_PURPOSE,
      tenantId,
      bound: {
        boundPairingSessionId: pairingSessionId,
        boundOwnerId: ownerId,
        deviceId: session.deviceId,
        deviceKeyId: session.deviceKeyId,
        boundEpoch:
          session.claim !== null && typeof session.claim === 'object'
            ? session.claim.expectedEpoch
            : null,
        boundSessionVersion: expectedSessionVersion,
      },
    });
    if (spend === null || typeof spend !== 'object' || spend.ok !== true) {
      const spendError =
        spend !== null && typeof spend === 'object' && spend.error
          ? spend.error
          : uniformMiss();
      const auditError = await emitClaimRefused({
        tenantId,
        deviceId: session.deviceId,
        ownerId,
        kind: 'claim',
        now,
        reasonCode: spendError.code,
      });
      return approveFailure(auditError ?? spendError);
    }

    let consumed;
    try {
      consumed = await db.PairingSession.findOneAndUpdate(
        {
          _id: pairingSessionId,
          tenantId,
          state: 'claim_pending',
          pendingOwnerId: ownerId,
          deviceId: session.deviceId,
          deviceKeyId: session.deviceKeyId,
          sessionVersion: expectedSessionVersion,
          'claim.challengeRef': session.claim?.challengeRef ?? null,
          'claim.expectedEpoch': session.claim?.expectedEpoch ?? null,
          expiresAt: { $gt: new Date(now) },
        },
        {
          $set: { state: 'consumed', consumedAt: new Date(now) },
          $inc: { sessionVersion: 1 },
        },
        { new: true, writeConcern: AUTHORITY_WRITE_CONCERN },
      );
    } catch (err) {
      return approveFailure(classifyWriteFailure(err));
    }
    if (consumed === null || consumed === undefined) {
      const auditError = await emitClaimRefused({
        tenantId,
        deviceId: session.deviceId,
        ownerId,
        kind: 'claim',
        now,
        reasonCode: 'session-consume-miss',
        authority,
      });
      return approveFailure(auditError ?? uniformMiss());
    }

    const grantProof = {
      ownerConfirmedAt: new Date(now),
      endpointSignatureVerifiedAt: new Date(now),
      verifiedKeyId: session.deviceKeyId,
      localApprovalNonceHash: consent.nonceHash,
    };
    const expectedEpoch =
      session.claim !== null && typeof session.claim === 'object'
        ? session.claim.expectedEpoch
        : null;
    const claim = await authorityService.claimAuthority({
      deviceId: session.deviceId,
      tenantId,
      ownerId,
      sessionId: pairingSessionId,
      expectedEpoch,
      grantProof,
    });

    let committed =
      claim !== null && typeof claim === 'object' && claim.authority
        ? claim.authority
        : null;
    let recoveredOutcomeError = null;

    if (claim === null || typeof claim !== 'object' || claim.ok !== true) {
      const claimError =
        claim !== null && typeof claim === 'object' && claim.error
          ? claim.error
          : new DeviceError(
              'WRITE_OUTCOME_UNCERTAIN',
              'Authority claim response was unavailable after the consumed session',
            );
      const mayHaveCommitted =
        (claim !== null && typeof claim === 'object' && claim.matched === 1) ||
        claimError.code === 'WRITE_OUTCOME_UNCERTAIN' ||
        claimError.code === 'AUDIT_DELIVERY_UNCERTAIN';
      if (mayHaveCommitted) {
        const recovered = await recoverCommittedClaim({
          tenantId,
          deviceId: session.deviceId,
          ownerId,
          pairingSessionId,
          expectedEpoch,
          now,
        });
        if (recovered !== null) {
          committed = recovered;
          recoveredOutcomeError =
            claimError.code === 'AUDIT_DELIVERY_UNCERTAIN'
              ? claimError
              : new DeviceError(
                  'AUDIT_DELIVERY_UNCERTAIN',
                  'Authority grant was recovered after an uncertain response; audit delivery is not provable',
                );
        }
      }
      if (committed === null || recoveredOutcomeError === null) {
        const auditError = await emitClaimRefused({
          tenantId,
          deviceId: session.deviceId,
          ownerId,
          kind: 'claim',
          now,
          reasonCode: claimError.code,
          authority:
            claim !== null && typeof claim === 'object' && claim.authority
              ? claim.authority
              : authority,
        });
        return approveFailure(auditError ?? claimError, consumed, null);
      }
    }

    const grantedGrantId =
      committed !== null && typeof committed === 'object' && isNonEmptyString(committed.grantId)
        ? committed.grantId
        : null;
    const marker = await completeGrantMarker({
      pairingSessionId,
      tenantId,
      consumed,
      grantedGrantId,
    });
    if (marker.error) {
      return approveFailure(marker.error, marker.session ?? consumed, committed);
    }
    if (recoveredOutcomeError) {
      return approveFailure(recoveredOutcomeError, marker.session, committed);
    }
    return { ok: true, pairingSession: marker.session, authority: committed, error: null };
  }

  /**
   * `denyPairingSession` (freeze §9). A verified deny proof makes the session terminally
   * `denied`; an unverified proof is the uniform miss with `attemptsUsed++`.
   */
  async function denyPairingSessionImpl(args = {}) {
    const requestError = rejectRequestSuppliedIdentity(args);
    if (requestError) {
      return denyFailure(requestError);
    }
    const tenantError = requireTrustedTenant(args.tenantId);
    if (tenantError) {
      return denyFailure(tenantError);
    }
    const ownerError = requireTrustedOwner(args.ownerId);
    if (ownerError) {
      return denyFailure(ownerError);
    }
    if (!isNonEmptyString(args.pairingSessionId)) {
      return denyFailure(uniformMiss());
    }
    const tenantId = args.tenantId;
    const ownerId = args.ownerId;
    const pairingSessionId = args.pairingSessionId;
    const now = currentTime();

    const read = await readSession({ pairingSessionId, tenantId });
    if (read.error) {
      return denyFailure(read.error);
    }
    const session = read.doc;
    if (session === null) {
      return denyFailure(uniformMiss());
    }
    if (!NON_TERMINAL_SESSION_STATES.includes(session.state)) {
      return denyFailure(uniformMiss());
    }
    const expiresAt = toMillis(session.expiresAt);
    if (expiresAt === null || expiresAt <= now) {
      return denyFailure(uniformMiss());
    }
    if (session.pendingOwnerId !== null && session.pendingOwnerId !== ownerId) {
      return denyFailure(
        new DeviceError('NOT_OWNER', 'The pending claim belongs to another principal'),
      );
    }

    const authority = await authorityService.readAuthority({
      deviceId: session.deviceId,
      tenantId,
    });
    if (authority === null || typeof authority !== 'object') {
      return denyFailure(
        new DeviceError('UNKNOWN_DEVICE', 'No authority row for this device in this tenant'),
      );
    }
    if (authority.identityState === 'retired') {
      return denyFailure(
        new DeviceError('DEVICE_IDENTITY_REVOKED', 'Device identity is retired'),
      );
    }

    const proof = args.proof;
    const challenge = proof !== null && typeof proof === 'object' ? proof.challenge : null;
    const proofResult = verifyDeviceProof({
      purpose: 'pairing-deny',
      publicKeySpkiB64u: authority.devicePublicKey,
      session,
      tenantId,
      ownerId,
      proof: proof ?? {},
      trustedDomainTag: args.domainTag,
      challenge,
    });
    if (!proofResult.ok) {
      const attemptError = await registerFailedAttempt({ session, now });
      if (attemptError) {
        return denyFailure(attemptError);
      }
      return denyFailure(proofResult.error);
    }

    const expectedSessionVersion = observedSessionVersion(session);
    if (expectedSessionVersion === null) {
      return denyFailure(staleSessionError());
    }
    let denied;
    try {
      denied = await db.PairingSession.findOneAndUpdate(
        {
          _id: pairingSessionId,
          tenantId,
          state: { $in: NON_TERMINAL_SESSION_STATES },
          sessionVersion: expectedSessionVersion,
          expiresAt: { $gt: new Date(now) },
        },
        {
          $set: { state: 'denied' },
          $inc: { sessionVersion: 1 },
        },
        { new: true, writeConcern: AUTHORITY_WRITE_CONCERN },
      );
    } catch (err) {
      return denyFailure(classifyWriteFailure(err));
    }
    if (denied === null || denied === undefined) {
      return denyFailure(staleSessionError());
    }

    const auditError = await emitClaimRefused({
      tenantId,
      deviceId: session.deviceId,
      ownerId,
      kind: 'deny',
      now,
      reasonCode: 'denied',
    });
    if (auditError) {
      return denyFailure(auditError);
    }
    return { ok: true, pairingSession: denied, error: null };
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
        safeLog('error', 'pairing operation failed closed', {
          code: 'WRITE_OUTCOME_UNCERTAIN',
        });
        return toFailure(
          new DeviceError('WRITE_OUTCOME_UNCERTAIN', 'Pairing operation failed closed', {
            cause: err,
          }),
        );
      }
    };
  }

  return {
    mintPairingOpenChallenge: guard(mintPairingOpenChallengeImpl, challengeFailure),
    issuePairingSession: guard(issuePairingSessionImpl, issueFailure),
    redeemPairingCode: guard(redeemPairingCodeImpl, redeemFailure),
    rejoinPendingPairing: guard(rejoinPendingPairingImpl, rejoinFailure),
    mintPairingClaimChallenge: guard(mintPairingClaimChallengeImpl, challengeFailure),
    approvePairingClaim: guard(approvePairingClaimImpl, approveFailure),
    denyPairingSession: guard(denyPairingSessionImpl, denyFailure),
  };
}

module.exports = {
  createPairingSessionService,
  PAIRING_CODE_TTL_MS,
  OPEN_CHALLENGE_TTL_MS,
  CLAIM_CHALLENGE_TTL_MS,
  MAX_CODE_ATTEMPTS,
  MAX_CODE_REGENERATIONS,
  SKEW_MARGIN_MS,
  AUTHORITY_WRITE_CONCERN,
};
