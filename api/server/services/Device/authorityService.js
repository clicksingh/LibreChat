'use strict';

/**
 * Device authority CAS service (lane I6, PHASE1-LOCAL-AUTHORITY-001 / W2-C).
 *
 * Implements the frozen PM-INTERFACE-FREEZE §8 and §10a authority operations plus Governor
 * gates G-1..G-9 against injected Mongoose models. Invariants held here:
 *   - every authority/challenge CAS pins `{ w: 'majority', j: true }` and carries its own
 *     explicit `tenantId` conjunct (G-9);
 *   - the only clock is the injected `clock.now()` (no `Date.now()`, no wall-clock reads, no
 *     sleeps);
 *   - authority success is exactly `matchedCount === 1`; an unacknowledged, non-integer,
 *     non-finite, negative or above-one matched count fails closed as `WRITE_OUTCOME_UNCERTAIN`
 *     and `0` is a truthful miss;
 *   - no raw driver collection access (no `.collection.`), no `bulkWrite`, no request-derived
 *     identity: `tenantId`/`ownerId` are trusted-context arguments supplied by the caller
 *     (I5) from the authenticated session, never from a request body;
 *   - audit is emitted through the injected `audit(event)` sink AFTER a committed CAS; a sink
 *     failure surfaces `AUDIT_DELIVERY_UNCERTAIN` without rolling back the CAS (G-5).
 */

const {
  DeviceError,
  DUPLICATE_DISPOSITIONS,
  classifyDuplicateKey,
  classifyWriteOutcome,
  isDuplicateKeyError,
} = require('./errors');

/** Frozen authority lease duration: exactly 48 hours. */
const LEASE_TTL_MS = 172800000;
/** Frozen inter-host skew margin: exactly 5 seconds. */
const SKEW_MARGIN_MS = 5000;
/** Authority-critical CAS write concern (G-5/G-6, §4.12). */
const AUTHORITY_WRITE_CONCERN = Object.freeze({ w: 'majority', j: true });
/** Bounded claim recovery attempts: initial + one owner-dislodge + one grant re-mint + one spare. */
const MAX_CLAIM_ATTEMPTS = 4;
/** Frozen authority-event kind vocabulary actually emitted by this lane (G-5). */
const AUDIT_KINDS = Object.freeze({
  GRANT: 'grant',
  RENEW: 'renew',
  REVOKE: 'revoke',
  EXPIRE: 'expire',
  RETIRE: 'retire',
  RELEASE: 'release',
});
/** Frozen retire roles (owner self-retire binds `ownerId`; admin is tenant-wide). */
const RETIRE_ROLES = Object.freeze({ OWNER: 'owner', ADMIN: 'admin' });
/** Fields a caller may pass through `bound` on a challenge spend; CAS conjuncts are immune. */
const CHALLENGE_BINDING_FIELDS = Object.freeze([
  'deviceId',
  'deviceKeyId',
  'boundPairingSessionId',
  'boundOwnerId',
  'boundGrantId',
  'boundEpoch',
  'boundSessionVersion',
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

function requireTenant(tenantId) {
  if (!isNonEmptyString(tenantId)) {
    return new DeviceError(
      'TENANT_MISMATCH',
      'tenantId must be supplied by the authenticated context',
    );
  }
  return null;
}

function mintGrantId(crypto) {
  const grantId = crypto.newGrantId();
  if (!isNonEmptyString(grantId)) {
    throw new DeviceError('WRITE_OUTCOME_UNCERTAIN', 'Grant mint returned no value');
  }
  return grantId;
}

/** Keeps only the four frozen `grantProof` fields so no unapproved value can be persisted. */
function normalizeGrantProof(grantProof) {
  if (grantProof === null || grantProof === undefined || typeof grantProof !== 'object') {
    return null;
  }
  return {
    ownerConfirmedAt: grantProof.ownerConfirmedAt ?? null,
    endpointSignatureVerifiedAt: grantProof.endpointSignatureVerifiedAt ?? null,
    verifiedKeyId: grantProof.verifiedKeyId ?? null,
    localApprovalNonceHash: grantProof.localApprovalNonceHash ?? null,
  };
}

function buildClaimFilter({ deviceId, tenantId, expectedEpoch, now }) {
  return {
    _id: deviceId,
    tenantId,
    identityState: { $ne: 'retired' },
    epoch: expectedEpoch,
    $or: [
      { leaseState: { $in: ['never', 'expired', 'revoked'] } },
      { leaseState: 'active', expiresAt: { $lte: new Date(now - SKEW_MARGIN_MS) } },
    ],
  };
}

function buildClaimPipeline({ ownerId, grantId, sessionId, grantProof, now }) {
  return [
    {
      $set: {
        ownerId,
        leaseState: 'active',
        identityState: 'active',
        grantId,
        activatedAt: new Date(now),
        expiresAt: new Date(now + LEASE_TTL_MS),
        revokedAt: null,
        revokedBy: null,
        renewalCount: 0,
        renewedAt: null,
        grantedByPairingSessionId: sessionId ?? null,
        grantProof: normalizeGrantProof(grantProof),
        prevOwner: '$ownerId',
        prevGrantId: '$grantId',
        prevEpoch: '$epoch',
        epoch: { $add: ['$epoch', 1] },
      },
    },
  ];
}

function buildRevokePipeline({ ownerId, now }) {
  return [
    {
      $set: {
        leaseState: 'revoked',
        revokedAt: new Date(now),
        revokedBy: ownerId,
        prevGrantId: '$grantId',
        prevEpoch: '$epoch',
        epoch: { $add: ['$epoch', 1] },
      },
    },
  ];
}

function buildRetirePipeline({ actor, now }) {
  return [
    {
      $set: {
        identityState: 'retired',
        retiredAt: new Date(now),
        retiredBy: actor,
        leaseState: { $cond: [{ $eq: ['$leaseState', 'active'] }, 'revoked', '$leaseState'] },
        epoch: { $add: ['$epoch', 1] },
        prevGrantId: '$grantId',
        prevEpoch: '$epoch',
      },
    },
  ];
}

function assertDependencies({ db, clock, crypto, verifyRenewalProof }) {
  if (db === null || typeof db !== 'object') {
    throw new TypeError('createAuthorityService requires a db object exposing Mongoose models');
  }
  for (const key of ['DeviceAuthority', 'Challenge']) {
    const model = db[key];
    if (
      model === null ||
      (typeof model !== 'object' && typeof model !== 'function') ||
      typeof model.findOne !== 'function' ||
      typeof model.updateOne !== 'function'
    ) {
      throw new TypeError(
        `createAuthorityService requires db.${key} to be a Mongoose model with findOne/updateOne`,
      );
    }
  }
  if (clock === null || typeof clock !== 'object' || typeof clock.now !== 'function') {
    throw new TypeError('createAuthorityService requires clock.now()');
  }
  if (!Number.isFinite(clock.now())) {
    throw new TypeError('clock.now() must return a finite epoch-millisecond number');
  }
  if (crypto === null || typeof crypto !== 'object' || typeof crypto.newGrantId !== 'function') {
    throw new TypeError('createAuthorityService requires crypto.newGrantId()');
  }
  if (typeof verifyRenewalProof !== 'function') {
    throw new TypeError('createAuthorityService requires an injected verifyRenewalProof');
  }
}

/**
 * Builds the frozen authority CAS surface.
 *
 * @param {object} deps
 * @param {{DeviceAuthority: object, PairingSession: object, Challenge: object, AuditEvent: object}} deps.db
 *   Mongoose models only (the object returned by `createModels(mongoose)`).
 * @param {{now: () => number}} deps.clock canonical epoch-millisecond clock.
 * @param {{newGrantId: () => string}} deps.crypto CSPRNG grant minter (I7 `crypto.js` surface).
 * @param {object} [deps.logger] injected logger; never receives codes, keys or HMAC inputs.
 * @param {(event: object) => (void|Promise<void>)} [deps.audit] authority-event sink.
 * @param {(input: object) => Promise<{ok: boolean, binding?: object}>} deps.verifyRenewalProof
 *   injected renewal-proof verifier; must return `{ ok: false }` for a failed proof.
 * @returns {{
 *   readAuthority: Function, releaseLapsedLease: Function, claimAuthority: Function,
 *   renewAuthority: Function, revokeLease: Function, retireIdentity: Function,
 *   spendChallenge: Function,
 * }}
 */
function createAuthorityService(deps = {}) {
  const { db, clock, crypto, logger, audit, verifyRenewalProof, tenantContext, resolveRetirePrincipal, verifyRetireAuthorization } = deps;

  assertDependencies({ db, clock, crypto, verifyRenewalProof });

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
      /* a logger failure must never change an authority outcome */
    }
  }

  /**
   * Runs one `updateOne` and returns the truthful matched count. A CAS is successful ONLY at
   * `matchedCount === 1`; an unacknowledged, non-integer/non-finite, negative or above-one
   * count is ambiguous and fails closed. `0` is a truthful miss.
   */
  async function performUpdate(model, filter, update) {
    const result = await model.updateOne(filter, update, {
      writeConcern: AUTHORITY_WRITE_CONCERN,
    });
    if (result === null || typeof result !== 'object') {
      throw new DeviceError('WRITE_OUTCOME_UNCERTAIN', 'Write returned no result object');
    }
    if (
      result.acknowledged !== true ||
      !Number.isInteger(result.matchedCount) ||
      result.matchedCount < 0 ||
      result.matchedCount > 1
    ) {
      throw new DeviceError(
        'WRITE_OUTCOME_UNCERTAIN',
        'Write did not ack a trustworthy matched count',
      );
    }
    return result.matchedCount;
  }

  function classifyCasFailure(err) {
    if (isDuplicateKeyError(err)) {
      return { duplicate: true, error: classifyDuplicateKey(err) };
    }
    if (classifyWriteOutcome(err) === 'uncertain') {
      return {
        duplicate: false,
        error: new DeviceError(
          'WRITE_OUTCOME_UNCERTAIN',
          'Ambiguous write outcome after send; re-read before any retry',
          { cause: err },
        ),
      };
    }
    return {
      duplicate: false,
      error: new DeviceError('WRITE_OUTCOME_UNCERTAIN', 'Unclassified write failure; fail closed', {
        cause: err,
      }),
    };
  }

  function failure(error) {
    return { ok: false, matched: 0, authority: null, error };
  }

  async function safeReadAuthority(deviceId, tenantId) {
    try {
      if (!isNonEmptyString(deviceId) || !isNonEmptyString(tenantId)) {
        return null;
      }
      const doc = await db.DeviceAuthority.findOne({ _id: deviceId, tenantId }).lean();
      return doc ?? null;
    } catch (err) {
      safeLog('warn', 'authority read failed closed', { deviceId, tenantId, code: 'READ_FAILED' });
      return null;
    }
  }

  async function safeReadOne(filter) {
    try {
      const doc = await db.DeviceAuthority.findOne(filter).lean();
      return doc ?? null;
    } catch (err) {
      safeLog('warn', 'authority pre-read failed', { code: 'READ_FAILED' });
      return null;
    }
  }

  /**
   * Emits one append-only authority event after a committed CAS. Returns `null` on delivery
   * and an `AUDIT_DELIVERY_UNCERTAIN` DeviceError otherwise (never a silent pass).
   */
  async function emitAuthorityAudit({ tenantId, deviceId, authority, now, kind, actor, reasonCode }) {
    const epoch =
      authority !== null && typeof authority.epoch === 'number' ? authority.epoch : null;
    const event = {
      tenantId,
      deviceId: deviceId ?? null,
      ownerId: authority !== null ? (authority.ownerId ?? null) : null,
      grantId: authority !== null ? (authority.grantId ?? null) : null,
      epoch,
      seq: epoch,
      kind,
      ts: new Date(now),
      actor: actor ?? null,
      reasonCode: reasonCode ?? null,
    };
    if (typeof audit !== 'function') {
      return new DeviceError(
        'AUDIT_DELIVERY_UNCERTAIN',
        'Authority CAS committed without a configured audit sink',
      );
    }
    try {
      await audit(event);
      return null;
    } catch (err) {
      safeLog('error', 'authority audit delivery failed after committed CAS', {
        deviceId: deviceId ?? null,
        tenantId,
        kind,
      });
      return new DeviceError(
        'AUDIT_DELIVERY_UNCERTAIN',
        'Authority CAS committed but audit delivery failed',
        { cause: err },
      );
    }
  }

  async function readAuthorityImpl({ deviceId, tenantId } = {}) {
    if (!isNonEmptyString(deviceId) || !isNonEmptyString(tenantId)) {
      return null;
    }
    return safeReadAuthority(deviceId, tenantId);
  }

  /**
   * Guarded lazy lease release (§10a A, §4.9). The expiry conjunct lives INSIDE the filter, so
   * a 0-match can never flip a racing live lease. A 0-match is a normal no-op (no error).
   */
  async function releaseLapsedLeaseImpl(args = {}) {
    const tenantError = requireTenant(args.tenantId);
    if (tenantError) {
      return failure(tenantError);
    }
    if (!isNonEmptyString(args.deviceId)) {
      return failure(new DeviceError('UNKNOWN_DEVICE', 'A server-resolved deviceId is required'));
    }
    const tenantId = args.tenantId;
    const deviceId = args.deviceId;
    const now = currentTime();
    const filter = {
      _id: deviceId,
      tenantId,
      leaseState: 'active',
      expiresAt: { $lte: new Date(now - SKEW_MARGIN_MS) },
    };
    const update = { $set: { leaseState: 'expired' }, $inc: { epoch: 1 } };
    let matched;
    try {
      matched = await performUpdate(db.DeviceAuthority, filter, update);
    } catch (err) {
      return {
        ok: false,
        matched: 0,
        authority: await safeReadAuthority(deviceId, tenantId),
        error: classifyCasFailure(err).error,
      };
    }
    if (matched === 0) {
      return { ok: false, matched: 0, authority: null, error: null };
    }
    const authority = await safeReadAuthority(deviceId, tenantId);
    const auditError = await emitAuthorityAudit({
      tenantId,
      deviceId,
      authority,
      now,
      kind: AUDIT_KINDS.EXPIRE,
      actor: null,
      reasonCode: null,
    });
    return { ok: auditError === null, matched, authority, error: auditError };
  }

  /**
   * Own-lapsed dislodge (§10a C 3a). The ONLY cross-row authority write: owner-scoped and
   * expiry-proven inside the filter, with the `identityState != retired` hardening (W1-D 1.4a).
   * A 0-match is the normal first-pairing case.
   */
  async function dislodgeOwnLapsedLease({ ownerId, tenantId, now }) {
    const filter = {
      ownerId,
      tenantId,
      leaseState: 'active',
      expiresAt: { $lte: new Date(now - SKEW_MARGIN_MS) },
      identityState: { $ne: 'retired' },
    };
    const candidate = await safeReadOne(filter);
    let matched;
    try {
      matched = await performUpdate(db.DeviceAuthority, filter, {
        $set: { leaseState: 'expired' },
        $inc: { epoch: 1 },
      });
    } catch (err) {
      return { fatal: classifyCasFailure(err).error, auditError: null };
    }
    if (matched === 0) {
      return { fatal: null, auditError: null };
    }
    const deviceId = candidate !== null && isNonEmptyString(candidate._id) ? candidate._id : null;
    const authority = deviceId === null ? null : await safeReadAuthority(deviceId, tenantId);
    const auditError = await emitAuthorityAudit({
      tenantId,
      deviceId,
      authority,
      now,
      kind: AUDIT_KINDS.RELEASE,
      actor: ownerId,
      reasonCode: null,
    });
    return { fatal: null, auditError };
  }

  /**
   * Exhaustive 0-match classifier for the generation-fenced claim CAS (§10a C, §4.4, F2).
   * Retired is checked first, then the ceremony generation; a same-generation lapsed/revoked
   * re-read never authorizes a retry of the target row. An active same-generation lease is
   * triaged by expiry: live, inside the skew margin, or an older ambiguous expiry that fails
   * closed as `WRITE_OUTCOME_UNCERTAIN`.
   */
  async function classifyClaimMiss({ deviceId, tenantId, expectedEpoch, now }) {
    const authority = await safeReadAuthority(deviceId, tenantId);
    if (authority === null) {
      return {
        authority: null,
        error: new DeviceError(
          'UNKNOWN_DEVICE',
          'No authority row for this device in this tenant',
        ),
      };
    }
    if (authority.identityState === 'retired') {
      return {
        authority,
        error: new DeviceError('DEVICE_IDENTITY_REVOKED', 'Device identity is retired'),
      };
    }
    if (authority.epoch !== expectedEpoch) {
      return {
        authority,
        error: new DeviceError(
          'PAIRING_CEREMONY_STALE',
          'Ceremony generation is stale; a fresh authorized pairing ceremony is required',
        ),
      };
    }
    if (authority.leaseState === 'active') {
      const expiresAt = toMillis(authority.expiresAt);
      if (expiresAt !== null && now < expiresAt) {
        return {
          authority,
          error: new DeviceError(
            'DEVICE_ALREADY_PAIRED_USE_RENEW',
            'Device already holds a live lease',
          ),
        };
      }
      if (expiresAt !== null && expiresAt > now - SKEW_MARGIN_MS) {
        return {
          authority,
          error: new DeviceError(
            'PAIRING_WINDOW_TOO_EARLY',
            'Lease lapsed inside the skew margin; a fresh pairing session is required',
          ),
        };
      }
    }
    return {
      authority,
      error: new DeviceError(
        'WRITE_OUTCOME_UNCERTAIN',
        'Claim CAS missed while the row re-read as claimable at the ceremony generation',
      ),
    };
  }

  /**
   * Claim CAS (§10a C / §4.4 LP-4, F2 generation fence), aggregation-pipeline primary form so
   * `prev*` lineage is read atomically with the CAS. The CAS is pinned to the server-derived
   * `expectedEpoch` and a miss is classified, never retried against the target row. Bounded
   * recovery remains only the duplicate-key own-lapsed dislodge and one grant-mint
   * regeneration, both strictly before any target commit.
   */
  async function claimAuthorityImpl(args = {}) {
    const tenantError = requireTenant(args.tenantId);
    if (tenantError) {
      return failure(tenantError);
    }
    const { deviceId, ownerId, sessionId, expectedEpoch, grantProof } = args;
    const tenantId = args.tenantId;
    if (!isNonEmptyString(deviceId)) {
      return failure(new DeviceError('UNKNOWN_DEVICE', 'A server-resolved deviceId is required'));
    }
    if (!isNonEmptyString(ownerId)) {
      return failure(
        new DeviceError('NOT_OWNER', 'ownerId must come from the authenticated session'),
      );
    }
    if (!Number.isInteger(expectedEpoch) || expectedEpoch < 0) {
      return failure(
        new DeviceError(
          'PAIRING_CEREMONY_REQUIRED',
          'A server-derived non-negative integer expectedEpoch is required',
        ),
      );
    }
    const now = currentTime();
    let grantId = mintGrantId(crypto);
    let dislodgeUsed = false;
    let grantRegenerationUsed = false;
    let auditError = null;

    for (let attempt = 0; attempt < MAX_CLAIM_ATTEMPTS; attempt += 1) {
      let matched;
      try {
        matched = await performUpdate(
          db.DeviceAuthority,
          buildClaimFilter({ deviceId, tenantId, expectedEpoch, now }),
          buildClaimPipeline({ ownerId, grantId, sessionId, grantProof, now }),
        );
      } catch (err) {
        const classified = classifyCasFailure(err);
        if (classified.duplicate) {
          const duplicate = classified.error;
          if (
            duplicate.disposition === DUPLICATE_DISPOSITIONS.OWN_DISLODGE_RETRY &&
            !dislodgeUsed
          ) {
            dislodgeUsed = true;
            const dislodged = await dislodgeOwnLapsedLease({ ownerId, tenantId, now });
            if (dislodged.fatal) {
              return {
                ok: false,
                matched: 0,
                authority: await safeReadAuthority(deviceId, tenantId),
                error: dislodged.fatal,
              };
            }
            if (dislodged.auditError) {
              auditError = auditError ?? dislodged.auditError;
            }
            continue;
          }
          if (
            duplicate.disposition === DUPLICATE_DISPOSITIONS.REGENERATE_GRANT &&
            !grantRegenerationUsed
          ) {
            grantRegenerationUsed = true;
            grantId = mintGrantId(crypto);
            continue;
          }
          return {
            ok: false,
            matched: 0,
            authority: await safeReadAuthority(deviceId, tenantId),
            error: duplicate,
          };
        }
        return {
          ok: false,
          matched: 0,
          authority: await safeReadAuthority(deviceId, tenantId),
          error: classified.error,
        };
      }

      if (matched === 1) {
        const authority = await safeReadAuthority(deviceId, tenantId);
        const claimAuditError = await emitAuthorityAudit({
          tenantId,
          deviceId,
          authority,
          now,
          kind: AUDIT_KINDS.GRANT,
          actor: ownerId,
          reasonCode: null,
        });
        const finalAuditError = auditError ?? claimAuditError;
        return { ok: finalAuditError === null, matched, authority, error: finalAuditError };
      }

      const miss = await classifyClaimMiss({ deviceId, tenantId, expectedEpoch, now });
      return { ok: false, matched: 0, authority: miss.authority, error: miss.error };
    }

    return {
      ok: false,
      matched: 0,
      authority: await safeReadAuthority(deviceId, tenantId),
      error: new DeviceError('WRITE_OUTCOME_UNCERTAIN', 'Claim recovery attempts exhausted'),
    };
  }

  async function verifyProof(proofInput) {
    try {
      const result = await verifyRenewalProof(proofInput);
      if (result === null || typeof result !== 'object' || result.ok !== true) {
        return { ok: false, error: null };
      }
      return { ok: true, binding: result.binding ?? null, error: null };
    } catch (err) {
      if (err instanceof DeviceError) {
        return { ok: false, error: err };
      }
      return {
        ok: false,
        error: new DeviceError('NOT_OWNER_OR_STALE', 'Renewal proof verification failed closed', {
          cause: err,
        }),
      };
    }
  }

  function checkRenewalBinding(binding, { tenantId, ownerId, deviceId, grantId, epoch }) {
    if (binding === null || binding === undefined || typeof binding !== 'object') {
      return null;
    }
    const pairs = [
      ['tenantId', tenantId],
      ['ownerPrincipalId', ownerId],
      ['deviceId', deviceId],
      ['grantId', grantId],
      ['epoch', epoch],
    ];
    for (const [field, expected] of pairs) {
      const observed = binding[field];
      if (observed === undefined || observed === null) {
        return new DeviceError(
          'NOT_OWNER_OR_STALE',
          `Renewal proof binding omits ${field}; failing closed`,
        );
      }
      if (observed !== expected) {
        return field === 'tenantId'
          ? new DeviceError('TENANT_MISMATCH', 'Renewal proof binding names another tenant')
          : new DeviceError('NOT_OWNER_OR_STALE', `Renewal proof binding disagrees on ${field}`);
      }
    }
    return null;
  }

  async function classifyRenewMiss({ deviceId, tenantId, ownerId, epoch, grantId, now }) {
    const authority = await safeReadAuthority(deviceId, tenantId);
    if (authority === null) {
      return {
        authority: null,
        error: new DeviceError('UNKNOWN_DEVICE', 'No authority row in this tenant'),
      };
    }
    if (authority.identityState === 'retired') {
      return {
        authority,
        error: new DeviceError('DEVICE_IDENTITY_REVOKED', 'Device identity is retired'),
      };
    }
    if (
      authority.ownerId !== ownerId ||
      authority.grantId !== grantId ||
      authority.epoch !== epoch
    ) {
      return {
        authority,
        error: new DeviceError('NOT_OWNER_OR_STALE', 'Lease is not held by this owner/grant/epoch'),
      };
    }
    if (authority.leaseState !== 'active') {
      return { authority, error: new DeviceError('LEASE_EXPIRED', 'Lease is not active') };
    }
    const expiresAt = toMillis(authority.expiresAt);
    if (expiresAt === null || expiresAt <= now + SKEW_MARGIN_MS) {
      return {
        authority,
        error: new DeviceError('LEASE_EXPIRED', 'Lease is inside the renewal skew margin'),
      };
    }
    return {
      authority,
      error: new DeviceError('NOT_OWNER_OR_STALE', 'Renewal CAS missed for an unclassified reason'),
    };
  }

  /**
   * Renewal CAS (§10a F / §4.8). The injected renewal proof is verified FIRST and the
   * operation fails closed when it is not ok. `grantId` and `expiresAt` commit atomically.
   */
  async function renewAuthorityImpl(args = {}) {
    const tenantError = requireTenant(args.tenantId);
    if (tenantError) {
      return failure(tenantError);
    }
    const { deviceId, ownerId, epoch, grantId } = args;
    const tenantId = args.tenantId;
    if (!isNonEmptyString(deviceId)) {
      return failure(new DeviceError('UNKNOWN_DEVICE', 'A server-resolved deviceId is required'));
    }
    if (!isNonEmptyString(ownerId)) {
      return failure(
        new DeviceError('NOT_OWNER', 'ownerId must come from the authenticated session'),
      );
    }
    if (!Number.isInteger(epoch) || epoch < 0) {
      return failure(
        new DeviceError('NOT_OWNER_OR_STALE', 'A non-negative integer epoch is required'),
      );
    }
    if (!isNonEmptyString(grantId)) {
      return failure(new DeviceError('NOT_OWNER_OR_STALE', 'The current grantId is required'));
    }
    const proofInput = args.proofInput !== undefined ? args.proofInput : args.verifyRenewalProof;
    const proof = await verifyProof(proofInput);
    if (!proof.ok) {
      return failure(proof.error ?? new DeviceError('NOT_OWNER_OR_STALE', 'Renewal proof rejected'));
    }
    const bindingError = checkRenewalBinding(proof.binding, {
      tenantId,
      ownerId,
      deviceId,
      grantId,
      epoch,
    });
    if (bindingError) {
      return failure(bindingError);
    }
    const now = currentTime();
    const filter = {
      _id: deviceId,
      tenantId,
      ownerId,
      leaseState: 'active',
      identityState: { $ne: 'retired' },
      epoch,
      grantId,
      expiresAt: { $gt: new Date(now + SKEW_MARGIN_MS) },
    };
    const update = {
      $set: {
        expiresAt: new Date(now + LEASE_TTL_MS),
        grantId: mintGrantId(crypto),
        renewedAt: new Date(now),
      },
      $inc: { epoch: 1, renewalCount: 1 },
    };
    let matched;
    try {
      matched = await performUpdate(db.DeviceAuthority, filter, update);
    } catch (err) {
      return {
        ok: false,
        matched: 0,
        authority: await safeReadAuthority(deviceId, tenantId),
        error: classifyCasFailure(err).error,
      };
    }
    if (matched === 0) {
      const classified = await classifyRenewMiss({
        deviceId,
        tenantId,
        ownerId,
        epoch,
        grantId,
        now,
      });
      return { ok: false, matched: 0, authority: classified.authority, error: classified.error };
    }
    const authority = await safeReadAuthority(deviceId, tenantId);
    const auditError = await emitAuthorityAudit({
      tenantId,
      deviceId,
      authority,
      now,
      kind: AUDIT_KINDS.RENEW,
      actor: ownerId,
      reasonCode: null,
    });
    return { ok: auditError === null, matched, authority, error: auditError };
  }

  /**
   * Revoke CAS (§10a D / §4.6). Advances the epoch and does NOT rotate `grantId` (G-2);
   * `prevGrantId`/`prevEpoch` are read atomically by the pipeline. 0-match is
   * `NOT_OWNER_OR_STALE` (a stale P1 owner is unmatchable by the owner+epoch conjuncts).
   */
  async function revokeLeaseImpl(args = {}) {
    const tenantError = requireTenant(args.tenantId);
    if (tenantError) {
      return failure(tenantError);
    }
    const { deviceId, ownerId, epoch } = args;
    const tenantId = args.tenantId;
    if (!isNonEmptyString(deviceId)) {
      return failure(new DeviceError('UNKNOWN_DEVICE', 'A server-resolved deviceId is required'));
    }
    if (!isNonEmptyString(ownerId)) {
      return failure(
        new DeviceError('NOT_OWNER', 'ownerId must come from the authenticated session'),
      );
    }
    if (!Number.isInteger(epoch) || epoch < 0) {
      return failure(
        new DeviceError('NOT_OWNER_OR_STALE', 'A non-negative integer epoch is required'),
      );
    }
    const now = currentTime();
    const filter = { _id: deviceId, tenantId, ownerId, leaseState: 'active', epoch };
    const pipeline = buildRevokePipeline({ ownerId, now });
    let matched;
    try {
      matched = await performUpdate(db.DeviceAuthority, filter, pipeline);
    } catch (err) {
      return {
        ok: false,
        matched: 0,
        authority: await safeReadAuthority(deviceId, tenantId),
        error: classifyCasFailure(err).error,
      };
    }
    if (matched === 0) {
      return {
        ok: false,
        matched: 0,
        authority: await safeReadAuthority(deviceId, tenantId),
        error: new DeviceError('NOT_OWNER_OR_STALE', 'No live lease matches this owner and epoch'),
      };
    }
    const authority = await safeReadAuthority(deviceId, tenantId);
    const auditError = await emitAuthorityAudit({
      tenantId,
      deviceId,
      authority,
      now,
      kind: AUDIT_KINDS.REVOKE,
      actor: ownerId,
      reasonCode: null,
    });
    return { ok: auditError === null, matched, authority, error: auditError };
  }

  /**
   * Identity retirement CAS (§10a E / §4.6b). ONE atomic terminal write; the owner form binds
   * the caller with `ownerId: actor` and 0-matches as `NOT_OWNER`.
   */
  async function retireIdentityImpl(args = {}) {
    const deniedFields = ['actor', 'role', 'ownerId', 'actorRole', 'isAdmin', 'admin', 'principal', 'authorization'];
    if (deniedFields.some((field) => Object.prototype.hasOwnProperty.call(args, field))) {
      return failure(new DeviceError('REQUEST_SUPPLIED_IDENTITY_REJECTED',
        'Retirement identity and privileges are resolved by the server, never by caller fields'));
    }
    const tenantId = args.tenantId;
    const deviceId = args.deviceId;
    const tenantError = requireTenant(tenantId);
    if (tenantError) return failure(tenantError);
    if (!isNonEmptyString(deviceId)) {
      return failure(new DeviceError('UNKNOWN_DEVICE', 'A server-resolved deviceId is required'));
    }
    if (typeof resolveRetirePrincipal !== 'function') {
      return failure(new DeviceError('NOT_OWNER', 'No authenticated retirement resolver is configured'));
    }
    let principal;
    try {
      principal = await resolveRetirePrincipal({ tenantId, deviceId });
    } catch {
      return failure(new DeviceError('NOT_OWNER', 'Authenticated principal resolution failed'));
    }
    if (principal === null || typeof principal !== 'object' ||
        principal.tenantId !== tenantId || !isNonEmptyString(principal.principalId)) {
      return failure(new DeviceError('NOT_OWNER', 'No trusted principal belongs to this tenant'));
    }

    const kind = principal.kind;
    const now = currentTime();
    if (kind === 'owner') {
      if (!isNonEmptyString(principal.sessionRef)) {
        return failure(new DeviceError('NOT_OWNER', 'Owner requires an authenticated session reference'));
      }
    } else if (kind === 'admin') {
      if (!isNonEmptyString(principal.adminGrantRef) ||
          !Number.isInteger(principal.authorizationEpoch) || principal.authorizationEpoch < 0 ||
          typeof verifyRetireAuthorization !== 'function') {
        return failure(new DeviceError('NOT_OWNER', 'No active server-verified admin grant'));
      }
      let attestation;
      try {
        attestation = await verifyRetireAuthorization({
          tenantId, principalId: principal.principalId,
          adminGrantRef: principal.adminGrantRef,
          authorizationEpoch: principal.authorizationEpoch,
          deviceId, now,
        });
      } catch {
        return failure(new DeviceError('NOT_OWNER', 'Retirement grant verification failed'));
      }
      const binding = attestation !== null && typeof attestation === 'object'
        ? attestation.binding : null;
      if (attestation?.ok !== true || binding === null || typeof binding !== 'object' ||
          binding.adminPrincipalId !== principal.principalId ||
          binding.scopeTenantId !== tenantId ||
          binding.adminGrantRef !== principal.adminGrantRef ||
          binding.authorizationEpoch !== principal.authorizationEpoch) {
        return failure(new DeviceError('NOT_OWNER', 'No matching, live tenant-scoped admin grant'));
      }
    } else {
      return failure(new DeviceError('NOT_OWNER', 'Unknown authenticated retirement principal kind'));
    }

    const before = await safeReadAuthority(deviceId, tenantId);
    if (before === null) {
      return failure(new DeviceError('UNKNOWN_DEVICE', 'No device identity exists in this tenant'));
    }
    if (before.identityState === 'retired') {
      return failure(new DeviceError('DEVICE_IDENTITY_REVOKED', 'Device identity already retired'));
    }
    if (!Number.isInteger(before.epoch) || before.epoch < 0) {
      return failure(new DeviceError('WRITE_OUTCOME_UNCERTAIN', 'Authority generation preimage is invalid'));
    }
    if (kind === 'owner' && before.ownerId !== principal.principalId) {
      return failure(new DeviceError('NOT_OWNER', 'Authenticated owner differs from identity owner'));
    }
    const actor = principal.principalId;
    const filter = {
      _id: deviceId, tenantId, epoch: before.epoch, identityState: { $ne: 'retired' },
    };
    if (kind === 'owner') filter.ownerId = actor;
    let matched;
    try {
      matched = await performUpdate(db.DeviceAuthority, filter, buildRetirePipeline({ actor, now }));
    } catch (err) {
      return { ok: false, matched: 0, authority: await safeReadAuthority(deviceId, tenantId),
        error: classifyCasFailure(err).error };
    }
    if (matched === 0) {
      const authority = await safeReadAuthority(deviceId, tenantId);
      const code = authority === null ? 'UNKNOWN_DEVICE'
        : authority.identityState === 'retired' ? 'DEVICE_IDENTITY_REVOKED'
          : kind === 'owner' && authority.ownerId !== actor ? 'NOT_OWNER'
            : 'NOT_OWNER_OR_STALE';
      return { ok: false, matched: 0, authority,
        error: new DeviceError(code, 'Retirement could not match the authenticated preimage') };
    }
    const authority = await safeReadAuthority(deviceId, tenantId);
    const auditError = await emitAuthorityAudit({
      tenantId, deviceId, authority, now, kind: AUDIT_KINDS.RETIRE,
      actor, reasonCode: kind === 'owner' ? 'owner-retire' : 'admin-retire',
    });
    return { ok: auditError === null, matched, authority, error: auditError };
  }

  /**
   * The only challenge spend path (G-4 / §8). CAS conjuncts: `consumedAt: null` and the
   * explicit `expiresAt: { $gt: now }`, plus `tenantId` (G-9) and the whitelisted server-side
   * binding fields. A 0-match carries no frozen error code; `ok:false` is the fail-closed
   * signal for the caller (I5).
   */
  async function spendChallengeImpl(args = {}) {
    const bound = args.bound !== null && typeof args.bound === 'object' ? args.bound : {};
    const tenantId = args.tenantId;
    if (!isNonEmptyString(tenantId)) {
      return failure(
        new DeviceError('TENANT_MISMATCH', 'tenantId must be supplied by the authenticated context'),
      );
    }
    if (!isNonEmptyString(args.challengeHash) || !isNonEmptyString(args.purpose)) {
      return failure(
        new DeviceError('INVALID_OR_EXPIRED_CODE', 'A frozen-purpose challenge hash is required'),
      );
    }
    const now = currentTime();
    const filter = {
      challengeHash: args.challengeHash,
      purpose: args.purpose,
      consumedAt: null,
      expiresAt: { $gt: new Date(now) },
      tenantId,
    };
    for (const field of CHALLENGE_BINDING_FIELDS) {
      if (bound[field] !== undefined) {
        filter[field] = bound[field];
      }
    }
    let matched;
    try {
      matched = await performUpdate(db.Challenge, filter, { $set: { consumedAt: new Date(now) } });
    } catch (err) {
      return failure(classifyCasFailure(err).error);
    }
    if (matched === 0) {
      return { ok: false, matched: 0, authority: null, error: null };
    }
    return { ok: true, matched, authority: null, error: null };
  }

  function guard(handler) {
    return async (args) => {
      try {
        const tenantError = tenantAgreementError(args);
        if (tenantError) return failure(tenantError);
        return await handler(args);
      } catch (err) {
        if (err instanceof DeviceError) {
          return failure(err);
        }
        safeLog('error', 'authority operation failed closed', { code: 'WRITE_OUTCOME_UNCERTAIN' });
        return failure(
          new DeviceError('WRITE_OUTCOME_UNCERTAIN', 'Authority operation failed closed', {
            cause: err,
          }),
        );
      }
    };
  }

  return {
    readAuthority: async (args = {}) => tenantAgreementError(args) ? null : readAuthorityImpl(args),
    releaseLapsedLease: guard(releaseLapsedLeaseImpl),
    claimAuthority: guard(claimAuthorityImpl),
    renewAuthority: guard(renewAuthorityImpl),
    revokeLease: guard(revokeLeaseImpl),
    retireIdentity: guard(retireIdentityImpl),
    spendChallenge: guard(spendChallengeImpl),
  };
}

module.exports = {
  createAuthorityService,
  LEASE_TTL_MS,
  SKEW_MARGIN_MS,
  AUTHORITY_AUDIT_KINDS: AUDIT_KINDS,
};
