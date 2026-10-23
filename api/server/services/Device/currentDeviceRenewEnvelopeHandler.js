'use strict';

/**
 * `CBHR-RENEW-V1` — device-signed manual lease renewal (`POST /api/devices/current/renew`).
 *
 * OWNER-AUTHORIZED SCOPE (GM-3 / GM-12, docs/GM-R3-FRICTION-FREE-FLOW-RULINGS-20261023.md and
 * docs/GM-RELAY-FIRST-PILOT-PLAN-20261023.md; LOCAL LAB ONLY; production G0 remains BLOCKED).
 *
 * This REPLACES the session-only local-lab renewal adapter (`currentDeviceHttpHandler`'s
 * `createSessionRenewalAuthorization`), whose binding "agrees by construction and therefore proves
 * nothing": it authorized a manual renewal from the authenticated browser session alone. Under
 * GM-12 the panel must NOT be able to renew — a stolen browser session must not extend a device's
 * access. Renewal approval is LOCAL: the endpoint signs with its own key.
 *
 * TRUST MODEL
 * - The route stays behind `requireJwtAuth` (it is the panel/tray path), so the trusted tenant and
 *   the authenticated principal are still server-resolved. That session is a ROUTE GATE and an
 *   ownership gate, never the renewal authorization.
 * - The renewal AUTHORIZATION comes only from the endpoint's Ed25519 signature over the
 *   server-minted single-use challenge with domain tag `cbhr:device:renew:v1`. A browser that holds
 *   a valid session but cannot sign is refused and writes nothing.
 * - Identity is resolved from the key thumbprint (`crypto.thumbprintB64u`) to a tenant-scoped
 *   `DeviceAuthority` row; the owner/epoch/grant/expiry binding is the server-observed row truth.
 *   No `deviceId`, `sessionId`, `ownerId`, `tenantId`, `epoch`, `grantId`, `expiresAt` or `role` is
 *   ever read from the request (`deviceHttpTrust.guardRequestInput` rejects them, with zero model
 *   calls, before any read or write).
 * - The device's own principal must hold the lease: the authenticated session principal is
 *   compared to the server-resolved row owner and a mismatch is a 404 `UNKNOWN_DEVICE` with no
 *   read-back of the other principal's device id in the response.
 *
 * ENVELOPE (frozen shape)
 * - Leg 1 (no proof): mint one single-use 256-bit `renewal` challenge bound to the server-observed
 *   `{tenantId, deviceId, deviceKeyId, boundOwnerId, boundGrantId, boundEpoch}`, TTL 120 s, and
 *   return the exact canonical preimage bytes the endpoint must sign:
 *   `cbhr:device:renew:v1 ‖ tenantId ‖ ownerId ‖ deviceId ‖ grantId ‖ epoch ‖ expiresAt ‖
 *    challengeHash`, where `epoch` and `expiresAt` are decimal epoch-millisecond strings. The
 *   preimage is returned as `signingMessageB64u` (base64url) so the endpoint signs exactly the
 *   bytes the server will verify — no client-side re-encoding of identity or authority values.
 * - Leg 2 (`devicePublicKey` + `challengeHash` + `signatureB64u`): look the challenge up by its
 *   server-stored hash, re-derive the preimage from CURRENT server row truth, verify the signature
 *   against the DB-stored public key, spend the challenge exactly once, then run the accepted
 *   `authorityService.renewAuthority` CAS with a server-owned proof binding.
 *
 * FROZEN LAW (unchanged, still enforced by the accepted CAS — never re-implemented or loosened)
 * - 48 h TTL (`LEASE_TTL_MS`), 5 s margin (`SKEW_MARGIN_MS`), renewal only strictly before expiry
 *   (`expiresAt > now + 5000`), `epoch+1`, `grantId` rotated, `renewalCount+1`, audit emitted.
 * - Inside the margin or after expiry: 409 `LEASE_EXPIRED` `committed:false` and NO write — the
 *   margin/expiry pre-check runs before the challenge spend, and the CAS filter enforces it again.
 * - `matched === 1` with audit-delivery failure: 500 `AUDIT_DELIVERY_UNCERTAIN` `committed:true`
 *   (the renewal is REAL; it must never be reported as a no-op).
 *
 * RESPONSE CONTRACT
 * - Leg 1: 200 `{ok:true, state:'challenge', deviceId, epoch, expiresAt, leaseState,
 *   challengeHash, issuedAt, challengeExpiresAt, signingMessageB64u}`. `grantId` is deliberately
 *   NOT echoed (the frozen status projection withholds it); the preimage carries it instead.
 * - Leg 2: 200 `{ok:true, renewed:true, deviceId, epoch, expiresAt, renewalCount}` — identical to
 *   the ratified session-lab contract, now authorized by the device signature.
 * - 400 `REQUEST_SUPPLIED_IDENTITY_REJECTED` / `INVALID_OR_EXPIRED_CODE`; 404 `UNKNOWN_DEVICE`;
 *   403 `TENANT_MISMATCH`/`NOT_OWNER`; 409 `LEASE_EXPIRED`/`DEVICE_IDENTITY_REVOKED`/
 *   `NOT_OWNER_OR_STALE` with `committed:false`; 500 with `committed:false|true` as above.
 * - The plaintext challenge nonce, private keys, peppers, `lookupTag` and `grantProof` are never
 *   returned, persisted or logged by this layer.
 */

const deviceCrypto = require('./crypto');
const { createAuthorityService, LEASE_TTL_MS, SKEW_MARGIN_MS } = require('./authorityService');
const { DeviceError } = require('./errors');
const { readAnchorNowMs, expiryPredicate, assertPredicateAnchorShape, createClockSkewGuard } = require('./databaseTime');
const {
  assertHttpHandlerDependencies,
  createAuditAccessor,
  guardRequestInput,
  isNonEmptyString,
  resolveTrustedContext,
  sendClassifiedError,
  sendFailClosed,
  toIsoOrNull,
  toObservedEpoch,
} = require('./deviceHttpTrust');

/** Frozen challenge purpose for the renewal envelope (frozen `Challenge` enum value). */
const RENEWAL_CHALLENGE_PURPOSE = 'renewal';
/** Server-minted renewal challenge lifetime: 120 s (mirrors the pairing challenge TTL). */
const RENEWAL_CHALLENGE_TTL_MS = 120000;
/** Bounded regeneration for a (astronomically unlikely) challenge-hash collision. */
const MAX_CHALLENGE_REGENERATIONS = 3;
/** Authority-critical write concern (G-5/G-6). */
const AUTHORITY_WRITE_CONCERN = Object.freeze({ w: 'majority', j: true });

/** Frozen request-field allowlist: flat strings only. */
const RENEW_FIELDS = Object.freeze(['devicePublicKey', 'challengeHash', 'signatureB64u']);

/**
 * Server-owned proof descriptor. The injected `verifyRenewalProof` accepts the renewal ONLY when it
 * is handed this exact per-request object AND the device envelope was fully verified in this
 * request; the object carries no client value.
 */
function createEnvelopeProofSource() {
  return Object.freeze({ source: 'device-signed-renewal-envelope', envelope: 'CBHR-RENEW-V1' });
}

function uniformMiss() {
  return new DeviceError('INVALID_OR_EXPIRED_CODE', 'The supplied renewal values cannot be used');
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

/** Frozen canonical renewal preimage: exactly the fields named by CBHR-RENEW-V1, in order. */
function buildRenewalMessage({
  crypto,
  tenantId,
  ownerId,
  deviceId,
  grantId,
  epoch,
  expiresAtMs,
  challengeHash,
  domainTag,
}) {
  if (
    !isNonEmptyString(grantId) ||
    !Number.isInteger(epoch) ||
    epoch < 0 ||
    !Number.isFinite(expiresAtMs) ||
    !isNonEmptyString(challengeHash)
  ) {
    return null;
  }
  try {
    return crypto.canonicalEncode({
      domainTag,
      fields: [
        tenantId,
        ownerId,
        deviceId,
        grantId,
        String(epoch),
        String(expiresAtMs),
        challengeHash,
      ],
    });
  } catch {
    return null;
  }
}

/**
 * Renewal eligibility: a live lease with more than the frozen margin left. Never a write.
 * `serverNow` MUST be database time (GM-44 site 10): a slow writer must not renew a lease that has
 * already expired on the true timeline, and a fast writer must not refuse a live one.
 */
function isRenewable(row, serverNow) {
  const expiresAt = toMillis(row?.expiresAt);
  return (
    row?.leaseState === 'active' &&
    row?.identityState !== 'retired' &&
    isNonEmptyString(row?.ownerId) &&
    isNonEmptyString(row?.grantId) &&
    Number.isInteger(row?.epoch) &&
    expiresAt !== null &&
    expiresAt > serverNow + SKEW_MARGIN_MS
  );
}

/** The frozen 409 refusal: nothing was committed and nothing was written. */
function sendLeaseExpired(res, { deviceId, epoch, expiresAt }) {
  return sendClassifiedError(
    res,
    new DeviceError('LEASE_EXPIRED', 'Lease is inside the renewal skew margin or has expired'),
    {
      committed: false,
      deviceId,
      epoch: toObservedEpoch(epoch),
      expiresAt: toIsoOrNull(expiresAt),
    },
  );
}

/** Resolves the caller's own device from endpoint key material: thumbprint -> row -> owner. */
async function readOwnedDeviceByPublicKey({ db, crypto, tenantId, ownerId, devicePublicKey }) {
  if (!isNonEmptyString(devicePublicKey)) {
    return { device: null, error: null, missingKey: true };
  }
  let deviceKeyId;
  try {
    deviceKeyId = crypto.thumbprintB64u(devicePublicKey);
  } catch {
    return { device: null, error: uniformMiss(), missingKey: false };
  }
  if (!isNonEmptyString(deviceKeyId)) {
    return { device: null, error: uniformMiss(), missingKey: false };
  }
  let row;
  try {
    row = await db.DeviceAuthority.findOne({ tenantId, deviceKeyId }).lean();
  } catch {
    return {
      device: null,
      error: new DeviceError(
        'WRITE_OUTCOME_UNCERTAIN',
        'Device identity lookup failed; failing closed',
      ),
      missingKey: false,
    };
  }
  const deviceId = row?._id?.toString?.();
  if (
    row === null ||
    row === undefined ||
    row.tenantId !== tenantId ||
    row.deviceKeyId !== deviceKeyId ||
    row.devicePublicKey !== devicePublicKey ||
    !isNonEmptyString(deviceId) ||
    // Only the caller's own device is visible: another principal's row is indistinguishable from
    // an unknown key (404), and its device id is never echoed back.
    row.ownerId !== ownerId
  ) {
    return { device: null, error: null, missingKey: false };
  }
  return { device: { deviceId, deviceKeyId, row }, error: null, missingKey: false };
}

/**
 * Reads the caller's single live-renewable device row. Returns a 404 sentinel instead of a
 * classified error so the caller can answer with the frozen `UNKNOWN_DEVICE` shape.
 */
async function readRenewableRow({ db, tenantId, deviceId }) {
  try {
    const row = await db.DeviceAuthority.findOne({ _id: deviceId, tenantId }).lean();
    return { row: row ?? null, error: null };
  } catch {
    return {
      row: null,
      error: new DeviceError(
        'WRITE_OUTCOME_UNCERTAIN',
        'Device authority read failed; failing closed',
      ),
    };
  }
}

function createCurrentDeviceRenewEnvelopeHandler(deps = {}) {
  const {
    db,
    tenantContext,
    clock = { now: () => Date.now() },
    crypto = deviceCrypto,
    logger = null,
    audit,
    domainTag,
    predicateAnchor,
  } = deps;
  assertHttpHandlerDependencies({ db, tenantContext, label: 'current device renew handler' });
  if (!isNonEmptyString(domainTag)) {
    throw new TypeError('current device renew handler requires the frozen canonical domain tag');
  }
  // GM-64/GM-65: the test-only comparison anchor (shape-validated here, resolved per predicate).
  assertPredicateAnchorShape(predicateAnchor);

  const auditFn = createAuditAccessor({ db, logger, audit });

  /**
   * GM-44: the DATABASE clock, used for every lease-state/TTL predicate in this handler. `null`
   * means the server clock could not be read, and every caller then fails closed rather than
   * deciding a lease state from the writer's own clock. A GM-65 test anchor stands in for the
   * server clock when one is supplied.
   */
  async function databaseNow() {
    const nowMs = await readAnchorNowMs(db, predicateAnchor);
    return Number.isFinite(nowMs) ? nowMs : null;
  }

  function databaseTimeUnavailable() {
    return new DeviceError(
      'WRITE_OUTCOME_UNCERTAIN',
      'Database time is unavailable; the lease state cannot be decided',
    );
  }

  async function mintLeg({ res, body, trusted, now }) {
    const read = await readOwnedDeviceByPublicKey({
      db,
      crypto,
      tenantId: trusted.tenantId,
      ownerId: trusted.principalId,
      devicePublicKey: body.devicePublicKey,
    });
    if (read.error) {
      return sendClassifiedError(res, read.error);
    }
    if (read.device === null) {
      return sendClassifiedError(
        res,
        new DeviceError(
          'UNKNOWN_DEVICE',
          'No current active device identity is available for this authenticated user',
        ),
      );
    }
    const { deviceId, deviceKeyId, row } = read.device;
    if (row.identityState === 'retired') {
      return sendClassifiedError(
        res,
        new DeviceError('DEVICE_IDENTITY_REVOKED', 'Device identity is retired'),
      );
    }
    const leaseNow = await databaseNow();
    if (leaseNow === null) {
      return sendClassifiedError(res, databaseTimeUnavailable(), { committed: false, deviceId });
    }
    if (!isRenewable(row, leaseNow)) {
      // Frozen law: the margin/expiry refusal must write nothing at all (no challenge row either).
      return sendLeaseExpired(res, { deviceId, epoch: row.epoch, expiresAt: row.expiresAt });
    }

    const expiresAtMs = toMillis(row.expiresAt);

    // Mint the single-use challenge. Only its hash is stored; the nonce never leaves this function.
    let challengeHash = null;
    let challengeExpiresAt = null;
    for (let attempt = 0; attempt <= MAX_CHALLENGE_REGENERATIONS; attempt += 1) {
      let nonce;
      try {
        nonce = crypto.newChallengeNonce();
        challengeHash = crypto.challengeHash(nonce);
      } catch {
        return sendClassifiedError(
          res,
          new DeviceError('WRITE_OUTCOME_UNCERTAIN', 'Challenge minting failed; failing closed'),
        );
      }
      try {
        await db.Challenge.create(
          [
            {
              challengeHash,
              purpose: RENEWAL_CHALLENGE_PURPOSE,
              deviceId,
              deviceKeyId,
              tenantId: trusted.tenantId,
              boundPairingSessionId: null,
              boundOwnerId: row.ownerId,
              boundGrantId: row.grantId,
              boundEpoch: row.epoch,
              boundSessionVersion: null,
              issuedAt: new Date(now),
              expiresAt: new Date(now + RENEWAL_CHALLENGE_TTL_MS),
              consumedAt: null,
            },
          ],
          { writeConcern: AUTHORITY_WRITE_CONCERN },
        );
        challengeExpiresAt = now + RENEWAL_CHALLENGE_TTL_MS;
        break;
      } catch (err) {
        const duplicate = err !== null && typeof err === 'object' && (err.code === 11000 || err.code === 11001);
        if (!duplicate || attempt === MAX_CHALLENGE_REGENERATIONS) {
          return sendClassifiedError(
            res,
            new DeviceError(
              'WRITE_OUTCOME_UNCERTAIN',
              'The renewal challenge could not be minted; failing closed',
              { cause: err },
            ),
          );
        }
        challengeHash = null;
      }
    }
    if (!isNonEmptyString(challengeHash)) {
      return sendClassifiedError(
        res,
        new DeviceError('WRITE_OUTCOME_UNCERTAIN', 'Challenge minting exhausted; failing closed'),
      );
    }

    const signingMessage = buildRenewalMessage({
      crypto,
      tenantId: trusted.tenantId,
      ownerId: row.ownerId,
      deviceId,
      grantId: row.grantId,
      epoch: row.epoch,
      expiresAtMs,
      challengeHash,
      domainTag,
    });
    if (signingMessage === null) {
      return sendClassifiedError(
        res,
        new DeviceError('WRITE_OUTCOME_UNCERTAIN', 'The renewal preimage could not be bound'),
      );
    }

    return res.status(200).json({
      ok: true,
      state: 'challenge',
      deviceId,
      epoch: toObservedEpoch(row.epoch),
      expiresAt: toIsoOrNull(row.expiresAt),
      leaseState: isNonEmptyString(row.leaseState) ? row.leaseState : null,
      challengeHash,
      issuedAt: String(now),
      challengeExpiresAt: toIsoOrNull(new Date(challengeExpiresAt)),
      signingMessageB64u: signingMessage.toString('base64url'),
    });
  }

  async function completeLeg({ res, body, trusted, now }) {
    const read = await readOwnedDeviceByPublicKey({
      db,
      crypto,
      tenantId: trusted.tenantId,
      ownerId: trusted.principalId,
      devicePublicKey: body.devicePublicKey,
    });
    if (read.error) {
      return sendClassifiedError(res, read.error);
    }
    if (read.device === null) {
      return sendClassifiedError(
        res,
        new DeviceError(
          'UNKNOWN_DEVICE',
          'No current active device identity is available for this authenticated user',
        ),
      );
    }
    const { deviceId, row } = read.device;
    if (row.identityState === 'retired') {
      return sendClassifiedError(
        res,
        new DeviceError('DEVICE_IDENTITY_REVOKED', 'Device identity is retired'),
      );
    }

    // Frozen law first: inside the margin / after expiry is a refusal with NO write at all.
    // GM-44 site 10: both eligibility tests use DATABASE time, read once for this leg.
    const leaseNow = await databaseNow();
    if (leaseNow === null) {
      return sendClassifiedError(res, databaseTimeUnavailable(), { committed: false, deviceId });
    }
    if (!isRenewable(row, leaseNow)) {
      return sendLeaseExpired(res, { deviceId, epoch: row.epoch, expiresAt: row.expiresAt });
    }

    const current = await readRenewableRow({ db, tenantId: trusted.tenantId, deviceId });
    if (current.error) {
      return sendClassifiedError(res, current.error);
    }
    const currentRow = current.row;
    if (currentRow === null) {
      return sendClassifiedError(
        res,
        new DeviceError(
          'UNKNOWN_DEVICE',
          'No current active device identity is available for this authenticated user',
        ),
      );
    }
    if (currentRow.identityState === 'retired') {
      return sendClassifiedError(
        res,
        new DeviceError('DEVICE_IDENTITY_REVOKED', 'Device identity is retired'),
      );
    }
    // Re-read on the CURRENT row, again against database time (the preimage may have moved).
    const currentNow = await databaseNow();
    if (currentNow === null) {
      return sendClassifiedError(res, databaseTimeUnavailable(), { committed: false, deviceId });
    }
    if (!isRenewable(currentRow, currentNow)) {
      return sendLeaseExpired(res, {
        deviceId,
        epoch: currentRow.epoch,
        expiresAt: currentRow.expiresAt,
      });
    }

    // The challenge must exist, be unconsumed, unexpired and bound to THIS server-observed row.
    let challenge;
    try {
      challenge = await db.Challenge.findOne({
        challengeHash: body.challengeHash,
        purpose: RENEWAL_CHALLENGE_PURPOSE,
        deviceId,
        tenantId: trusted.tenantId,
        consumedAt: null,
        // GM-44: the 120 s renewal-challenge TTL is a TTL decision ⇒ database time.
        $expr: expiryPredicate({ predicateAnchor, operator: '$gt' }),
      }).lean();
    } catch {
      return sendClassifiedError(
        res,
        new DeviceError(
          'WRITE_OUTCOME_UNCERTAIN',
          'The renewal challenge could not be read; failing closed',
        ),
      );
    }
    if (
      challenge === null ||
      challenge === undefined ||
      challenge.boundOwnerId !== currentRow.ownerId ||
      challenge.boundGrantId !== currentRow.grantId ||
      challenge.boundEpoch !== currentRow.epoch
    ) {
      return sendClassifiedError(res, uniformMiss(), { committed: false, deviceId });
    }

    // The signed preimage is rebuilt from CURRENT server truth: if epoch/grant/expiry moved, the
    // bytes differ and the signature cannot verify.
    const message = buildRenewalMessage({
      crypto,
      tenantId: trusted.tenantId,
      ownerId: currentRow.ownerId,
      deviceId,
      grantId: currentRow.grantId,
      epoch: currentRow.epoch,
      expiresAtMs: toMillis(currentRow.expiresAt),
      challengeHash: body.challengeHash,
      domainTag,
    });
    if (message === null) {
      return sendClassifiedError(
        res,
        new DeviceError(
          'WRITE_OUTCOME_UNCERTAIN',
          'The renewal preimage could not be built from server truth; failing closed',
        ),
      );
    }
    let verified = false;
    if (isNonEmptyString(currentRow.devicePublicKey)) {
      try {
        verified = crypto.verifyEd25519({
          publicKeySpkiB64u: currentRow.devicePublicKey,
          message,
          signatureB64u: body.signatureB64u,
        });
      } catch {
        verified = false;
      }
    }
    if (verified !== true) {
      return sendClassifiedError(res, uniformMiss(), { committed: false, deviceId });
    }

    // Server-owned proof binding, captured from the same server-observed preimage as the signature.
    const proofSource = createEnvelopeProofSource();
    const binding = Object.freeze({
      tenantId: trusted.tenantId,
      ownerPrincipalId: currentRow.ownerId,
      deviceId,
      grantId: currentRow.grantId,
      epoch: currentRow.epoch,
    });
    const authorityService = createAuthorityService({
      db,
      clock,
      crypto,
      logger,
      audit: auditFn,
      tenantContext,
      // GM-65: the test anchor rides along so the renewal CAS decides against the same timeline.
      predicateAnchor,
      // GM-44 rule 3: the lease-state CAS this handler drives refuses to write when this host
      // cannot prove its clock is inside the frozen skew budget.
      clockSkewGuard: createClockSkewGuard({ db, logger }),
      verifyRenewalProof: async (input) => {
        if (input !== proofSource) {
          return { ok: false, binding: null };
        }
        return { ok: true, binding };
      },
    });

    // Single-use spend through the accepted G-4 CAS (never a raw write).
    const spend = await authorityService.spendChallenge({
      challengeHash: body.challengeHash,
      purpose: RENEWAL_CHALLENGE_PURPOSE,
      tenantId: trusted.tenantId,
      bound: {
        deviceId,
        deviceKeyId: currentRow.deviceKeyId,
        boundOwnerId: currentRow.ownerId,
        boundGrantId: currentRow.grantId,
        boundEpoch: currentRow.epoch,
      },
    });
    if (spend === null || typeof spend !== 'object' || spend.ok !== true) {
      return sendClassifiedError(
        res,
        spend !== null && typeof spend === 'object' && spend.error ? spend.error : uniformMiss(),
        { committed: false, deviceId },
      );
    }

    const result = await authorityService.renewAuthority({
      deviceId,
      tenantId: trusted.tenantId,
      ownerId: currentRow.ownerId,
      epoch: currentRow.epoch,
      grantId: currentRow.grantId,
      proofInput: proofSource,
    });

    if (result?.ok === true && result?.matched === 1) {
      return res.status(200).json({
        ok: true,
        renewed: true,
        deviceId,
        epoch: toObservedEpoch(result.authority?.epoch),
        expiresAt: toIsoOrNull(result.authority?.expiresAt),
        renewalCount: Number.isInteger(result.authority?.renewalCount)
          ? result.authority.renewalCount
          : null,
      });
    }

    const error = result?.error ?? null;

    if (result?.matched === 1) {
      // Committed CAS whose audit delivery failed: the renewal is real, never a no-op.
      return sendClassifiedError(
        res,
        error ??
          new DeviceError(
            'AUDIT_DELIVERY_UNCERTAIN',
            'Device renewal committed but audit delivery is uncertain',
          ),
        {
          committed: true,
          deviceId,
          epoch: toObservedEpoch(result.authority?.epoch),
          expiresAt: toIsoOrNull(result.authority?.expiresAt),
        },
      );
    }

    return sendClassifiedError(
      res,
      error ??
        new DeviceError(
          'NOT_OWNER_OR_STALE',
          'No live lease matched the device-signed preimage; nothing was committed',
        ),
      {
        committed: false,
        deviceId,
        epoch: toObservedEpoch(currentRow.epoch),
        expiresAt: toIsoOrNull(currentRow.expiresAt),
      },
    );
  }

  return async function currentDeviceRenewEnvelopeHandler(req, res) {
    try {
      if (
        guardRequestInput(req, res, {
          endpoint: 'Current device renewal',
          allowedBodyFields: RENEW_FIELDS,
        })
      ) {
        return;
      }

      const trusted = resolveTrustedContext({ req, tenantContext });
      if (trusted.error) {
        return sendClassifiedError(res, trusted.error);
      }

      const now = clock.now();
      if (!Number.isFinite(now)) {
        return sendClassifiedError(
          res,
          new DeviceError('WRITE_OUTCOME_UNCERTAIN', 'Injected clock returned a non-finite time'),
        );
      }

      const body = req.body !== null && typeof req.body === 'object' ? req.body : {};
      const hasChallenge = isNonEmptyString(body.challengeHash);
      const hasSignature = isNonEmptyString(body.signatureB64u);
      if (hasChallenge !== hasSignature) {
        return sendClassifiedError(res, uniformMiss(), { committed: false });
      }
      if (!hasChallenge) {
        return await mintLeg({ res, body, trusted, now });
      }
      return await completeLeg({ res, body, trusted, now });
    } catch {
      return sendFailClosed(res, 'Current device renewal failed closed');
    }
  };
}

module.exports = {
  createCurrentDeviceRenewEnvelopeHandler,
  buildRenewalMessage,
  isRenewable,
  RENEWAL_CHALLENGE_PURPOSE,
  RENEWAL_CHALLENGE_TTL_MS,
  RENEW_FIELDS,
  LEASE_TTL_MS,
  SKEW_MARGIN_MS,
};