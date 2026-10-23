'use strict';

/**
 * Device pairing HTTP handlers (`POST /api/devices/pairing/{challenge,issue,approve}`).
 *
 * OWNER-AUTHORIZED SCOPE (2026-10-22, owner outranks Governor; LOCAL LAB ONLY and requiring
 * Governor ratification later; production G0 remains BLOCKED).
 *
 * These handlers are thin, fail-closed HTTP adapters over the ACCEPTED services
 * (`pairingSessionService.js`, `authorityService.js`, `crypto.js`). No accepted service file is
 * modified; every id, tenant, principal and authority value is server-resolved.
 *
 * TRUST MODEL (identical in shape to `ownerCurrentRetireHandler.js`)
 * - `requireJwtAuth` runs before every handler (wired in `routes/devices.js`).
 * - The request is read for PROTOCOL VALUES ONLY, from an exact flat-string allowlist per
 *   endpoint; container/identity/authority input is rejected with 400
 *   `REQUEST_SUPPLIED_IDENTITY_REJECTED` before any model method is touched
 *   (`deviceHttpTrust.guardRequestInput`).
 * - tenantId comes from the trusted ALS tenant context; ownerId comes from the authenticated
 *   session (`req.user.id`). Neither is ever read from the request.
 * - The endpoint is identified by KEY MATERIAL only: the caller submits its Ed25519 public key
 *   (the one frozen legal request-supplied key) and the server derives `deviceKeyId` as the
 *   server-side SHA-256 thumbprint, then resolves the authority row by the tenant-scoped
 *   `{tenantId, deviceKeyId}` lookup. A raw `deviceId` is never accepted.
 * - Possession is proven per the frozen ceremony: the server mints a single-use 256-bit
 *   pairing-open challenge, the endpoint signs the canonical message over the server's own
 *   `issuedAt`, and the accepted service verifies the signature against the DB-stored public key.
 *
 * RESPONSE CONTRACT
 * - `POST /pairing/challenge` 200 `{ ok:true, challengeHash, issuedAt, expiresAt }`
 *   `issuedAt` is the server row's epoch-millisecond decimal string — the exact value the endpoint
 *   must sign. The plaintext challenge nonce is never returned.
 * - `POST /pairing/issue` 200 `{ ok:true, code, pairingSessionId, state, expiresAt }`
 *   The six-digit code is returned EXACTLY ONCE to the requesting endpoint (the accepted service
 *   returns it to its caller and persists only the tenant-bound HMAC lookupTag). It is never
 *   logged, never echoed anywhere else, and never stored by this layer.
 * - `POST /pairing/approve` 200 `{ ok:true, pairingSessionId, state:'claim_pending', deviceKeyId,
 *   expiresAt }` — the frozen LP-2 redemption: the submitted code resolves to the pending session
 *   and binds `pendingOwnerId` to the authenticated owner. NO authority/lease is granted by this
 *   endpoint; the grant-completing claim leg (device PoP over a server-armed claim challenge plus
 *   the local-endpoint consent prompt) is deliberately NOT exposed here — it needs the
 *   PoP-authenticated device poll channel and a device-local approval, neither of which exists in
 *   this local lab. `approve` therefore cannot escalate authority.
 * - `400 INVALID_OR_EXPIRED_CODE` is the uniform miss of this ceremony (unknown/expired/consumed
 *   code, malformed key material, failed proof). Real write uncertainty keeps its own classified
 *   code (`WRITE_OUTCOME_UNCERTAIN`/`AUDIT_DELIVERY_UNCERTAIN` 500) and is never disguised as a
 *   miss.
 * - `404 UNKNOWN_DEVICE`: no registered identity row matches the derived key id in this tenant.
 *
 * SERVER-OWNED SEAMS (never from the request)
 * - `tenantContext.getActiveTenantId` — ALS tenant (frozen in the route).
 * - `clock.now()` — the only clock; default is the process clock.
 * - `crypto` — the accepted `Device/crypto.js` surface.
 * - `audit` — the accepted Mongoose audit sink (`AuditEvent`), lazily constructed.
 * - `domainTag` — the frozen canonical domain separator, injected by the route (never a literal in
 *   Device/**).
 * - `requestSource` — a server-derived source descriptor string (hashed by the service; no IP).
 * - `pepperLookup`/`resolvePepperLookup` — the deployment HMAC pepper from server configuration;
 *   when unset the endpoints fail closed rather than accepting a request-supplied value.
 */

const deviceCrypto = require('./crypto');
const { createAuthorityService } = require('./authorityService');
const { createPairingSessionService } = require('./pairingSessionService');
const { DeviceError } = require('./errors');
const {
  assertHttpHandlerDependencies,
  createAuditAccessor,
  guardRequestInput,
  isNonEmptyString,
  resolvePepperSeam,
  resolveTrustedContext,
  sendClassifiedError,
  sendFailClosed,
} = require('./deviceHttpTrust');

/** The frozen challenge purpose used by the accepted pairing service for open-challenge spend. */
const OPEN_CHALLENGE_PURPOSE = 'pairing-open';

/** Frozen request-field allowlist per endpoint: flat strings only. */
const CHALLENGE_FIELDS = Object.freeze(['devicePublicKey']);
const ISSUE_FIELDS = Object.freeze(['devicePublicKey', 'challengeHash', 'signatureB64u']);
const APPROVE_FIELDS = Object.freeze(['code']);

function uniformMiss() {
  return new DeviceError('INVALID_OR_EXPIRED_CODE', 'The supplied pairing values cannot be used');
}

function sessionIdOf(session) {
  const value = session?._id?.toString?.();
  return isNonEmptyString(value) ? value : null;
}

function toMillis(value) {
  if (value instanceof Date) {
    return value.getTime();
  }
  if (typeof value === 'string') {
    const parsed = Date.parse(value);
    return Number.isNaN(parsed) ? null : parsed;
  }
  return null;
}

function isSixDigitCode(value) {
  return typeof value === 'string' && /^\d{6}$/.test(value);
}

/**
 * Resolves the server-side device identity from endpoint key material only: the public key is
 * thumbprinted server-side and the authority row is read by the tenant-scoped key id. The supplied
 * key is never treated as identity and a raw `deviceId` is never accepted.
 */
async function readDeviceByPublicKey({ db, crypto, tenantId, devicePublicKey }) {
  if (!isNonEmptyString(devicePublicKey)) {
    return { device: null, error: uniformMiss() };
  }
  let deviceKeyId;
  try {
    deviceKeyId = crypto.thumbprintB64u(devicePublicKey);
  } catch {
    return { device: null, error: uniformMiss() };
  }
  if (!isNonEmptyString(deviceKeyId)) {
    return { device: null, error: uniformMiss() };
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
    };
  }
  const deviceId = row?._id?.toString?.();
  if (
    row === null ||
    row === undefined ||
    row.tenantId !== tenantId ||
    row.deviceKeyId !== deviceKeyId ||
    row.devicePublicKey !== devicePublicKey ||
    !isNonEmptyString(deviceId)
  ) {
    return {
      device: null,
      error: new DeviceError(
        'UNKNOWN_DEVICE',
        'No registered device identity matches the supplied endpoint key in this tenant',
      ),
    };
  }
  return { device: { deviceId, deviceKeyId }, error: null };
}

/** Reads back the `issuedAt` of the challenge row the service just minted (tenant + purpose scoped). */
async function readMintedChallenge({ db, tenantId, challengeHash }) {
  let row;
  try {
    row = await db.Challenge.findOne({
      challengeHash,
      purpose: OPEN_CHALLENGE_PURPOSE,
      tenantId,
    }).lean();
  } catch {
    return {
      issuedAt: null,
      expiresAt: null,
      error: new DeviceError(
        'WRITE_OUTCOME_UNCERTAIN',
        'The minted pairing challenge could not be read back; failing closed',
      ),
    };
  }
  const issuedAt = toMillis(row?.issuedAt);
  if (row === null || row === undefined || row.tenantId !== tenantId || issuedAt === null) {
    return {
      issuedAt: null,
      expiresAt: null,
      error: new DeviceError(
        'WRITE_OUTCOME_UNCERTAIN',
        'The minted pairing challenge is not readable as server truth; failing closed',
      ),
    };
  }
  return { issuedAt: String(issuedAt), expiresAt: row.expiresAt ?? null, error: null };
}

/**
 * Builds the accepted services for one request with server-owned seams only. Construction happens
 * per request (the retire-handler pattern) so a misconfigured model surface fails closed inside the
 * request instead of at module load.
 */
function buildPairingServices({ db, clock, crypto, logger, audit, tenantContext, pepperLookup }) {
  const authorityService = createAuthorityService({
    db,
    clock,
    crypto,
    logger,
    audit,
    tenantContext,
    verifyRenewalProof: async () => ({ ok: false }),
  });
  const pairingSessionService = createPairingSessionService({
    db,
    clock,
    crypto,
    logger,
    audit,
    authorityService,
    tenantContext,
    pepperLookup,
  });
  return { authorityService, pairingSessionService };
}

function assertPairingHandlerDependencies({ db, tenantContext, domainTag, label }) {
  assertHttpHandlerDependencies({ db, tenantContext, label });
  if (!isNonEmptyString(domainTag)) {
    throw new TypeError(`${label} requires the frozen canonical domain tag seam`);
  }
}

/**
 * `POST /api/devices/pairing/challenge` — mints one single-use 256-bit pairing-open challenge for
 * an endpoint that presents its public key. No code, session or authority row is created.
 */
function createPairingChallengeHandler(deps = {}) {
  const {
    db,
    tenantContext,
    clock = { now: () => Date.now() },
    crypto = deviceCrypto,
    logger = null,
    audit,
    domainTag,
    pepperLookup,
    resolvePepperLookup,
  } = deps;
  assertPairingHandlerDependencies({
    db,
    tenantContext,
    domainTag,
    label: 'pairing challenge handler',
  });

  const auditFn = createAuditAccessor({ db, logger, audit });

  return async function pairingChallengeHandler(req, res) {
    try {
      if (
        guardRequestInput(req, res, {
          endpoint: 'Pairing challenge',
          allowedBodyFields: CHALLENGE_FIELDS,
        })
      ) {
        return;
      }
      const trusted = resolveTrustedContext({ req, tenantContext });
      if (trusted.error) {
        return sendClassifiedError(res, trusted.error);
      }
      const pepper = resolvePepperSeam({ pepperLookup, resolvePepperLookup });
      if (pepper === null) {
        return sendClassifiedError(
          res,
          new DeviceError(
            'WRITE_OUTCOME_UNCERTAIN',
            'No pairing lookup pepper is configured server-side; the ceremony fails closed',
          ),
        );
      }

      const read = await readDeviceByPublicKey({
        db,
        crypto,
        tenantId: trusted.tenantId,
        devicePublicKey: req.body.devicePublicKey,
      });
      if (read.error) {
        return sendClassifiedError(res, read.error);
      }

      const { pairingSessionService } = buildPairingServices({
        db,
        clock,
        crypto,
        logger,
        audit: auditFn,
        tenantContext,
        pepperLookup: pepper,
      });
      const minted = await pairingSessionService.mintPairingOpenChallenge({
        tenantId: trusted.tenantId,
        deviceId: read.device.deviceId,
        deviceKeyId: read.device.deviceKeyId,
      });
      if (minted === null || typeof minted !== 'object' || minted.ok !== true) {
        return sendClassifiedError(res, minted?.error ?? uniformMiss());
      }

      const stamp = await readMintedChallenge({
        db,
        tenantId: trusted.tenantId,
        challengeHash: minted.challengeHash,
      });
      if (stamp.error) {
        return sendClassifiedError(res, stamp.error);
      }
      return res.status(200).json({
        ok: true,
        challengeHash: minted.challengeHash,
        issuedAt: stamp.issuedAt,
        expiresAt: stamp.expiresAt instanceof Date ? stamp.expiresAt.toISOString() : null,
      });
    } catch {
      return sendFailClosed(res, 'Pairing challenge failed closed');
    }
  };
}

/**
 * `POST /api/devices/pairing/issue` — verifies the endpoint's proof over the server-minted
 * challenge and issues one 6-digit single-use pairing session. The plaintext code is returned once
 * to the endpoint and is never logged or persisted by this layer.
 */
function createPairingIssueHandler(deps = {}) {
  const {
    db,
    tenantContext,
    clock = { now: () => Date.now() },
    crypto = deviceCrypto,
    logger = null,
    audit,
    domainTag,
    requestSource,
    pepperLookup,
    resolvePepperLookup,
  } = deps;
  assertPairingHandlerDependencies({
    db,
    tenantContext,
    domainTag,
    label: 'pairing issue handler',
  });
  if (!isNonEmptyString(requestSource)) {
    throw new TypeError('pairing issue handler requires a server-derived request source');
  }

  const auditFn = createAuditAccessor({ db, logger, audit });

  return async function pairingIssueHandler(req, res) {
    try {
      if (
        guardRequestInput(req, res, {
          endpoint: 'Pairing issue',
          allowedBodyFields: ISSUE_FIELDS,
        })
      ) {
        return;
      }
      const trusted = resolveTrustedContext({ req, tenantContext });
      if (trusted.error) {
        return sendClassifiedError(res, trusted.error);
      }
      const pepper = resolvePepperSeam({ pepperLookup, resolvePepperLookup });
      if (pepper === null) {
        return sendClassifiedError(
          res,
          new DeviceError(
            'WRITE_OUTCOME_UNCERTAIN',
            'No pairing lookup pepper is configured server-side; the ceremony fails closed',
          ),
        );
      }

      const read = await readDeviceByPublicKey({
        db,
        crypto,
        tenantId: trusted.tenantId,
        devicePublicKey: req.body.devicePublicKey,
      });
      if (read.error) {
        return sendClassifiedError(res, read.error);
      }

      const { pairingSessionService } = buildPairingServices({
        db,
        clock,
        crypto,
        logger,
        audit: auditFn,
        tenantContext,
        pepperLookup: pepper,
      });
      const issued = await pairingSessionService.issuePairingSession({
        tenantId: trusted.tenantId,
        deviceId: read.device.deviceId,
        deviceKeyId: read.device.deviceKeyId,
        challengeHash: req.body.challengeHash,
        domainTag,
        requestSource,
        proof: { signatureB64u: req.body.signatureB64u },
      });
      if (issued === null || typeof issued !== 'object' || issued.ok !== true) {
        return sendClassifiedError(res, issued?.error ?? uniformMiss());
      }
      if (!isSixDigitCode(issued.code)) {
        return sendClassifiedError(
          res,
          new DeviceError(
            'WRITE_OUTCOME_UNCERTAIN',
            'The issued pairing code is not a well-formed six-digit value; failing closed',
          ),
        );
      }
      return res.status(200).json({
        ok: true,
        code: issued.code,
        pairingSessionId: sessionIdOf(issued.pairingSession),
        state: isNonEmptyString(issued.pairingSession?.state)
          ? issued.pairingSession.state
          : 'open',
        expiresAt: issued.pairingSession?.expiresAt
          ? new Date(issued.pairingSession.expiresAt).toISOString()
          : null,
      });
    } catch {
      return sendFailClosed(res, 'Pairing issuance failed closed');
    }
  };
}

/**
 * `POST /api/devices/pairing/approve` — the frozen LP-2 redemption: resolves the submitted code
 * inside the authenticated tenant and binds `pendingOwnerId` to the authenticated owner. Grants no
 * authority.
 */
function createPairingApproveHandler(deps = {}) {
  const {
    db,
    tenantContext,
    clock = { now: () => Date.now() },
    crypto = deviceCrypto,
    logger = null,
    audit,
    pepperLookup,
    resolvePepperLookup,
  } = deps;
  assertHttpHandlerDependencies({ db, tenantContext, label: 'pairing approve handler' });

  const auditFn = createAuditAccessor({ db, logger, audit });

  return async function pairingApproveHandler(req, res) {
    try {
      if (
        guardRequestInput(req, res, {
          endpoint: 'Pairing approve',
          allowedBodyFields: APPROVE_FIELDS,
        })
      ) {
        return;
      }
      const trusted = resolveTrustedContext({ req, tenantContext });
      if (trusted.error) {
        return sendClassifiedError(res, trusted.error);
      }
      const pepper = resolvePepperSeam({ pepperLookup, resolvePepperLookup });
      if (pepper === null) {
        return sendClassifiedError(
          res,
          new DeviceError(
            'WRITE_OUTCOME_UNCERTAIN',
            'No pairing lookup pepper is configured server-side; the ceremony fails closed',
          ),
        );
      }

      const { pairingSessionService } = buildPairingServices({
        db,
        clock,
        crypto,
        logger,
        audit: auditFn,
        tenantContext,
        pepperLookup: pepper,
      });
      const redeemed = await pairingSessionService.redeemPairingCode({
        tenantId: trusted.tenantId,
        ownerId: trusted.principalId,
        code: req.body.code,
      });
      if (redeemed === null || typeof redeemed !== 'object' || redeemed.ok !== true) {
        return sendClassifiedError(res, redeemed?.error ?? uniformMiss());
      }
      return res.status(200).json({
        ok: true,
        pairingSessionId: sessionIdOf(redeemed.pairingSession),
        state: isNonEmptyString(redeemed.pairingSession?.state)
          ? redeemed.pairingSession.state
          : 'claim_pending',
        deviceKeyId: isNonEmptyString(redeemed.pairingSession?.deviceKeyId)
          ? redeemed.pairingSession.deviceKeyId
          : null,
        expiresAt: redeemed.pairingSession?.expiresAt
          ? new Date(redeemed.pairingSession.expiresAt).toISOString()
          : null,
      });
    } catch {
      return sendFailClosed(res, 'Pairing approval failed closed');
    }
  };
}

module.exports = {
  createPairingChallengeHandler,
  createPairingIssueHandler,
  createPairingApproveHandler,
  OPEN_CHALLENGE_PURPOSE,
};
