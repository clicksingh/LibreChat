'use strict';

/**
 * Device-authenticated pairing completion (`POST /api/devices/pairing/complete`).
 *
 * OWNER-AUTHORIZED SCOPE (GM-2 ruling, docs/GM-R3-FRICTION-FREE-FLOW-RULINGS-20261023.md;
 * LOCAL LAB ONLY; production G0 remains BLOCKED). This closes the claim leg the LP-2 approval
 * deliberately left open: `pairing/approve` stops at `claim_pending` and grants nothing, so before
 * this handler an employee could approve forever and never receive a working PC.
 *
 * WHO CALLS IT
 * The enrolled endpoint (the employee's PC), not the browser. It is therefore mounted WITHOUT
 * `requireJwtAuth` (see `routes/devices.js`); every other device route keeps that middleware. The
 * endpoint polls this route while the six-digit code is on screen: the poll that lands after the
 * employee approves in the browser is the one that receives the 48h lease. The employee performs
 * exactly one action — typing the code.
 *
 * TRUST MODEL
 * - The caller is authenticated by its OWN Ed25519 key material only. There is no session, no
 *   cookie, no bearer token and no server-side "who is this" table: possession of the private key
 *   is proven per the frozen ceremony (server-minted single-use 256-bit challenge with the frozen
 *   domain tag `cbhr:device:pairing-complete:v1`; the endpoint signs the canonical message over the
 *   server's own `issuedAt`; the accepted service verifies the signature against the DB-stored
 *   public key).
 * - Identity is resolved server-side from the key thumbprint (`crypto.thumbprintB64u`) to a
 *   tenant-scoped `DeviceAuthority` row, exactly as `pairing/issue` does. A raw `deviceId`,
 *   `sessionId`, `ownerId`, `tenantId`, `epoch`, `grantId` or any other identity/authority field in
 *   the request is rejected with 400 `REQUEST_SUPPLIED_IDENTITY_REJECTED` BEFORE any model call
 *   (`deviceHttpTrust.guardRequestInput`), so an injected container can never reach a query.
 * - The owner is the session's server-recorded `pendingOwnerId` (bound by the authenticated LP-2
 *   approval). The pairing session is the device's own `claim_pending` session. Neither is read
 *   from the request.
 * - The endpoint's signature over the server-armed `pairing-claim` challenge IS the endpoint-local
 *   approval required by the frozen claim order (device PoP -> local endpoint consent -> challenge
 *   spend -> session consume -> authority claim): the browser session cannot produce it, which is
 *   exactly GM-12's "renewal/claim approval is LOCAL" boundary. The injected consent verifier
 *   echoes only the server-observed session truth the accepted service hands it and invents no
 *   identity.
 *
 * SERVICE LEGS (reused unchanged — no new protocol semantics)
 * - LP-3: `pairingSessionService.mintPairingClaimChallenge` (arm the single-use claim challenge)
 *   and `pairingSessionService.approvePairingClaim` (device PoP -> consent -> challenge spend ->
 *   session `claim_pending` -> `consumed`).
 * - LP-4: `authorityService.claimAuthority`, invoked by `approvePairingClaim` itself, exactly as
 *   the E1 product fixtures drive it (`tests/device/e1/product/crash.cjs` crash points c3/c4 and
 *   `tests/device/e1/product/context.cjs` + `tests/device/e1/w3a/support.cjs`
 *   `runPairingCeremony`).
 *
 * IDEMPOTENCY (hard requirement)
 * - A device that already holds a LIVE lease reports it with 200 and its current state; it never
 *   receives an error. A double-poll, a retried request or a flaky network can therefore never
 *   strand an employee mid-pairing.
 * - While the browser has not approved yet, the poll answers 200 `state:'awaiting_approval'` and
 *   writes nothing.
 * - A half-supplied proof (only one of `challengeHash` / `signatureB64u`) is a protocol error
 *   answered with the uniform miss, never with a write.
 *
 * RESPONSE CONTRACT
 * - 200 `{ok:true, state:'active', deviceId, epoch, expiresAt, leaseState}` — the claim committed
 *   (or was already committed). `epoch`/`expiresAt`/`leaseState` are the server row's values.
 * - 200 `{ok:true, state:'claim_ready', deviceId, epoch, expiresAt, leaseState, challengeHash,
 *   issuedAt, signingMessageB64u, challengeExpiresAt}` — a single-use claim challenge is armed; the
 *   endpoint must sign the exact canonical bytes and POST them back. `signingMessageB64u` is the
 *   base64url canonical preimage (never a secret: the device must sign exactly these bytes).
 * - 200 `{ok:true, state:'awaiting_approval', deviceId, epoch, expiresAt, leaseState}` — the code
 *   has not been approved in the browser yet; nothing was written.
 * - 400 `REQUEST_SUPPLIED_IDENTITY_REJECTED` — the request carried identity/authority input.
 * - 400 `INVALID_OR_EXPIRED_CODE` — the uniform miss (unknown key, unusable challenge, failed
 *   proof, no claimable session).
 * - 404 `UNKNOWN_DEVICE` / 409 `DEVICE_IDENTITY_REVOKED` — no usable registered identity.
 * - 500 `WRITE_OUTCOME_UNCERTAIN` / `AUDIT_DELIVERY_UNCERTAIN` — a genuinely uncertain write.
 *   `AUDIT_DELIVERY_UNCERTAIN` carries `committed:true` only when the lease is provably live.
 * - The plaintext six-digit code, private keys, peppers, `lookupTag`, `grantProof`, tickets and the
 *   plaintext challenge nonce are NEVER returned, persisted or logged by this layer.
 *
 * TENANT RESOLUTION — the only seam this local lab needs
 * The accepted services require a trusted tenant context (`getActiveTenantId()`) that agrees with
 * the tenant they are asked to act in. This route is not session-authenticated, so when the ALS
 * tenant is absent (no `requireJwtAuth` -> no `tenantContextMiddleware`) the tenant is resolved
 * from server truth instead: the `DeviceAuthority` row found by the key thumbprint, which is
 * itself unique per `{tenantId, deviceKeyId}`. The lookup then refuses to continue unless exactly
 * one row matches across tenants, so an ambiguous key can never pick a tenant. When the ALS tenant
 * IS present it always wins and a row from another tenant is simply invisible (404). No request
 * field can influence the tenant.
 */

const deviceCrypto = require('./crypto');
const { createAuthorityService } = require('./authorityService');
const { createPairingSessionService } = require('./pairingSessionService');
const { DeviceError } = require('./errors');
const { readAnchorNowMs, assertPredicateAnchorShape, createClockSkewGuard } = require('./databaseTime');
const {
  assertHttpHandlerDependencies,
  createAuditAccessor,
  guardRequestInput,
  isNonEmptyString,
  sendClassifiedError,
  sendFailClosed,
  toIsoOrNull,
  toObservedEpoch,
} = require('./deviceHttpTrust');

/** The frozen claim-challenge purpose of the accepted pairing service. */
const CLAIM_CHALLENGE_PURPOSE = 'pairing-claim';
/** The frozen system tenant: never a usable authority tenant (mirrors `deviceHttpTrust`). */
const SYSTEM_TENANT_ID = '__SYSTEM__';

/**
 * Frozen request-field allowlist: flat strings only. Everything else — including every identity
 * and authority field — is rejected before any model method is touched.
 */
const COMPLETE_FIELDS = Object.freeze(['devicePublicKey', 'challengeHash', 'signatureB64u']);

function uniformMiss() {
  return new DeviceError('INVALID_OR_EXPIRED_CODE', 'The supplied device values cannot be used');
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

/**
 * True when the row carries a lease that is still live at `serverNow` (identity included).
 *
 * GM-44 site 11 (MARGIN-FREE): `serverNow` MUST be database time. This is the idempotency and
 * committed-lease test, and reading the writer's clock here let a writer skewed by the full budget
 * treat a live lease as absent.
 */
function isLiveLease(row, serverNow) {
  const expiresAt = toMillis(row?.expiresAt);
  return (
    row?.leaseState === 'active' &&
    row?.identityState !== 'retired' &&
    expiresAt !== null &&
    expiresAt > serverNow
  );
}

/** Safe lease summary: no key material, no lookupTag, no grantId, no grantProof, no lineage. */
function leaseSummary(row, deviceId, state) {
  return {
    ok: true,
    state,
    deviceId,
    epoch: toObservedEpoch(row?.epoch),
    expiresAt: toIsoOrNull(row?.expiresAt),
    leaseState: isNonEmptyString(row?.leaseState) ? row.leaseState : null,
  };
}

/**
 * Resolves the trusted ALS tenant. `null` means "no ALS tenant is active", which the caller turns
 * into a server-truth tenant resolution from the device row. `__SYSTEM__` is never usable.
 */
function resolveActiveTenantId({ tenantContext }) {
  if (
    tenantContext === null ||
    typeof tenantContext !== 'object' ||
    typeof tenantContext.getActiveTenantId !== 'function'
  ) {
    return {
      tenantId: null,
      error: new DeviceError('TENANT_MISMATCH', 'Trusted tenant context is not configured'),
    };
  }
  let active;
  try {
    active = tenantContext.getActiveTenantId();
  } catch {
    return {
      tenantId: null,
      error: new DeviceError('TENANT_MISMATCH', 'Tenant context lookup failed closed'),
    };
  }
  if (active === null || active === undefined || active === '') {
    return { tenantId: null, error: null };
  }
  if (!isNonEmptyString(active) || active === SYSTEM_TENANT_ID) {
    return {
      tenantId: null,
      error: new DeviceError(
        'TENANT_MISMATCH',
        'No authenticated tenant is active for this request',
      ),
    };
  }
  return { tenantId: active, error: null };
}

function identityMismatch() {
  return new DeviceError(
    'UNKNOWN_DEVICE',
    'No registered device identity matches the supplied endpoint key in this tenant',
  );
}

/**
 * Resolves the device identity from endpoint key material only.
 *
 * The public key is thumbprinted server-side and the row is read by `{tenantId, deviceKeyId}` when
 * an ALS tenant is active. Without an ALS tenant the same thumbprint is looked up across tenants
 * and the request fails closed unless EXACTLY one row matches, so the tenant can never be chosen by
 * ambiguity. The supplied key is never treated as identity and a raw `deviceId` is never accepted.
 *
 * @returns {Promise<{device: (null|{deviceId: string, deviceKeyId: string, tenantId: string}),
 *   error: (DeviceError|null)}>}
 */
async function readDeviceByIdentity({ db, crypto, tenantId, devicePublicKey }) {
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

  let row = null;
  try {
    if (tenantId !== null) {
      row = await db.DeviceAuthority.findOne({ tenantId, deviceKeyId }).lean();
    } else {
      const rows = await db.DeviceAuthority.find({ deviceKeyId }).limit(2).lean();
      if (!Array.isArray(rows) || rows.length !== 1) {
        // 0 matches: unknown key. 2+ matches across tenants: ambiguous, fail closed.
        return { device: null, error: identityMismatch() };
      }
      row = rows[0];
    }
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
    !isNonEmptyString(row.tenantId) ||
    row.tenantId === SYSTEM_TENANT_ID ||
    row.deviceKeyId !== deviceKeyId ||
    row.devicePublicKey !== devicePublicKey ||
    !isNonEmptyString(deviceId) ||
    (tenantId !== null && row.tenantId !== tenantId)
  ) {
    return { device: null, error: identityMismatch() };
  }
  return {
    device: { deviceId, deviceKeyId, tenantId: row.tenantId },
    error: null,
  };
}

/** Reads the device's own claimable session (tenant + device scoped). Never a request value. */
async function readClaimPendingSession({ db, tenantId, deviceId, deviceKeyId }) {
  let row;
  try {
    row = await db.PairingSession.findOne({
      tenantId,
      deviceId,
      deviceKeyId,
      state: 'claim_pending',
    }).lean();
  } catch {
    return {
      session: null,
      error: new DeviceError(
        'WRITE_OUTCOME_UNCERTAIN',
        'Pairing session read failed; failing closed',
      ),
    };
  }
  if (row === null || row === undefined) {
    return { session: null, error: null };
  }
  return { session: row, error: null };
}

/** Reads back the server-minted challenge row (authoritative `issuedAt`/`expiresAt`). */
async function readChallengeRow({ db, challengeHash, purpose, tenantId, deviceId }) {
  let row;
  try {
    row = await db.Challenge.findOne({ challengeHash, purpose, tenantId, deviceId }).lean();
  } catch {
    return {
      row: null,
      error: new DeviceError(
        'WRITE_OUTCOME_UNCERTAIN',
        'Pairing challenge read failed; failing closed',
      ),
    };
  }
  return { row: row ?? null, error: null };
}

/**
 * The canonical claim-challenge preimage the endpoint must sign. Field order and purpose literal
 * mirror the accepted `pairingSessionService.buildClaimChallengeMessage` exactly; the domain tag is
 * this route's frozen `cbhr:device:pairing-complete:v1` and is injected, never hard-coded here.
 * The end-to-end tests prove equivalence: a signature over THESE bytes is accepted by the accepted
 * service's own verifier.
 */
function buildClaimSigningMessage({
  crypto,
  tenantId,
  ownerId,
  deviceId,
  deviceKeyId,
  challengeHash,
  pairingSessionId,
  issuedAt,
  domainTag,
}) {
  if (!isNonEmptyString(issuedAt) || !/^\d+$/.test(issuedAt)) {
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
 * Server-owned endpoint-local approval seam.
 *
 * GM-12 makes claim/renewal approval LOCAL: the endpoint's signature over the server-armed claim
 * challenge is the employee's local approval, and a browser session cannot mint it. The accepted
 * service hands this verifier ONLY server-observed session truth, so echoing it back invents no
 * identity and can only ever approve the session the service is currently claiming.
 */
function createEndpointSignatureConsent({ clock, crypto }) {
  return async function verifyEndpointLocalConsent(input) {
    const signature = input?.proof?.signatureB64u;
    if (!isNonEmptyString(signature)) {
      return { approved: false };
    }
    const approvedAt = clock.now();
    if (!Number.isFinite(approvedAt)) {
      return { approved: false };
    }
    let localApprovalNonceHash;
    try {
      localApprovalNonceHash = crypto.sha256B64u(signature);
    } catch {
      return { approved: false };
    }
    return {
      approved: true,
      approvedAt,
      localApprovalNonceHash,
      boundTenantId: input.tenantId,
      boundOwnerId: input.ownerId,
      boundDeviceId: input.deviceId,
      boundPairingSessionId: input.pairingSessionId,
      boundChallengeRef: input.challengeRef ?? null,
    };
  };
}

/**
 * Builds the accepted services for one request with server-owned seams only. Construction happens
 * per request (the retire-handler pattern) so a misconfigured model surface fails closed inside the
 * request instead of at module load.
 */
function buildPairingServices({
  db,
  clock,
  crypto,
  logger,
  audit,
  tenantContext,
  tenantId,
  predicateAnchor,
}) {
  // The tenant seam is pinned to the server-resolved tenant for this request. Both accepted
  // services require the trusted context to agree with the tenant they act in; the value is
  // server-resolved (ALS first, otherwise the unique device row) and never request-derived.
  const requestTenantContext = Object.freeze({
    getActiveTenantId: () => tenantId,
    alsAbsencePermitted: false,
  });
  const authorityService = createAuthorityService({
    db,
    clock,
    crypto,
    logger,
    audit,
    tenantContext: requestTenantContext,
    // GM-65: the test anchor rides along so the claim CAS decides against the same timeline.
    predicateAnchor,
    // GM-44 rule 3: the claim CAS refuses to write when this host cannot prove its clock.
    clockSkewGuard: createClockSkewGuard({ db, logger }),
    verifyRenewalProof: async () => ({ ok: false }),
  });
  const pairingSessionService = createPairingSessionService({
    db,
    clock,
    crypto,
    logger,
    audit,
    authorityService,
    tenantContext: requestTenantContext,
    // GM-65: the test anchor rides along so the claim CAS decides against the same timeline.
    predicateAnchor,
    verifyLocalConsent: createEndpointSignatureConsent({ clock, crypto }),
  });
  return { authorityService, pairingSessionService };
}

/**
 * `POST /api/devices/pairing/complete` — device-authenticated claim pickup (GM-2).
 *
 * Two legs on one route, disambiguated by the presence of the proof fields:
 *   - no `challengeHash`/`signatureB64u` -> arm (or re-report) the single-use claim challenge;
 *   - both present                       -> verify the proof and run the accepted LP-3 + LP-4.
 * A device that already holds a live lease from this ceremony always gets 200 + current state.
 */
function createPairingCompleteHandler(deps = {}) {
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
  assertHttpHandlerDependencies({ db, tenantContext, label: 'pairing complete handler' });
  if (!isNonEmptyString(domainTag)) {
    throw new TypeError('pairing complete handler requires the frozen canonical domain tag seam');
  }
  // GM-64/GM-65: the test-only comparison anchor (shape-validated here, resolved per predicate).
  assertPredicateAnchorShape(predicateAnchor);

  const auditFn = createAuditAccessor({ db, logger, audit });

  /**
   * GM-44: the DATABASE clock for every lease-state predicate in this handler (`null` ⇒ refuse).
   * A GM-65 test anchor stands in for the server clock when one is supplied.
   */
  async function databaseNow() {
    const nowMs = await readAnchorNowMs(db, predicateAnchor);
    return Number.isFinite(nowMs) ? nowMs : null;
  }

  async function armLeg({ res, device, now }) {
    const { tenantId, deviceId, deviceKeyId } = device;
    const sessionRead = await readClaimPendingSession({ db, tenantId, deviceId, deviceKeyId });
    if (sessionRead.error) {
      return sendClassifiedError(res, sessionRead.error);
    }
    const session = sessionRead.session;
    if (session === null) {
      // Nothing approved yet (or the ceremony already moved past `claim_pending` without a live
      // lease). Report state truthfully and write nothing: the poll simply repeats.
      const row = await readAuthorityRow({ db, tenantId, deviceId });
      if (row.error) {
        return sendClassifiedError(res, row.error);
      }
      return res.status(200).json(leaseSummary(row.row, deviceId, 'awaiting_approval'));
    }

    const ownerId = session.pendingOwnerId;
    if (!isNonEmptyString(ownerId)) {
      return sendClassifiedError(
        res,
        new DeviceError(
          'WRITE_OUTCOME_UNCERTAIN',
          'The pending pairing session carries no approved owner; failing closed',
        ),
      );
    }
    const pairingSessionId = String(session._id);

    const armedRef =
      session.claim !== null && typeof session.claim === 'object'
        ? session.claim.challengeRef
        : null;

    let challengeHash;
    let issuedAtMs;
    let challengeExpiresAt;

    if (isNonEmptyString(armedRef)) {
      // Idempotent re-poll: the session already has its one armed challenge. Re-report it instead
      // of minting a second one (a session may have only one armed claim challenge).
      const read = await readChallengeRow({
        db,
        challengeHash: armedRef,
        purpose: CLAIM_CHALLENGE_PURPOSE,
        tenantId,
        deviceId,
      });
      if (read.error) {
        return sendClassifiedError(res, read.error);
      }
      const row = read.row;
      const issued = toMillis(row?.issuedAt);
      const expires = toMillis(row?.expiresAt);
      if (
        row === null ||
        row.consumedAt !== null ||
        issued === null ||
        expires === null ||
        expires <= now
      ) {
        return sendClassifiedError(
          res,
          new DeviceError(
            'PAIRING_CEREMONY_STALE',
            'The armed claim challenge is no longer usable; a fresh pairing code is required',
          ),
          { deviceId },
        );
      }
      challengeHash = armedRef;
      issuedAtMs = issued;
      challengeExpiresAt = expires;
    } else {
      const { pairingSessionService } = buildPairingServices({
        db,
        clock,
        crypto,
        logger,
        audit: auditFn,
        tenantContext,
        tenantId,
        predicateAnchor,
      });
      const minted = await pairingSessionService.mintPairingClaimChallenge({
        pairingSessionId,
        tenantId,
        ownerId,
      });
      if (minted === null || typeof minted !== 'object' || minted.ok !== true) {
        return sendClassifiedError(res, minted?.error ?? uniformMiss(), { deviceId });
      }
      const read = await readChallengeRow({
        db,
        challengeHash: minted.challengeHash,
        purpose: CLAIM_CHALLENGE_PURPOSE,
        tenantId,
        deviceId,
      });
      if (read.error) {
        return sendClassifiedError(res, read.error);
      }
      const issued = toMillis(read.row?.issuedAt);
      const expires = toMillis(read.row?.expiresAt);
      if (read.row === null || issued === null || expires === null) {
        return sendClassifiedError(
          res,
          new DeviceError(
            'WRITE_OUTCOME_UNCERTAIN',
            'The minted claim challenge is not readable as server truth; failing closed',
          ),
        );
      }
      challengeHash = minted.challengeHash;
      issuedAtMs = issued;
      challengeExpiresAt = expires;
    }

    const message = buildClaimSigningMessage({
      crypto,
      tenantId,
      ownerId,
      deviceId,
      deviceKeyId,
      challengeHash,
      pairingSessionId,
      issuedAt: String(issuedAtMs),
      domainTag,
    });
    if (message === null) {
      return sendClassifiedError(
        res,
        new DeviceError(
          'WRITE_OUTCOME_UNCERTAIN',
          'The claim preimage could not be built; failing closed',
        ),
      );
    }

    const row = await readAuthorityRow({ db, tenantId, deviceId });
    if (row.error) {
      return sendClassifiedError(res, row.error);
    }
    return res.status(200).json({
      ...leaseSummary(row.row, deviceId, 'claim_ready'),
      challengeHash,
      issuedAt: String(issuedAtMs),
      signingMessageB64u: message.toString('base64url'),
      challengeExpiresAt: toIsoOrNull(new Date(challengeExpiresAt)),
    });
  }

  async function completeLeg({ res, body, device, now }) {
    const { tenantId, deviceId, deviceKeyId } = device;
    const sessionRead = await readClaimPendingSession({ db, tenantId, deviceId, deviceKeyId });
    if (sessionRead.error) {
      return sendClassifiedError(res, sessionRead.error);
    }
    const session = sessionRead.session;
    if (session === null || !isNonEmptyString(session.pendingOwnerId)) {
      return sendClassifiedError(res, uniformMiss());
    }

    const { pairingSessionService } = buildPairingServices({
      db,
      clock,
      crypto,
      logger,
      audit: auditFn,
      tenantContext,
      tenantId,
      predicateAnchor,
    });
    const result = await pairingSessionService.approvePairingClaim({
      pairingSessionId: String(session._id),
      tenantId,
      ownerId: session.pendingOwnerId,
      domainTag,
      localConsent: null,
      proof: {
        challengeHash: body.challengeHash,
        signatureB64u: body.signatureB64u,
      },
    });

    const authority = result !== null && typeof result === 'object' ? result.authority : null;
    if (result !== null && typeof result === 'object' && result.ok === true && authority) {
      return res.status(200).json(leaseSummary(authority, deviceId, 'active'));
    }

    const error =
      result !== null && typeof result === 'object' && result.error
        ? result.error
        : uniformMiss();

    // A committed lease whose audit delivery is uncertain is REAL and must never be reported as a
    // no-op: the device holds the lease and the employee is not stranded. GM-44 site 11: the
    // liveness test is DATABASE time; without it the committed lease is simply reported as
    // "not provably live" and the request falls through to the error envelope.
    const serverNow = await databaseNow();
    const liveAfter = serverNow !== null && isLiveLease(authority, serverNow);
    if (liveAfter) {
      const committedError =
        error.code === 'AUDIT_DELIVERY_UNCERTAIN'
          ? error
          : new DeviceError(
              'AUDIT_DELIVERY_UNCERTAIN',
              'The device claim committed but audit delivery is uncertain',
            );
      return sendClassifiedError(res, committedError, {
        committed: true,
        deviceId,
        epoch: toObservedEpoch(authority?.epoch),
        expiresAt: toIsoOrNull(authority?.expiresAt),
        leaseState: isNonEmptyString(authority?.leaseState) ? authority.leaseState : null,
      });
    }

    // Late idempotency re-read: a concurrent poll (or a lost acknowledgement) may have landed the
    // lease after this request's own pre-check. A live lease is a success, never an error.
    const fresh = await readAuthorityRow({ db, tenantId, deviceId });
    const freshNow = fresh.error === null ? await databaseNow() : null;
    if (fresh.error === null && freshNow !== null && isLiveLease(fresh.row, freshNow)) {
      return res.status(200).json(leaseSummary(fresh.row, deviceId, 'active'));
    }

    const row = fresh;
    return sendClassifiedError(res, error, {
      committed: false,
      deviceId,
      epoch: toObservedEpoch(row.row?.epoch),
      expiresAt: toIsoOrNull(row.row?.expiresAt),
      leaseState: isNonEmptyString(row.row?.leaseState) ? row.row.leaseState : null,
    });
  }

  return async function pairingCompleteHandler(req, res) {
    try {
      if (
        guardRequestInput(req, res, {
          endpoint: 'Pairing complete',
          allowedBodyFields: COMPLETE_FIELDS,
        })
      ) {
        return;
      }

      const active = resolveActiveTenantId({ tenantContext });
      if (active.error) {
        return sendClassifiedError(res, active.error);
      }

      const body = req.body !== null && typeof req.body === 'object' ? req.body : {};
      const hasChallenge = isNonEmptyString(body.challengeHash);
      const hasSignature = isNonEmptyString(body.signatureB64u);
      if (hasChallenge !== hasSignature) {
        // Half a proof is a protocol error, never a partial write.
        return sendClassifiedError(res, uniformMiss());
      }

      const now = clock.now();
      if (!Number.isFinite(now)) {
        return sendClassifiedError(
          res,
          new DeviceError('WRITE_OUTCOME_UNCERTAIN', 'Injected clock returned a non-finite time'),
        );
      }

      const read = await readDeviceByIdentity({
        db,
        crypto,
        tenantId: active.tenantId,
        devicePublicKey: body.devicePublicKey,
      });
      if (read.error) {
        return sendClassifiedError(res, read.error);
      }
      const device = read.device;

      const current = await readAuthorityRow({
        db,
        tenantId: device.tenantId,
        deviceId: device.deviceId,
      });
      if (current.error) {
        return sendClassifiedError(res, current.error);
      }
      if (current.row === null) {
        return sendClassifiedError(res, identityMismatch());
      }
      if (current.row.identityState === 'retired') {
        return sendClassifiedError(
          res,
          new DeviceError('DEVICE_IDENTITY_REVOKED', 'Device identity is retired'),
        );
      }

      // IDEMPOTENCY: a live lease from this ceremony means the claim already landed. Report it.
      // GM-44 site 11: database time decides, so a fast writer cannot mistake a live lease for an
      // absent one (and a slow writer cannot mistake an expired one for live).
      const idempotencyNow = await databaseNow();
      if (idempotencyNow !== null && isLiveLease(current.row, idempotencyNow)) {
        return res.status(200).json(leaseSummary(current.row, device.deviceId, 'active'));
      }

      if (!hasChallenge) {
        return await armLeg({ res, device, now });
      }
      return await completeLeg({ res, body, device, now });
    } catch {
      return sendFailClosed(res, 'Pairing completion failed closed');
    }
  };
}

/** Tenant-scoped authority read (plain model read; never a request value). */
async function readAuthorityRow({ db, tenantId, deviceId }) {
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

module.exports = {
  createPairingCompleteHandler,
  createEndpointSignatureConsent,
  buildClaimSigningMessage,
  readDeviceByIdentity,
  resolveActiveTenantId,
  CLAIM_CHALLENGE_PURPOSE,
  COMPLETE_FIELDS,
};
