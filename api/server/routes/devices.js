const express = require('express');
const { getTenantId } = require('@librechat/data-schemas');
const requireJwtAuth = require('~/server/middleware/requireJwtAuth');
const db = require('~/db/models');
const {
  createOwnerCurrentRetireHandler,
} = require('~/server/services/Device/ownerCurrentRetireHandler');
const {
  createPairingChallengeHandler,
  createPairingIssueHandler,
  createPairingApproveHandler,
} = require('~/server/services/Device/pairingHttpHandler');
const {
  createPairingCompleteHandler,
} = require('~/server/services/Device/pairingCompleteHttpHandler');
const {
  createCurrentDeviceStatusHandler,
} = require('~/server/services/Device/currentDeviceHttpHandler');
const {
  createCurrentDeviceRenewEnvelopeHandler,
} = require('~/server/services/Device/currentDeviceRenewEnvelopeHandler');

const router = express.Router();

const tenantContext = Object.freeze({
  getActiveTenantId: getTenantId,
  alsAbsencePermitted: false,
});

/**
 * Frozen canonical domain separators are injected from this server-owned route module; the accepted
 * services never hard-code them. Values mirror the accepted E1 ceremony constants.
 */
const PAIRING_OPEN_DOMAIN = 'cbhr:device:pairing-open:v1';
/** GM-2: the device-authenticated claim pickup (LP-3 + LP-4). */
const PAIRING_COMPLETE_DOMAIN = 'cbhr:device:pairing-complete:v1';
/** GM-3 / GM-12: the device-signed renewal envelope (CBHR-RENEW-V1). */
const RENEWAL_DOMAIN = 'cbhr:device:renew:v1';
/** Server-derived issuance source descriptor; the service hashes it and never persists an IP. */
const PAIRING_ISSUE_SOURCE = 'local-lab:device-pairing-issue';

const retireCurrentOwnedDevice = createOwnerCurrentRetireHandler({
  db,
  tenantContext,
});

const pairingChallenge = createPairingChallengeHandler({
  db,
  tenantContext,
  domainTag: PAIRING_OPEN_DOMAIN,
});

const pairingIssue = createPairingIssueHandler({
  db,
  tenantContext,
  domainTag: PAIRING_OPEN_DOMAIN,
  requestSource: PAIRING_ISSUE_SOURCE,
});

const pairingApprove = createPairingApproveHandler({
  db,
  tenantContext,
});

const pairingComplete = createPairingCompleteHandler({
  db,
  tenantContext,
  domainTag: PAIRING_COMPLETE_DOMAIN,
});

const currentDeviceStatus = createCurrentDeviceStatusHandler({
  db,
  tenantContext,
});

const currentDeviceRenew = createCurrentDeviceRenewEnvelopeHandler({
  db,
  tenantContext,
  domainTag: RENEWAL_DOMAIN,
});

/**
 * `POST /api/devices/pairing/complete` is DEVICE-authenticated, not session-authenticated: the
 * caller is the enrolled endpoint proving possession of its own Ed25519 key over a server-minted
 * single-use challenge, and the accepted LP-3/LP-4 legs resolve tenant, owner and device identity
 * server-side from that key's thumbprint. It therefore must be registered BEFORE the router-level
 * `requireJwtAuth` gate, and it must stay the ONLY route outside that gate: the browser/panel
 * endpoints below keep it.
 */
router.post('/pairing/complete', pairingComplete);

router.use(requireJwtAuth);
router.post('/current/retire', retireCurrentOwnedDevice);
router.get('/current', currentDeviceStatus);
router.post('/current/renew', currentDeviceRenew);
router.post('/pairing/challenge', pairingChallenge);
router.post('/pairing/issue', pairingIssue);
router.post('/pairing/approve', pairingApprove);

module.exports = router;
