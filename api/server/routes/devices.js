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
  createCurrentDeviceStatusHandler,
  createCurrentDeviceRenewHandler,
} = require('~/server/services/Device/currentDeviceHttpHandler');

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

const currentDeviceStatus = createCurrentDeviceStatusHandler({
  db,
  tenantContext,
});

const currentDeviceRenew = createCurrentDeviceRenewHandler({
  db,
  tenantContext,
});

router.use(requireJwtAuth);
router.post('/current/retire', retireCurrentOwnedDevice);
router.get('/current', currentDeviceStatus);
router.post('/current/renew', currentDeviceRenew);
router.post('/pairing/challenge', pairingChallenge);
router.post('/pairing/issue', pairingIssue);
router.post('/pairing/approve', pairingApprove);

module.exports = router;
