const express = require('express');
const { getTenantId } = require('@librechat/data-schemas');
const requireJwtAuth = require('~/server/middleware/requireJwtAuth');
const db = require('~/db/models');
const {
  createOwnerCurrentRetireHandler,
} = require('~/server/services/Device/ownerCurrentRetireHandler');

const router = express.Router();

const tenantContext = Object.freeze({
  getActiveTenantId: getTenantId,
  alsAbsencePermitted: false,
});

const retireCurrentOwnedDevice = createOwnerCurrentRetireHandler({
  db,
  tenantContext,
});

router.use(requireJwtAuth);
router.post('/current/retire', retireCurrentOwnedDevice);

module.exports = router;
