const express = require('express');
const mongoose = require('mongoose');
const { logger, runAsSystem } = require('@librechat/data-schemas');
const db = require('../../models');
const { invalidateConfigCaches } = require('../services/Config');
const {
  createModelPolicyServiceAuth,
  fileTokenLoader,
} = require('../middleware/modelPolicyServiceAuth');
const { publishModelPolicyProjection } = require('../services/Config/modelPolicyPublisher');

function defaultPublisher(input) {
  return runAsSystem(() =>
    commitManagedModelPolicy(input, {
      findConfigByPrincipal: db.findConfigByPrincipal,
      patchConfigFields: db.patchConfigFields,
      commitModelPolicyRevision: db.commitModelPolicyRevision,
      invalidateConfigCaches,
      startSession: () => mongoose.startSession(),
    }),
  );
}

function createModelPolicyInternalApp({ loadExpectedToken, publish = defaultPublisher } = {}) {
  if (typeof loadExpectedToken !== 'function') {
    throw new TypeError('loadExpectedToken is required');
  }
  if (typeof publish !== 'function') {
    throw new TypeError('publish is required');
  }

  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '64kb' }));
  app.use(createModelPolicyServiceAuth({ loadExpectedToken }));

  app.post('/publish', async (req, res) => {
    try {
      const result = await publish(req.body);
      return res.status(200).json({
        ok: true,
        policyVersion: result.policyVersion,
        policyNoop: result.policyNoop,
        transition: result.transition,
        noop: result.noop,
        writes: result.writes,
      });
    } catch (error) {
      const status =
        Number.isInteger(error?.status) && error.status >= 400 && error.status < 500
          ? error.status
          : 500;
      if (status >= 500) {
        logger.error('[modelPolicyInternal] publish failed', {
          code: error?.code,
          message: error?.message,
        });
      }
      return res.status(status).json({
        ok: false,
        code: error?.code || 'MODEL_POLICY_PUBLICATION_FAILED',
        error: status >= 500 ? 'Model policy publication failed' : error.message,
      });
    }
  });

  return app;
}

function startModelPolicyInternalServer({
  port = Number(process.env.MODEL_POLICY_INTERNAL_PORT || 0),
  host = process.env.MODEL_POLICY_INTERNAL_HOST || '0.0.0.0',
  tokenFile = process.env.MODEL_POLICY_SERVICE_TOKEN_FILE,
} = {}) {
  if (!Number.isInteger(port) || port <= 0 || port > 65535 || !tokenFile) {
    return Promise.resolve(null);
  }

  const app = createModelPolicyInternalApp({
    loadExpectedToken: fileTokenLoader(tokenFile),
  });

  return new Promise((resolve, reject) => {
    const server = app.listen(port, host, () => {
      logger.info('[modelPolicyInternal] internal publisher listening', { host, port });
      resolve(server);
    });
    server.once('error', reject);
  });
}

module.exports = {
  createModelPolicyInternalApp,
  startModelPolicyInternalServer,
};
