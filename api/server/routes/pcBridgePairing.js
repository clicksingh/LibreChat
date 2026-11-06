'use strict';
/**
 * Employee PC device pairing.
 * The web session issues a short-lived code. The PC redeems it once to obtain
 * ONLY its own tunnel connector credential. Cloudflare management stays here.
 */
const fs = require('fs');
const path = require('path');
const { Router } = require('express');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');
const { generateCheckAccess } = require('@librechat/api');
const { Permissions, PermissionTypes } = require('librechat-data-provider');
const { logger } = require('@librechat/data-schemas');
const { requireJwtAuth } = require('~/server/middleware');
const db = require('~/models');
const { getUserById } = db;
const { getMCPServersRegistry } = require('~/config');
const {
  createPCBridgeMCPServerController,
  deletePCBridgeMCPServerController,
} = require('~/server/controllers/mcp');
const { createPairingTickets } = require('~/server/services/PCBridge/pairingTickets');
const { createSessions } = require('~/server/services/PCBridge/sessions');
const { reinitMCPServer } = require('~/server/services/Tools/mcp');
const { createCloudflareServer } = require('~/server/services/PCBridge/cloudflareServer');

const router = Router();
const checkMCPUse = generateCheckAccess({
  permissionType: PermissionTypes.MCP_SERVERS,
  permissions: [Permissions.USE],
  getRoleByName: db.getRoleByName,
});
const limitUntrusted = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 18,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { message: 'Too many PC pairing attempts. Try again later.' },
});

const limitActivation = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 80,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
});

const limitHeartbeat = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 180,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
});

function fakeResponse() {
  return {
    statusCode: 200,
    payload: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.payload = payload;
      return this;
    },
  };
}

async function userForId(userId) {
  const doc = await getUserById(userId, '-password -__v -totpSecret -backupCodes');
  if (!doc) throw new Error('Pairing account no longer exists');
  const value = typeof doc.toObject === 'function' ? doc.toObject() : doc;
  return { ...value, id: userId };
}

async function register({ userId, url, bearerToken }) {
  const user = await userForId(userId);
  const response = fakeResponse();
  await createPCBridgeMCPServerController({ user, body: { url, bearerToken } }, response);
  if (response.statusCode !== 201 || !response.payload?.serverName) {
    const error = new Error('Native PC MCP registration failed');
    error.code = 'PC_MCP_REGISTRATION_FAILED';
    throw error;
  }
  return {
    serverName: response.payload.serverName,
    tools: response.payload.tools,
  };
}

async function refreshUserPCTools({ userId, serverName }) {
  const user = await userForId(userId);
  const config = await getMCPServersRegistry().getServerConfig(serverName, userId);
  if (!config || config.title !== 'CBHR PC' || config.type !== 'streamable-http') {
    throw new Error('PC MCP server no longer exists');
  }
  const result = await reinitMCPServer({
    user,
    serverName,
    serverConfig: config,
    returnOnOAuth: false,
  });
  if (!result?.success || !Array.isArray(result.tools)) {
    throw new Error('PC MCP tool rediscovery failed');
  }
  return result.tools.map((tool) => tool.name).filter((name) => typeof name === 'string');
}
async function unregister({ userId, serverName }) {
  const user = await userForId(userId);
  const response = fakeResponse();
  await deletePCBridgeMCPServerController({ user, params: { serverName } }, response);
  if (response.statusCode === 404) return;
  if (response.statusCode !== 200) {
    const error = new Error('Native PC MCP removal failed');
    error.code = 'PC_MCP_REMOVAL_FAILED';
    throw error;
  }
}

let loaded = null;
async function getServices() {
  if (!loaded) {
    loaded = (async () => {
      const database = mongoose.connection.db;
      if (!database) throw new Error('LibreChat database is unavailable');
      const provider = createCloudflareServer();
      const tickets = createPairingTickets({
        collection: database.collection('pcbridgepairingtickets'),
      });
      const sessions = createSessions({
        collection: database.collection('pcbridgepairingsessions'),
        tickets,
        provider,
        register,
        unregister,
        refresh: refreshUserPCTools,
        isRegistered: async ({ userId, serverName }) =>
          Boolean(await getMCPServersRegistry().getServerConfig(serverName, userId)),
      });
      await Promise.all([tickets.ensureIndexes(), sessions.ensureIndexes()]);
      return { tickets, sessions };
    })().catch((error) => {
      loaded = null;
      throw error;
    });
  }
  return loaded;
}

// Run cleanup independently of user traffic. It never runs without central
// provisioning configuration, and Mongo atomic state transitions prevent duplicate cleanup.
if (process.env.CBHR_PC_CF_API_TOKEN || process.env.CBHR_PC_CF_API_TOKEN_FILE) {
  const cleanupTimer = setInterval(async () => {
    try {
      const { sessions } = await getServices();
      await sessions.reap();
    } catch (error) {
      logger.warn('[PC Bridge] Session cleanup retry required:', error.code || error.name);
    }
  }, 60 * 1000);
  cleanupTimer.unref?.();
}

function fail(res, error) {
  const code = error?.code;
  if (code === 'PAIRING_PENDING_LIMIT' || code === 'PC_SESSION_EXISTS') {
    return res.status(409).json({ message: error.message });
  }
  if (code === 'PC_PORT_INVALID' || code === 'PC_BEARER_INVALID') {
    return res.status(400).json({ message: 'Invalid PC connection parameters' });
  }
  if (code === 'CF_NOT_CONFIGURED')
    return res.status(503).json({ message: 'PC connection service is not configured' });
  logger.error('[PC Bridge Pairing]', { code: code || error?.name || 'unknown' });
  return res.status(502).json({ message: 'PC connection could not be completed' });
}

/** Authenticated browser: download the signed Windows desktop bridge. */
router.get('/download/windows', requireJwtAuth, checkMCPUse, async (req, res) => {
  if (!req.user?.id) return res.status(401).json({ message: 'Unauthorized' });
  const releasePath = path.resolve(
    process.env.CBHR_PC_BRIDGE_WINDOWS_EXE_PATH || '/app/releases/CBHR-PC-Bridge-Desktop-1.1.1.exe',
  );
  try {
    const stat = await fs.promises.stat(releasePath);
    if (!stat.isFile()) throw new Error('not a file');
  } catch {
    logger.warn('[PC Bridge] Windows release artifact is unavailable');
    return res.status(404).json({ message: 'PC Bridge download is not available' });
  }
  res.setHeader('Cache-Control', 'private, no-store');
  res.setHeader('X-CBHR-PC-Bridge-Version', '1.1.1');
  return res.download(releasePath, 'CBHR-PC-Bridge-Desktop-1.1.1.exe');
});

/** Browser presence signal for attaching a newly paired PC to an existing chat. */
router.get('/status', requireJwtAuth, checkMCPUse, async (req, res) => {
  if (!req.user?.id) return res.status(401).json({ message: 'Unauthorized' });
  res.setHeader('Cache-Control', 'private, no-store');
  try {
    const { sessions } = await getServices();
    return res.status(200).json(await sessions.getUserStatus(String(req.user.id)));
  } catch (error) {
    return fail(res, error);
  }
});
/** Authenticated browser: create a 3-minute single-use code. */
router.post('/start', requireJwtAuth, checkMCPUse, async (req, res) => {
  if (!req.user?.id) return res.status(401).json({ message: 'Unauthorized' });
  try {
    const { tickets } = await getServices();
    return res.status(201).json(await tickets.issue({ userId: req.user.id }));
  } catch (error) {
    return fail(res, error);
  }
});

/** Desktop helper: redeem code for only this PC's scoped Cloudflare tunnel. */
router.post('/claim', limitUntrusted, async (req, res) => {
  try {
    const { sessions } = await getServices();
    const result = await sessions.claim({ code: req.body?.code, port: req.body?.port });
    if (!result) return res.status(401).json({ message: 'Invalid or expired pairing code' });
    return res.status(201).json(result);
  } catch (error) {
    return fail(res, error);
  }
});

/** Desktop helper: register once its secure tunnel is operational. */
router.post('/activate', limitActivation, async (req, res) => {
  try {
    const { sessions } = await getServices();
    const result = await sessions.activate(req.body || {});
    if (!result) return res.status(401).json({ message: 'Invalid or expired PC connection' });
    return res.status(200).json(result);
  } catch (error) {
    return fail(res, error);
  }
});

router.post('/refresh', limitActivation, async (req, res) => {
  try {
    const { sessions } = await getServices();
    const result = await sessions.refreshTools(req.body || {});
    return res.status(result ? 200 : 401).json(result || { message: 'PC session unavailable' });
  } catch (error) {
    return fail(res, error);
  }
});
router.post('/heartbeat', limitHeartbeat, async (req, res) => {
  try {
    const { sessions } = await getServices();
    const ok = await sessions.heartbeat(req.body || {});
    return res.status(ok ? 200 : 401).json({ connected: ok });
  } catch (error) {
    return fail(res, error);
  }
});

router.post('/disconnect', limitUntrusted, async (req, res) => {
  try {
    const { sessions } = await getServices();
    const ok = await sessions.disconnect(req.body || {});
    return res.status(ok ? 200 : 404).json({ disconnected: ok });
  } catch (error) {
    return fail(res, error);
  }
});

module.exports = router;
