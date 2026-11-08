'use strict';
const crypto = require('node:crypto');
const { registerWhenReady, publicMCPReachable } = require('./readiness');

const CLAIM_WINDOW_MS = 10 * 60 * 1000;
const ACTIVE_HEARTBEAT_WINDOW_MS = 5 * 60 * 1000;
const PURGE_MS = 7 * 24 * 60 * 60 * 1000;
const LIVE_STATES = ['claimed', 'activating', 'active', 'disconnecting', 'cleanup_pending'];

async function publicDnsReady(hostname, fetcher = fetch) {
  try {
    const response = await fetcher(
      'https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(hostname) + '&type=A',
      {
        headers: { Accept: 'application/dns-json' },
        signal: AbortSignal.timeout(5000),
      },
    );
    const payload = await response.json();
    return Boolean(
      response.ok &&
        payload?.Status === 0 &&
        Array.isArray(payload.Answer) &&
        payload.Answer.some((answer) => answer?.type === 1),
    );
  } catch {
    return false;
  }
}

function hashSecret(secret) {
  return crypto
    .createHash('sha256')
    .update('cbhr-pc-session-v1:' + secret)
    .digest('hex');
}

function normalizeDeviceName(value) {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value !== 'string') {
    throw Object.assign(new Error('PC name is invalid'), { code: 'PC_DEVICE_NAME_INVALID' });
  }
  const deviceName = value.trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(deviceName)) {
    throw Object.assign(new Error('PC name is invalid'), { code: 'PC_DEVICE_NAME_INVALID' });
  }
  return deviceName;
}

function createSessions({
  collection,
  tickets,
  provider,
  register,
  unregister,
  refresh = async () => {
    throw new Error('PC tool refresh is unavailable');
  },
  isRegistered = async () => true,
  now = () => new Date(),
  randomBytes = crypto.randomBytes,
  randomUUID = crypto.randomUUID,
  dnsReady = publicDnsReady,
  endpointReady = publicMCPReachable,
  sleep,
  activationBackoffs,
}) {
  if (!collection || !tickets || !provider || !register || !unregister) {
    throw new TypeError('Pairing session dependencies are required');
  }

  async function ensureIndexes() {
    await collection.createIndex({ sessionId: 1 }, { unique: true, name: 'pc_session_id' });
    await collection.createIndex(
      { purgeAfter: 1 },
      { expireAfterSeconds: 0, name: 'pc_session_purge' },
    );
    await collection.createIndex(
      { userId: 1 },
      {
        unique: true,
        partialFilterExpression: { state: { $in: LIVE_STATES } },
        name: 'pc_session_one_live_per_user',
      },
    );
    await collection.createIndex({ state: 1, expiresAt: 1 }, { name: 'pc_session_stale' });
  }

  async function claim({ code, port, deviceName }) {
    if (!Number.isInteger(port) || port < 1024 || port > 65535) {
      throw Object.assign(new Error('Port is invalid'), { code: 'PC_PORT_INVALID' });
    }
    const normalizedDeviceName = normalizeDeviceName(deviceName);
    const ticket = await tickets.claim({ code });
    if (!ticket) return null;
    const existing = await collection.countDocuments({
      userId: ticket.userId,
      state: { $in: LIVE_STATES },
    });
    if (existing > 0) {
      throw Object.assign(new Error('An existing PC connection must be disconnected first'), {
        code: 'PC_SESSION_EXISTS',
      });
    }
    const sessionId = randomUUID();
    const sessionSecret = randomBytes(32).toString('base64url');
    const resource = await provider.provision({ userId: ticket.userId, port });
    const createdAt = now();
    try {
      await collection.insertOne({
        sessionId,
        secretDigest: hashSecret(sessionSecret),
        userId: ticket.userId,
        state: 'claimed',
        deviceName: normalizedDeviceName,
        tunnelId: resource.tunnelId,
        dnsRecordId: resource.dnsRecordId,
        hostname: resource.hostname,
        url: resource.url,
        port,
        serverName: null,
        createdAt,
        expiresAt: new Date(createdAt.getTime() + CLAIM_WINDOW_MS),
        purgeAfter: new Date(createdAt.getTime() + PURGE_MS),
      });
    } catch (err) {
      await provider.destroy(resource).catch(() => {});
      throw err;
    }
    // Connector credential and session secret are returned once and are never persisted.
    return {
      sessionId,
      sessionSecret,
      connectorToken: resource.connectorToken,
      url: resource.url,
      hostname: resource.hostname,
      expiresInSeconds: CLAIM_WINDOW_MS / 1000,
    };
  }

  function authQuery(sessionId, secret) {
    if (
      typeof sessionId !== 'string' ||
      !/^[0-9a-f-]{36}$/i.test(sessionId) ||
      typeof secret !== 'string' ||
      secret.length < 40 ||
      secret.length > 256
    )
      return null;
    return { sessionId, secretDigest: hashSecret(secret) };
  }

  async function activate({ sessionId, sessionSecret, bearerToken }) {
    const auth = authQuery(sessionId, sessionSecret);
    if (!auth) return null;
    if (typeof bearerToken !== 'string' || bearerToken.length < 32 || bearerToken.length > 512) {
      throw Object.assign(new Error('Invalid PC bearer'), { code: 'PC_BEARER_INVALID' });
    }
    const current = now();
    const doc = await collection.findOneAndUpdate(
      {
        ...auth,
        state: 'claimed',
        expiresAt: { $gt: current },
      },
      { $set: { state: 'activating' } },
      { returnDocument: 'after' },
    );
    if (!doc) return null;
    let registeredName = null;
    try {
      const result = await registerWhenReady({
        hostname: doc.hostname,
        endpoint: doc.url + '/mcp',
        expiresAt: doc.expiresAt,
        now,
        dnsReady,
        endpointReady,
        ...(sleep ? { sleep } : {}),
        ...(activationBackoffs ? { backoffs: activationBackoffs } : {}),
        register: () =>
          register({
            userId: doc.userId,
            url: doc.url + '/mcp',
            bearerToken,
          }),
      });
      registeredName = result?.serverName || null;
      if (!registeredName || !Array.isArray(result.tools) || !result.tools.length) {
        throw Object.assign(new Error('MCP registration returned no tools'), {
          code: 'PC_TOOLS_NOT_FOUND',
        });
      }
      const updated = await collection.updateOne(
        { sessionId, state: 'activating', expiresAt: { $gt: now() } },
        {
          $set: {
            state: 'active',
            serverName: registeredName,
            toolRevision: 1,
            lastSeenAt: now(),
            expiresAt: new Date(now().getTime() + ACTIVE_HEARTBEAT_WINDOW_MS),
            purgeAfter: new Date(now().getTime() + PURGE_MS),
          },
        },
      );
      if (updated.modifiedCount !== 1)
        throw new Error('PC pairing session changed during activation');
      return { serverName: registeredName, tools: result.tools };
    } catch (err) {
      // A successful native registration followed by a DB failure must not
      // leave an MCP server with no owning session.
      if (registeredName) {
        try {
          await unregister({ userId: doc.userId, serverName: registeredName });
        } catch {
          // Do not forget a server that has already been created if its
          // compensation fails. The session reaper will retry removal.
          await collection.updateOne(
            { sessionId, state: 'activating' },
            {
              $set: {
                state: 'cleanup_pending',
                serverName: registeredName,
                toolRevision: 1,
                expiresAt: now(),
                purgeAfter: new Date(now().getTime() + PURGE_MS),
              },
            },
          );
          throw err;
        }
      }
      await collection.updateOne(
        { sessionId, state: 'activating' },
        { $set: { state: 'claimed' } },
      );
      throw err;
    }
  }

  // Authenticated browser-visible presence signal. No pairing or tunnel secret
  // is exposed; use only the signed-in user's own active session.
  async function getUserStatus(userId) {
    if (typeof userId !== 'string' || !/^[0-9a-f]{24}$/i.test(userId)) {
      return { connected: false };
    }
    const live = await collection.findOne({
      userId,
      state: 'active',
      expiresAt: { $gt: now() },
    });
    if (!live || typeof live.serverName !== 'string' || !live.serverName) {
      return { connected: false };
    }
    if (!(await isRegistered({ userId, serverName: live.serverName }))) {
      return { connected: false };
    }
    const status = {
      connected: true,
      serverName: live.serverName,
      toolRevision: Number.isInteger(live.toolRevision) ? live.toolRevision : 1,
    };
    if (typeof live.deviceName === 'string' && live.deviceName) {
      status.deviceName = live.deviceName;
    }
    return status;
  }
  // Re-read the already registered PC's live MCP tools after the employee
  // revokes a local capability. Server authorization stays local at call time.
  // The revision only tells open browser chats to re-fetch their tool catalog.
  async function refreshTools({ sessionId, sessionSecret }) {
    const auth = authQuery(sessionId, sessionSecret);
    if (!auth) return null;
    const live = await collection.findOne({
      ...auth,
      state: 'active',
      expiresAt: { $gt: now() },
    });
    if (!live || !live.serverName) return null;
    const tools = await refresh({ userId: live.userId, serverName: live.serverName });
    if (!Array.isArray(tools)) throw new Error('PC tool refresh returned no catalog');
    const previous = Number.isInteger(live.toolRevision) ? live.toolRevision : 1;
    const result = await collection.updateOne(
      {
        ...auth,
        state: 'active',
        toolRevision: live.toolRevision,
      },
      { $set: { toolRevision: previous + 1 } },
    );
    if (result.modifiedCount !== 1) return null;
    return { refreshed: true, toolRevision: previous + 1, tools };
  }
  async function heartbeat({ sessionId, sessionSecret }) {
    const auth = authQuery(sessionId, sessionSecret);
    if (!auth) return false;
    const observedAt = now();
    const live = await collection.findOne({
      ...auth,
      state: 'active',
      expiresAt: { $gt: observedAt },
    });
    if (!live) return false;
    if (
      live.serverName &&
      !(await isRegistered({
        userId: live.userId,
        serverName: live.serverName,
      }))
    ) {
      await disconnect({ sessionId, sessionSecret });
      return false;
    }
    const result = await collection.updateOne(
      { ...auth, state: 'active', expiresAt: { $gt: observedAt } },
      {
        $set: {
          lastSeenAt: observedAt,
          expiresAt: new Date(observedAt.getTime() + ACTIVE_HEARTBEAT_WINDOW_MS),
          purgeAfter: new Date(observedAt.getTime() + PURGE_MS),
        },
      },
    );
    return result.modifiedCount === 1;
  }

  async function closeDoc(doc) {
    const failures = [];
    if (doc.serverName) {
      try {
        await unregister({ userId: doc.userId, serverName: doc.serverName });
      } catch (err) {
        failures.push(err);
      }
    }
    try {
      await provider.destroy({ tunnelId: doc.tunnelId, dnsRecordId: doc.dnsRecordId });
    } catch (err) {
      failures.push(err);
    }
    if (failures.length) {
      await collection.updateOne(
        { sessionId: doc.sessionId, state: 'disconnecting' },
        {
          $set: {
            state: 'cleanup_pending',
            expiresAt: now(),
            purgeAfter: new Date(now().getTime() + PURGE_MS),
          },
        },
      );
      throw failures[0];
    }
    await collection.updateOne(
      { sessionId: doc.sessionId, state: 'disconnecting' },
      {
        $set: {
          state: 'closed',
          expiresAt: now(),
          purgeAfter: new Date(now().getTime() + PURGE_MS),
        },
      },
    );
    return true;
  }

  async function disconnect({ sessionId, sessionSecret }) {
    const auth = authQuery(sessionId, sessionSecret);
    if (!auth) return false;
    const doc = await collection.findOneAndUpdate(
      {
        ...auth,
        state: { $in: ['claimed', 'activating', 'active', 'cleanup_pending'] },
      },
      { $set: { state: 'disconnecting' } },
      { returnDocument: 'after' },
    );
    return doc ? closeDoc(doc) : false;
  }

  async function disconnectUser(userId) {
    if (typeof userId !== 'string' || !/^[0-9a-f]{24}$/i.test(userId)) return false;
    const doc = await collection.findOneAndUpdate(
      {
        userId,
        state: { $in: ['claimed', 'activating', 'active', 'cleanup_pending'] },
      },
      { $set: { state: 'disconnecting' } },
      { returnDocument: 'after' },
    );
    return doc ? closeDoc(doc) : false;
  }

  async function reap({ limit = 20 } = {}) {
    const stale = await collection
      .find({
        state: { $in: ['claimed', 'activating', 'active', 'disconnecting', 'cleanup_pending'] },
        expiresAt: { $lte: now() },
      })
      .limit(Math.min(limit, 100))
      .toArray();
    let cleaned = 0;
    for (const candidate of stale) {
      const doc = await collection.findOneAndUpdate(
        {
          sessionId: candidate.sessionId,
          state: candidate.state,
        },
        { $set: { state: 'disconnecting' } },
        { returnDocument: 'after' },
      );
      if (!doc) continue;
      try {
        await closeDoc(doc);
        cleaned += 1;
      } catch {
        /* retained for later retry */
      }
    }
    return cleaned;
  }

  return {
    ensureIndexes,
    claim,
    activate,
    getUserStatus,
    refreshTools,
    heartbeat,
    disconnect,
    disconnectUser,
    reap,
  };
}

module.exports = {
  createSessions,
  hashSecret,
  normalizeDeviceName,
  CLAIM_WINDOW_MS,
  ACTIVE_HEARTBEAT_WINDOW_MS,
};
