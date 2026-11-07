'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {
  createSessions,
  hashSecret,
  CLAIM_WINDOW_MS,
  ACTIVE_HEARTBEAT_WINDOW_MS,
} = require('../sessions');

const USER = '6a31557594ab025c7537576e';
function db() {
  const rows = [];
  const matches = (x, q) =>
    Object.entries(q).every(([k, v]) => {
      if (v && typeof v === 'object' && !(v instanceof Date)) {
        if ('$in' in v) return v.$in.includes(x[k]);
        if ('$gt' in v) return x[k] > v.$gt;
        if ('$lte' in v) return x[k] <= v.$lte;
      }
      return x[k] === v;
    });
  return {
    rows,
    async createIndex() {},
    async insertOne(row) {
      rows.push({ ...row });
    },
    async countDocuments(q) {
      return rows.filter((x) => matches(x, q)).length;
    },
    async findOne(q) {
      return rows.find((r) => matches(r, q)) || null;
    },
    async findOneAndUpdate(q, patch) {
      const row = rows.find((r) => matches(r, q));
      if (!row) return null;
      Object.assign(row, patch.$set);
      return { ...row };
    },
    async updateOne(q, patch) {
      const row = rows.find((r) => matches(r, q));
      if (!row) return { modifiedCount: 0 };
      Object.assign(row, patch.$set);
      return { modifiedCount: 1 };
    },
    find(q) {
      return {
        limit(max) {
          return {
            async toArray() {
              return rows
                .filter((r) => matches(r, q))
                .slice(0, max)
                .map((x) => ({ ...x }));
            },
          };
        },
      };
    },
  };
}
function fixture({
  failUnregisterOnce = false,
  dnsReady = async () => true,
  endpointReady = async () => true,
  registerFailures = 0,
  refreshFailure = false,
} = {}) {
  const collection = db();
  let fixtureRegistered = true;
  let unregisterFailuresRemaining = failUnregisterOnce ? 1 : 0;
  let current = new Date('2026-11-03T08:00:00.000Z');
  const events = [];
  const provider = {
    async provision({ userId, port }) {
      events.push(['provision', userId, port]);
      return {
        tunnelId: '00000000-0000-4000-8000-000000000111',
        dnsRecordId: 'dns-1',
        hostname: 'pc-test.kelownarealestate.com',
        url: 'https://pc-test.kelownarealestate.com',
        connectorToken: 'test-single-tunnel-connector-credential',
      };
    },
    async destroy(v) {
      events.push(['destroy', v.tunnelId]);
    },
  };
  const service = createSessions({
    collection,
    tickets: {
      async claim({ code }) {
        return code === 'valid' ? { userId: USER } : null;
      },
    },
    provider,
    dnsReady,
    endpointReady,
    sleep: async () => {},
    now: () => new Date(current),
    randomUUID: () => '00000000-0000-4000-8000-000000000222',
    randomBytes: (n) => Buffer.alloc(n, 88),
    register: async (input) => {
      events.push(['register', input.userId]);
      if (registerFailures-- > 0) {
        throw Object.assign(new Error('Cloudflare 1033 / HTTP 530'), {
          code: 'PC_MCP_REGISTRATION_FAILED',
        });
      }
      return { serverName: 'cbhr_pc', tools: ['read_file', 'list_directory'] };
    },
    unregister: async (input) => {
      events.push(['unregister', input.serverName]);
      if (unregisterFailuresRemaining > 0) {
        unregisterFailuresRemaining -= 1;
        throw new Error('Temporary MCP cleanup outage');
      }
    },
    refresh: async ({ userId, serverName }) => {
      events.push(['refresh', userId, serverName]);
      if (refreshFailure) throw new Error('Tool discovery failed');
      return ['read_file'];
    },
    isRegistered: async () => fixtureRegistered,
  });
  return {
    service,
    events,
    collection,
    advance: (ms) => {
      current = new Date(current.getTime() + ms);
    },
    removeInPlatform: () => {
      fixtureRegistered = false;
    },
    provider,
  };
}
test('claim creates a single scoped tunnel and stores only a secret digest', async () => {
  const { service, collection, events } = fixture();
  assert.equal(await service.claim({ code: 'invalid', port: 8845 }), null);
  const result = await service.claim({ code: 'valid', port: 8845 });
  assert.equal(result.hostname, 'pc-test.kelownarealestate.com');
  assert.equal(result.expiresInSeconds, CLAIM_WINDOW_MS / 1000);
  assert.deepEqual(events[0], ['provision', USER, 8845]);
  assert.equal(collection.rows[0].secretDigest, hashSecret(result.sessionSecret));
  assert.ok(!JSON.stringify(collection.rows).includes(result.sessionSecret));
  assert.ok(!JSON.stringify(collection.rows).includes(result.connectorToken));
});
test('activate requires the matching secret and registers tools once', async () => {
  const { service, events } = fixture();
  const s = await service.claim({ code: 'valid', port: 8845 });
  const base = { sessionId: s.sessionId, bearerToken: 'x'.repeat(48) };
  assert.equal(await service.activate({ ...base, sessionSecret: 'y'.repeat(48) }), null);
  const active = await service.activate({ ...base, sessionSecret: s.sessionSecret });
  assert.deepEqual(active.tools, ['read_file', 'list_directory']);
  assert.equal(await service.activate({ ...base, sessionSecret: s.sessionSecret }), null);
  assert.equal(events.filter((x) => x[0] === 'register').length, 1);
});

test('authenticated status reports only this user active PC, never session secrets', async () => {
  const { service, advance } = fixture();
  assert.deepEqual(await service.getUserStatus(USER), { connected: false });
  const pair = await service.claim({ code: 'valid', port: 8845 });
  assert.deepEqual(await service.getUserStatus(USER), { connected: false });
  await service.activate({
    sessionId: pair.sessionId,
    sessionSecret: pair.sessionSecret,
    bearerToken: 'x'.repeat(48),
  });
  const status = await service.getUserStatus(USER);
  assert.deepEqual(status, { connected: true, serverName: 'cbhr_pc', toolRevision: 1 });
  assert.ok(!JSON.stringify(status).includes(pair.sessionSecret));
  assert.deepEqual(await service.getUserStatus('111111111111111111111111'), { connected: false });
  advance(ACTIVE_HEARTBEAT_WINDOW_MS + 1);
  assert.deepEqual(await service.getUserStatus(USER), { connected: false });
});
test('live tool refresh requires the real PC secret and increments active catalog revision', async () => {
  const { service, events } = fixture();
  const pair = await service.claim({ code: 'valid', port: 8845 });
  const params = {
    sessionId: pair.sessionId,
    sessionSecret: pair.sessionSecret,
    bearerToken: 'x'.repeat(48),
  };
  assert.equal(
    await service.refreshTools({ sessionId: pair.sessionId, sessionSecret: 'invalid-secret' }),
    null,
  );
  assert.equal(events.filter((e) => e[0] === 'refresh').length, 0);
  await service.activate(params);
  assert.deepEqual(await service.getUserStatus(USER), {
    connected: true,
    serverName: 'cbhr_pc',
    toolRevision: 1,
  });
  const updated = await service.refreshTools({
    sessionId: pair.sessionId,
    sessionSecret: pair.sessionSecret,
  });
  assert.deepEqual(updated, { refreshed: true, toolRevision: 2, tools: ['read_file'] });
  assert.deepEqual(await service.getUserStatus(USER), {
    connected: true,
    serverName: 'cbhr_pc',
    toolRevision: 2,
  });
  assert.equal(events.filter((e) => e[0] === 'refresh').length, 1);
  await service.disconnect({ sessionId: pair.sessionId, sessionSecret: pair.sessionSecret });
  assert.equal(
    await service.refreshTools({ sessionId: pair.sessionId, sessionSecret: pair.sessionSecret }),
    null,
  );
});
test('activation rejects unresolved DNS without publishing MCP tools', async () => {
  const { service, collection, events } = fixture({ dnsReady: async () => false });
  const session = await service.claim({ code: 'valid', port: 8845 });
  await assert.rejects(
    service.activate({
      sessionId: session.sessionId,
      sessionSecret: session.sessionSecret,
      bearerToken: 'x'.repeat(48),
    }),
    { code: 'CF_DNS_NOT_READY' },
  );
  assert.equal(collection.rows[0].state, 'claimed');
  assert.equal(events.filter((event) => event[0] === 'register').length, 0);
});

test('heartbeat and disconnect enforce the session secret, unregister then destroy', async () => {
  const { service, events } = fixture();
  const s = await service.claim({ code: 'valid', port: 8845 });
  await service.activate({
    sessionId: s.sessionId,
    sessionSecret: s.sessionSecret,
    bearerToken: 'x'.repeat(48),
  });
  assert.equal(
    await service.heartbeat({ sessionId: s.sessionId, sessionSecret: 'z'.repeat(48) }),
    false,
  );
  assert.equal(
    await service.heartbeat({ sessionId: s.sessionId, sessionSecret: s.sessionSecret }),
    true,
  );
  assert.equal(
    await service.disconnect({ sessionId: s.sessionId, sessionSecret: 'z'.repeat(48) }),
    false,
  );
  assert.equal(
    await service.disconnect({ sessionId: s.sessionId, sessionSecret: s.sessionSecret }),
    true,
  );
  assert.equal(
    await service.disconnect({ sessionId: s.sessionId, sessionSecret: s.sessionSecret }),
    false,
  );
  assert.deepEqual(
    events.slice(-2).map((x) => x[0]),
    ['unregister', 'destroy'],
  );
});
test('stale claimed session is reaped and cannot be activated', async () => {
  const { service, events, advance } = fixture();
  const s = await service.claim({ code: 'valid', port: 8845 });
  advance(CLAIM_WINDOW_MS + 1);
  assert.equal(
    await service.activate({
      sessionId: s.sessionId,
      sessionSecret: s.sessionSecret,
      bearerToken: 'x'.repeat(48),
    }),
    null,
  );
  assert.equal(await service.reap(), 1);
  assert.equal(events.filter((x) => x[0] === 'destroy').length, 1);
});
test('active expiry is extended on heartbeat and later reaped', async () => {
  const { service, advance, events } = fixture();
  const s = await service.claim({ code: 'valid', port: 8845 });
  await service.activate({
    sessionId: s.sessionId,
    sessionSecret: s.sessionSecret,
    bearerToken: 'x'.repeat(48),
  });
  advance(ACTIVE_HEARTBEAT_WINDOW_MS - 1000);
  assert.equal(
    await service.heartbeat({ sessionId: s.sessionId, sessionSecret: s.sessionSecret }),
    true,
  );
  advance(ACTIVE_HEARTBEAT_WINDOW_MS + 1);
  assert.equal(await service.reap(), 1);
  assert.ok(events.some((x) => x[0] === 'unregister'));
});
test('invalid port fails before consuming a code', async () => {
  const { service, events } = fixture();
  await assert.rejects(service.claim({ code: 'valid', port: 443 }), { code: 'PC_PORT_INVALID' });
  assert.equal(events.length, 0);
});

test('browser deletion is detected at next heartbeat and tears tunnel down', async () => {
  const { service, removeInPlatform, events } = fixture();
  const session = await service.claim({ code: 'valid', port: 8845 });
  await service.activate({
    sessionId: session.sessionId,
    sessionSecret: session.sessionSecret,
    bearerToken: 'x'.repeat(48),
  });
  removeInPlatform();
  assert.equal(
    await service.heartbeat({
      sessionId: session.sessionId,
      sessionSecret: session.sessionSecret,
    }),
    false,
  );
  assert.ok(events.some((x) => x[0] === 'destroy'));
});

test('an abandoned activating session expires and the tunnel is reaped', async () => {
  const { service, collection, advance, events } = fixture();
  await service.claim({ code: 'valid', port: 8845 });
  collection.rows[0].state = 'activating';
  advance(CLAIM_WINDOW_MS + 1);
  assert.equal(await service.reap(), 1);
  assert.equal(collection.rows[0].state, 'closed');
  assert.ok(events.some((item) => item[0] === 'destroy'));
});

test('disconnect can cancel an in-flight activation and prevent an orphan', async () => {
  const { service, collection, events } = fixture();
  const session = await service.claim({ code: 'valid', port: 8845 });
  collection.rows[0].state = 'activating';
  assert.equal(
    await service.disconnect({
      sessionId: session.sessionId,
      sessionSecret: session.sessionSecret,
    }),
    true,
  );
  assert.equal(collection.rows[0].state, 'closed');
  assert.ok(events.some((item) => item[0] === 'destroy'));
});

test('an interrupted disconnect is eventually reaped, unblocking a new PC session', async () => {
  const { service, collection, advance, events } = fixture();
  await service.claim({ code: 'valid', port: 8845 });
  collection.rows[0].state = 'disconnecting';
  advance(CLAIM_WINDOW_MS + 1);
  assert.equal(await service.reap(), 1);
  assert.equal(collection.rows[0].state, 'closed');
  assert.ok(events.some((item) => item[0] === 'destroy'));
});

test('failed registration compensation retains cleanup state for the reaper', async () => {
  const { service, collection, events } = fixture({ failUnregisterOnce: true });
  const s = await service.claim({ code: 'valid', port: 8845 });
  const originalUpdate = collection.updateOne;
  collection.updateOne = async (filter, patch) => {
    if (patch.$set.state === 'active') return { modifiedCount: 0 };
    return originalUpdate(filter, patch);
  };
  await assert.rejects(
    service.activate({
      sessionId: s.sessionId,
      sessionSecret: s.sessionSecret,
      bearerToken: 'x'.repeat(48),
    }),
    /changed during activation/,
  );
  assert.equal(collection.rows[0].state, 'cleanup_pending');
  assert.equal(collection.rows[0].serverName, 'cbhr_pc');
  assert.equal(await service.reap(), 1);
  assert.equal(collection.rows[0].state, 'closed');
  assert.equal(events.filter((event) => event[0] === 'unregister').length, 2);
});

test('heartbeat extends TTL retention so a live session cannot be purged', async () => {
  const { service, collection, advance } = fixture();
  const session = await service.claim({ code: 'valid', port: 8845 });
  await service.activate({
    sessionId: session.sessionId,
    sessionSecret: session.sessionSecret,
    bearerToken: 'x'.repeat(48),
  });
  const before = collection.rows[0].purgeAfter;
  advance(ACTIVE_HEARTBEAT_WINDOW_MS - 1000);
  assert.equal(
    await service.heartbeat({
      sessionId: session.sessionId,
      sessionSecret: session.sessionSecret,
    }),
    true,
  );
  assert.ok(collection.rows[0].purgeAfter > before);
});

test('Cloudflare warmup registration errors retry and eventually activate', async () => {
  const { service, events } = fixture({ registerFailures: 2 });
  const s = await service.claim({ code: 'valid', port: 8845 });
  const active = await service.activate({
    sessionId: s.sessionId,
    sessionSecret: s.sessionSecret,
    bearerToken: 'x'.repeat(48),
  });
  assert.equal(active.serverName, 'cbhr_pc');
  assert.equal(events.filter((event) => event[0] === 'register').length, 3);
  assert.equal((await service.getUserStatus(USER)).connected, true);
});

test('permanent MCP initialize failure leaves no active or orphan registration', async () => {
  const { service, collection, events } = fixture({ registerFailures: 20 });
  const s = await service.claim({ code: 'valid', port: 8845 });
  await assert.rejects(
    service.activate({
      sessionId: s.sessionId,
      sessionSecret: s.sessionSecret,
      bearerToken: 'x'.repeat(48),
    }),
    { code: 'PC_MCP_NOT_READY' },
  );
  assert.equal(collection.rows[0].state, 'claimed');
  assert.equal(collection.rows[0].serverName, null);
  assert.deepEqual(await service.getUserStatus(USER), { connected: false });
  assert.equal(events.filter((event) => event[0] === 'register').length, 5);
});

test('failed local tool rediscovery does not increment revision', async () => {
  const { service } = fixture({ refreshFailure: true });
  const s = await service.claim({ code: 'valid', port: 8845 });
  await service.activate({
    sessionId: s.sessionId,
    sessionSecret: s.sessionSecret,
    bearerToken: 'x'.repeat(48),
  });
  await assert.rejects(
    service.refreshTools({ sessionId: s.sessionId, sessionSecret: s.sessionSecret }),
    /Tool discovery failed/,
  );
  assert.equal((await service.getUserStatus(USER)).toolRevision, 1);
});

test('browser status never reports Connected after registered MCP removal', async () => {
  const { service, removeInPlatform } = fixture();
  const s = await service.claim({ code: 'valid', port: 8845 });
  await service.activate({
    sessionId: s.sessionId,
    sessionSecret: s.sessionSecret,
    bearerToken: 'x'.repeat(48),
  });
  assert.equal((await service.getUserStatus(USER)).connected, true);
  removeInPlatform();
  assert.deepEqual(await service.getUserStatus(USER), { connected: false });
});
