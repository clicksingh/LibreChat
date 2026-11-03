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
function fixture() {
  const collection = db();
  let fixtureRegistered = true;
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
    now: () => new Date(current),
    randomUUID: () => '00000000-0000-4000-8000-000000000222',
    randomBytes: (n) => Buffer.alloc(n, 88),
    register: async (input) => {
      events.push(['register', input.userId]);
      return { serverName: 'cbhr_pc', tools: ['read_file', 'list_directory'] };
    },
    unregister: async (input) => {
      events.push(['unregister', input.serverName]);
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
  const session = await service.claim({ code: 'valid', port: 8845 });
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
  assert.equal(await service.disconnect({
    sessionId: session.sessionId, sessionSecret: session.sessionSecret,
  }), true);
  assert.equal(collection.rows[0].state, 'closed');
  assert.ok(events.some((item) => item[0] === 'destroy'));
});
