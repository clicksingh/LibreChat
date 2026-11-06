'use strict';
/**
 * PM-F independent acceptance. Frozen expectations, not implementation repairs.
 * Run: node --test api/server/services/PCBridge/tests/pmF.hostile-20261106.check.cjs
 * Source gates are deliberately separate from live/staging certification.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createSessions } = require('../sessions');
const ROOT = path.resolve(__dirname, '../../../../..');
const USER_A = 'aaaaaaaaaaaaaaaaaaaaaaaa';
const USER_B = 'bbbbbbbbbbbbbbbbbbbbbbbb';
const read = (name) => fs.readFileSync(path.join(ROOT, name), 'utf8');
const expectMatch = (value, expression, note) => assert.ok(expression.test(value), note || ("Missing source contract: " + expression));
const sourceFiles = (dir) => {
  const full = path.join(ROOT, dir);
  if (!fs.existsSync(full)) return [];
  const visit = (current) => fs.readdirSync(current, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? visit(path.join(current, e.name)) :
      /[.](js|cjs|ts|tsx|md)$/.test(e.name) && !/[.]((spec|test|check)[.]|snap)/.test(e.name)
        ? [path.join(current, e.name)] : []);
  return visit(full);
};
const serverSources = () => [
  ...sourceFiles('api/server/services/PCBridge'),
  ...sourceFiles('api/server/services/Endpoints/agents'),
  ...sourceFiles('api/server/controllers/agents'),
  path.join(ROOT, 'api/server/services/ToolService.js'),
].map((p) => fs.readFileSync(p, 'utf8')).join('\n');
const fakeDb = () => {
  const rows = [];
  function match(row, query) {
    return Object.entries(query).every(([key, value]) => {
      const got = row[key];
      if (value && typeof value === 'object' && !(value instanceof Date)) {
        if ('$in' in value) return value.$in.includes(got);
        if ('$gt' in value) return got > value.$gt;
        if ('$lte' in value) return got <= value.$lte;
      }
      return got === value;
    });
  }
  const find = (query) => rows.find((r) => match(r, query));
  return {
    rows,
    async createIndex() {},
    async countDocuments(query) { return rows.filter((r) => match(r, query)).length; },
    async findOne(query) { return find(query) || null; },
    async insertOne(row) { rows.push({ ...row }); },
    async findOneAndUpdate(query, patch) {
      const row = find(query);
      if (!row) return null;
      Object.assign(row, patch.$set);
      return { ...row };
    },
    async updateOne(query, patch) {
      const row = find(query);
      if (!row) return { modifiedCount: 0 };
      Object.assign(row, patch.$set);
      return { modifiedCount: 1 };
    },
    find(query) {
      return {
        limit(n) { return { async toArray() { return rows.filter((r) => match(r, query)).slice(0, n); } }; },
      };
    },
  };
};
function setup({ register, refresh, dnsReady } = {}) {
  const collection = fakeDb();
  const calls = [];
  let serial = 0;
  const service = createSessions({
    collection,
    tickets: { async claim({ code }) { return { a: USER_A, b: USER_B }[code] ? { userId: { a: USER_A, b: USER_B }[code] } : null; } },
    provider: {
      async provision({ userId }) {
        calls.push(['provision', userId]);
        return { tunnelId: 't-' + userId, dnsRecordId: 'd-' + userId,
          hostname: 'pc.example.test', url: 'https://pc.example.test',
          connectorToken: 'connector-token-redacted-and-long-enough' };
      },
      async destroy(info) { calls.push(['destroy', info.tunnelId]); },
    },
    now: () => new Date('2026-11-06T22:00:00Z'),
    randomUUID: () => String(++serial).padStart(8, '0') + '-0000-4000-8000-000000000000',
    randomBytes: () => Buffer.alloc(32, 100 + serial),
    dnsReady: dnsReady || (async () => true),
    register: async (args) => {
      calls.push(['register', args.userId]);
      return register ? register(args, calls) :
        { serverName: 'cbhr-pc-' + args.userId, tools: ['Read', 'Screenshot'] };
    },
    unregister: async (args) => { calls.push(['unregister', args.userId, args.serverName]); },
    refresh: refresh || (async () => ['Read']),
  });
  const claim = (code) => service.claim({ code, port: 8845 });
  const activate = (pair) => service.activate({ sessionId: pair.sessionId,
    sessionSecret: pair.sessionSecret, bearerToken: 'b'.repeat(48) });
  return { service, calls, collection, claim, activate };
}
test('PM-F / isolation: independently claimed user A and B expose only their own PC', async () => {
  const f = setup();
  const a = await f.claim('a');
  const b = await f.claim('b');
  await f.activate(a); await f.activate(b);
  assert.equal((await f.service.getUserStatus(USER_A)).serverName, 'cbhr-pc-' + USER_A);
  assert.equal((await f.service.getUserStatus(USER_B)).serverName, 'cbhr-pc-' + USER_B);
  assert.equal((await f.service.getUserStatus('cccccccccccccccccccccccc')).connected, false);
  assert.equal(await f.service.refreshTools({ sessionId: a.sessionId, sessionSecret: b.sessionSecret }), null);
  await f.service.disconnect({ sessionId: a.sessionId, sessionSecret: a.sessionSecret });
  assert.deepEqual(await f.service.getUserStatus(USER_A), { connected: false });
  assert.equal((await f.service.getUserStatus(USER_B)).connected, true);
});
test('PM-F / activation: DNS success + temporary Cloudflare 1033 retries registration before active', async () => {
  let attempts = 0;
  const f = setup({ register: async () => {
    attempts += 1;
    if (attempts === 1) throw Object.assign(new Error('Cloudflare Error 1033 / HTTP 530'), { code: 'CF_1033', status: 530 });
    return { serverName: 'cbhr-pc-recovered', tools: ['Read'] };
  } });
  const pair = await f.claim('a');
  assert.equal((await f.service.getUserStatus(USER_A)).connected, false);
  const active = await f.activate(pair);
  assert.equal(active.serverName, 'cbhr-pc-recovered');
  assert.equal(attempts, 2, 'must retry transient 1033 without relying on DNS alone');
  assert.equal((await f.service.getUserStatus(USER_A)).connected, true);
});
test('PM-F / activation: permanent public MCP failure is never marked connected', async () => {
  const f = setup({ register: async () => { throw Object.assign(new Error('HTTP 530 / Cloudflare 1033'), { status: 530 }); } });
  const pair = await f.claim('a');
  await assert.rejects(f.activate(pair));
  assert.equal((await f.service.getUserStatus(USER_A)).connected, false);
  assert.equal(f.collection.rows.some((row) => row.state === 'active'), false);
  assert.equal(f.calls.filter(([kind]) => kind === 'unregister').length, 0);
});
test('PM-F / activation: successful register without tools is compensated with no orphan', async () => {
  const f = setup({ register: async () => ({ serverName: 'cbhr-pc-created', tools: [] }) });
  const pair = await f.claim('a');
  await assert.rejects(f.activate(pair), { code: 'PC_TOOLS_NOT_FOUND' });
  assert.equal((await f.service.getUserStatus(USER_A)).connected, false);
  assert.deepEqual(f.calls.filter(([kind]) => kind === 'unregister').map((x) => x[2]), ['cbhr-pc-created']);
});
test('PM-F / hot permissions: failed rediscovery does not advance tool revision', async () => {
  const f = setup({ refresh: async () => { throw new Error('refresh failure'); } });
  const pair = await f.claim('a'); await f.activate(pair);
  await assert.rejects(f.service.refreshTools({ sessionId: pair.sessionId, sessionSecret: pair.sessionSecret }));
  assert.equal((await f.service.getUserStatus(USER_A)).toolRevision, 1);
});
test('PM-F / hot permissions: successful rediscovery advances revision exactly once', async () => {
  const f = setup({ refresh: async () => ['Read'] });
  const pair = await f.claim('a'); await f.activate(pair);
  const first = await f.service.refreshTools({ sessionId: pair.sessionId, sessionSecret: pair.sessionSecret });
  const second = await f.service.refreshTools({ sessionId: pair.sessionId, sessionSecret: pair.sessionSecret });
  assert.equal(first.toolRevision, 2);
  assert.equal(second.toolRevision, 3);
});
test('PM-F / server authority: authenticated model-turn path resolves live bridge server-side', () => {
  const s = serverSources();
  expectMatch(s, /(?:getActive|resolveActive|resolveUser|resolveManaged).*?(?:PCBridge|PCServer|BridgeServer|PcBridge)/s,
    'need an explicitly server-owned per-user active Bridge resolver, not only GET /status');
  expectMatch(s, /(?:agent|req|request|turn|user).*?(?:pcBridge|PCBridge|bridgeServer|pcServer).*?(?:tools|mcp|serverNames)/is,
    'server request/tool assembly must consume live Bridge authority on every turn');
});
test('PM-F / server authority: old chats and browser-stale turns do not require client MCP selection', () => {
  const s = serverSources();
  expectMatch(s, /(?:req[.]user[.]id|userId).*?(?:getActive|resolveActive|resolveManaged).*?(?:Bridge|PC)/s,
    'server-side user identity must drive attachment independent of conversation and browser');
});
test('PM-F / coexistence: server turn attachment preserves UltraSearch', () => {
  const s = serverSources();
  expectMatch(s, /ultrasearch/i, 'UltraSearch must coexist server-side; browser-only managed selection is insufficient');
  expectMatch(s, /(?:Bridge|PC).*?(?:ultrasearch)|ultrasearch.*?(?:Bridge|PC)/is);
});
test('PM-F / tool refresh: model-turn tool catalog has revision-sensitive re-read', () => {
  const s = serverSources();
  expectMatch(s, /toolRevision/);
  expectMatch(s, /(?:reinitMCPServer|refreshTools|rediscover|toolRevision).*?(?:mcp|tools|server)/is);
});
test('PM-F / prompt: centrally deployed default skill describes physical PC versus AI sandbox', () => {
  const files = [...sourceFiles('skill'), ...sourceFiles('api'), ...sourceFiles('config')];
  const matched = files.filter((p) => /cb[-_]bridge/i.test(path.basename(p)) || /managed.*prompt|system.*prompt/i.test(path.basename(p)))
    .map((p) => fs.readFileSync(p, 'utf8')).join('\n');
  expectMatch(matched, /cb[- ]bridge/i, 'default skill or managed contract not found');
  expectMatch(matched, /physical.{0,40}(?:windows|computer|pc)|(?:windows|pc).{0,40}physical/i);
  expectMatch(matched, /sandbox/i);
  expectMatch(matched, /permission|denied|revok/i);
  expectMatch(matched, /reconnect/i);
});
test('PM-F / prompt: exact exposed tools and no false connected claim', () => {
  const files = [...sourceFiles('skill'), ...sourceFiles('config')];
  const text = files.map((p) => fs.readFileSync(p, 'utf8')).join('\n');
  expectMatch(text, /(?:exact|advertised|exposed).{0,70}tool.{0,50}name|tool.{0,20}name.{0,30}exact/i);
  expectMatch(text, /(?:unavailable|not connected|no bridge)/i);
  expectMatch(text, /(?:Read|Edit|PowerShell)/);
});
test('PM-F / interruption: durable resumable checkpoint records completed effects and saved artifacts', () => {
  const sources = [path.join(ROOT, 'api/server/controllers/agents/agentFailure.js')]
    .map((p) => fs.readFileSync(p, 'utf8')).join('\n');
  expectMatch(sources, /(?:checkpoint|recoveryReceipt|resumeReceipt)/i);
  expectMatch(sources, /(?:completed.{0,20}(?:tool|effect)|lastCompletedTool)/i);
  expectMatch(sources, /(?:saved.{0,20}(?:artifact|file)|artifact.{0,20}checkpoint)/i);
});
test('PM-F / interruption: before-tool, after-read and after-write resume never auto-replays writes', () => {
  const sources = [path.join(ROOT, 'api/server/controllers/agents/agentFailure.js')]
    .map((p) => fs.readFileSync(p, 'utf8')).join('\n');
  expectMatch(sources, /(?:side.effect|non.?idempotent|mutation|write.{0,15}replay)/i);
  expectMatch(sources, /(?:auto.?replay|replay).{0,70}(?:never|forbid|deny|skip|block)|(?:never|forbid|deny|skip|block).{0,70}(?:auto.?replay|replay)/i);
});
test('PM-F / interruption: returned failure receipt contains sanitized cause and stable run ID', () => {
  const sources = sourceFiles('api/server/controllers/agents').map((p) => fs.readFileSync(p, 'utf8')).join('\n');
  expectMatch(sources, /(?:runId|run_id|streamId).*?(?:checkpoint|receipt)|(?:checkpoint|receipt).*?(?:runId|run_id|streamId)/is);
  expectMatch(sources, /(?:saniti[sz]e|redact).{0,80}(?:cause|error|receipt)|(?:cause|error|receipt).{0,80}(?:saniti[sz]e|redact)/i);
});
test('PM-F / attachment: first-call injection path is present, not deferred to second call', () => {
  const init = read('api/server/controllers/agents/client.js');
  const handler = read('packages/api/src/agents/handlers.ts');
  expectMatch(init, /buildInitialToolSessions/);
  expectMatch(handler, /_injected_files/);
  expectMatch(handler, /codeSessionContext[.]files/);
});
test('PM-F / attachment: next-turn artifact and filename identity checked at sandbox boundary', () => {
  const src = sourceFiles('packages/api/src/agents').concat(sourceFiles('api/server/services/Files'))
    .map((p) => fs.readFileSync(p, 'utf8')).join('\n');
  expectMatch(src, /(?:generated|artifact).{0,45}(?:next.turn|persist|carry|conversation)/is);
  expectMatch(src, /(?:saniti[sz]ed|safe).{0,50}(?:file.?name|path)|(?:file.?name|path).{0,50}saniti[sz]ed/is);
});
test('PM-F / invalid aliases: unknown bash_terminal has correction and cannot execute', () => {
  const src = [path.join(ROOT, 'packages/api/src/agents/handlers.ts')]
    .map((p) => fs.readFileSync(p, 'utf8')).join('\n');
  expectMatch(src, /(?:unknown|invalid|unavailable|unrecognized).{0,55}(?:tool|name)|(?:tool|name).{0,55}(?:unknown|invalid|unavailable|unrecognized)/i);
  expectMatch(src, /(?:available|actual|valid).{0,45}tool.{0,20}name/i);
  expectMatch(src, /(?:bash_terminal|bash).{0,70}(?:unknown|invalid|correction|alias)|(?:unknown|invalid|alias).{0,70}(?:bash_terminal|bash)/i);
});

test('PM-F / interruption: public error sanitization does not expose raw provider secret', () => {
  const { normalizeAgentFailure } = require('../../../controllers/agents/agentFailure');
  const secret = 'Bearer-TEST-DO-NOT-LEAK-29384';
  const output = normalizeAgentFailure({ status: 503, code: 'upstream_failed', message: secret });
  assert.ok(output.startsWith('MODEL_REQUEST_INTERRUPTED:'));
  assert.ok(!output.includes(secret));
});
test('PM-F / interruption: pubsub outage still records failed job status, never false completion', async () => {
  const { persistAgentFailure } = require('../../../controllers/agents/agentFailure');
  const events = [];
  const manager = {
    async emitError() { events.push('emit'); throw new Error('pubsub down'); },
    async completeJob(_id, message) { events.push('complete'); assert.ok(message.startsWith('MODEL_REQUEST_INTERRUPTED')); },
  };
  const result = await persistAgentFailure(manager, 'test-stream', new Error('provider closed'));
  assert.equal(result.eventDelivered, false);
  assert.deepEqual(events, ['emit', 'complete']);
});
