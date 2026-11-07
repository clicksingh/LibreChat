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
const { resolveEffectivePCTools } = require('../activeTools');
const ROOT = path.resolve(__dirname, '../../../../..');
const USER_A = 'aaaaaaaaaaaaaaaaaaaaaaaa';
const USER_B = 'bbbbbbbbbbbbbbbbbbbbbbbb';
const read = (name) => fs.readFileSync(path.join(ROOT, name), 'utf8');
const expectMatch = (value, expression, note) =>
  assert.ok(expression.test(value), note || 'Missing source contract: ' + expression);
const sourceFiles = (dir) => {
  const full = path.join(ROOT, dir);
  if (!fs.existsSync(full)) return [];
  const visit = (current) =>
    fs.readdirSync(current, { withFileTypes: true }).flatMap((entry) => {
      if (entry.isDirectory()) {
        return visit(path.join(current, entry.name));
      }
      const isSource =
        /[.](js|cjs|ts|tsx|md)$/.test(entry.name) &&
        !/[.]((spec|test|check)[.]|snap)/.test(entry.name);
      return isSource ? [path.join(current, entry.name)] : [];
    });
  return visit(full);
};
const serverSources = () =>
  [
    ...sourceFiles('api/server/services/PCBridge'),
    ...sourceFiles('api/server/services/Endpoints/agents'),
    ...sourceFiles('api/server/controllers/agents'),
    path.join(ROOT, 'api/server/services/ToolService.js'),
  ]
    .map((p) => fs.readFileSync(p, 'utf8'))
    .join('\n');
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
    async countDocuments(query) {
      return rows.filter((r) => match(r, query)).length;
    },
    async findOne(query) {
      return find(query) || null;
    },
    async insertOne(row) {
      rows.push({ ...row });
    },
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
        limit(n) {
          return {
            async toArray() {
              return rows.filter((r) => match(r, query)).slice(0, n);
            },
          };
        },
      };
    },
  };
};
function setup({ register, refresh, dnsReady, endpointReady, activationBackoffs } = {}) {
  const collection = fakeDb();
  const calls = [];
  let serial = 0;
  const service = createSessions({
    collection,
    tickets: {
      async claim({ code }) {
        return { a: USER_A, b: USER_B }[code] ? { userId: { a: USER_A, b: USER_B }[code] } : null;
      },
    },
    provider: {
      async provision({ userId }) {
        calls.push(['provision', userId]);
        return {
          tunnelId: 't-' + userId,
          dnsRecordId: 'd-' + userId,
          hostname: 'pc.example.test',
          url: 'https://pc.example.test',
          connectorToken: 'connector-token-redacted-and-long-enough',
        };
      },
      async destroy(info) {
        calls.push(['destroy', info.tunnelId]);
      },
    },
    now: () => new Date('2026-11-06T22:00:00Z'),
    randomUUID: () => String(++serial).padStart(8, '0') + '-0000-4000-8000-000000000000',
    randomBytes: () => Buffer.alloc(32, 100 + serial),
    dnsReady: dnsReady || (async () => true),
    endpointReady: endpointReady || (async () => true),
    sleep: async () => {},
    activationBackoffs: activationBackoffs || [0, 0, 0, 0, 0],
    register: async (args) => {
      calls.push(['register', args.userId]);
      return register
        ? register(args, calls)
        : { serverName: 'cbhr-pc-' + args.userId, tools: ['Read', 'Screenshot'] };
    },
    unregister: async (args) => {
      calls.push(['unregister', args.userId, args.serverName]);
    },
    refresh: refresh || (async () => ['Read']),
  });
  const claim = (code) => service.claim({ code, port: 8845 });
  const activate = (pair) =>
    service.activate({
      sessionId: pair.sessionId,
      sessionSecret: pair.sessionSecret,
      bearerToken: 'b'.repeat(48),
    });
  return { service, calls, collection, claim, activate };
}
test('PM-F / isolation: independently claimed user A and B expose only their own PC', async () => {
  const f = setup();
  const a = await f.claim('a');
  const b = await f.claim('b');
  await f.activate(a);
  await f.activate(b);
  assert.equal((await f.service.getUserStatus(USER_A)).serverName, 'cbhr-pc-' + USER_A);
  assert.equal((await f.service.getUserStatus(USER_B)).serverName, 'cbhr-pc-' + USER_B);
  assert.equal((await f.service.getUserStatus('cccccccccccccccccccccccc')).connected, false);
  assert.equal(
    await f.service.refreshTools({ sessionId: a.sessionId, sessionSecret: b.sessionSecret }),
    null,
  );
  await f.service.disconnect({ sessionId: a.sessionId, sessionSecret: a.sessionSecret });
  assert.deepEqual(await f.service.getUserStatus(USER_A), { connected: false });
  assert.equal((await f.service.getUserStatus(USER_B)).connected, true);
});
test('PM-F / activation: DNS success + temporary Cloudflare 1033 retries registration before active', async () => {
  let publicAttempts = 0;
  let registrationAttempts = 0;
  const f = setup({
    endpointReady: async () => {
      publicAttempts += 1;
      return publicAttempts >= 3;
    },
    register: async () => {
      registrationAttempts += 1;
      return { serverName: 'cbhr-pc-recovered', tools: ['Read'] };
    },
  });
  const pair = await f.claim('a');
  assert.equal((await f.service.getUserStatus(USER_A)).connected, false);
  const active = await f.activate(pair);
  assert.equal(active.serverName, 'cbhr-pc-recovered');
  assert.equal(
    publicAttempts,
    3,
    'must retry transient public-endpoint unavailability after DNS is ready',
  );
  assert.equal(
    registrationAttempts,
    1,
    'must not register before the public endpoint is reachable',
  );
  assert.equal((await f.service.getUserStatus(USER_A)).connected, true);
});
test('PM-F / activation: permanent public MCP failure is never marked connected', async () => {
  const f = setup({ endpointReady: async () => false });
  const pair = await f.claim('a');
  await assert.rejects(f.activate(pair), { code: 'PC_ENDPOINT_NOT_READY' });
  assert.equal((await f.service.getUserStatus(USER_A)).connected, false);
  assert.equal(
    f.collection.rows.some((row) => row.state === 'active'),
    false,
  );
  assert.equal(f.calls.filter(([kind]) => kind === 'register').length, 0);
  assert.equal(f.calls.filter(([kind]) => kind === 'unregister').length, 0);
});
test('PM-F / activation: successful register without tools is compensated with no orphan', async () => {
  const f = setup({ register: async () => ({ serverName: 'cbhr-pc-created', tools: [] }) });
  const pair = await f.claim('a');
  await assert.rejects(f.activate(pair), { code: 'PC_TOOLS_NOT_FOUND' });
  assert.equal((await f.service.getUserStatus(USER_A)).connected, false);
  assert.deepEqual(
    f.calls.filter(([kind]) => kind === 'unregister').map((x) => x[2]),
    ['cbhr-pc-created'],
  );
});
test('PM-F / hot permissions: failed rediscovery does not advance tool revision', async () => {
  const f = setup({
    refresh: async () => {
      throw new Error('refresh failure');
    },
  });
  const pair = await f.claim('a');
  await f.activate(pair);
  await assert.rejects(
    f.service.refreshTools({ sessionId: pair.sessionId, sessionSecret: pair.sessionSecret }),
  );
  assert.equal((await f.service.getUserStatus(USER_A)).toolRevision, 1);
});
test('PM-F / hot permissions: successful rediscovery advances revision exactly once', async () => {
  const f = setup({ refresh: async () => ['Read'] });
  const pair = await f.claim('a');
  await f.activate(pair);
  const first = await f.service.refreshTools({
    sessionId: pair.sessionId,
    sessionSecret: pair.sessionSecret,
  });
  const second = await f.service.refreshTools({
    sessionId: pair.sessionId,
    sessionSecret: pair.sessionSecret,
  });
  assert.equal(first.toolRevision, 2);
  assert.equal(second.toolRevision, 3);
});
const ACTIVE_PC = 'cbhr_pc_11111111-1111-4111-8111-111111111111';
const STALE_PC = 'cbhr_pc_22222222-2222-4222-8222-222222222222';
const MCP_DELIMITER = '__';
const MCP_ALL = 'mcp_all';
const pcWildcard = (serverName) => MCP_ALL + MCP_DELIMITER + serverName;
const activeCollection = {
  async findOne(query) {
    assert.equal(query.userId, USER_A);
    assert.equal(query.state, 'active');
    return {
      userId: USER_A,
      state: 'active',
      expiresAt: new Date('2026-11-06T23:00:00Z'),
      serverName: ACTIVE_PC,
    };
  },
};
const getTrustedPCConfig = async (serverName, userId) => {
  assert.equal(serverName, ACTIVE_PC);
  assert.equal(userId, USER_A);
  return {
    title: 'CBHR PC',
    type: 'streamable-http',
    url: 'https://pc-fixture.kelownarealestate.com/mcp',
  };
};
const resolveTurnTools = (tools) =>
  resolveEffectivePCTools({
    userId: USER_A,
    tools,
    canUseServers: true,
    collection: activeCollection,
    getServerConfig: getTrustedPCConfig,
    delimiter: MCP_DELIMITER,
    allToolName: MCP_ALL,
    now: () => new Date('2026-11-06T22:00:00Z'),
  });

test('PM-F / server authority: authenticated model-turn path resolves live bridge server-side', async () => {
  assert.deepEqual(await resolveTurnTools([]), [pcWildcard(ACTIVE_PC)]);
});
test('PM-F / server authority: old chats and browser-stale turns do not require client MCP selection', async () => {
  const tools = await resolveTurnTools(['ultrasearch', pcWildcard(STALE_PC)]);
  assert.ok(tools.includes(pcWildcard(ACTIVE_PC)));
  assert.ok(!tools.includes(pcWildcard(STALE_PC)));
});
test('PM-F / coexistence: server turn attachment preserves UltraSearch', async () => {
  const tools = await resolveTurnTools(['ultrasearch']);
  assert.deepEqual(tools, ['ultrasearch', pcWildcard(ACTIVE_PC)]);
});
test('PM-F / tool refresh: model-turn tool catalog has revision-sensitive re-read', () => {
  const s = serverSources();
  expectMatch(s, /toolRevision/);
  expectMatch(
    s,
    /(?:reinitMCPServer|refreshTools|rediscover|toolRevision).*?(?:mcp|tools|server)/is,
  );
});
test('PM-F / prompt: centrally deployed default skill describes physical PC versus AI sandbox', () => {
  const skill = read('skill/cb-bridge/SKILL.md');
  const contract = read('packages/api/src/agents/staffWorkstationContract.ts');
  const text = skill + '\\n' + contract;
  expectMatch(text, /CB Bridge/i);
  expectMatch(text, /physical Windows|physical PC|physical workstation/i);
  expectMatch(text, /sandbox/i);
  expectMatch(text, /permission|denial|denied|revok/i);
  expectMatch(text, /reconnect/i);
  expectMatch(skill, /centrally deployed/i);
  expectMatch(skill, /cannot grant permissions|cannot grant/i);
});
test('PM-F / prompt: exact exposed tools and no false connected claim', () => {
  const text =
    read('skill/cb-bridge/SKILL.md') +
    '\\n' +
    read('packages/api/src/agents/staffWorkstationContract.ts');
  expectMatch(text, /exact (?:offered|tool) names|exact tool names/i);
  expectMatch(
    text,
    /not exposed.*cannot inspect|No CB Bridge tool is exposed.*Do not claim physical-PC access/is,
  );
  expectMatch(text, /Read/i);
  expectMatch(text, /Edit/i);
  expectMatch(text, /PowerShell/i);
});
test('PM-F / interruption: durable resumable checkpoint records completed effects and saved artifacts', () => {
  const sources = [path.join(ROOT, 'api/server/controllers/agents/agentFailure.js')]
    .map((p) => fs.readFileSync(p, 'utf8'))
    .join('\n');
  expectMatch(sources, /(?:checkpoint|recoveryReceipt|resumeReceipt)/i);
  expectMatch(sources, /(?:completed.{0,20}(?:tool|effect)|lastCompletedTool)/i);
  expectMatch(sources, /(?:saved.{0,20}(?:artifact|file)|artifact.{0,20}checkpoint)/i);
});
test('PM-F / interruption: before-tool, after-read and after-write resume never auto-replays writes', () => {
  const {
    buildRecoveryReceipt,
    formatRecoveryContext,
  } = require('../../../controllers/agents/agentFailure');
  const receipt = buildRecoveryReceipt({
    error: Object.assign(new Error('secret provider body'), { status: 503 }),
    conversationId: 'convo-1',
    runId: 'run-1',
    model: 'model-1',
    provider: 'provider-1',
    startedAt: Date.parse('2026-11-06T22:00:00Z'),
    failedAt: Date.parse('2026-11-06T22:00:01Z'),
    contentParts: [
      {
        type: 'tool_call',
        tool_call: {
          id: 'write-1',
          name: 'edit_file',
          output: 'completed',
          artifact: { files: [{ id: 'file-1' }] },
        },
      },
    ],
  });
  assert.equal(receipt.sideEffectsAutoReplayed, false);
  assert.equal(receipt.completedTools[0].replay, 'side_effecting');
  assert.equal(receipt.completedTools[0].status, 'completed');
  assert.deepEqual(receipt.artifactRefs, ['file-1']);
  assert.match(
    formatRecoveryContext(receipt),
    /Do not automatically repeat.*writes.*side effects/i,
  );
});
test('PM-F / interruption: returned failure receipt contains sanitized cause and stable run ID', () => {
  const { buildRecoveryReceipt } = require('../../../controllers/agents/agentFailure');
  const secret = 'Bearer-SHOULD-NOT-APPEAR';
  const receipt = buildRecoveryReceipt({
    error: Object.assign(new Error(secret), { status: 503 }),
    conversationId: 'convo-2',
    runId: 'run-stable-2',
    model: 'model-2',
    provider: 'provider-2',
    startedAt: Date.parse('2026-11-06T22:00:00Z'),
  });
  assert.equal(receipt.runId, 'run-stable-2');
  assert.equal(receipt.failureClass, 'gateway_network');
  assert.ok(!JSON.stringify(receipt).includes(secret));
});
test('PM-F / attachment: first-call injection path is present, not deferred to second call', () => {
  const init = read('api/server/controllers/agents/client.js');
  const handler = read('packages/api/src/agents/handlers.ts');
  expectMatch(init, /buildInitialToolSessions/);
  expectMatch(handler, /_injected_files/);
  expectMatch(handler, /codeSessionContext[.]files/);
});
test('PM-F / attachment: next-turn artifact and filename identity checked at sandbox boundary', () => {
  const src = sourceFiles('packages/api/src/agents')
    .concat(sourceFiles('api/server/services/Files'))
    .map((p) => fs.readFileSync(p, 'utf8'))
    .join('\n');
  expectMatch(src, /(?:generated|artifact).{0,45}(?:next.turn|persist|carry|conversation)/is);
  expectMatch(
    src,
    /(?:saniti[sz]ed|safe).{0,50}(?:file.?name|path)|(?:file.?name|path).{0,50}saniti[sz]ed/is,
  );
});
test('PM-F / invalid aliases: unknown bash_terminal has correction and cannot execute', () => {
  const helper = read('packages/api/src/agents/unknownToolFeedback.ts');
  const handlers = read('packages/api/src/agents/handlers.ts');
  expectMatch(helper, /The requested tool was not executed/);
  expectMatch(helper, /Use the exact registered name|exact tool name available/i);
  expectMatch(helper, /Related available tool/);
  expectMatch(handlers, /buildUnknownToolError/);
  expectMatch(handlers, /correctiveToolNames/);
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
    async emitError() {
      events.push('emit');
      throw new Error('pubsub down');
    },
    async completeJob(_id, message) {
      events.push('complete');
      assert.ok(message.startsWith('MODEL_REQUEST_INTERRUPTED'));
    },
  };
  const result = await persistAgentFailure(manager, 'test-stream', new Error('provider closed'));
  assert.equal(result.eventDelivered, false);
  assert.deepEqual(events, ['emit', 'complete']);
});
