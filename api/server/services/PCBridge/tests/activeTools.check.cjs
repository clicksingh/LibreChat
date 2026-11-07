'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { resolveEffectivePCTools } = require('../activeTools');

const A = '6a31557594ab025c7537576e';
const B = '111111111111111111111111';
const NAME = 'cbhr_pc_00000000-0000-4000-8000-000000000222';
const DELIMITER = '_mcp_';
const PC = 'mcp_all' + DELIMITER + NAME;
const SEARCH = 'mcp_all_mcp_UltraSearch';
const config = {
  title: 'CBHR PC',
  type: 'streamable-http',
  url: 'https://pc-test.kelownarealestate.com/mcp',
};

function fixture({
  owner = A,
  state = 'active',
  expired = false,
  allowed = true,
  publishedConfig = config,
} = {}) {
  const queries = [];
  const configs = [];
  const row = {
    userId: owner,
    state,
    serverName: NAME,
    expiresAt: new Date(expired ? '2026-11-01' : '2026-11-08'),
  };
  const collection = {
    async findOne(query) {
      queries.push(query);
      return row.userId === query.userId &&
        row.state === query.state &&
        row.expiresAt > query.expiresAt.$gt
        ? row
        : null;
    },
  };
  const resolve = (userId = A, tools = [SEARCH]) =>
    resolveEffectivePCTools({
      userId,
      tools,
      canUseServers: allowed,
      collection,
      getServerConfig: async (name, id) => {
        configs.push({ name, id });
        return name === NAME && id === owner ? publishedConfig : null;
      },
      delimiter: DELIMITER,
      allToolName: 'mcp_all',
      now: () => new Date('2026-11-06'),
    });
  return { resolve, queries, configs, row };
}

test('new conversation gets connected PC without browser MCP values', async () => {
  assert.deepEqual(await fixture().resolve(A, []), [PC]);
});
test('existing conversation gets PC on next turn without refresh', async () => {
  const f = fixture({ state: 'claimed' });
  assert.deepEqual(await f.resolve(A, [SEARCH]), [SEARCH]);
  f.row.state = 'active';
  assert.deepEqual(await f.resolve(A, [SEARCH]), [SEARCH, PC]);
});
test('UltraSearch coexists and the wildcard is not duplicated', async () => {
  const f = fixture();
  assert.deepEqual(await f.resolve(A, [SEARCH, PC]), [SEARCH, PC]);
});
test('disconnect removes previously selected PC on next turn', async () => {
  const f = fixture();
  assert.deepEqual(await f.resolve(A, [SEARCH, PC]), [SEARCH, PC]);
  f.row.state = 'closed';
  assert.deepEqual(await f.resolve(A, [SEARCH, PC]), [SEARCH]);
});
test('user B cannot attach user A PC, even with stolen browser key', async () => {
  const f = fixture();
  assert.deepEqual(await f.resolve(B, [SEARCH, PC]), [SEARCH]);
  assert.equal(f.configs.length, 0);
  assert.equal(f.queries[0].userId, B);
});
test('expired session never attaches', async () => {
  assert.deepEqual(await fixture({ expired: true }).resolve(A, [SEARCH, PC]), [SEARCH]);
});
test('MCP use denial strips stale PC and keeps managed tools', async () => {
  const f = fixture({ allowed: false });
  assert.deepEqual(await f.resolve(A, [SEARCH, PC]), [SEARCH]);
  assert.equal(f.queries.length, 1);
  assert.equal(f.configs.length, 0);
});
test('unregistered or mismatched server config never attaches', async () => {
  assert.deepEqual(await fixture({ publishedConfig: null }).resolve(A, []), []);
  assert.deepEqual(
    await fixture({ publishedConfig: { ...config, title: 'Other' } }).resolve(A, []),
    [],
  );
});
test('an invalid principal fails closed and strips old PC keys', async () => {
  const f = fixture();
  assert.deepEqual(await f.resolve('wrong', [SEARCH, PC]), [SEARCH]);
  assert.equal(f.queries.length, 0);
});
