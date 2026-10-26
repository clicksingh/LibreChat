const test = require('node:test');
const assert = require('node:assert/strict');
const { shouldUseScopedExecution, verifyExecutionConversation } = require('./b1Cutover');
const cutoverUtc = '2026-10-19T08:00:00Z';
const check = (conversation) => shouldUseScopedExecution({ cutoverUtc, conversation });
test('new chat after explicit rollout gets fresh isolated B1 identity', () => {
  assert.equal(check(null), true);
  assert.equal(check(undefined), true);
});
test('existing legacy chat preserves old session; new persistent chat uses B1', () => {
  assert.equal(check({ createdAt: new Date('2026-10-16T18:10:00Z') }), false);
  assert.equal(check({ createdAt: new Date('2026-10-19T08:00:00Z') }), true);
  assert.equal(check({ createdAt: '2026-10-19T08:01:00Z' }), true);
});
test('old ambiguous records are never guessed to be new', () => {
  assert.equal(check({}), false);
  assert.equal(check({ createdAt: 'invalid' }), false);
});
test('missing/invalid cutover config fails closed rather than changing all chats', () => {
  for (const s of ['', 'tomorrow', '2026-10-19', '2026-10-19T08:00:00+00:00'])
    assert.throws(
      () => shouldUseScopedExecution({ cutoverUtc: s, conversation: null }),
      /TIMESTAMP_REQUIRED/,
    );
});

const idA = '0a98a665-ffe0-4ba4-8906-8dc94320de92';
const idB = '40991b6e-7c65-44d3-b86e-c43b24f266f3';
function verify(overrides = {}) {
  return verifyExecutionConversation({
    userId: 'test-owner',
    conversationId: idA,
    requestedId: idA,
    ownedConversation: null,
    lookupGlobalConversation: async () => null,
    ...overrides,
  });
}
test('first message with already assigned UUID but no Convo row is NEW', async () => {
  assert.equal(await verify(), null);
});
test('existing owned chat preserves trusted cutover timestamp', async () => {
  const row = { createdAt: '2026-10-18T00:00:00Z', user: 'test-owner' };
  assert.equal(await verify({ ownedConversation: row }), row);
});
test('existing foreign or claimed UUID fails closed, even without owned row', async () => {
  await assert.rejects(
    verify({ lookupGlobalConversation: async () => ({ _id: 'foreign' }) }),
    /access denied/,
  );
  await assert.rejects(verify({ requestedId: idB }), /identity mismatch/);
  await assert.rejects(verify({ lookupGlobalConversation: undefined }), /access denied/);
});
test('malformed and unauthenticated execution identity denied', async () => {
  await assert.rejects(verify({ conversationId: '../forged' }), /authenticated conversation/);
  await assert.rejects(verify({ userId: '' }), /authenticated conversation/);
});
