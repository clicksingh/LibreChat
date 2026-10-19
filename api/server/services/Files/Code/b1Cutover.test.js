const test=require('node:test');
const assert=require('node:assert/strict');
const {shouldUseScopedExecution}=require('./b1Cutover');
const cutoverUtc='2026-10-19T08:00:00Z';
const check=conversation=>shouldUseScopedExecution({cutoverUtc,conversation});
test('new chat after explicit rollout gets fresh isolated B1 identity',()=>{
 assert.equal(check(null),true);
 assert.equal(check(undefined),true);
});
test('existing legacy chat preserves old session; new persistent chat uses B1',()=>{
 assert.equal(check({createdAt:new Date('2026-10-16T18:10:00Z')}),false);
 assert.equal(check({createdAt:new Date('2026-10-19T08:00:00Z')}),true);
 assert.equal(check({createdAt:'2026-10-19T08:01:00Z'}),true);
});
test('old ambiguous records are never guessed to be new',()=>{
 assert.equal(check({}),false);
 assert.equal(check({createdAt:'invalid'}),false);
});
test('missing/invalid cutover config fails closed rather than changing all chats',()=>{
 for(const s of ['', 'tomorrow','2026-10-19','2026-10-19T08:00:00+00:00'])
  assert.throws(()=>shouldUseScopedExecution({cutoverUtc:s,conversation:null}),/TIMESTAMP_REQUIRED/);
});
