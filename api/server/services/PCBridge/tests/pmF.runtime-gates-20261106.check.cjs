'use strict';
/**
 * PM-F adapter-driven black-box contract, NEVER production-mutating.
 * Run ONLY against an explicitly supplied isolated staging/test adapter:
 *   set PMF_RUNTIME_ADAPTER=C:\path\to\isolated-test-adapter.cjs
 *   node --test api/server/services/PCBridge/tests/pmF.runtime-gates-20261106.check.cjs
 * Missing adapter means INCOMPLETE, not PASS.
 * See pmF.runtime-gates-20261106.md for the strict adapter interface.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const adapterPath = process.env.PMF_RUNTIME_ADAPTER || '';
const usable = adapterPath && fs.existsSync(path.resolve(adapterPath));
const adapter = usable ? require(path.resolve(adapterPath)) : null;
const userA = 'user-a-fixture';
const userB = 'user-b-fixture';
const bridge = 'cbhr-pc-fixture-A';
const bridgeB = 'cbhr-pc-fixture-B';
// Invoke tools by the exact live catalog name. Never guess aliases.
function gate(label, callback) {
  test('PM-F runtime / ' + label, { skip: usable ? false : 'INCOMPLETE: PMF_RUNTIME_ADAPTER not supplied' },
    async () => {
      assert.equal(typeof adapter?.createFixture, 'function', 'adapter.createFixture missing');
      const fixture = await adapter.createFixture({ isolated: true, productionMutation: false });
      try { await callback(fixture); } finally { await fixture.close(); }
    });
}
const servers = (turn) => turn.serverNames || [];
const names = (turn) => turn.toolNames || [];
gate('connected before chat is available on the first server-owned model turn', async (f) => {
  await f.connect({ userId: userA, serverName: bridge });
  const conversationId = await f.conversation({ userId: userA, kind: 'new' });
  const turn = await f.turn({ userId: userA, conversationId, browserSelection: [] });
  assert.ok(servers(turn).includes(bridge));
});
gate('connected mid-chat attaches without refresh or manual selection', async (f) => {
  const conversationId = await f.conversation({ userId: userA, kind: 'new' });
  assert.ok(!servers(await f.turn({ userId: userA, conversationId, browserSelection: [] })).includes(bridge));
  await f.connect({ userId: userA, serverName: bridge });
  assert.ok(servers(await f.turn({ userId: userA, conversationId, browserSelection: [] })).includes(bridge));
});
gate('reopened old conversation resolves current active PC', async (f) => {
  const conversationId = await f.conversation({ userId: userA, kind: 'old' });
  await f.connect({ userId: userA, serverName: bridge });
  assert.ok(servers(await f.turn({ userId: userA, conversationId, browserSelection: [] })).includes(bridge));
});
gate('stale browser MCP selection cannot override authenticated user session', async (f) => {
  await f.connect({ userId: userA, serverName: bridge });
  const conversationId = await f.conversation({ userId: userA, kind: 'existing' });
  const turn = await f.turn({ userId: userA, conversationId,
    browserSelection: [bridgeB], staleRevision: -1 });
  assert.ok(servers(turn).includes(bridge));
  assert.ok(!servers(turn).includes(bridgeB));
});
gate('disconnect removes PC and subsequent reconnect restores it', async (f) => {
  await f.connect({ userId: userA, serverName: bridge });
  const conversationId = await f.conversation({ userId: userA, kind: 'new' });
  await f.disconnect({ userId: userA });
  assert.ok(!servers(await f.turn({ userId: userA, conversationId, browserSelection: [bridge] })).includes(bridge));
  await f.connect({ userId: userA, serverName: bridge });
  assert.ok(servers(await f.turn({ userId: userA, conversationId, browserSelection: [] })).includes(bridge));
});
gate('cross-user isolation even with malicious/stale client selection', async (f) => {
  await f.connect({ userId: userA, serverName: bridge });
  await f.connect({ userId: userB, serverName: bridgeB });
  const conversationId = await f.conversation({ userId: userB, kind: 'new' });
  const b = await f.turn({ userId: userB, conversationId, browserSelection: [bridge, bridgeB] });
  assert.ok(servers(b).includes(bridgeB));
  assert.ok(!servers(b).includes(bridge));
});
gate('UltraSearch continues alongside connected Bridge', async (f) => {
  await f.connect({ userId: userA, serverName: bridge });
  const conversationId = await f.conversation({ userId: userA, kind: 'new' });
  const t = await f.turn({ userId: userA, conversationId, browserSelection: [] });
  assert.ok(servers(t).includes(bridge));
  assert.ok(servers(t).some((s) => /ultrasearch/i.test(s)));
});
gate('Cloudflare 1033/530 with valid DNS retries boundedly then activates', async (f) => {
  const receipt = await f.activation({ dnsReady: true, publicResponses: [530, 1033, 200], userId: userA });
  assert.equal(receipt.connected, true);
  assert.ok(receipt.attempts >= 3 && receipt.attempts <= 10);
  assert.equal(receipt.registeredOrphans, 0);
});
gate('permanent 530 cannot become Connected and leaves no registered orphan', async (f) => {
  const receipt = await f.activation({ dnsReady: true, publicResponses: Array(12).fill(530), userId: userA });
  assert.equal(receipt.connected, false);
  assert.ok(receipt.attempts >= 1 && receipt.attempts <= 10);
  assert.equal(receipt.registeredOrphans, 0);
});
gate('hot folder removal and addition change tool catalog without reconnect', async (f) => {
  await f.connect({ userId: userA, serverName: bridge });
  const a = await f.permissions({ userId: userA, folders: ['C:\\allowed'] });
  const b = await f.permissions({ userId: userA, folders: [] });
  const c = await f.permissions({ userId: userA, folders: ['C:\\new'] });
  assert.ok(a.revision < b.revision && b.revision < c.revision);
  assert.ok(!b.folders.includes('C:\\allowed'));
  assert.ok(c.folders.includes('C:\\new'));
});
gate('hot Read/Edit downgrade rejects stale Edit invocation locally', async (f) => {
  await f.connect({ userId: userA, serverName: bridge });
  const earlier = await f.permissions({ userId: userA, mode: 'Edit' });
  const changed = await f.permissions({ userId: userA, mode: 'Read' });
  const exactEditName = earlier.toolNames.find((name) => /edit/i.test(name));
  assert.ok(exactEditName, 'no exposed Edit tool');
  const denied = await f.invoke({ userId: userA, name: exactEditName, staleRevision: earlier.revision });
  assert.ok(changed.revision > earlier.revision);
  assert.equal(denied.executed, false);
  assert.equal(denied.denial, 'permission');
});
gate('PowerShell enable and revoke reject stale mutation locally', async (f) => {
  await f.connect({ userId: userA, serverName: bridge });
  const earlier = await f.permissions({ userId: userA, powerShell: true });
  const changed = await f.permissions({ userId: userA, powerShell: false });
  const exactPowerShellName = earlier.toolNames.find((name) => /powershell/i.test(name));
  assert.ok(exactPowerShellName, 'no exposed PowerShell tool');
  const denied = await f.invoke({ userId: userA, name: exactPowerShellName, staleRevision: earlier.revision,
    argument: 'Set-Content C:\\never-execute.txt bad' });
  assert.ok(changed.revision > earlier.revision);
  assert.equal(denied.executed, false);
});
gate('screen capture is permission-gated and delivered to vision as image bytes', async (f) => {
  await f.connect({ userId: userA, serverName: bridge });
  await f.permissions({ userId: userA, screenshot: true });
  const shown = await f.screenshot({ userId: userA });
  assert.ok(shown?.imageBytes > 100);
  assert.equal(shown.modelReceivedImage, true);
  await f.permissions({ userId: userA, screenshot: false });
  assert.equal((await f.screenshot({ userId: userA })).denial, 'permission');
});
for (const phase of ['before_tool', 'after_read', 'after_write']) {
  gate('interrupt '+phase+' produces durable sanitized receipt and safe continuation', async (f) => {
    const original = await f.interrupt({ userId: userA, phase, marker: 'fixture-secret-must-not-appear' });
    assert.ok(original.receipt?.id);
    assert.ok(original.receipt?.runId);
    assert.ok(original.receipt?.conversationId);
    assert.ok(original.receipt?.lastCompletedTool === null || typeof original.receipt?.lastCompletedTool === 'string');
    assert.ok(!JSON.stringify(original.receipt).includes('fixture-secret-must-not-appear'));
    const next = await f.resume({ receiptId: original.receipt.id });
    assert.equal(next.duplicateWrites, 0);
    if (phase === 'after_write') {
      assert.equal(original.receipt.completedEffects.some((effect) => effect.kind === 'write'), true);
      assert.equal(next.writeCount, original.writeCount);
    }
    assert.equal(next.savedArtifactsPreserved, true);
  });
}
gate('attachment is injected on first shell/code call, without warmup call', async (f) => {
  await f.attachment({ userId: userA, name: 'incoming.csv', content: 'a,b\n1,2\n' });
  const first = await f.firstCodeCall({ userId: userA });
  assert.ok(first.injectedFiles.some((entry) => entry.actualName === 'incoming.csv'));
  assert.equal(first.callNumber, 1);
});
gate('generated artifact appears on the next turn first code call', async (f) => {
  await f.generate({ userId: userA, name: 'result.csv', content: 'x\n9\n' });
  const next = await f.firstCodeCall({ userId: userA, newTurn: true });
  assert.ok(next.injectedFiles.some((entry) => entry.actualName === 'result.csv'));
});
gate('sanitized filename matches real file and duplicate resource refs collapse', async (f) => {
  await f.attachment({ userId: userA, name: '../strange name?.csv', content: 'z\n1\n', duplicates: 3 });
  const first = await f.firstCodeCall({ userId: userA });
  const matches = first.injectedFiles.filter((entry) => entry.id === first.injectedFiles[0].id);
  assert.equal(matches.length, 1);
  assert.equal(first.injectedFiles[0].advertisedName, first.injectedFiles[0].actualName);
  assert.ok(!first.injectedFiles[0].actualPath.includes('..'));
});
gate('invalid bash_terminal alias suggests true tools and executes nothing', async (f) => {
  const receipt = await f.invalidTool({ userId: userA, name: 'bash_terminal' });
  assert.equal(receipt.executed, false);
  assert.equal(receipt.success, false);
  assert.ok(receipt.suggestedNames.every((name) => receipt.availableNames.includes(name)));
  assert.ok(receipt.suggestedNames.length > 0);
});
gate('managed prompt explains PC versus sandbox and never fabricates PC access', async (f) => {
  const unavailable = await f.agentUnderstanding({ userId: userA, bridgeAvailable: false });
  assert.equal(unavailable.claimsPCConnected, false);
  const available = await f.agentUnderstanding({ userId: userA, bridgeAvailable: true });
  assert.equal(available.prefersBridgeForPhysicalPC, true);
  assert.equal(available.exposesInternalServerName, false);
});
