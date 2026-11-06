# PM-F isolated runtime adapter contract

Status: INCOMPLETE until the manager provides an exact-SHA convergence candidate and an isolated test adapter.

Run from candidate root with PMF_RUNTIME_ADAPTER set to an absolute path for a test-only CommonJS module, then invoke: node --test api/server/services/PCBridge/tests/pmF.runtime-gates-20261106.check.cjs

## Isolation

Adapter exports async createFixture({ isolated: true, productionMutation: false }). It MUST reject non-isolated use and return a disposable context with close(). Never point this at any live staff account, production Cloudflare tunnel, staff workstation, or production database. The verifier oracle is independent and should not be weakened to make a candidate green.

## Test fixture API

- connect({userId,serverName}), disconnect({userId}), conversation({userId,kind}), turn({userId,conversationId,browserSelection,staleRevision?}). Turn returns serverNames and toolNames ACTUALLY offered to the model, not client-cache projections.
- activation({userId,dnsReady,publicResponses}) returns connected, attempts, registeredOrphans. DNS readiness cannot imply Connected while MCP returns 1033/530.
- permissions({userId,mode?,folders?,powerShell?,screenshot?}) returns revision, folders, toolNames. invoke({userId,name,staleRevision,argument?}) returns executed and denial. Invoke exact names discovered from the catalog; local authorization must deny stale calls.
- screenshot({userId}) returns imageBytes, modelReceivedImage, denial. The live gate must also prove actual pixels were received by a vision model, never only tool availability.
- interrupt({userId,phase,marker}) returns receipt and writeCount; resume({receiptId}) returns duplicateWrites, writeCount, savedArtifactsPreserved. Phases are before_tool, after_read, after_write. Receipt includes id, runId, conversationId, lastCompletedTool, completedEffects. No secret can appear. After-write resume must not repeat a mutation.
- attachment({userId,name,content,duplicates?}), generate({userId,name,content}), firstCodeCall({userId,newTurn?}). First call returns callNumber and injectedFiles with id, actualName, advertisedName, actualPath. Verify first-call visibility and prior artifact on the next turn.
- invalidTool({userId,name}) returns executed, success, suggestedNames, availableNames. Invalid bash_terminal must not execute and must suggest only genuinely exposed tools.
- agentUnderstanding({userId,bridgeAvailable}) returns claimsPCConnected, prefersBridgeForPhysicalPC, exposesInternalServerName.

## Evidence and verdicts

For every scenario retain candidate SHA, native SHA, catalog revision, model-visible tool names, sanitized actor/conversation aliases, injected failure phase, completed side effects, and output artifact/file receipts. Live/staging must include two authorized users, reconnect, hot permissions, screenshot interpreted as pixels, safe forced interrupted test write, and first code call attachment.

Missing adapter: INCOMPLETE. Failed assertion: FAIL. Unsafe/unexecuted live scenario: HOLD. PASS requires exact-SHA repeatable evidence; no production mutation authorized.
