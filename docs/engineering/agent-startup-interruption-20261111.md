# Agent startup interruption: diagnostic and canary runbook (2026-11-11)

## Scope and authority

This branch is based on the deployed source commit `8b527a53b40823630397d12d55017f6b5fc54757`.
It adds **diagnostics only**, not retry policy, provider changes, side-effect replay, database edits, or deployment.
The incident's conversation, user, host address, artifact IDs, and business content are intentionally absent from this public repository.

## Observed incident (redacted)

- One tool-heavy conversation completed and published three generated files.
- The first subsequent user turn and four more turns failed before any new tool execution.
- Five server receipts classify `agent_exception`, all with `upstreamStatus: null`, no completed/uncertain tool calls.
- Failures occur in well under one second; this is not evidence of a provider HTTP response.
- The preceding healthy assistant turn retains reasoning blocks and 130 tool result messages.
- In-process `formatAgentMessages` passed on the production history (eight DB messages to 142 reconstructed messages).
- Historical output attachments are display-only, not automatically resent as user files.
- Conversation-scoped CodeAPI execution session ownership is consistent with generated file provenance.
- `buildMessages()` completes before `chatCompletion()` catches the exception.

**Do not diagnose by hypothesis alone:** the exact throwing operation and exception were absent from existing production logs.

## New diagnostic contract

The `chatCompletion` catch now prints one bounded structured JSON string to the server error log:
`failureStage`, `failureClass`, `errorName`, `errorCode`, `errorShape`,
`stackSite`, `failureFingerprint`, `conversationId`, `runId`, `streamEntered`.

- `errorShape` uses a strict allowlist of generic JavaScript exception forms.
- `stackSite` includes only a whitelisted application/package path and line/column.
- `failureFingerprint` is a one-way, truncated hash of the original exception for correlation.
- Raw exception messages, user prompts, tool arguments/outputs, artifact paths and unredacted stacks are never emitted.
- `streamEntered` means `processStream` was entered; it does **not** prove a provider request occurred.

## Execution sequence

1. Establish exact image/source parity with the deployed SHA; record commit and image digest. Confirm worktree and branch are clean.
2. Build this branch into a **nonproduction** image. Keep the original production container intact.
3. Copy only the minimum necessary authorized conversation state into a private canary store. Keep PII, credentials, file content, and generated artifacts out of Git and general logs. Do not point canary at production tool endpoints.
4. In the canary, simulate the first user continuation following the last healthy assistant message. Do not authorize any tool to write, send, rename, or execute on live endpoints.
5. Capture the bounded `[AgentInterruption]` JSON event. Identify `failureStage` plus safe `stackSite` and `errorShape` before changing runtime logic.
6. Add a failing regression reproducing that precise invariant, patch only that invariant, and prove the second turn reaches the LLM. Also test third turn after DB roundtrip/restart.
7. Repeat with memory on/off, B1 sessions, generated artifacts, 100+ tools, missing historical tools, HITL on/off, and `hide_sequential_outputs` modes.
8. Promote only after these tests plus normal build, security and endpoint gates pass. Keep a rollback image/commit.
9. Recovery of the affected chat must branch from the last healthy node and verify saved artifacts before any side effects. Never rewrite the incident branch or automatically replay completed/uncertain operations.

## Acceptance gates

| Gate | Required result |
| --- | --- |
| G0 source/evidence | Exact deployed SHA and no production mutation |
| G1 diagnostics | Sanitized phase + fingerprint + code-site in canary logs |
| G2 reproduction | Exact second-turn failure isolated without real tools |
| G3 regression | Test fails before fix and passes after |
| G4 contract | Local vs provider failure distinguishable; no sensitive logging |
| G5 integration | Second and third turns complete; artifacts and tool history survive reload |
| G6 deployment | Canary accepted; production rollout explicitly authorized and reversible |

## Current status

- Diagnostic branch and tests: prepared.
- JavaScript syntax and standalone diagnostic privacy smoke: passed on an isolated checkout.
- Full repository Jest and canary conversation replay: **not yet verified**.
- Functional root-cause patch and production deployment: **not performed**.

Do not describe this incident as fixed until G2 through G6 are evidenced.
