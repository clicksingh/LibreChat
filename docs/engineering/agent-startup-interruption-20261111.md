# Agent startup interruption: B1 CSV grant fix and canary runbook (2026-11-11)

## Scope and authority

This branch is based on the deployed source commit `8b527a53b40823630397d12d55017f6b5fc54757`.
It fixes a narrowly demonstrated B1 CSV file-grant mismatch and adds bounded diagnostics. It does not change provider routing, retries, side-effect replay, database content, or deployment.
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

## Validated contract mismatch

The prior completed turn emitted two CSV output files and one XLSX with owner-bound `codeEnvRef` metadata.
The initialize/prime path collects output `attachments` from the conversation's parent chain and
seeds `execute_code` sessions with those references on subsequent turns. The B1 scoped grant
validator previously allowed only DOCX, PDF and XLSX and rejected every CSV, including
**legitimately generated output registers**. A read-only production metadata probe
through `authorizedFileGrants` reproduced two
`CODEAPI_EXECUTION_INPUT_SCOPE_UNVERIFIED` failures (CSV) and one pass (XLSX).

The patch permits **CSV data files only** in addition to the existing three types. It
does not admit scripts, executables or macros. The original owner/tenant/resource
identity, session, filename, size, duplicate handling and storage SHA attestation
remain mandatory. Contract tests now cover mixed CSV + XLSX outputs, rejection of
executables, and SHA verification with exact DB-backed records.

This explains the timing and class of the five startup failures. The complete
conversation canary is still required to distinguish this cause from any concurrent
failure and certify user-visible recovery.

## Reproduction and canary evidence (2026-11-11)

- **Baseline RED:** the 13-case B1 contract suite against the deployed `8b527a53` validator fails its two generated-CSV continuation cases: **11 PASS, 2 FAIL**, both `CODEAPI_EXECUTION_INPUT_SCOPE_UNVERIFIED`.
- **Patched GREEN:** the identical suite against the branch validator passes **13/13**, including forged ref, cross-owner/tenant/session, unsupported executable extension, oversized file, duplicate and bad digest negatives.
- **Production-data metadata canary:** read-only records for the completed turn were streamed directly from Mongo into an isolated canary process; nothing was written to Mongo or logged beyond file types and pass/fail. Patched B1 validation: **CSV, CSV, XLSX all PASS**.
- **Full B1 scoped grant resolver in canary:** those three exact metadata records produced three authorized grants and three synthetic hash attestations, with owner-bound database query verification. **PASS**. Hashing was deliberately mocked; this did **not** read or assert the physical file contents.
- **Canary runtime:** production image `sha256:ad3c414b14d3d14b9be3f17165267fdc0474d28986e10ca01abab125c1974210`, bound read-only patched modules, isolated staging Mongo, loopback-only port 33312. `/readyz` returned **200**; the original `LibreChat` container remained running at the same image digest.
- **Synthetic conversation history integration:** `b1Continuation.spec.js` traverses stored parent ancestry, collects assistant-generated attachments, excludes an unrelated sibling, seeds execute-code session, authorizes both CSVs and XLSX, and verifies the same grants survive turn three. **PASS** in GitHub backend shard 2/3.
- **Diagnostics:** standalone privacy tests and CI `agentStartupDiagnostics.spec.js` and `client.test.js` passed. A local B1 classification smoke verified the new `CODE_FILE_VALIDATION` error and lack of unsafe replay messaging.

The isolated canary did **not** exercise a fully authenticated, model-backed second-turn HTTP request. Therefore it validates the proven B1 failure boundary, not complete user-visible chat recovery.

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
2. Use the exact production image with read-only patched-module bind mounts in a private, loopback-only container, or build an equivalent immutable image. Keep the original production container intact.
3. Copy only the minimum necessary authorized conversation state into a private canary store. Keep PII, credentials, file content, and generated artifacts out of Git and general logs. Do not point canary at production tool endpoints.
4. In the canary, simulate the first user continuation following the last healthy assistant message. Do not authorize any tool to write, send, rename, or execute on live endpoints.
5. Capture bounded startup diagnostics if any additional failure survives the B1 CSV fix. Identify `failureStage` plus safe `stackSite` and `errorShape` before altering another runtime invariant.
6. Add a failing regression reproducing that precise invariant, patch only that invariant, and prove the second turn reaches the LLM. Also test third turn after DB roundtrip/restart.
7. Repeat with memory on/off, B1 sessions, generated artifacts, 100+ tools, missing historical tools, HITL on/off, and `hide_sequential_outputs` modes.
8. Promote only after these tests plus normal build, security and endpoint gates pass. Keep a rollback image/commit.
9. Recovery of the affected chat must branch from the last healthy node and verify saved artifacts before any side effects. Never rewrite the incident branch or automatically replay completed/uncertain operations.

## Acceptance gates

| Gate | Required result |
| --- | --- |
| G0 source/evidence | PASS: exact deployed image/source; live container unchanged |
| G1 diagnostics | PARTIAL: privacy/unit tests PASS; no live thrown canary event yet |
| G2 reproduction | PARTIAL: exact metadata rejects 2 CSVs on deployed validator; no full HTTP replay |
| G3 regression | PASS: baseline 11/13, patched 13/13; security negatives preserved |
| G4 contract | PASS: local B1 classified distinctly; no raw error/user data logged |
| G5 integration | PARTIAL: two-/three-turn synthetic lineage test PASS; no full provider backed replay |
| G6 deployment | HOLD: production image/DB/chat unchanged; promotion not authorized or executed |

## Current status

- CSV allowlist and local B1 failure classification: implemented and verified at their contract boundaries.
- Same tests baseline RED **11/13**, patch GREEN **13/13**.
- Real-metadata isolated canary and full B1 resolver: **3/3 PASS**; file bytes not accessed.
- Two-/three-turn synthetic-history integration, client diagnostics Jest, syntax, privacy smoke: **PASS**.
- Relevant GitHub jobs: Static Checks, Docker Build Smoke, scoped conversation issuer, workspace ABC, and Bombadil completed **PASS** on the earlier diagnostic/CSV build. The backend aggregate remains red in unrelated unmodified test areas (disconnect persistence, MCP missing-tool text expectation, and TypeScript provider enum). These need their own baseline validation or explicit release waiver, not hidden test edits.
- Full authenticated HTTP second-turn recovery and provider-backed integration: **not yet certified**.
- Production deployment and live conversation changes: **not performed**.

Do not describe the user-visible production chat as fixed until G2/G5/G6 are evidenced and production is promoted through the normal release boundary.
