# Agent interruption test contract alignment (2026-11-11)

## Authority and scope

- Baseline: deployed production source commit `ad21cf1994a1fbd6514df40755c9a9645ed877a9`.
- This lane changes only two Playwright tests. No application code, model routing, tool authorization, MongoDB production records or historical conversation branches are modified.
- Context: the B1 CSV continuation defect was fixed in merged PR #50. Its separate opt-in authenticated red/green evidence is in draft PR #51.
- The live production container is already running `cbhr-ai:pam-csv-ad21cf199-20261111`, with that exact revision label, and `/readyz` returns 200.

## What the production code actually guarantees

An interrupted agent run is an **unfinished response**, not a successfully finalized model answer. The checkpoint is persisted with:

- `unfinished: true`, `error: false`
- a bounded structured `content` error
- a `metadata.interruption` receipt containing failure classification and completed/uncertain tool history
- `sideEffectsAutoReplayed: false`

The frontend's run-end handling treats the unfinished response as aborted, preventing automatic draining of queued state-changing tasks. The normal success helper, `sendMessageAndWaitForCompletion`, correctly requires a finalized error-free response. The forced-error test must therefore not call that helper.

## Baseline evidence

On the unchanged baseline, the two focused Playwright cases both failed:

1. `completion.spec.ts` expected an obsolete generic error sentence and used the success-only completion helper for a deliberate failure.
2. `message-tree.spec.ts` expected that same obsolete sentence instead of `MODEL_REQUEST_INTERRUPTED`.

The application displayed the structured `MODEL_REQUEST_INTERRUPTED` alert and recovery receipt. Neither failure alone demonstrated inability to continue.

## Test-only repair

- `e2e/specs/mock/completion.spec.ts`: use admission-only `sendMessage`, poll durable Mongo for the precise user/assistant edge, `unfinished:true`, a sanitized model error part, interruption receipt, empty completed/uncertain tool arrays and explicit `sideEffectsAutoReplayed:false`; verify UI alert and persistence after reload.
- `e2e/specs/mock/message-tree.spec.ts`: expect the current structured interruption prefix, then exercise the *actual* subsequent successful turn, parent/child lineage, reload and revisit.

Do **not** change `e2e/specs/mock/helpers.ts` to consider an unfinished response a successful generation. Do not change runtime response persistence merely to appease obsolete test assertions.

## Reproduction and acceptance

Isolated TECH worktree, separate authenticated synthetic test account, fake model, private local MongoDB `mongo:8.0`, in-memory stream store, Playwright Chrome, workers=1, retries=0. No real model or accounting tool credentials.

- Exact lockfile install: **PASS**, 2943 packages.
- Full frontend/API build: **PASS**.
- Baseline original two focused tests: **0/2 PASS**.
- First expectation-only repair: message-tree **PASS**, completion **FAIL** because the helper wrongly waited for `unfinished:false` in the intentional-error case.
- Correct durable-error contract repair: **2/2 PASS**, 58.1 seconds, no retries.
- ESLint/Prettier and `git diff --check`: **PASS**.
- Runtime files changed: **zero**.

Focused test invocation:

```sh
playwright test completion.spec.ts message-tree.spec.ts --grep 'preserves an interrupted assistant checkpoint|error responses remain valid parents' --config=e2e/playwright.config.mock.ts --workers=1 --reporter=line --retries=0
```

Do not run without configured isolated fake-model server and disposable Mongo.

## Remaining separate gates

- GitHub Backend Unit Tests still fail in unmodified test paths: `request.partialDisconnect.spec.js`, `request.resumeMetadata.spec.js`, `handlers.background.spec.ts`, and `parsers.test.ts` TypeScript Provider enum usage. Each needs separate baseline-to-candidate contract reconciliation. Do not waive by changing application behavior or suppressing assertions.
- An isolated Playwright synthetic continuation is **not** a production user turn. The affected production conversation was not edited or sent a message, and no completed/uncertain accounting work was replayed.
- The original production conversation has three physical output artifacts present, with exact byte sizes 20091 CSV, 10537 CSV, 26925 XLSX, and five stored interrupted assistant responses after the last healthy output turn.
- Production recovery should use the supported UI to branch from the last verified completed output turn and begin with **read-only inventory**. Verify the CSV/XLSX contents and any external effects separately before authorizing new accounting actions. Never force-edit an interruption row or auto-replay tool calls.

## Release classification

**Test-contract correction only.** Eligible for separate review as a draft PR, not evidence that every repository-wide gate is green, not production deployment authorization, and not proof the human user successfully resumed the original chat.
