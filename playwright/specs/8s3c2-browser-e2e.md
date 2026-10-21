# 8S3C.2 browser E2E — Planner spec (Blocker 2)

Test agents (constitution model): this file is the **Planner** output (journeys
+ pass criteria). `playwright/tests/allowed-user-workstation-journey.spec.ts`
and `playwright/tests/malformed-layout-repair-loop.spec.ts` are the
**Generator** output, produced from live execution against the deployed,
post-8S3C.2-fix LibreChat (`297415a13`). The **Healer** may only classify
TEST_DRIFT — never relax a security or product expectation.

Directive: no direct handcrafted API call may substitute for a step that a
real user performs through the UI. Every message send in both journeys goes
through the actual browser composer (`textarea` + Enter), for the
`RUN_CODE.USE:true` browser-test user (`USERS.enabled`). Network
request/response interception is used only to VERIFY what the browser sent
and received — never to drive the action.

## J4 — normal-user 14-step workstation journey

Proves the authorized path still works end-to-end after the 8S3C.2 fix (the
fix must deny the unauthorized path without breaking the authorized one).

1. **Auth** — session injection (`loginAs`), no `/api/auth/login` call.
2. **Fresh conversation** — `page.goto('/c/new')`.
3. **Run Code via UI** — open the tools dropdown, click "Run Code", verify a
   `LAST_CODE_TOGGLE_*` localStorage key flips to `'true'`.
4. **PPTX/XLSX gen request** — type into the real composer a request to
   generate an XLSX workbook (openpyxl, a formula cell) and press Enter.
5. **bash_tool executes** — the outgoing `/api/agents/chat/:endpoint` request
   is captured; the SSE stream is parsed for a `bash_tool` tool_call.
6. **Source artifact** — the workbook file exists (bash_tool actually ran
   openpyxl and wrote a file — evidenced by a subsequent read/render step
   succeeding, not a fabricated claim).
7. **render-doc** — the model renders the workbook via the platform renderer
   (bash_tool invocation referencing the render pipeline).
8. **docvqa in FINAL tool defs** — `document_visual_qa` appears in the
   `on_context_usage` tool list actually sent to the provider.
9. **QA executes** — a real `document_visual_qa` tool_call in the stream.
10. **Artifact in UI** — the rendered/created file surfaces in the message
    (filename text visible in the transcript DOM).
11. **Same-convo modify/reuse** — a SECOND message, same conversation
    (`parentMessageId` chained), sent through the SAME composer, asking the
    model to open the EXISTING workbook (not recreate it) and change a value.
12. **Workspace reuse** — the model's final text reflects it read the
    pre-existing file (recomputed total reflects the changed input, not a
    freshly fabricated one).
13. **Modified artifact resurfaces** — the updated file/render appears in the
    UI for the second turn.
14. **Denied-user negative control held** — the 8S3C.2 post-fix proof
    (`post-fix-exploit-proof-20260817.json`) already establishes the ceiling
    holds for a denied user on this exact deployed image; this journey proves
    the allowed path is unaffected by that same fix (paired proof).

**Pass criteria:** steps 3, 5, 8, 9 are hard network/DOM assertions. Steps 6,
7, 12 are evidenced by the model's reported computed values matching the
expected arithmetic (deterministic — not free-text trust). Step 10/13 are
DOM-visibility assertions on the artifact filename.

## J5 — malformed-layout repair loop

Proves the render→QA→fix→re-QA loop (the "prove it renders correctly" loop)
through the real browser, using a deterministically-clipping PPTX slide (same
fixture as the accepted `verify-doc-workstation-e2e.js` T3/T4, 11/11 API-level
pass) — now driven by browser composer sends instead of direct fetch.

1. Same conversation as J4 (chained `parentMessageId`), or a fresh one — a
   THIRD/first browser-sent message requests a 2-slide investor deck
   (pptxgenjs) whose Terms slide carries a long verbatim paragraph that
   deterministically clips in a default text box.
2. Render + QA-every-page request in the same message.
3. **Malformed detected** — the QA verdict text (`ISSUES_FOUND` / `clip` /
   `overlap` / `cut off`) appears in the model's final response for at least
   one page.
4. A FOURTH browser-sent message (same conversation) asks the model to fix the
   clipping (shrink font / autofit / split box), re-render, and re-QA.
5. **Repair loop closes** — the response contains both a fix description
   (shrink/autofit/split/resize keywords) and a clean re-QA verdict, backed by
   a real `document_visual_qa` tool_call in that turn's stream.

**Pass criteria:** step 3 and step 5 are hard assertions on tool_calls (real
`document_visual_qa` invocation) AND text-pattern matches on the verdict
language — mirroring the accepted `render-visual-qa` regression class
(`workspace-persistence`, `render-visual-qa` regression files).

## Runner

`scripts/e2e-browser/run-e2e.sh --grep "J4|J5"` (same docker-Chromium runner
as 8S3C.1; this host's system Chromium crashes on the authenticated dashboard).
Targets the deployed stack (`LC_BASE` default `http://127.0.0.1:3080`), which
is running the post-8S3C.2-fix image (`297415a13`) at execution time.
