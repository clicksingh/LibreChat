# 8S3C.1 Browser E2E — journey spec (Planner)

Planner output for the required browser E2E (directive item E). Grounded in the
empirically verified server behavior of the deployed image `89807b0ec`
(probes A–E, 2026-08-16).

## Scope

Three journeys, mirroring the directive's "normal / malformed / negative":

1. **J1 normal enabled user** — the real UI path a user with Run Code enabled
   takes to get the document-visual-QA capability, and the client/server
   coupling proof.
2. **J2 malformed visual case** — an ephemeral agent that requests
   `document_visual_qa` without its required `execute_code` pairing. The normal
   UI cannot produce this; it is expressed at the request layer.
3. **J3 negative user** — a user whose role has `RUN_CODE.USE:false`. UI must
   not expose the toggle, the outgoing request must carry no capability flags,
   a forged flag must not gain the direct tool-call surface, and the RUN_CODE
   server gate must hold.

## Verified fact set (deployed `89807b0ec`)

- `codeEnvAvailable = true` for **all** users — server-computed from config
  default capabilities, not per-user permission.
- Chat-path docvqa gate (`initialize.ts:1079`): `codeEnvAvailable && agent.tools
  includes document_visual_qa`. bash gate (`1024`): `codeEnvAvailable &&
  agent.tools includes execute_code`.
- ZERO RUN_CODE checks on the agents chat path — the honest forged-flag finding
  the acceptance record must state (task F).
- RUN_CODE.USE is enforced at exactly two surfaces: the client UI toggle
  (`canRunCode`) and the direct tool-call endpoint
  (`POST /api/agents/tools/:toolId/call` → 403 "Forbidden: Insufficient
  permissions").
- Default ephemeral agent has `execute_code:false` (librechat.yaml has no model
  specs) → enabled user MUST toggle Run Code for docvqa to couple.
- `applyVisualQaToRequest` couples `document_visual_qa:true` onto any agent with
  `execute_code:true` at request time (client).
- Probes:
  - [A] enabled `{execute_code:true, document_visual_qa:true}` →
    toolTokenCounts `[read_file, bash_tool, create_file, edit_file,
    document_visual_qa]`.
  - [B] enabled malformed `{document_visual_qa:true}` → `[document_visual_qa]`
    only (server registers docvqa on the client flag alone; bash requires
    execute_code).
  - [C] nocode `{}` → `[]`.
  - [D] nocode forged `{execute_code:true, document_visual_qa:true}` → all tools
    registered (chat-path bypass — recorded, not auto-healed).
  - [E] direct endpoint nocode → **403**; enabled → 404 (message ownership).

## Journey 1 — normal enabled user (browser)

State: fresh session for `e2e-enabled` (role USER, RUN_CODE.USE:true).

1. Authenticate via session injection (sessions doc + refreshToken cookie) —
   never `/api/auth/login`.
2. Navigate to a new chat.
3. Assert the **Run Code** toggle is **visible** in the tools dropdown.
4. Toggle it **ON**; assert `localStorage` holds the per-conversation
   `LAST_CODE_TOGGLE_<convoId>` override = `true`.
5. Send a message.
6. Capture the outgoing `POST /api/agents/chat/CBHR%20AI` request body; assert
   `ephemeralAgent.execute_code === true` **and**
   `ephemeralAgent.document_visual_qa === true` — the client coupling proof
   (task B) through the real UI, with the ephemeral agent read from the stored
   conversation.

Pass = toggle visible, toggle persists, outgoing body couples both flags.

## Journey 2 — malformed visual case (host-side API)

A request that asks for `document_visual_qa` without `execute_code`. The server
must not crash and must tolerate it: docvqa registers, bash does not. The
pairing guarantee lives in the client coupling, not the server — this is
expected, documented behavior.

Pass = HTTP 200, stream `toolTokenCounts` includes `document_visual_qa` and does
NOT include `bash_tool`.

## Journey 3 — negative user

(a) **Browser**: session for `e2e-nocode` (role E2E_NOCODE, RUN_CODE.USE:false).
- Run Code toggle is **not visible** in the tools dropdown.
- Send a message; outgoing request carries `ephemeralAgent` with **no**
  `execute_code` and **no** `document_visual_qa`.

(b) **Host-side forged flag**: `ephemeralAgent: {execute_code:true,
document_visual_qa:true}` as `e2e-nocode`. Expected outcome is recorded, not
asserted as denial: toolTokenCounts includes both (chat-path bypass —
`codeEnvAvailable` global + client flag). This is the honest finding for task F
and the acceptance record; it is NOT a product/security expectation to auto-heal
("No security/product expectation may be auto-healed").

(c) **Direct endpoint**: `POST /api/agents/tools/execute_code/call` for a real
`e2e-nocode` message. Assert **403** — the RUN_CODE server gate holds where the
platform actually enforces it.

Pass = (a) UI hides toggle + request carries no flags; (c) 403. (b) is a
recorded observation.

## Host-side request helpers

Forge/malformed bodies are only expressible at the request layer. The helpers in
`utils/api.ts` drive them through the SAME `/api/agents/chat/:endpoint` surface
the deployed client uses, with a real browser User-Agent and a server-minted
access token — never `/api/auth/login` (login rate-limiter ban; see
librechat-login-ban memory). Stream parsed by `utils/stream.ts` for
toolTokenCounts/toolCalls ("inspect tool definitions, not just narration").

## Test agents

- **Planner**: this document (journeys + pass criteria above).
- **Generator**: the `.spec.ts` files under `playwright/tests/`.
- **Healer**: may only classify TEST_DRIFT (a test that no longer reflects the
  deployed server contract) — never a product/security expectation.
