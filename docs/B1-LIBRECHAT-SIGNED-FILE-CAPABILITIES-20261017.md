# B1 LibreChat signed conversation execution and file provenance, 2026-10-17

**Independent, undeployed source only.** New isolated LibreChat worktree `/opt/cbhr-ai/librechat-wt-b1-signedscope-20261017` derives from integrated ABC + Files DnD + staff skill source `a10c1f842648749e60f51ff9140273212e4551e6` (descendant of requested ABC `96534c3`). No edits in prime's integrated branch, A13, C2, worker-3 UI or trackers. The runtime gates `CBHR_CONVERSATION_EXECUTION_SESSIONS` and `CODEAPI_B1_SESSION_UID_ENABLED` remain OFF.

## Actual server-side authorization

`api/server/controllers/agents/client.js` already resolves persistent `conv-UUID` from `code_execution_sessions` **only after** authenticated chat ownership and project scope checks. This candidate additionally calls a DB-backed attachment provenance resolver for the run-wide seeded CodeAPI refs, then calls `bindCodeApiExecutionScope(req, ...)`. The binding is a nonenumerable, non-writable server-only Symbol value, frozen independently of mutable browser/model `req.body`. A second or mismatched binding is refused. The source function also rechecks canonical authenticated user ID, tenant ID, project workspace identity and strict `conv-UUID`.

`packages/api/src/auth/codeapi.ts` continues legacy 300-second cached JWTs outside B1. For server-bound B1 requests it signs a **fresh** EdDSA JWT (no token cache) with <=60s lifetime and verified user/tenant/project/chat/conversation session IDs. Each trusted file capability includes source kind, owner, storage session, file id, basename, byte size and full SHA256. Any subsequent project context change on the same request fails closed on token mint; a raw client-provided `execution_session_id` in JSON is ignored.

`api/server/services/Files/Code/b1Grants.js` derives eligible refs only from run-wide, explicitly primed CodeAPI files and re-queries Mongo **read-only** for exact per-file storage IDs, requiring an authenticated same-user, same-tenant TFile with matching kind, owner, storage session, file id, exact filename, positive bounded length, and current project membership/explicit Project Files attachment marker. It hashes original saved TFile bytes through the configured storage strategy (streaming, max 25 MiB), **not** the model-referenced CodeAPI source bucket. Missing/mismatched/duplicated/unhashable records fail closed; unsupported source kinds/extensions fail closed. No plaintext user content or signing private keys were retrieved during engineering/tests.

Only DOCX/PDF/XLSX are permitted by the current narrowly tested grant broker. Existing Personal/Project File attach workflows already save a user-owned TFile plus original CodeAPI ref. For unsupported skill/agent input refs in the same tool session, authorization deliberately refuses the run rather than silently import broad resource kinds.

## Evidence

- Actual JWT issuer test suite through isolated TypeScript Babel/Jest: **15/15 PASS**, including new cryptographically verified EdDSA scoped claims, no-cache repeat mint, <=60s TTL, client request-body spoof rejection, immutable binding and signed Project binding/in-flight membership mismatch.
- Pure DB-provenance grant validator Node tests: **10/10 PASS**, including Personal DOCX/PDF/XLSX, Project attach PDF, cross-tenant/owner/scope/ref denial, oversized/unsupported/missing/ambiguous/duplicate references, DB unavailable and digest source failure. No real Mongo writes or customer file reads.
- Paired CodeAPI exact-source, pinned-image/default-seccomp synthetic test: **46/46 plus second-container 6/6 PASS**, full CodeAPI Node suite **138/138 PASS**. Refer to CodeAPI handoff for exact image ID and boundaries.

## Remaining gates

- No full dependency-consistent LibreChat root/workspace build or E2E UI run is claimed in this isolated worktree; only the focused TypeScript JWT suite and pure Node grant tests were executed. Run exact-source GitHub CI, source build, new/old chat, multi-agent, project membership revocation and 5 real DOCX/PDF/XLSX staff file acceptance in a nonproduction environment.
- CodeAPI still needs actual rebuilt A13+B1 immutable OCI, XFS/quotas helper and OS broker race review. Upload/skill/agent file grants are out of scope and must remain blocked, not broadly permitted.
- Per-run grant authentication is at the beginning of the user's chat request; project membership changes mid-run need explicit session cancellation and token invalidation, beyond the <=60s JWT gate. Revocation markers block future requests but cannot terminate an already-running process.
- Roll out only matching LibreChat issuer + CodeAPI verifier after independent security approval, preserve historic legacy `lc-*` file provenance and **keep both production B1 flags OFF**.
