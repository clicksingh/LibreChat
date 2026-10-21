# CBHR Release B session and direct-file source candidate

**State:** isolated source, for review only. `CBHR_CONVERSATION_EXECUTION_SESSIONS` is unset/disabled in production. No production deployment or session migration is authorized by this candidate.

**Base:** LibreChat production source `0655e0c5aaf1f6c39d7ad349a71de32abc7968f0`.

## Behavior included

- `packages/api/src/agents/sessionRegistry.ts` keys durable `code_execution_sessions` Mongo records by tenant, user, workspace kind/id and conversation ID. Atomic `$setOnInsert` preserves the session across turns, regeneration, retries, resumes and the shared graph used by subagents. The random `conv-<uuid>` execution ID is minted on the server; primed file refs retain their original verified storage bucket IDs.
- `api/server/controllers/agents/client.js` wires the registry behind `CBHR_CONVERSATION_EXECUTION_SESSIONS=1`; a persisted existing chat cannot be implicitly remapped to a new session. Without a pre-existing migration record it fails closed. First-time chats can mint a new record. The request's existing `getConvo` and `resolveWorkspaceContext` paths verify ownership and current project membership.
- `packages/api/src/agents/resources.ts` adds up-to-25-MiB unindexed DOCX/PDF/ODT/TXT/MD/XLSX/XLS/XLSM/CSV/ODS attachments to direct code execution inputs without calling them indexed. Once indexed, the same uploaded document can be available in both `file_search` and `execute_code`.
- `api/server/services/Files/Code/process.js` stages only owned unindexed input files through the existing authorized storage-read and CodeAPI upload strategies. `metadata.codeEnvRef` is persisted for later turns; repeated IDs from `file_ids` and `resourceFiles` are deduplicated. Existing verified Project Files `kind: project` refs continue through the pre-existing CodeAPI claim route without duplicate staging.

## Release blockers and security findings

1. **Filesystem isolation is NOT achieved.** CodeAPI `server.js:297-315,699-755,827-849` still maps one OS UID per user and executes `runuser -u <same-user> -- unshare -Urn` without a filesystem/mount namespace or jail; the runner therefore has a plausible direct path to sibling session scratch under the same UID. CodeAPI accepts arbitrary sanitized `session_id` in `/exec`. Enforce server-proven execution identity and actual filesystem isolation, then run cross-chat negative acceptance against two synthetic sessions. This flag must remain OFF until that proof exists.
2. **Legacy migrations require explicit mapping.** Old chats previously used the deterministic per-user CodeAPI bucket; no individual chat can be assigned its past files merely by looking at the old shared directory. Do not auto-migrate or delete existing user buckets. Backfill only after audited conversation/file provenance or explicit user reattach.
3. **Project ACL requires real acceptance.** The existing `resolveWorkspaceContext(req)` checks project EDIT permission each request and attaches the signed project claim to CodeAPI JWT; `Workspace/attach.js` authenticates project Files and materializes a user-owned chat attachment. These existing gates must be verified end-to-end alongside the new file staging, including membership revocation.
4. **Indexing and runtime tools remain separate.** `file_search` requires embedded documents. An unembedded DOCX is accessible to code tools only when the user has execute-code permission and the actual CodeAPI runtime has a DOCX reader. Full A2 packaging and browser 5-DOCX acceptance remain outstanding.
5. **Concurrency and lifecycle remain open.** Concurrent initial staging of the same document may duplicate temporary upload bytes before the persisted ref wins. Leases, interrupted upload recovery, branch-specific scratch policy, cleanup, and true cross-session import still require dedicated B work.

## Local source verification

- 45/45 focused `sessionRegistry.spec.ts` and `resources.test.ts` Jest tests passed, including legacy nonmigration, scoped ID uniqueness, five DOCX, XLSX, size limits and indexed coexistence.
- 5/5 new `process.spec.js` direct-file tests passed, covering DOCX, XLSX, duplicate IDs, Project Files ref reuse, foreign-owner and size denial.
- 13/13 additional dependency-light exact-source regression assertions passed (before the final indexed-coexistence/dedupe tests, whose Jest results are above).
- `node --check` for changed `client.js` and `process.js` and `git diff --check` passed.
- The shared Tech LibreChat `node_modules` is incomplete (Babel visitor and LangChain missing files). Focused Jest ran with an isolated test dependency install under `/tmp/cbhr-b-testtools`, with **minimal stubs of runtime constants**. This is useful unit coverage, not a production integration/CI certification. Run the standard full suite and Docker-backed integration on a clean dependency installation before release.

## Ownership

This source worktree is independent of CodeAPI A1/A12, LibreChat C1, production Compose and unrelated Forge/Paperclip infrastructure.
