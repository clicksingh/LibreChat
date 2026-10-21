# CBHR LibreChat — staff "capture what we just did as a skill" audit

**Audit date:** 2026-10-16. **Source baseline:** `b5b155b852686a9044a13fff1e6aab040097c6d3`, isolated worktree `incident/20261016-skill-capture-audit-w2`. Read-only live Mongo diagnostics; **no production mutation**. This document maps effective instruction sources and technical contracts without reproducing private prompt contents.

## Verdict

Staff **can create new reusable skills from chat**, not merely select existing PPTX/XLSX. The host registers first-party `create_file` and `edit_file` definitions after checking effective agent skills capability and the current user's SKILLS.CREATE/EDIT permission. A model call to `create_file` with `file_path: "skills/{kebab-name}/SKILL.md"` invokes first-party backend create/update, not CodeAPI sandbox storage. It writes the main `SKILL.md` into the MongoDB skills collection, then grants the creator `skill_owner`. Optional textual `references/`, `scripts/`, `assets/`, `templates/` are stored through the existing skill-file storage strategy and Mongo metadata. New skills are **private to the creator** until separately shared.

The natural-language request is **not a deterministic command/router**: success still depends on the LLM deciding to invoke `create_file` after seeing its tool definition and relevant chat history. A process from a different conversation or absent from visible context cannot be reconstructed reliably without sources, so do not claim exact repeatability unless steps, inputs and checks were actually observed.

## End-to-end paths and control gates

| Stage | Source/behavior | Security or quality condition |
|---|---|---|
| User role | Live `db.roles USER.permissions.SKILLS`: USE/CREATE/SHARE true, SHARE_PUBLIC false | Authorization checked per request, not inferred from prompt |
| Managed ephemeral chat | `client/src/Providers/BadgeRowContext.tsx` managed USER tool baseline sets `ephemeralAgent.skills=true` | Backend still independently enforces skill capability and role |
| Agent runtime | `api/server/services/Endpoints/agents/initialize.js` evaluates `AgentCapabilities.skills`; computes scoped viewer/editor ACL IDs and `skillCreateAllowed` | `canAuthorSkillFiles` also gates by per-agent activation (`api/server/services/Endpoints/agents/skillDeps.js`) |
| Model-visible tools | `packages/api/src/agents/initialize.ts` calls `registerFileAuthoringTools`, implemented in `packages/api/src/agents/tools.ts` | `create_file`/`edit_file` included only if either effective code execution or skill authoring is allowed; skill path instructions shown only when skill-authoring authorization exists |
| Model invocation | `packages/api/src/agents/handlers.ts` event handler matches exact host definitions via `fileAuthoringToolNames`, parses `skills/{name}/SKILL.md` | Host path parser rejects traversal/invalid names; if skill creation not allowed, role check denies; no arbitrary direct HTTP model-grant surface |
| Main creation | `writeSkillMd` parses/normalizes YAML and delegates `db.createSkill` (`packages/data-schemas/src/methods/skill.ts`) | Name unique by (name, author, tenant), validation limits and reserve words; initial version 1 |
| Owner ACL | `grantSkillOwner` uses existing PermissionService role `skill_owner` for current authenticated user; creation handler compensating-deletes new skill on grant failure | **Does not public-share** or fabricate a broader staff ACL |
| Version and edits | `updateSkill({id, expectedVersion, update})` conflict-safe; `edit_file` yields diff; `upsertSkillFile` adjusts version and file count | Requires effective EDIT permission and known skill scope, detects stale skill revisions |
| Bundled text files | `saveSkillFileContent` resolves storage backend and writes UTF-8 blob + skillFile metadata, cleans failed upload and replaces old content | Binary generated sandbox files are **not automatically bundled**; use skill file upload UI/API for binaries |
| Staff sharing | `api/server/routes/accessPermissions.js` / `api/server/controllers/PermissionsController.js` handle user/group ACL sharing separately | Authorized owner with SHARE + role SKILLS.SHARE can share `skill_viewer` to named users; not implied by `create_file` |
| UI discoverability | `api/server/routes/skills.js` and client Skills view | Private owned skills default active; ACL-shared skills need default or per-user active state. Deactivated skill still cannot be invoked |

### Live read-only observations

At the time of audit, the live `LibreChat` database held 8 inline skill documents and 10 skill ACL rows, all of principal type `user`. USER role had SKILLS.USE/CREATE/SHARE true, SHARE_PUBLIC false; ADMIN role had all four true. There were no active USER/base config overrides that disabled agents' skills capability. Kim's two previously authorized skills remained activated. Existing agent skill capability defaults include `skills`. No test skill was created in production.

## Effective prompt/instruction injection paths (names and ordering only)

1. **Agent/model-spec baseline:** Persisted agent `instructions` and `additional_instructions` or ephemeral model-spec/preset properties; variable interpolation in `packages/api/src/agents/initialize.ts`. The config overlay sources are deployment `librechat.yaml` and Mongo `configs.overrides` under effective principals. Avoid exposing source secret fields in diagnostic output.
2. **Tool definitions:** Actual authorized `agent.toolDefinitions`, including named `create_file`, `edit_file`, `read_file`, `skill`, `bash_tool` where qualified. `packages/api/src/agents/context.ts` appends a compact list of loaded tool names to additional system instructions; tool descriptions and JSON schemas are presented separately to the model.
3. **Skill catalog:** `packages/api/src/agents/skills.ts` `injectSkillCatalog` appends ACL-scoped, active, model-invocable skill names/descriptions in `additional_instructions`; full `SKILL.md` bodies injected only when invoked or always-apply-primed. Catalog and skill files are untrusted user-authored instructions; they do not create permissions.
4. **MCP instructions:** `getMCPInstructionsForServers` appends directions for active authorized MCP servers into `agent.instructions`.
5. **Context and memory:** `api/server/controllers/agents/client.js` `buildMessages` constructs current/historical conversation messages; augments with RAG/context handler and memory context into per-agent dynamic system tail. Files, previous tool outputs, and summaries may be truncated or unavailable. Model cannot assume it has all hidden steps from an earlier execution.
6. **Artifact prompt path:** `api/app/clients/prompts/artifacts.js` via initialization when agent artifacts mode enabled, independent of skill creation. Sandbox-generated downloads remain separate from first-class skill documents.
7. **Skill replay:** `injectSkillPrimes` inserts current manual/always-apply skill bodies; historical invocation body reconstruction is de-duplicated.

The prime agent is handling any verbatim prompt disclosure; this audit intentionally reports source paths and gates only.

## Repair proposed in isolated worktree

Prior to the patch, an existing source test **failed**: `SKILL_CREATE_FILE_DESCRIPTION` was 1,161 characters, exceeding the repository's 1,024-character provider advisory max. The model also had no explicit cue connecting “create a skill from what we just did” to `skills/{name}/SKILL.md` and no clear private-versus-sandbox distinction.

Changed `packages/api/src/agents/tools.ts` to a **1,004-character** skill-aware `create_file` description that explicitly handles this request, asks for verifiable steps, prerequisites, validation, recovery, and excludes secrets/private data. Clarifies that first-class skills are private until authorized sharing and non-skill sandbox artifacts are separate. Aligned the `edit_file` code-only path description with its existing sandbox-working-directory contract. Added regression assertions in `packages/api/src/agents/tools.spec.ts`. No permission widening, model-spec default change, DB migration, or production deployment.

### Qualification

- Reproduced baseline provider-advisory test failure: expected max 1,024, received 1,161.
- After patch: `registerFileAuthoringTools` 7/7 tests PASS including descriptions, upgrade, idempotence, provider length and collisions.
- Existing full tool test suite 37/38 PASS. Sole remaining failure is an **unrelated pre-existing literal assertion** in the bash normalization test: it expects “verify the file is listed” but published bash tool says equivalent “verify the final file appears in the returned file list.” Confirmed on unchanged baseline image.
- Existing focused `handlers.spec.ts` tests: creation, frontmatter normalization, same-batch bundled files, next-round persistence 4/4 PASS; ACL/version/hidden-skill/sandbox isolation and first-time authoring gate tests 8/8 PASS.
- Node24 Jest ran in isolated, no-network build container with actual source; no live test skill created.

## Remaining acceptance

Under an authorized staff account, request: `Create a reusable skill from the steps we just completed for [specific task]. Keep it private for review and include prerequisites, precise steps, validation, and recovery.` Check that the model calls `create_file` with `skills/{descriptive-name}/SKILL.md` (not sandbox `outputs/`), that the created skill appears in Skills, that the stored `SKILL.md` matches the just-completed task and does not contain secrets, and that the same user can invoke it in a fresh chat. Sharing it with others should be a **separate explicit approval** and ACL operation. This is the only true end-to-end model/browser acceptance, and cannot be honestly replaced by source tests.
