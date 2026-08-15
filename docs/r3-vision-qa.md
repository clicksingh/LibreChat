# 8S3C R3 — `document_visual_qa` tool (issue #8)

Professional Document Workstation milestone — Vision QA lane.

The `document_visual_qa` agent tool inspects **rendered** document page PNGs
(from a prior `render/exec` step in the codeapi sandbox) for layout defects and
returns a strict pass/issues verdict to the orchestrating model.

**Architecture gate:** the tool fetches rendered page PNGs through the EXISTING
CodeAPI client and sends them through the EXISTING aibridge vision path
(`POST http://aibridge:4103/v1/chat/completions`, model `glm-5v-turbo`). No
second vision transport, no codeapi/aibridge/docker-compose/seccomp changes.
**Render-then-describe ONLY** — raw source documents are NEVER sent to the
vision model.

---

## 1. Scope / files

### Changed (committed on `feat/document-vision-qa-8s3c`)

| File | Change |
| --- | --- |
| `api/server/services/Tools/documentVisualQAContract.js` | **NEW** dependency-free contract module (source of truth). |
| `api/server/services/Tools/documentVisualQA.js` | **NEW** runtime tool (DynamicStructuredTool) + transports. |
| `api/server/services/Tools/documentVisualQA.spec.js` | **NEW** unit suite (38 tests). |
| `api/server/services/ToolService.js` | Register runtime tool when the agent requests it (`specialToolNames`). |
| `packages/api/src/agents/tools.ts` | Model-facing LCTool definition + `registerDocumentVisualQATool`. |
| `packages/api/src/agents/initialize.ts` | Register the model-facing tool when the agent requests it and `codeEnvAvailable === true`. |
| `packages/api/src/agents/load.ts` | `loadEphemeralAgent` pushes `Tools.document_visual_qa` from the ephemeral agent / model spec. |
| `packages/api/src/agents/tools.spec.ts` | 5 new tests for `registerDocumentVisualQATool`. |
| `packages/data-provider/src/types.ts` | `TEphemeralAgent.document_visual_qa?: boolean`. |
| `packages/data-provider/src/models.ts` | `TModelSpec.documentVisualQA?: boolean` + zod schema. |
| `packages/data-provider/src/types/assistants.ts` | `Tools` enum: `document_visual_qa`. |
| `verify-vision-qa-smoke.js` | **NEW** live smoke (host → real aibridge → LiteLLM → z.ai glm-5v-turbo). |
| `docs/r3-vision-qa.md` | This document. |

### Inspected (read-only, not changed)

- `api/server/services/ToolService.js` (bash_tool run-code wiring pattern),
  `packages/api/src/agents/load.ts`, `initialize.ts`, `tools.ts`,
  `librechat.yaml` (custom endpoint `apiKey`/`baseURL`),
  `/opt/cbhr-ai/aibridge/config.json` (vision model, timeouts, body cap),
  codeapi `r2-child-runner.sh` + `render-doc.sh` (manifest/output contract).

---

## 2. Tool name, description, schema

- **Name:** `document_visual_qa`
- **Contract version:** `document_visual_qa/1` (`CONTRACT_VERSION`).
- **Vision model:** `glm-5v-turbo` (routed via aibridge's EXISTING vision path).
- **Description (1010 chars, under the 1024 advisory limit):** documents the
  exact input keys and the strict-JSON verdict it returns.

### Exact input keys (JSON Schema in `TOOL_PARAMETERS`)

| Key | Type | Required | Meaning |
| --- | --- | --- | --- |
| `session_id` | string | **yes** | CodeAPI execution session id of the render step whose workspace holds the PNG pages. |
| `file_ids` | array\<string\> | no | CodeAPI file ids of the PNG pages (`.png` entries in the render step artifact refs). |
| `file_names` | array\<string\> | no | Sandbox-relative paths (`render-out/pages/report-001.png`, manifest `outputs[].path`). Use exactly one of `file_ids`/`file_names`. |
| `focus` | string | no | Comma-separated: `clipping, overlap, hierarchy, charts, legibility, layout`. Defaults to all six. |
| `maxPages` | integer 1..8 | no | Pages per vision pass. Default 4, hard cap 8 (per single call, 24 pages absolute across batches). |

```json
{
  "type": "object",
  "properties": {
    "session_id": { "type": "string", "description": "..." },
    "file_ids": { "type": "array", "items": { "type": "string" }, "description": "..." },
    "file_names": { "type": "array", "items": { "type": "string" }, "description": "..." },
    "focus": { "type": "string", "description": "..." },
    "maxPages": { "type": "integer", "minimum": 1, "maximum": 8, "default": 4, "description": "..." }
  },
  "required": ["session_id"]
}
```

The runtime tool deep-clones the frozen canonical schema before handing it to
langchain because `@cfworker/json-schema` (used by `DynamicStructuredTool`)
dereferences the schema **in place** (`__absolute_uri__`), which throws on a
frozen object.

---

## 3. How the model's agent tool list exposes the tool

Mirrors the bash_tool / run-code gate:

1. **Enum:** `Tools.document_visual_qa` in `packages/data-provider/src/types/assistants.ts`.
2. **Ephemeral agent:** `loadEphemeralAgent`
   (`packages/api/src/agents/load.ts`) pushes `Tools.document_visual_qa` when
   `ephemeralAgent?.document_visual_qa === true || modelSpec?.documentVisualQA === true`.
   CBHR AI is an ephemeral agent (the Mongo `agents` collection is empty), so
   the tool is enabled via the sidecar materialized `cap_*` role / model spec.
3. **Model-facing LCTool definition:** `registerDocumentVisualQATool`
   (`packages/api/src/agents/tools.ts`) adds `DOCUMENT_VISUAL_QA_DEF` to the
   tool registry; `initialize.ts` calls it only when
   `agent.tools.includes(Tools.document_visual_qa) && params.codeEnvAvailable === true`
   (idempotent; logs a debug skip otherwise). This gates the tool on the same
   code-execution availability flag the codeapi tools use.
4. **Runtime instance:** `ToolService.loadToolsForExecution` creates the
   `DynamicStructuredTool` via `createDocumentVisualQATool({ req })` when
   `toolNames.includes(Tools.document_visual_qa)` (added to `specialToolNames`).

---

## 4. Verdict schema

Strict JSON (single object, no fences/prose):

```json
{
  "verdict": "PASS" | "ISSUES_FOUND",
  "issues": [
    {
      "artifact": "<png file name>",
      "page": 1,
      "severity": "low" | "medium" | "high",
      "description": "what is wrong",
      "suggestion": "how to fix it"
    }
  ],
  "summary": "one or two sentence overall assessment"
}
```

Defensive parsing (`parseVerdict`): strips markdown fences, tries `JSON.parse`,
then the first `{...}` block; coerces `verdict` from the issues array when
absent; sanitizes every issue; **throws coded `VQA_PARSE_FAILED`** (never
crashes). `reconcileArtifactNames` maps a generic model image label (e.g.
`image.png`) back to the real page-map artifact for that page, so the offending
artifact list always names the actual rendered file.

**Tool output text** (`formatVerdict`): always ends with `RAW: {json}` so the
orchestrator can re-derive structured facts without re-calling.

---

## 5. QA prompt text

The prompt is the `user` text part alongside the page image `image_url` parts:

> You are a professional document layout QA inspector. Examine the rendered
> page image(s) attached to this message. Check each page for:
> - Clipping: text, shapes, or table columns cut off at page/slide edges or overlapping container boundaries.
> - Overlap: text boxes, shapes, or table cells overlapping when they should be separated.
> - Visual hierarchy: headings not visually distinct from body text, or inconsistent alignment/spacing.
> - Unreadable charts/tables: tiny fonts, legend cut off, axis labels overlapping, data bars clipped.
> - Malformed layouts: elements off-canvas, broken tables, images spilling outside their containers.
> - Legibility: low-contrast text, text overflowing its box, truncated labels.
>
> Focus areas for this pass: ...
>
> The attached images correspond to these artifacts and absolute document page
> numbers, in order: - image X: artifact "render-out/pages/report-001.png",
> page 1 ... Report "artifact" as the listed file name and "page" as the listed
> absolute page number (never image position).
>
> Respond with ONE strict JSON object and nothing else ... Schema:
> {...}. Rules: ... If the image(s) cannot be read at all, set verdict
> "ISSUES_FOUND" with one high-severity issue and description "page image
> unreadable".

---

## 6. Payload shape (aibridge chat-completions body)

```json
{
  "model": "glm-5v-turbo",
  "temperature": 0.2,
  "max_tokens": 4096,
  "messages": [
    {
      "role": "user",
      "content": [
        { "type": "text", "text": "<QA prompt with pageMap>" },
        { "type": "image_url", "image_url": { "url": "data:image/png;base64,<...>" } }
      ]
    }
  ]
}
```

Pages are downscaled with sharp (target `PAGE_MAX_DIM = 1024`, shrinking by
0.75 down to a 256px floor) so the total base64 body stays under the aibridge
`MAX_BODY_BYTES = 32 MiB` cap with a `BODY_BUDGET_SAFETY = 0.75` frame reserve
(≈ 1.37× base64 expansion included). Per-batch timeout `AIBRIDGE_TIMEOUT_MS =
90s`, well under aibridge `VISION_TIMEOUT_MS = 120s`.

---

## 7. How the aibridge auth key is resolved

The CBHR AI custom endpoint in `librechat.yaml` has
`apiKey: "${LITELLM_MASTER_KEY}"`, `baseURL: "http://litellm:4000/v1"`.
`LITELLM_MASTER_KEY` is NOT in the container OS env — it is loaded by dotenv
into the LibreChat node process at startup.

Resolution (in `resolveAIBridgeAuth`):
`getCustomEndpointConfig({ endpoint: 'CBHR AI', appConfig: req.config })` →
`apiKey` string → `extractEnvVariable(apiKey)` over the dotenv-loaded
`process.env` (dotenv-order-safe: existing env wins, placeholder untouched) →
`Bearer <resolved>`.

The resolved key is used only for the `Authorization` header. It is **never**
printed, logged, written, or commented (including in this repo's tests, smoke,
and docs). When it cannot be resolved, the tool fails with coded
`VQA_AUTH_UNRESOLVED`.

---

## 8. Bounding numbers

| Parameter | Value |
| --- | --- |
| `DEFAULT_MAX_PAGES` | 4 |
| `MAX_PAGES_CAP` (per pass) | 8 |
| `MAX_TOTAL_PAGES` (per call) | 24 |
| `PAGE_MAX_DIM` | 1024 px (downscale floor 256 px) |
| `MAX_BODY_BYTES` (aibridge) | 32 MiB |
| `BODY_BUDGET_SAFETY` | 0.75 |
| `AIBRIDGE_TIMEOUT_MS` | 90 000 |
| vision model | `glm-5v-turbo` |

Pages are fetched one at a time (15s per-page fetch timeout) and downscaled
before batching; each batch of ≤ `maxPages` is one aibridge call.

---

## 9. Tests & smoke

### Unit suites

- `api/server/services/Tools/documentVisualQA.spec.js` — **38 passed**.
  Pure contract (prompt, payload, limit, batching, sanitize, parse defensive,
  reconcile, combine, format) + runtime with stubbed transports (proves the
  tool's ONLY outbound calls are the codeapi page fetch and the aibridge vision
  call, and that ONLY rendered PNG data-URLs + the QA text reach the vision
  model) + real `callAIBridge` boundary.
- `api/server/services/__tests__/ToolService.spec.js` — **58 passed** (unchanged, green).
- `packages/api/src/agents/tools.spec.ts` — **38 passed** (5 new for
  `registerDocumentVisualQATool`).
- `packages/api/src/agents` (full) — **940 passed / 4 skipped / 1 suite skipped**.

### Live smoke — `node verify-vision-qa-smoke.js`

Starts a THROWAWAY `cbhr-codeapi:d9dba74e8066` container on a non-production
port (default `127.0.0.1:4221`) with the SAME seccomp profile, generates a
**ground-truth malformed** pptx (text box clipped past the right slide edge +
a bright overlapping box on a table), renders it to PNG in the EXACT child
context (`runuser → unshare -Urn`, loopback-only), then from the HOST POSTs the
real QA prompt + page data URL to `http://127.0.0.1:4103/v1/chat/completions`
(aibridge → LiteLLM → z.ai glm-5v-turbo) with the RESOLVED key (never printed),
and asserts the planted defects are reported.

Result (2026-08-15): **verdict `ISSUES_FOUND`** with both planted defects —
`[page 1][high] malformed-001.png: Severe right-edge clipping ... truncated at
the page boundary` and `[page 1][medium] malformed-001.png: Overlap defect: the
yellow 'OVERLAP DEFECT' box spills across the borders of the first column
header in the table`. `EXIT=0`. The throwaway container and temp key material
are removed on exit.

### How to run

```bash
export PATH=/opt/cbhr-ai/tools/node/bin:$PATH
cd /opt/cbhr-ai/LibreChat-wt-r3/api && npx jest server/services/Tools/documentVisualQA.spec.js --silent
cd /opt/cbhr-ai/LibreChat-wt-r3/api && npx jest server/services/__tests__/ToolService.spec.js --silent
cd /opt/cbhr-ai/LibreChat-wt-r3/packages/api && npx jest src/agents/tools.spec.ts --silent
cd /opt/cbhr-ai/LibreChat-wt-r3 && node verify-vision-qa-smoke.js   # requires prod aibridge + image present
```

---

## 10. Security & isolation

- Child sandbox network isolation is UNCHANGED — no new egress.
- Raw source documents are NEVER sent to vision — only downscaled rendered PNGs.
- aibridge auth uses the RESOLVED key only; the key is never printed/logged.
- Nothing in `codeapi`, `aibridge`, `docker-compose`, or `seccomp` changes.
- No production container or production file was mutated; production untouched.
