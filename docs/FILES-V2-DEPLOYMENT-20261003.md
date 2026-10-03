# Files v2 deployment — 2026-10-03

## Production state

### LibreChat
- Running image: `librechat-cbhr:61ea432a7137`
- Deployed source SHA: `61ea432a7137ae7f5ab8c2d06e450a2a1ec67cc1`
- Deployment tag: `deployed/files-v2-20261003`
- Rollback image: `librechat-cbhr:fb9b316ed4f1`
- Rollback Compose backup: `/opt/cbhr-ai/LibreChat/docker-compose.override.yml.backup-files-v2-20261003`

### CodeAPI
- Running image: `cbhr-codeapi:371e26fa6280`
- Deployed source SHA: `371e26fa628009b4b02b7d892022f76f1afa2406`
- `main`, `feat/files-workspace-v2-20261001`, and `deployed/files-v2-20261003` all point to that SHA.

## Network contract

LibreChat must reach CodeAPI directly over Docker DNS, not through the host loopback publication.

Production contract:

```yaml
services:
  api:
    environment:
      - LIBRECHAT_CODE_BASEURL=http://codeapi:4100
    networks:
      - default
      - codeapi_net

  codeapi:
    networks:
      - codeapi_net
    ports:
      - "127.0.0.1:4101:4100" # operator/debug only
```

Why: a container cannot reach a host service published only on `127.0.0.1` through `host.docker.internal`. The prior `http://host.docker.internal:4101` setting produced `ECONNREFUSED 172.17.0.1:4101` for live workspace/files/cleanup calls.

## Files v2 contract

- The 2 GiB workspace is temporary agent working storage.
- Arbitrary working state, dependencies, renders, caches, and scratch files remain in `work/` and do not become user-facing attachments.
- `outputs/` is the explicit publication zone.
- Existing Office-document workflows retain compatibility auto-publication for obvious deliverables such as PDF/DOCX/XLSX/PPTX.
- Only files returned by CodeAPI's publication scanner are copied into the durable `files/` bucket and surfaced by LibreChat.
- `create_file` / `edit_file` use CodeAPI `/exec`, so they pass through the same publication boundary as ordinary code execution.
- Same-session CodeAPI executions are serialized; different users/sessions remain concurrent.
- Cleanup removes only explicitly disposable dependency/cache trees and skips active/queued sessions. Unknown working files and published results are preserved.
- Managed USER tool activity is collapsed by default as `Working…` / `Work completed`; details remain manually expandable.
- Managed USER model/tool/MCP controls stay hidden while the enforced request state remains active.
- Managed USER attachment flow remains one-click.

## Validation evidence

- CodeAPI full suite: **69/69 PASS**
- CodeAPI focused workspace/output/cleanup suite: **23/23 PASS**
- LibreChat API package production build: **PASS**
- LibreChat production Vite client build: **PASS**
- Managed frontend regression suites: **32/32 PASS**
- Client TypeScript `tsc --noEmit`: **PASS**
- Managed-user side-by-side browser tests: **2/2 PASS**
- Managed-user production browser tests: **2/2 PASS**
- Production same-session concurrent `/exec` smoke: **PASS**
  - two requests launched together against one session
  - total runtime ~2.4 s with one request sleeping 2 s
  - output A contained only A markers
  - output B contained only B marker
  - both exit code 0
  - both returned zero files

Permanent browser regression:
- `playwright/tests/files-v2-managed-smoke.spec.ts`

It proves:
1. one private working text file remains hidden,
2. one `outputs/` result surfaces in Files,
3. tool detail stays collapsed,
4. the published result can be trashed and purged,
5. scratch state can be removed in the same conversation.

## Source-control status

CodeAPI Files v2 is merged to `main`.

LibreChat is intentionally **not** merged to current `main` during this deployment. Current LibreChat `main` has many independent upstream commits beyond the CBHR deployment base. Merging them into Files v2 would create a separate upstream-convergence release and must receive its own build/browser regression cycle. The deployed source remains durable through:
- feature branch `feat/files-workspace-v2-20261001`
- deployment tag `deployed/files-v2-20261003`

Do not force-merge or rebase the deployed branch into current LibreChat `main` as a housekeeping step.
