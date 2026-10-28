# CBHR AI V2 production cutover gates
Date: 2026-10-28. Authority: PR #41 exact-head CI and reviews, plus read-only live production probes.

This is a release gate record, not a deployment authorization.

## Proven
- Existing app canary image remains cbhr-ai:v2-integrated-7f1f7f6fd; production app config HTTP 200 on latest read-only probe.
- CodeAPI retains CODEAPI_RETENTION_MODE=preview. No destructive retention apply.
- Existing Admin/broker/aibridge rollback images all resolve; rollback-preflight.sh returned ROLLBACK_PREFLIGHT_PASS.
- New model-policy source is tenant-bound, requires a transaction-capable MongoDB, and keeps its internal listener dark until explicitly configured.
- Canonical revision source now records endpoint plus ordered deployment model/reasoning bindings so same-ID rebinding must advance CAS. Legacy revision records need explicit reconciliation if discovered.
- Protected CI at reviewed pre-fix head 9ce8056f8c was nine of nine applicable workflows SUCCESS. Its exact-head Codex review identified a further P1 runtime deep-merge conflict, so its CI does not qualify the subsequent source correction.
- Read-only live MongoDB hello has setName=null: standalone, not a transaction-capable replica set.
- Production LibreChat configs collection has exactly three role records; all three lack tenantId. Canonical modelpolicyheads and modelpolicyrevisions collections do not yet exist.
- Latest source branch adds transactional conflict detection for non-role Config and duplicate endpoints, plus a fail-closed runtime role-only check. Earlier review must be repeated on final exact head.

## Exact-head review correction in progress (not yet certified)
- Review on 9ce8056f8c identified inherited YAML addParams.model hidden by an empty role addParams override in the publisher's shallow projection check. Actual Config resolution deep-merges those objects, permitting a wrong upstream model.
- The release branch now rejects model-changing endpoint parameters at their trusted YAML origin and at each managed-role override before policy CAS, with a regression for the inherited-empty-override case.
- Isolated schemas, data-provider and API builds completed; local Jest remains unqualified due to the host Node 22 ESM dependency loading mismatch. The next pushed exact head must pass protected CI and independent re-review before this finding is closed.
- The separate authenticated G2, MongoDB migration, Admin/CodeAPI formal review and executed G4 gates remain open. No live publisher activation or retention apply is authorized here.

## October 28 independent preflight receipts (no production mutation)

- **Exact source** `58ebf2e97ef8864e28cd7e7a83d16724bc1ebabf`: all nine applicable protected CI workflows passed, including Backend, Frontend, static, Docker, Playwright, and CBHR-specific authorization/model contracts. Accessibility lint was skipped as configured. The new inherited `addParams.model` regression ran green in Backend CI.
- **Restorable logical backup proven:** created `/opt/cbhr-ai/backups/v2-mongo-restore-proof-20261028T203608Z/librechat.archive.gz` (about 3.1 MiB, permissions 0600). Checksum verified and archive restored to a one-off MongoDB 7 container with no network. Verified 51 collections, three Config documents, 259 conversations, 622 messages and 494 file records. Isolated restore container removed.
- **Production Mongo facts (read-only):** `chat-mongodb` is still standalone (`hello.setName=null`); exactly three active legacy role Configs have no `tenantId`, and all 12 users also lack tenantId. The Config collection already has unique `principalType_1_principalId_1_tenantId_1` index; canonical head/revision collections do not yet exist.
- **Production-data migration dry-run:** restore of the logical archive into a disposable isolated replica set succeeded; all three copied role Configs accepted a *synthetic* tenant tag under the existing unique index, and an aborted Config transaction rolled back. No production rows changed.
- **Exact-source transaction integration:** on disposable Mongo replica set and Node 24, create/no-op/advance, injected mid-transaction rollback, stale-version 409 and cache invalidation checks passed. Fixture cleaned.
- **Authenticated internal HTTP integration:** using an isolated real Mongo replica set and random ephemeral token, missing/invalid tokens returned 401, initial publication committed version 1, repeat no-op held version 1, stale request returned 409, and valid advance committed version 2. A teardown cleanup check found and removed one leftover test-only container/network; none remained part of production.
- **Limits:** live `mongodump` on standalone Mongo is not guaranteed a write-consistent migration snapshot. The authoritative tenant identity, final write freeze/snapshot, host/URI/index change review, maintenance authorization, authenticated real-staff G2, independent approval and executed G4 remain open. Click browser is currently at Cloudflare Access login, not signed-in G2 evidence.

## Mandatory production database gate (NOT DONE)
1. Establish and verify a restorable production backup plus recent filesystem/volume snapshots with an isolated restore proof.
2. Freeze Config/model-policy writes, identify the actual bound tenant from authoritative tenancy records, and verify exactly which three current role documents belong to it. Never guess or bulk-backfill tenants without evidence.
3. Review a reversible MongoDB 7 standalone-to-replica-set migration; check application Mongo URI, authentication, volumes, persistent replica set hostnames, connection pools, downtime/recovery, and maintenance scheduling.
4. Migrate topology in a separately authorized window, verify transactions and all dependent services, and rehearse rollback. No rs.initiate or MongoDB restart is part of this gate record.
5. Inventory legacy uniqueness and tenant-scoped indexes for configs and canonical head/revision collections. Create or migrate exact compound unique indexes only after conflict checks, never blind syncIndexes on production.
6. Run synthetic two-tenant CAS/version, repeat/noop, adversarial isolation, and mid-transaction rollback acceptance against a disposable transaction-capable environment, then authenticated service publication in an authorized staging environment.
7. Keep publisher port/token/tenant configuration disabled until every prior gate passes.

## Authenticated G2 browser acceptance (NOT DONE)
Use a signed-in, authorized staff persona in the target deployment, plus an ADMIN persona separately. Prove: effective funded USER model and effort, stale/browser BYOK normalization, saved-agent VIEW ACL, project-owned file upload/download/preview and image rendering, conversation/project ownership boundaries, ADMIN active catalogue selection, and logout/login persistence. Record screenshots or traces and compare network responses with backend receipts. CI mock E2E does not replace this.

## G4 rollback baseline correction (NOT YET READY)

- The historical rollback preflight presently fails: its October 23 LibreChat image `cbhr-ai:pr35-beta-47014eda` is not present. Do not use that snapshot as the next release rollback authority.
- A protected October 28 current-image/config baseline exists at `/opt/cbhr-ai/backups/v2-current-rollback-baseline-20261028T205916Z`. Five running image digest checks and ten configuration/secret file checksums passed. This is **inventory evidence**, not a tested coordinated rollback.
- Live deployment metadata includes additional per-service overrides; a Compose dry-run using only the saved base/ordinary override resolves a different LibreChat image from the one actually running. Preserve and independently validate the exact effective Compose file chain for LibreChat, Bridge, and CodeAPI before any G4 dispatch.
- Never run generic `docker compose up` with incomplete overrides or silently retag an unrelated image. At the authorized cutover, refresh backups and image pins after any intervening changes; test the exact rollback and re-promotion sequence using all active service generations. Keep retention preview.
- A new P2 finding identified inherited ADMIN reasoning profiles after capability removal. The source correction neutralizes retired profiles before Config publication. Protected CI and independent exact-head review are required again; G3 is not yet approved.

## Current-generation G4 image / Compose preflight (PASS, read-only)

- A reproducible validator now lives at `scripts/cbhr-v2-rollback-image-preflight.py`. Run `python3 scripts/cbhr-v2-rollback-image-preflight.py` on the authorized Tech host before changing any production service.
- On October 28 it passed for six running components: LibreChat `cbhr-ai:v2-integrated-7f1f7f6fd`, Bridge and Admin/Broker `33030c8e739e`, CodeAPI `retention-rc-e76c7f2`, and Mongo `mongo:7.0`. The script compares the exact rendered Compose image, Docker image digest and, for five app services, the runtime Compose config-file label and protected five-image baseline manifest.
- LibreChat's source chain contains `docker-compose.yml`, `docker-compose.override.yml`, `/opt/cbhr-ai/pr35-live-api-only.override.yml`, and `/tmp/cbhr-g2-project-canary.override.yml`. Bridge requires the first three; CodeAPI requires the base two plus `/opt/cbhr-ai/retention-rc-preview.override.yml`. Admin and Broker use `/opt/cbhr-ai/admin/docker-compose.yml`. Missing overrides fail closed. Rendered configurations are parsed in memory; the validator emits no secrets and performs no service or database mutations.
- **Critical G4 limit:** the preflight proves today's image/configuration mapping, not a rehearsed live downgrade/re-promotion. The `/tmp` canary override is ephemeral and must be retained/replaced through an independently verified release artifact before cutover. Do not claim this snapshot is sufficient for unattended recovery after reboot; refresh the baseline and verifier when the deployment topology changes.

## G4 live release and rollback drill (NOT DONE)
Only after exact-head protected CI, independent security approval, authenticated G2, and MongoDB gate: pin immutable new image and rollback image, perform a bounded production rollout, capture running image/health/chat receipts, execute one coordinated rollback across LibreChat/Admin/Broker/Bridge/CodeAPI as actually required, verify app health and user workflows, and re-promote only after the rollback passes. CodeAPI destructive retention remains preview until separately accepted.

## Rules
- Do not merge or deploy PR #41 just because automated tests are green.
- Do not enable model-policy internal listener or apply production schema changes while MongoDB is standalone.
- Do not infer authenticated G2 success from unauthenticated HTTP 200 or mock Playwright E2E.
- Do not infer an executed G4 rollback from ROLLBACK_PREFLIGHT_PASS.
