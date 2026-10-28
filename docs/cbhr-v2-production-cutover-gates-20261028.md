# CBHR AI V2 production cutover gates
Date: 2026-10-28. Authority: PR #41 exact-head CI and reviews, plus read-only live production probes.

This is a release gate record, not a deployment authorization.

## Proven
- Existing app canary image remains cbhr-ai:v2-integrated-7f1f7f6fd; production app config HTTP 200 on latest read-only probe.
- CodeAPI retains CODEAPI_RETENTION_MODE=preview. No destructive retention apply.
- Existing Admin/broker/aibridge rollback images all resolve; rollback-preflight.sh returned ROLLBACK_PREFLIGHT_PASS.
- New model-policy source is tenant-bound, requires a transaction-capable MongoDB, and keeps its internal listener dark until explicitly configured.
- Canonical revision source now records endpoint plus ordered deployment model/reasoning bindings so same-ID rebinding must advance CAS. Legacy revision records need explicit reconciliation if discovered.
- Protected CI for prior PR #41 head 332a981414 was nine of nine applicable workflows SUCCESS. This does not certify later commits.
- Read-only live MongoDB hello has setName=null: standalone, not a transaction-capable replica set.
- Production LibreChat configs collection has exactly three role records; all three lack tenantId. Canonical modelpolicyheads and modelpolicyrevisions collections do not yet exist.
- Latest source branch adds transactional conflict detection for non-role Config and duplicate endpoints, plus a fail-closed runtime role-only check. Earlier review must be repeated on final exact head.

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

## G4 live release and rollback drill (NOT DONE)
Only after exact-head protected CI, independent security approval, authenticated G2, and MongoDB gate: pin immutable new image and rollback image, perform a bounded production rollout, capture running image/health/chat receipts, execute one coordinated rollback across LibreChat/Admin/Broker/Bridge/CodeAPI as actually required, verify app health and user workflows, and re-promote only after the rollback passes. CodeAPI destructive retention remains preview until separately accepted.

## Rules
- Do not merge or deploy PR #41 just because automated tests are green.
- Do not enable model-policy internal listener or apply production schema changes while MongoDB is standalone.
- Do not infer authenticated G2 success from unauthenticated HTTP 200 or mock Playwright E2E.
- Do not infer an executed G4 rollback from ROLLBACK_PREFLIGHT_PASS.
