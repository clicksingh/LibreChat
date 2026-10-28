# CBHR managed-model integration contract

The canonical architecture and migration plan lives in the companion `clicksingh/cbhr-admin` repository: `docs/model-policy-control-plane-v2.md`. This file records LibreChat-specific responsibilities.

1. The normal chat selector consumes the authenticated effective endpoint catalogue. USER is locked server-side; ADMIN receives the active managed catalogue.
2. A company default is not a concrete modelSpec. Do not reintroduce a pinned modelSpec as policy authority. LibreChat's upstream modelSpecs alter selector behavior when interface fields are omitted; see https://www.librechat.ai/docs/configuration/librechat_yaml/object_structure/model_specs.
3. Admin/config mutations must flow through the validated LibreChat config service so merged-schema validation and `invalidateConfigCaches()` run. Direct external Mongo writes bypass those semantics. See https://www.librechat.ai/docs/features/admin_panel.
4. Authenticated startup state will carry a config/policy revision. Client caches invalidate from revision events; focus/reconnect/version check are fallbacks. Logout is never a propagation mechanism.
5. Request admission is authoritative. A stale USER browser model is replaced by the current company default. An ADMIN selection is admitted only when active in policy.
6. Reasoning UI renders canonical verified capability metadata for the selected deployment. No model-name switches or raw provider transport strings in the frontend.
7. Browser E2E is a release gate: USER live default change without logout, ADMIN multi-model selection, capability-specific controls, forged request denial, and upstream request verification.

## Phase 2 implementation status

The branch contains an **unmounted** service-auth primitive (`modelPolicyServiceAuth`) and typed projection builder (`modelPolicyProjection`). They establish the service identity and USER/ADMIN projection contract only; they do not expose an endpoint or mutate config yet. Targeted Jest: 7/7 PASS; local Prettier/ESLint PASS. The publisher must next reuse LibreChat's existing Admin config validation/persistence/cache invalidation path and add revision/idempotence semantics before it can be mounted in staging.

## Transactional publication boundary

The internal publisher is the only runtime writer for the canonical `modelpolicyheads` / immutable `modelpolicyrevisions` stream. It commits the canonical revision and the owned `__base__`, `USER`, and `ADMIN` Config projections in the **same Mongo transaction**. Cache invalidation happens only after commit.

The CBHR Admin service is the control-plane client and supplies `expectedVersion`, actor/source metadata, deployment IDs and the role contract. It must not pre-commit the canonical policy itself before calling LibreChat. Same policy at the current expected version is a no-op; stale/concurrent expected versions fail closed with 409; a projection failure rolls back both the canonical revision and any earlier role writes.

There is intentionally **no separate publication-marker/replay collection**. One canonical revision stream is sufficient and avoids dual authority.


The internal publisher must persist its last applied external policy revision in the same Mongo transaction as the base, USER, and ADMIN Config updates. Cache invalidation happens only after transaction commit. Same version plus same digest is idempotent; same version plus different digest is a conflict; lower version is stale; a newer revision advances only through the configured monotonic rule. This avoids creating a second partial-publication problem inside LibreChat.



The branch now includes a dedicated LibreChat-owned model-policy publication state contract: `modelpolicypublications` stores the last applied external policy revision and SHA-256 content digest. The method layer defines monotonic transitions: first publication must be revision 1; same revision plus same digest is an idempotent no-op; same revision with different content, stale revisions, revision gaps, and concurrent CAS changes fail closed. The state is derived integration metadata only. It is not the canonical model policy, and it is not yet wired into the runtime publisher route.

The next step is to execute the state transition and the three owned Config projections inside one Mongo transaction, then invalidate effective config caches only after commit. Only after a real staging transaction/rollback test will the internal route be mounted.

## Phase 2 real transaction acceptance

On 2026-10-23, exact image `cbhr-ai:model-policy-v2-stage-9cb5d7f8a` (OCI source `9cb5d7f8a82d9db9f3b94487597a168ac5b36174`) passed the canonical policy transaction acceptance against a disposable MongoDB 7 single-node replica set. The ordinary stage Mongo is standalone and correctly rejected transactions; it was not reconfigured. The acceptance harness therefore used a dedicated database matching `cbhr_model_policy_acceptance_*` and refused any other database name.

Result: `create -> noop -> advance`, active canonical revision 2, synthetic mid-transaction ADMIN projection failure fully rolled back canonical revision + all Config versions, stale expected revision was rejected, cache invalidation count stayed unchanged on failed transaction, and the disposable database/container/network were removed after the run. Production and normal staging data were untouched.

This closes the Phase 2 **atomicity** gate. Remaining Phase 2 work is service-to-service HTTP acceptance with the dedicated secret on an isolated replica-set fixture, then wiring CBHR Admin as the CAS client. The internal listener remains disabled unless explicitly configured.

## Reasoning metadata and cache refresh

The typed model-policy command now accepts optional reasoning capability metadata per deployment. LibreChat validates the finite transport contract and effort IDs, then materializes `customParams.reasoningProfiles` only on the ADMIN endpoint projection while preserving unrelated custom parameters. USER never receives the override metadata.

The command also supports an explicit `refreshConfigCaches` flag. This exists for the migration window where Admin still writes non-policy compatibility fields such as title/summarize and tokenConfig before the publisher call; LibreChat therefore invalidates effective config caches when policy-owned role fields changed **or** an explicit refresh was requested. A same-policy/reasoning-only retry can remain canonical-revision-idempotent while still refreshing changed derived metadata.

## 2026-10-27 PR #41 integration-review corrections

The internal policy publisher requires a fixed **server-side**
\`MODEL_POLICY_TENANT_ID\` when its listener is enabled, in addition to its
bearer token file and port. A caller cannot choose the tenant in a publish
body. Role Config reads and writes carry this exact tenant filter, including
new upserts. A missing tenant refuses listener startup / policy publication.
The canonical version stream remains one service-instance policy authority,
not an invitation to administer multiple tenants with one bearer identity.

Publication also rejects an inactive \`__base__\`, \`USER\`, or \`ADMIN\`
Config inside the same transaction. A disabled projection may be reactivated
by the standard separately authorized Config administration procedure, not by
silently advancing a policy that chat would not consume.

Ordinary USER chat admission now accepts exactly one marked-default centrally
credentialed custom endpoint even when no legacy default \`modelSpec\` exists.
A missing default, multiple marked defaults, user-provided credentials, or
invalid model still fails closed. Existing valid preset-based behavior is
preserved as a migration compatibility path.

**Production activation remains gated.** The current production MongoDB is a
standalone server, not a replica set, and existing role Config documents do
not yet have explicit tenant IDs. Do not set the internal publisher port,
backfill production Config, enable policy publication, or claim end-to-end
model-policy V2 activation until database topology/migration and live browser
admission tests are independently reviewed. The active V2 LibreChat image
was a bounded canary and CodeAPI retention stays \`preview\`.

## Transactional effective USER admission acceptance

The publisher must not create a managed endpoint from only a name/model or
commit a canonical revision whose effective USER configuration remains stale.
Inside the transaction it now requires a managed endpoint in the
already validated server/YAML configuration with company-owned credentials
and an HTTP(S) base URL. The effective USER endpoint is evaluated through
validated YAML, tenant-scoped \`__base__\` role Config, the proposed
published base patch, and tenant-scoped USER Config in merge order; it rejects:
an unconfigured endpoint; ambiguous marked defaults; an overridden managed
model list; or an overridden company API key/URL. The whole transaction rolls
back on rejection, including the canonical version. Cache invalidation is
scoped to the fixed tenant after successful commit. Four adversarial
regression cases cover these failure modes.

This is a narrow fail-closed acceptance boundary. Publishing an unrelated
endpoint through a raw request body cannot bootstrap credentials.
Keys can remain in the validated server configuration and need not be
duplicated in Config documents. The isolated replica-set transaction harness
is updated to use a synthetic tenant and synthetic YAML credential fixture.
Future per-user/group policy layers and complete live config-service E2E
acceptance remain independent release obligations before enabling the
listener. Production MongoDB remains standalone, and the listener remains
OFF. No automatic CodeAPI file-retention apply is authorized.

## Tombstones and legacy-preset precedence

The Config resolver applies tombstones before keyed endpoint overrides.
Publisher acceptance rejects a \`__base__\` or USER tombstone for
\`endpoints\` or \`endpoints.custom\` (including descendants), rather than
committing a revision whose funded endpoint would be deleted at read time.
Separately, ordinary USER admission gives exactly one centrally marked
custom endpoint priority over any retained legacy default \`modelSpec\`.
The preset name is used only when it matches the selected endpoint and
model; ambiguous marked defaults fail closed. This preserves the existing
legacy-only fallback only before a marked company default is available.
Synthetic regressions verify rollback and legacy-preset bypass denial.
