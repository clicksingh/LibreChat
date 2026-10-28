# CBHR managed-model integration contract

The canonical architecture and migration plan lives in the companion `clicksingh/cbhr-admin` repository: `docs/model-policy-control-plane-v2.md`. This file records LibreChat-specific responsibilities.

1. The normal chat selector consumes the authenticated effective endpoint catalogue. USER is locked server-side; ADMIN receives the active managed catalogue.
2. A company default is not a concrete modelSpec. Do not reintroduce a pinned modelSpec as policy authority. LibreChat's upstream modelSpecs alter selector behavior when interface fields are omitted; see https://www.librechat.ai/docs/configuration/librechat_yaml/object_structure/model_specs.
3. Admin/config mutations must flow through the validated LibreChat config service so merged-schema validation and `invalidateConfigCaches()` run. Direct external Mongo writes bypass those semantics. See https://www.librechat.ai/docs/features/admin_panel.
4. Authenticated startup state will carry a config/policy revision. Client caches invalidate from revision events; focus/reconnect/version check are fallbacks. Logout is never a propagation mechanism.
5. Request admission is authoritative. A stale USER browser model is replaced by the current company default. An ADMIN selection is admitted only when active in policy.
6. Reasoning UI renders canonical verified capability metadata for the selected deployment. No model-name switches or raw provider transport strings in the frontend.
7. Browser E2E is a release gate: USER live default change without logout, ADMIN multi-model selection, capability-specific controls, forged request denial, and upstream request verification.

## Phase 2 implementation status (2026-10-27)

The branch contains service-token authentication, a mounted-when-enabled internal
publisher, a typed policy projection, transactional canonical revision / role
Config commits, and post-commit cache invalidation. **The production publisher
is not enabled.** Production MongoDB remains standalone; migration to a
transaction-capable replica set and live service-to-service/browser acceptance
remain release gates. Earlier descriptions of these components as unmounted
or yet to be wired were historical implementation notes, not present status.

## Transactional publication boundary

The internal publisher is the only runtime writer for the canonical `modelpolicyheads` / immutable `modelpolicyrevisions` stream. It commits the canonical revision and the owned `__base__`, `USER`, and `ADMIN` Config projections in the **same Mongo transaction**. Cache invalidation happens only after commit.

The CBHR Admin service is the control-plane client and supplies `expectedVersion`, actor/source metadata, deployment IDs and the role contract. It must not pre-commit the canonical policy itself before calling LibreChat. Same policy at the current expected version is a no-op; stale/concurrent expected versions fail closed with 409; a projection failure rolls back both the canonical revision and any earlier role writes.

There is intentionally **no second publication-marker/replay collection** in
the current canonical publisher. The canonical head/revision stream and atomic
role Config projections are the sole authoritative write contract.
The older prototype \`modelpolicypublications\` state machine is not a
dependency of this route and must not be enabled as a second policy authority.

**Tenant migration remains an activation blocker:** Config projections and
canonical head/revision reads, CAS writes, and unique indexes are now
tenant-scoped in source. Existing databases may still carry legacy globally
unique indexes and unscoped documents. The publisher must stay disabled until
the migration and index inventory have independently verified this boundary.

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
The canonical head/revision keys are now tenant-scoped, but each listener's
service token remains bound to exactly one configured tenant. The request body
cannot choose or override that tenant.

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


## Role priority ordering

The runtime Config resolver sorts role Config documents by ascending priority.
The publisher's effective USER validation requires a strict \`__base__\` priority
less than USER priority, rejecting inverted or equal priorities as a 422
transaction error. Canonical version and role projections roll back on this
failure. Changing role priorities is a separate reviewed Config operation,
not an implicit side effect of model publication.


## Server-managed default and downstream legacy spec enforcement

For spec-free centrally funded USER admission, the server normalizer stamps
a request-local verified company endpoint/model identity after resolving the
current funded default. Downstream endpoint-option middleware bypasses
legacy modelSpec enforcement only when that trusted server-side identity
matches the normalized endpoint/model. Browser request-body fields cannot
supply this marker, ADMIN and other requests retain existing legacy spec
enforcement, and the published funded default remains authoritative.


## Canonical tenant-index migration gate (not executed in production)

Source schema now requires \`tenantId\` on both canonical collections and
declares unique \`{tenantId: 1, key: 1}\` for \`modelpolicyheads\` and unique
\`{tenantId: 1, version: 1}\` for \`modelpolicyrevisions\`.
Canonical queries and transaction writes include the bound tenant ID.
The publisher forwards the same fixed tenant to Config projection and
canonical revision methods.

Before enabling the publisher in any persistent environment, an independently
authorized migration must inventory existing canonical records and MongoDB
indexes, reconcile/assign their tenant ownership without guessing, and replace
legacy global unique \`key_1\` / \`version_1\` indexes with the compound
unique indexes. Do not use automatic destructive \`syncIndexes\` in production,
drop indexes blindly, or backfill tenant IDs onto unrelated records.
Verify two isolated synthetic tenants can each CAS from version 0 to version
1 without reading one another's head or revisions. This migration has **not**
been run on production. Transaction-capable MongoDB and an authenticated
service-to-service/browser end-to-end acceptance are still required.


## October 28 exact-head CI and ADMIN admission corrections

Canonical model-policy head and revision schemas both use the standard tenant
isolation plugin, in addition to explicit tenant-scoped method queries and
compound unique indexes. The tenant isolation coverage test is a required
guard and must not be bypassed by adding these models to the manual-scoping
allowlist.

The transaction validator checks effective ADMIN endpoint credentials and
URL against the validated YAML authority, as well as the proposed ADMIN
managed model catalogue. Empty or redirected ADMIN endpoint overrides fail
closed before the canonical version can advance. Environment-backed YAML
credential fields are resolved for validation while retaining their stored
references; missing placeholders are rejected.

For a verified effective managed ADMIN custom endpoint with a centrally
credentialed model in the published active list, the endpoint option builder
accepts that model without a conflicting legacy concrete-model preset.
Unlisted models and non-managed endpoints remain subject to legacy spec
enforcement; the USER request-local marker is not accepted from browser
payload fields.

The TypeScript backend relocation finding remains separately reviewable:
new implementation should live in the packages/api workspace, leaving thin
legacy API wiring. Do not treat source-level test success as full release
approval until that architectural review is resolved.


## TypeScript backend migration (2026-10-28)

Policy candidate validation, projection construction, credential-bound endpoint
checks, and transactional publication orchestration have moved into
\`packages/api/src/modelPolicy/{projection,publisher}.ts\`. The shared
\`@librechat/api\` package exports the typed backend functions. The legacy
\`api/server/services/Config/modelPolicyProjection.js\` and
\`modelPolicyPublisher.js\` are import-only compatibility shims without policy
business logic. The internal server is limited to authentication, trusted
base-config dependency wiring, and HTTP routing.

The moved modules pass local TypeScript and targeted ESLint checks. Local
tsdown packaging could not be completed: first the isolated older dependency
tree was missing \`unrun\`, then the alternative host installation produced
a native bundler bus error. A protected GitHub CI build and runtime tests
against the compiled \`@librechat/api\` package are therefore mandatory;
do not treat the local module-level TypeScript check as bundled release
qualification. Production activation remains disabled until all prior gates
are satisfied.


## Real replica-set integration acceptance

A new protected backend regression test at
\`packages/api/src/modelPolicy/publisher.transaction.spec.ts\` uses only a
fresh in-process MongoMemoryReplSet. It validates independent canonical
version-one commits for two synthetic tenants sharing one replica-set
database, tenant-isolated revision reads, and complete rollback of a
mid-transaction ADMIN patch failure without cache invalidation. Test failure
blocks a release candidate. This is synthetic infrastructure evidence only:
it is not a production MongoDB topology migration or authenticated G2
browser acceptance.


## Non-role precedence and duplicate endpoint guard (October 28)

The transaction now reads active non-role (user, group and future non-role)
Config documents through a tenant-bound query using the same MongoDB session
as canonical policy CAS. Publication rejects any such document that deletes
the endpoint hierarchy, overrides the published endpoint by name, or marks a
different endpoint as the default. The server never silently rewrites
individual-user or group Configs. A rejected publication does not advance its
canonical revision or invalidate caches.

The validator rejects duplicate endpoint names in the trusted server config
and existing __base__, USER, ADMIN role endpoint arrays before mutation,
including duplicate managed endpoint entries that otherwise create a
validator/runtime precedence mismatch. A database policy gate is not a
substitute for write-time protections on future non-role Config changes;
those future changes must be governed by the central Config service. The
internal publisher remains disabled in production.


## USER runtime authority after publication

When the internal model-policy publisher is enabled, the ordinary USER chat
normalizer additionally obtains the tenant-scoped role-only effective config
from the same Config service and compares the published funded
endpoint/model/API-key reference/baseURL against the full request-effective
config. If later user or group Config edits alter the funded model or
credential destination, chat fails closed with 503 instead of using the stale
or redirected endpoint. ADMIN continues to use its separate managed
catalogue. The extra check is dark until the model-policy publisher is
enabled; production currently retains the previous pre-activation behavior.

This fail-closed check does not make a legacy Config mutation acceptable:
central Config writes must still be reviewed to prevent future
role/tenant-policy conflicts at the source.


## Model-changing parameters and generic Config write lock

Publication rejects effective managed USER and ADMIN endpoints that retain
addParams.model (or dropParams containing model), since downstream model
construction can override the otherwise validated published model list.
When the publisher is enabled, USER runtime authority compares the entire
managed endpoint object against role-only effective config, so a later
model parameter or credential mutation fails closed before generation.

The generic Admin Config API is not a second policy publisher. While the
dedicated publisher port is enabled, it rejects writes to managed __base__,
USER, and ADMIN role Configs, as well as endpoint-section upserts, patches,
tombstones, and field deletes for individual users/groups. Inactive user/group
endpoint overrides cannot be reactivated through the generic toggle route.
Unrelated Config sections remain available where supported by existing
permissions. These checks are feature-dark until publisher activation.


## Immutable canonical routing identity

A canonical managed-model revision now stores the publisher endpoint name
and the ordered deployment bindings, including each deployment ID, concrete
model, and normalized reasoning capability. The tenant-specific revision CAS
compares these bindings alongside the company default, deployment ordering,
audiences, and schema contract. Rebinding the same deployment ID to another
concrete model or changing its endpoint can no longer return a policy no-op:
it must advance the canonical version or reject a stale expected version.

The MongoDB revision schema requires routing metadata on new records, with
embedded binding documents using no generated IDs. Any legacy canonical
records without these bindings must be inventoried and deliberately migrated
or superseded through a reviewed version transition before activation.
The production canonical collections were absent in the read-only inventory,
so no live canonical metadata was changed.
