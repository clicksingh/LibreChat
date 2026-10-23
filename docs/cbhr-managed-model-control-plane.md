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
