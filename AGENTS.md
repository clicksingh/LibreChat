See CLAUDE.md.

## Frontend theming and styling

For frontend work, compose existing `@librechat/client` primitives and variants before adding
feature-local styles. Use semantic theme/Tailwind roles for color and shared appearance; do not
introduce raw palette utilities, hard-coded colors, or arbitrary theme CSS. If the system cannot
express a reusable design need, deepen the shared primitive or versioned theme-token registry
instead of copying classes into a feature. Keep genuine layout and behavior local, and document
why any new custom CSS cannot be expressed by the shared system. See the detailed policy in
`CLAUDE.md` under “Theming and styling.”

When adding or changing code that mutates user documents, invalidate the auth user document cache for affected users. This includes single-user updates and bulk role/user mutations; otherwise OpenID JWT request burst caching can serve a stale `req.user` until its TTL expires.


## CBHR managed-model control plane

The target architecture is documented in companion Admin PR #1 at `docs/model-policy-control-plane-v2.md`. During migration:

- `USER` has no model choice; request admission resolves the current company default server-side. `ADMIN` may choose from the active managed catalogue.
- Never use a concrete-model `modelSpec` as the long-term company-default authority. Model specs are UI presets and have upstream interactions with `interface.modelSelect`.
- Treat an omitted optional `interface.modelSelect` according to LibreChat defaults; only an explicit false disables model selection.
- Config changes must not require logout. Browser query caches are projections; server policy remains authoritative. The temporary polling hotfix is migration-only and should be removed after config-revision events/versioned caches land.
- Any new config mutation path must use LibreChat's validated config service and its cache invalidation hooks; do not introduce new sidecar/direct Mongo writes.
- Reasoning/thinking controls are canonical capability data plus reviewed adapters. React must never contain model/vendor-specific wire syntax.
- Do not claim model-policy completion without normal-chat USER and ADMIN Playwright tests that verify the actual upstream model/control request.
