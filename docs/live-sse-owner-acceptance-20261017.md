# 2026-10-17 exact-live LibreChat authenticated SSE route hardening

Base deployed LibreChat source: 4224a703a6ba.
This is a **draft fix** only. Do not deploy without review.

## Reproduced defect

Before this patch, GET /agents/chat/stream/:streamId only denied access when
job.metadata.userId was present and different from req.user.id. A missing
owner field (e.g., an empty/corrupted persisted generation job) bypassed
ownership checking and opened HTTP 200 SSE to a different authenticated user.
The abort handler had the same conditional and the status handler accessed
job.metadata.userId without null protection, producing 500 in malformed
cases. No evidence establishes that normal live staff jobs have missing
owner metadata; this is conditional fail-open, not a documented incident of
cross-user content disclosure.

## Fix

All three endpoints (stream, status, abort) now require a nonblank job
metadata.userId and a nonblank authenticated req.user.id that match exactly.
Tenant authorization remains an independent additional guard, including
legacy single-tenant jobs with no tenantId. Job subscriptions, resume state
or abort are never invoked for jobs with missing owner metadata.

## Synthetic acceptance

- Existing Express/Supertest route test uses mocked auth and JobManager;
  it does not access production users, Redis, Mongo or real job streams.
- Proven before fix: missing owner metadata allowed 200 SSE.
- After fix: missing metadata, empty metadata, tenant-only metadata, malformed
  requester identity and other-user same-tenant requests all 403 for stream
  and resume, status and abort. Authorized owner/tenant remains 200.
- Authorized synthetic SSE resume payload emits a sync envelope with one
  published-output reference, pending event and final done event, proving
  route serialization only, not a downstream browser chip.
- Run from api/:
  NODE_ENV=test ../node_modules/.bin/jest --config jest.config.js --runInBand
  --coverage=false server/routes/agents/__tests__/streamTenant.spec.js

## file_search diagnostics (read-only)

The exact 4224 source is unchanged from ABC 96534c3 for
packages/api/src/agents/resources.ts and the Code file priming service.
Nonembedded DOCX/XLSX only join execute_code when requested and authorized;
file_search is populated for embedded/indexed files only. The staff prompt
explicitly warns that empty file_search says nothing about unindexed attached
documents. The unchanged package resources test suite passed 39/39. No
live uploaded staff document or real search backend was queried.

## Exact-source test counts and compatibility

- Authenticated SSE/abort route group: 2 suites passed; 29/29 active
  tests passed, with 17 intentionally skipped in the existing third suite.
- The pre-existing abort.spec.js explicitly expected fail-open behavior
  for jobs lacking owner metadata ("backwards compatibility"). That
  expectation has been changed to 403 and abortJob must not run. This
  is a deliberate security-over-legacy-compatibility decision requiring
  release review if there are old jobs without owner metadata.
- No staff production job was queried, altered, or aborted.

## Release gates

This is not end-to-end authenticated staff browser proof. Real-user login,
download chips, conversation resume, five-DOCX retrieval/extraction,
unindexed file_search diagnostic presentation, and B1 per-chat OS isolation
still require separate acceptance. No production config/DB/files were touched.
