# T4 — Independent Verification & Hostile Review (R3: T1 + T2 + T3)

Verifier: `device-verifier` (did not write this code)
Repo: `C:\Users\Aryan\Desktop\codellm\librechat-rdc-phase1`
Branch: `agent/cbhr-rdc-phase1-local-authority-20261010`
Verified HEAD: `03c351bea816dacbf19e1352dd88022ff92e6ce8` (`feat(device): execute E1/E2 fixtures against real I6/I5 services`)
Mongo: `mongodb://127.0.0.1:27027/?directConnection=true&replicaSet=cbhrRdcP1` (7.0.43, driver 6.21.0, node v22.19.0)
Date: 2026-10-23
Scope: adversarial verification only. **Nothing was fixed.** All writes are under `tests/device/_phase1_evidence/r3-verify/**`.

---

## 1. Claim table

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| 1 | `node tests/device/e1/run-e1.cjs --fixture=all` exits 0, 12/12 product PASS, 5/5 controls green, Node suite 20/20 | **CONFIRMED** | `e1-run-1.log` last line: `"status":"PASS","exitCode":0`, `counts:{total:17, productFixtures:12, productBlocked:0, controls:5, controlFailures:0, fabricatedProductPasses:0, productFailures:0}`. Suite: `node --test --experimental-test-isolation=none --test-concurrency=1 --test-timeout=900000 tests/device/e1/suite.test.cjs` → `# tests 20 / # pass 20 / # fail 0`, exit 0 (`node-suite.log`). Gate logic at `tests/device/e1/run-e1.cjs:171-198`. |
| 2 | Every product PASS is backed by a REAL product write through the REAL service against REAL MongoDB | **CONFIRMED** (with 1 disclosed caveat, see NOTE-1) | `tests/device/e1/w3a/env.cjs:45-59` resolves the genuine files under `api/server/services/Device/`; `w3a/support.cjs:400-439` calls the real `createAuthorityService` / `createRegistrationService` / `createPairingSessionService`; `product/context.cjs:43-52` uses `mode:'raw-registry'`; `w3a/support.cjs:308-319` opens the fenced real Mongo and `syncDeclaredIndexes`; the only interception is a pass-through recording `Proxy` that delegates every call to the real Mongoose model (`w3a/env.cjs:211-311`). Independently reproduced by my own probes, which wrote real rows with the same factories. |
| 3 | Fixture DBs use `cbhr_rdc_phase1_` prefix, are dropped, namespace before == after, only `cbhr_rdc_phase1_*` touched | **CONFIRMED** | Aggregate `namespaceAudit:{before==after, created:[], removed:[], leftoverOwnDatabases:[], foreignAfter:[], ok:true}`. Independent raw-driver snapshot around one real fixture: `probe-namespace.cjs` → `created:[]`, `removed:[]`, `foreignDatabases:[]`, protected DBs present with identical document counts → `CONFIRMED_CLEAN`. My own probe DBs also dropped (`leftoverR3VerifyDatabases:[]`). |
| 4 | Security fixes hold: resolver tenant isolation; duplicate audit event rejected; stale-epoch revoke refused; one-account cardinality under 2-process N≥50 | **CONFIRMED** | Four independent probes: `probe-resolver.cjs` (11/11 fail-closed), `probe-audit-dupe.cjs` (E11000 on `{tenantId:1,deviceId:1,epoch:1,seq:1}`), `probe-contention.cjs` (stale revoke → `NOT_OWNER_OR_STALE` matched 0, row byte-unchanged; 60 attempts → matched 1, active rows 1). Details §3. |
| 5 | Route mount keeps `requireJwtAuth` before the handler and exposes ONLY `POST /current/retire` | **CONFIRMED** | `npx jest api/server/routes/__tests__/devices.spec.js` → 5/5 pass, exit 0 (`jest-devices.log`). Source: `api/server/routes/devices.js:21-22` (`router.use(requireJwtAuth)` then `router.post('/current/retire', …)`) — exactly one route; `api/server/index.js:274` mounts it after all other `/api/*` mounts and before `apiNotFound` (`:283`); `api/server/routes/index.js:38,82` exports it. |
| 6 | No changed path persists or logs a plaintext 6-digit code, private key, pepper, HMAC pepper or unredacted auth header | **CONFIRMED for real secrets** (2 hygiene NOTEs) | Product changed paths contain no such logging: `authorityService.js:448,458,492,1188` log only `deviceId/tenantId/kind/code:'READ_FAILED'`. Fixture assertions: `inline.cjs:690-694` (no plaintext code persisted in all four collections), `inline.cjs:810-811` (code absent from DB dump and from injected logger), `inline.cjs:576-582` (no `lookupTag`/`authorization`/`Bearer`/`privateKey`/`pepper` in audit rows). Empirical scan of the 200 KB run log: no pepper literal, **0** `"code":"\d{6}"` occurrences. See NOTE-2/NOTE-3. |
| 7 | T2 behaviour preservation (3 files) | **PARTIAL** | `errors.js` six classified mappings: **CONFIRMED unchanged** vs pre-T2 `685e3ee39` (only the *unclassified* message changed). `ownerCurrentRetireHandler.js`: **CONFIRMED** (0-match → 409 `NOT_OWNER_OR_STALE`, `committed:false`; `committed:true` only at `matched===1`). `authorityService.js`: **CONFIRMED** (absence constructs; supplied-but-malformed → clear `TypeError`). **But** the `util.inspect` part of the claim is **REFUTED** — see MINOR-1. |

---

## 2. Suspicion 1 — `ttlMs: 345594999` on a renewed lease: probe artifact, not a TTL violation

**Determination: PROBE MEASUREMENT ARTIFACT.** Arithmetic, from the frozen constants and the exact code path:

- `LEASE_TTL_MS = 172800000` (`authorityService.js:31`).
- The renewal is issued at `ctx.clock.set(T + LEASE_TTL_MS - SKEW_MARGIN_MS - 1)` = **T + 172,794,999** (`inline.cjs:348`), i.e. `TTL − 5,001`.
- `renewAuthority` sets `expiresAt = new Date(now + LEASE_TTL_MS)` (`authorityService.js:924`) → **T + 345,594,999**.
- `authorityView.ttlMs` is computed as `expiresAt − activatedAt` (`support.cjs:187-190`), and `activatedAt` is **not touched by renewal** — it is still the ORIGINAL claim's `T` (`authorityService.js:922-929` sets only `expiresAt`, `grantId`, `renewedAt`, `epoch`, `renewalCount`).
- Therefore `ttlMs = 345,594,999 = 2×172,800,000 − 5,001` = **2·TTL − 5,001**, exactly the number observed.
- The correct TTL invariant is `expiresAt − renewedAt`, and the fixture asserts precisely that: `inline.cjs:441-445` ("renewal advances expiresAt by exactly the lease TTL") → **172,800,000**.
- Cross-check against the recorded ISO values: `T = 2026-10-03T04:00:00.000Z`, `expiresAt = 2026-10-07T03:59:54.999Z` → delta `345,594,999 ms` = 3 d 23 h 59 m 54.999 s. `renewedAt` is `T+172,794,999` = `2026-10-05T03:59:54.999Z`, so `expiresAt − renewedAt = 172,800,000`. Consistent.

So `dbReadBack.renewOkAfter.ttlMs` is a *derived* field that subtracts the original activation, not a stored TTL. **No TTL violation.** (Minor reporting trap: the field is named `ttlMs` but is not the lease TTL after a renewal; the `dbReadBack` row at `inline.cjs:476` could mislead a reader — see NOTE-4.)

---

## 3. Suspicion 2 — E2-T7 `PAIRING_CEREMONY_STALE` in the loser histogram: assertion is NOT vacuous

**Determination: the exactly-one-winner assertion remains meaningful.**

- `race.cjs:260,290`: `winners = flat.filter(ok===true && matched>0)`; `checks.eq('exactly one winner across the two shards', winners.length, 1)`. This is a strict equality, so a second matched CAS would fail the fixture.
- Observed: `errorHistogram = {MATCHED:1, ONE_DEVICE_PER_ACCOUNT:24, PAIRING_CEREMONY_STALE:25}`, `casAttempts:50`, `winners:1` → 49 real losers, each with a non-null frozen code (`race.cjs:292-307`), plus `countActive(OWNER_A)===1` read back with the real model (`race.cjs:287,291`).
- **Independently reproduced by me** (`probe-contention.cjs`, verifier-authored, 2 real OS processes, 60 attempts): `{MATCHED:1, ONE_DEVICE_PER_ACCOUNT:30, PAIRING_CEREMONY_STALE:29}`, `matchedCount:1`, `activeRowsForOwner:1`, `everyLoserFailedClosed:true`.
- Why the third code appears: after the winner commits, further attempts on the *same* row carry `expectedEpoch 0` against `epoch 1`, so the generation fence classifies them `PAIRING_CEREMONY_STALE` (`authorityService.js:625-633`). Attempts on the *other* row hit `uq_owner_active` → `ONE_DEVICE_PER_ACCOUNT`. Both are frozen fail-closed rejections.
- Verdict: non-vacuous. **However** the frozen plan's allowed loser set is only `ONE_DEVICE_PER_ACCOUNT | DEVICE_ALREADY_PAIRED_USE_RENEW` (`fixtures.cjs:113`), and the fixture admits a third code (`race.cjs:298-303`). That is a deviation from the plan text — see MINOR-2.

---

## 4. Suspicion 3 — E2-V24T15: **MAJOR / BLOCKING deviation from the frozen assertionPlan**

**Determination: unjustified reinterpretation of a frozen contract. This is a real deviation, not a faithful product-observable assertion.**

Frozen plan (`tests/device/e1/fixtures.cjs:146-158`), verbatim:
- steps: "seed **one** device D with a live lease held by owner A (grant gA, epoch eA)"; "process A issues `revokeLease({ownerId:A, epoch:eA})`; process B issues `claimAuthority` for owner B"; "N>=50 attempts total".
- expected: "**exactly one CAS matches; loser matched 0, never a blind write**"; "**epoch delta exactly 1**"; "final row satisfies exactly one of {leaseState revoked} or {leaseState active under the new owner}".

What the fixture actually asserts (`race.cjs:365-379`):
- `revoke matches read exactly one per raced row === rounds` (25)
- `each row commits exactly the two legal CAS transitions in order (revoke, then fresh claim) === rounds` (25)
- `each raced row advanced its epoch by exactly 2 (epoch 1->2 revoke, 2->3 claim) === rounds` (25)

Observed run: `errorHistogram = {"MATCHED":50}` — **zero losers**; `totalMatches:50`, `revokeMatches:25`, `claimMatches:25`, `epochDelta:2` for all 25 rows, `claimArmsThatFailedClosed:0`, `roundsWithTwoMatches:25`. The fixture PASSes while its own plan's two headline observables are **contradicted** (1 CAS vs 2; delta 1 vs 2; loser matched 0 vs no loser at all).

Why the "race" cannot contend — structural, not incidental:
- `issuePairingSession` refuses a device holding a live lease with `DEVICE_ALREADY_PAIRED_USE_RENEW` (`pairingSessionService.js:1200-1207`). So shard B's arm can only succeed **after** shard A's revoke has committed. The two operations are ordered by the product's own preconditions.
- Empirically confirmed: `claimArmsThatFailedClosed: 0` in all 25 rounds — every single arm succeeded, which is only possible once the revoke was already durable. There was never a window in which both could match.
- The implementer's own `counterexample` field concedes this (`race.cjs:457-460`): *"the plans literal 'exactly one CAS matches / epoch delta exactly 1' describes the revoked-only fragment, not the product-observable end state."*

Why this is not a faithful substitute: the property V24-T15 exists to test is **mutual exclusion between a concurrent revoke and a concurrent claim on one row** — that a loser is rejected rather than blind-writing. The implemented fixture cannot fail that property, because it never creates a loser. A product regression that allowed a double-write in the real revoke/claim overlap would still produce `matched:2`-per-row-ish numbers that this fixture's *rewritten* checks would accept (`matches===2` is the expected value). The PASS is therefore self-certifying.

**Required disposition (GM decision, not a worker decision):** either (a) the GM amends the frozen V24-T15 assertionPlan to the sequential revoke→claim observable with an explicit rationale, or (b) the fixture must be reworked to create a genuine overlap (e.g. arm the claim before the revoke can be observed, or drive `claimAuthority` directly with a server-derived epoch inside the same window) and assert exactly-one-winner with real losers. Until then the T1 deliverable line *"V24T15 … with exactly-one-winner assertions"* is **not met**.

---

## 5. Suspicion 4 — was any fixture weakened vs the `assertionPlan` text?

Systematic comparison of every plan's `expected` list against the implemented checks:

| Fixture | Plan observables | Faithful? |
|---|---|---|
| E1-ONEPC-GRANT-CAS | matched 1/active/22-char grantId/`expiresAt=activatedAt+TTL`/epoch 1; 2nd rejected with one-per-account; active count 1; re-claim after revoke with NEW grantId | **Yes** — `inline.cjs:101-135` |
| E1-T16 | stale revoke `NOT_OWNER_OR_STALE` matched 0; no write; B authorized; sweep disabled | **Yes** — `inline.cjs:199-221` |
| E1-T17 | B on PC1 true; A on PC2 true; PC1 `prev*` untouched; per-owner axis one active row "enforced by `uq_owner_active`" | **PARTIAL** — the counts are asserted (`inline.cjs:296-297`) but no E11000/index rejection is ever exercised (scenario never collides) → MINOR-3 |
| E2-T7 | exactly one winner; active count 1; loser codes; 2 distinct PIDs | **PARTIAL** — loser allowlist widened by `PAIRING_CEREMONY_STALE` (`race.cjs:298-303`) → MINOR-2 |
| E2-T8 | active 1; one of O1/O2; loser 0-match; epoch +1 | **Yes** — `race.cjs:315-334` |
| E2-V24T15 | exactly one CAS; delta 1; one of two end states | **NO** — refuted, §4 (BLOCKING-1) |
| E1-V24T04 | 299999 match + `claim_pending` + `attemptsUsed 1`; 300000/300001 0-match uniform; never `claim_pending`; no margin | **Yes** — `inline.cjs:675-688` (incl. `attemptsUsed`, `pendingOwnerId`, "state stays open") |
| E1-V24T03 | E11000 keyPattern exactly `{tenantId:1,lookupTag:1}`; one non-terminal session; 4 attempts / 3 regenerations; `CODE_ISSUANCE_EXHAUSTED` 409; no plaintext code persisted/logged | **Yes** — `inline.cjs:787-811` |
| E1-T09-T10 | ALLOW/DENY boundaries; dead zone; lazy release at +5000; renewal at −1 and −5000; margin constant 5000 | **Yes** — `inline.cjs:429-463` |
| E1-T20-AUDIT | `AUDIT_DELIVERY_UNCERTAIN` 500; no rollback; read-back; required fields; no secrets | **Yes** — `inline.cjs:536-582` |
| E1-T20-CRASH | c2–c6 all five points + global no-authorize-without-lease | **Yes** — `crash.cjs:166-217` (all five points present) |
| E1-V24T12 | identical sha256 across arms; no decision depends on sweep; `sweepReliantDecisions === 0` | **PARTIAL** — literal `sweepReliantDecisions` is not asserted for the product fixture; equivalent/stronger assertions used (`sweep.cjs:125-134`) → MINOR-4 |

---

## 6. Findings

### BLOCKING-1 (MAJOR) — E2-V24T15 PASSes on a rewritten observable that contradicts its frozen assertionPlan
`tests/device/e1/product/race.cjs:365-379` (rewritten checks), `:457-460` (self-declared counterexample), `tests/device/e1/fixtures.cjs:146-158` (frozen plan). Observed: 50/50 matched, 0 losers, epoch delta 2. Plan requires: exactly one match, loser matched 0, epoch delta 1.
Minimal reproduction:
```
node tests/device/e1/run-e1.cjs --fixture=E2-V24T15-REVOKE-VS-CLAIM-RACE
```
→ `status:"PASS"`, `realReturns.errorHistogram:{"MATCHED":50}`, `dbReadBack.perDevice[*].epochDelta:2`, `roundsWithTwoMatches:25`, `claimArmsThatFailedClosed:0`. Structural cause: `api/server/services/Device/pairingSessionService.js:1200-1207` forbids arming a claim while a live lease exists, so the two operations are serialized by construction. **GM adjudication required.**

### MINOR-1 — `util.inspect(err)` still exposes the normalized `keyPattern` (claim 7's `util.inspect` clause is false)
`api/server/services/Device/errors.js:145` claims the detail "can never reach a client through `toJSON()`, `JSON.stringify(err)` or `util.inspect(err)`". The first three are true; **`util.inspect` is false**: `classifyDuplicateKey` passes the raw Mongo error as `cause` (`errors.js:245`), and `super(..., { cause })` (`errors.js:168`) makes Node's inspector print the whole cause chain, including `keyPattern`.
Minimal reproduction:
```
node tests/device/_phase1_evidence/r3-verify/probe-inspect-leak.cjs
```
→ `ownSurface.toJSON/stringify/objectKeys/message` clean; `inspectIncludesKeyPattern: true`; `sourceOfDefaultInspectLeak: "cause (Error#cause)"`. Client exposure is **not** present (`res.json` → `toJSON()` is clean), so the original review finding is genuinely fixed for clients; the residual risk is a server-side `console.error(err)`/inspector log. Fix direction (not applied): do not attach the raw error as `cause` on the unclassified path, or wrap it in a redacted error.

### MINOR-2 — E2-T7 loser allowlist widened beyond the frozen plan text
`tests/device/e1/product/race.cjs:298-303` accepts `PAIRING_CEREMONY_STALE` in addition to the plan's `ONE_DEVICE_PER_ACCOUNT | DEVICE_ALREADY_PAIRED_USE_RENEW` (`fixtures.cjs:113`). The added code is the correct generation-fence classification, and the one-winner/one-active-row assertions are independent and non-vacuous — but the accepted-loser set should be reconciled with the frozen text rather than widened in the fixture.

### MINOR-3 — E1-T17 does not exercise `uq_owner_active` enforcement, though the plan says "enforced by uq_owner_active"
`tests/device/e1/fixtures.cjs:92` vs `tests/device/e1/product/inline.cjs:296-297`. The scenario (A on PC1, B takes PC1 after lapse, A claims PC2) never produces two active rows for one owner, so no `E11000` is observed; the check is a post-hoc `countDocuments`. Not a false PASS, but weaker than the plan's wording.

### MINOR-4 — E1-V24T12's literal `sweepReliantDecisions === 0` is not asserted for the product fixture
`tests/device/e1/fixtures.cjs:287` vs `tests/device/e1/product/sweep.cjs:125-134`. The fixture instead asserts the lapsed sentinel was never swept in either arm, that the only expiry transition was the explicit product CAS, and byte-identical decision vectors — an equivalent (arguably stronger) observable. The literal field is asserted only in the harness control `NC-SWEEP-KNOB`.

### NOTE-1 — `authorize(...)` assertions are a harness oracle, not a product call
Every "authorize(...) === true/false" observable (e.g. `inline.cjs:212,283-295`) is evaluated by `support.authorizePredicate` (`tests/device/e1/w3a/support.cjs:147-171`), a disclosed oracle over product-produced rows — the frozen §8 surface exposes no admission function. The *writes* are real product writes, so claim 2 stands; but a GM reading "authorize" in a report should know it is harness-evaluated.

### NOTE-2 — the test-controlled constant `424242` is echoed into the emitted evidence ledger
`inline.cjs:788` records `{"name":"the forced code was used","observed":"424242","expected":"424242"}`, which lands in stdout logs and in `tests/device/_phase1_evidence/w3/I11-runs/**`. It is a source-visible test constant with no secret value (not a minted code), and the real-secret checks pass — but it is a plaintext 6-digit string in a log artifact. The same pattern exists in pre-R3, untracked artifacts (`run-202610132039047-29492/…`, `run-dev-smoke-4/…`). Recommend masking.

### NOTE-3 — lab-only pepper and deterministic private-key seed are literals in a test file (pre-existing)
`tests/device/e1/w3a/env.cjs:89` (`LAB_PEPPER = 'w3a-i11-lab-only-lookup-pepper-0001'`) and `:95` (`LAB_KEY_SEED`). Both pre-date T1 (present at `685e3ee39`) and are clearly marked lab-only; no product path reads them. Flagged only so the GM can decide whether even lab pepper material belongs in committed test bytes.

### NOTE-4 — `authorityView.ttlMs` is misnamed after a renewal
`support.cjs:187-190` computes `expiresAt − activatedAt`, which after a renewal is not the lease TTL (§2). The fixture's real TTL assertion uses `expiresAt − renewedAt`, so this is a reporting-label trap only.

### NOTE-5 — audit uniqueness is partial: events with `null` epoch/seq are not deduplicated
`packages/data-schemas/src/schema/auditEvent.ts:73-83` filters on `$type` number/string. My probe inserted two identical `{kind:'register', epoch:null, seq:null}` events for the same `(tenantId, deviceId)` and both were accepted. The claim ("a duplicate event for the same `(tenantId, deviceId, epoch, seq)` is rejected") is **true**; the note is that `register`-style events fall outside the constraint.

### NOTE-6 — unauthenticated non-POST verbs return 401, not 404
Because `api/server/routes/devices.js:21` applies `requireJwtAuth` to the whole router, an unauthenticated `GET /api/devices/current/retire` returns 401 before the 404. The jest "no other verb" test runs with a permissive auth mock (`devices.spec.js:11-16`), so it observes 404. This is *more* fail-closed, not an exposure — no action needed, just not what the spec text implies.

---

## 7. What I could NOT verify

1. **No live HTTP server was started.** `POST /api/devices/current/retire` was verified only at the router/middleware layer (jest + source), never against a booted Express app with a real JWT and a real Mongo. `api/server/index.js` mounting is verified by source inspection and by the spec's mocked router, not by an end-to-end request.
2. **The real JWT strategy's `req.user.tenantId`.** The resolver requires `authenticatedUser.tenantId === tenantId` (`currentOwnerDeviceResolver.js:52`). I did not boot passport, so I could not confirm that the real JWT user object carries `tenantId`; if it did not, the route would fail closed to 404 for every user. (`User` schema does declare `tenantId` at `packages/data-schemas/src/schema/user.ts:161`, which suggests it does.)
3. **`api/server/index.js` was not executed.** `node --check` is clean, but I did not start the LibreChat server (it needs a full env/config), so the mount ordering at `:274` is verified statically only.
4. **Production-relevant paths beyond the lab.** All fixtures, both of my two-process probes and every assertion run against the isolated local replica set only. Nothing here speaks to G0/production.
5. **Frozen contract manifests.** I did not have/read the M7/M7R frozen contract manifests or `PM-INTERFACE-FREEZE` itself; my "frozen intent" comparisons rely on the `assertionPlan` text embedded in `tests/device/e1/fixtures.cjs`, which is what the task instructed me to compare against.
6. **The `s2ir/` untracked directory** present in the worktree was not inspected; it is outside the T1/T2/T3 change set.
7. **`V24T12`'s sweep semantics under a real sweep implementation** — the product exposes no sweep at all, so the knob is a no-op by design; the fixture can only prove absence, not correct behaviour of a sweep.

---

## 8. Final verdict

**BLOCKED_NEEDS_GM**

Rationale: 11 of 12 product fixtures and all 5 controls are genuinely backed by real product writes against real MongoDB; claims 1, 2, 3, 4, 5, 6 hold; the T2 behaviour-preservation work holds except one overclaiming sentence. The single blocking item is **E2-V24T15**, which reports PASS while its frozen `assertionPlan` observables ("exactly one CAS matches", "loser matched 0", "epoch delta exactly 1") are contradicted by its own recorded evidence (50/50 matched, 0 losers, epoch delta 2), because the product's own preconditions serialize the two operations. Reinterpreting a frozen contract is a Governor decision, not a worker decision, so this cannot be self-accepted. Everything else is ready to be reviewed; the remaining findings are MINOR/NOTE.

**To unblock:** GM either amends the V24-T15 frozen plan (documenting the sequential revoke→claim observable as the intended contract) or directs a fixture rework that produces a genuine overlap with real losers. MINOR-1 should be fixed in the same pass (drop the raw `cause` on the `UNCLASSIFIED_DUPLICATE` path so `util.inspect` is truthful).

---

## 9. Reproduce everything (all commands, exact)

```powershell
cd C:\Users\Aryan\Desktop\codellm\librechat-rdc-phase1

# Claim 1
node tests/device/e1/run-e1.cjs --fixture=all                       # exit 0, 12 product PASS + 5 controls
node --test --experimental-test-isolation=none --test-concurrency=1 --test-timeout=900000 tests/device/e1/suite.test.cjs   # 20/20

# Claim 5
npx jest api/server/routes/__tests__/devices.spec.js                # 5/5

# Claims 3, 4, 7 (verifier-authored probes, read-only w.r.t. product code)
node tests/device/_phase1_evidence/r3-verify/probe-resolver.cjs        # 11/11 fail-closed
node tests/device/_phase1_evidence/r3-verify/probe-audit-dupe.cjs      # E11000 + live indexes, own DB dropped
node tests/device/_phase1_evidence/r3-verify/probe-contention.cjs 60   # 2 procs, 60 attempts, matched 1, active 1, stale revoke 0-match
node tests/device/_phase1_evidence/r3-verify/probe-t2-behaviour.cjs    # T2 matrix
node tests/device/_phase1_evidence/r3-verify/probe-inspect-leak.cjs    # MINOR-1 (exits 1 by design)
node tests/device/_phase1_evidence/r3-verify/probe-namespace.cjs E1-ONEPC-GRANT-CAS  # before==after

# §4 (V24T15 deviation)
node tests/device/e1/run-e1.cjs --fixture=E2-V24T15-REVOKE-VS-CLAIM-RACE
```

Evidence files in this directory: `e1-run-1.log`, `node-suite.log`, `jest-devices.log`, `probe-resolver.cjs`, `probe-audit-dupe.cjs`, `probe-contention.cjs`, `probe-contention-child.cjs`, `probe-t2-behaviour.cjs`, `probe-inspect-leak.cjs`, `probe-namespace.cjs`, `T4-VERDICT.md`.
