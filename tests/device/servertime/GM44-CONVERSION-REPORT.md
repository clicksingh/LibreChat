# GM-44 / GM-45 — DATABASE-TIME CONVERSION: PER-SITE RECORD

Commission: `PHASE1-LOCAL-AUTHORITY-001`. Worktree: `librechat-rdc-phase1`, branch
`agent/cbhr-rdc-phase1-local-authority-20261010`. Ruling:
`docs/GM-RULINGS-GM36-WITHDRAWN-SERVER-TIME-20261023.md` (GM-44, GM-45, GM-46), superseded in part by
`docs/GM-RULING-GM44-TIME-ANCHOR-20261023.md` (GM-64, GM-65, GM-66).

**Status: CONVERSION COMPLETE AND PROVEN; GATE 1 + GATE 2 REGRESS PENDING THE GM-64 ANCHOR SEAM.**

- The 13 GM-45 sites **and 6 further clock-driven sites** are converted to database time. §1.
- The skew class is **closed on the production path**: zero over-release, zero over-acceptance at
  ±300 s, and the margin-free admission case now **refuses**. §3.
- `devices.spec.js` (112) and `run-e1.cjs` (12+5) regress for **one** reason: their fixtures pin an
  **absolute past epoch**. GM-64 authorizes the fix (a test-only `predicateAnchor`); a sibling agent is
  wiring it. §4. I did not rewrite an oracle, and I did not invent the seam before it was ruled.

---

## 1. Per-site table

Legend — **predicate**: what decided lease state / TTL; **converted to**: what decides it now.
`$$NOW` = MongoDB server-side aggregation variable. "DB read" = `readDatabaseNowMs()` in the new
`api/server/services/Device/databaseTime.js`, which reads `$$NOW` via a `$collStats` head stage
(no document touched).

| # | Site | Old predicate (writer clock) | Converted to | Margin |
|---|---|---|---|---|
| 1 | `authorityService.buildClaimFilter` | `leaseState:'active', expiresAt:{$lte:new Date(now-5000)}` inside `$or` | `$expr:{$lte:['$expiresAt',{$subtract:['$$NOW',5000]}]}` **inside the `active` branch of `$or`** | yes |
| 2 | `authorityService.releaseLapsedLeaseImpl` | `expiresAt:{$lte:new Date(now-5000)}` | `$expr:{$lte:['$expiresAt',{$subtract:['$$NOW',5000]}]}` | yes |
| 3 | `authorityService.dislodgeOwnLapsedLease` | `expiresAt:{$lte:new Date(now-5000)}` | same `$expr` form | yes |
| 4 | `authorityService.renewAuthorityImpl` | `expiresAt:{$gt:new Date(now+5000)}` | `$expr:{$gt:['$expiresAt',{$add:['$$NOW',5000]}]}` | yes |
| 5 | `pairingSessionService.isLiveLease` (+ its 3 call sites) | `now < expiresAt` | DB read passed in as `serverNow` | **none** |
| 6 | `pairingSessionService.isLapsedLease` | `expiresAt+5000 <= now` | DB read passed in as `serverNow` | yes |
| 7 | `authorityService.spendChallengeImpl` | `expiresAt:{$gt:new Date(now)}` | `$expr:{$gt:['$expiresAt','$$NOW']}` | **none** |
| 8 | `pairingSessionService.redeemPairingCodeImpl` | `expiresAt:{$gt:new Date(now)}` (read **and** CAS) | `$expr:{$gt:['$expiresAt','$$NOW']}` in both | **none** |
| 9a | `rejoinPendingPairingImpl` | `expiresAt:{$gt:new Date(now)}` (read + CAS) | `$expr` in both | **none** |
| 9b | `mintPairingClaimChallengeImpl` | `sessionExpiresAt <= now`; `expiresAt:{$gt:new Date(now)}` | DB read for the pre-check; `$expr` in the arm CAS | **none** |
| 9c | `approvePairingClaimImpl` | `expiresAt <= now`; `expiresAt:{$gt:new Date(now)}` | DB read for the pre-check; `$expr` in the consume CAS | **none** |
| 10 | `currentDeviceRenewEnvelopeHandler.isRenewable` (2 sites) | `expiresAt > now+5000` | DB read (`leaseNow`, `currentNow`) | yes |
| 11 | `pairingCompleteHttpHandler.isLiveLease` (2 sites) | `expiresAt > now` | DB read (`idempotencyNow`, `serverNow`, `freshNow`) | **none** |
| 13 | `registrationService` registration-challenge spend | `expiresAt:{$gt:new Date(now)}` | `$expr:{$gt:['$expiresAt','$$NOW']}` | **none** |

### Sites beyond the GM-45 list, converted for the same reason (GM-44 rule 2)

| Site | Why | Converted to |
|---|---|---|
| `authorityService.classifyClaimMiss` | Classifies a CAS miss into `DEVICE_ALREADY_PAIRED_USE_RENEW` / `PAIRING_WINDOW_TOO_EARLY` — a lease-state *disposition*. | DB read |
| `authorityService.classifyRenewMiss` | Classifies into `LEASE_EXPIRED` ("inside the renewal skew margin"). | DB read |
| `pairingSessionService.recoverCommittedClaim` | Decides whether a recovered grant is a **live** lease. | DB read |
| `pairingSessionService.readChallengeRecord` | 120 s challenge TTL — a TTL, and it gates the ceremony PoP. | `$expr` |
| `pairingSessionService.denyPairingSessionImpl` | Carries the identical margin-free session-TTL pattern as sites 9a–9c but is absent from GM-45's table. | DB read + `$expr` |
| `currentDeviceRenewEnvelopeHandler` renewal-challenge read | 120 s renewal-challenge TTL. | `$expr` |

### Deliberately NOT converted (still writer time — and why that is correct)

`activatedAt`, `expiresAt`, `renewedAt`, `claimedAt`, `consumedAt`, `openedAt`, audit `ts`,
`ownerConfirmedAt`, `endpointSignatureVerifiedAt`, response `issuedAt`, and the local-consent
freshness test (`approvedAt >= openedAt && approvedAt <= now && approvedAt < expiresAt`). These are
**values written into a row, audit timestamps, freshness checks or response fields**, not
predicates that decide lease state or a TTL. GM-44 scopes the conversion to the predicates; the
injected `clock` seam is retained for everything else (constraint 1).

---

## 2. Defence-in-depth skew guard (GM-44 rule 3)

New module `api/server/services/Device/databaseTime.js`:

- `readDatabaseNowMs(db)` — server clock via `$collStats` + `$$NOW`, no document read.
- `createClockSkewGuard({db, hostNow, budgetMs=5000, cacheMs=1000})` — `check()` resolves
  `{ok, skewMs, databaseNowMs, budgetMs, error}`. `|skew| > 5000` ⇒ `ok:false` with the new frozen
  code `CLOCK_SKEW_EXCEEDED` (**HTTP 503** — a self-detected inability to serve, not a client fault
  and not a 500 defect). An **unmeasurable** clock is also `ok:false`: an unprovable clock is not a
  passing clock.

**Where it hooks** — the guard is injected as `clockSkewGuard` and is the **last gate before every
lease-state write**, so it can never mask or reorder an auth/authorization outcome:

| Hook | Operations refused when the guard fails |
|---|---|
| `authorityService.requireClockBudget()` | `claimAuthority` (before the CAS), `renewAuthority` (after the proof binding check), `releaseLapsedLease`, `disownOwnLapsedLease` (inside `dislodgeOwnLapsedLease`) |
| `pairingHttpHandler.buildPairingServices` | the whole ceremony path (`createClockSkewGuard({db, logger})`) |
| `pairingCompleteHttpHandler.buildPairingServices` | the claim CAS |
| `currentDeviceRenewEnvelopeHandler.completeLeg` | the renewal CAS |

The guard is **optional at construction** so a composition with no database surface (pure unit
harness) still works; when supplied and unusable it fails closed. Correctness does **not** depend on
it: every `$expr` predicate is already clock-independent, and the new oracle proves the skew cases
pass with **no guard configured at all** (cases 1–7).

---

## 3. What is proven (acceptance gate 3's actual subject)

`node tests/device/servertime/run-servertime.cjs` — **new in-scope oracle**, 8 cases, **32/32 PASS,
exit 0**. It takes its reference timeline from `hello.localTime` (the server), applies the writer
offset on top, and drives only real product calls over the frozen registry.

| Case | Proves |
|---|---|
| `ST-ADMISSION-AT-BUDGET` | skew **+5000 ms**, lease live by **4000 ms** ⇒ issuance **REFUSED**, no code, no session row. This is the verifier's `PROBE-ADMISSION.json` case, now closed. |
| `ST-ADMISSION-CONTROL` | same at skew 0 (the control still refuses). |
| `ST-CLAIM-OVER-RELEASE-FAST` | skew +300 s, lease live by 1000 ms ⇒ claim 0-matches, `DEVICE_ALREADY_PAIRED_USE_RENEW`, owner/epoch untouched. |
| `ST-LAZY-RELEASE-FAST` | skew +300 s ⇒ lazy release 0-matches a live lease. |
| `ST-RENEW-OVER-ACCEPT-SLOW` | skew −300 s, lease expired by 1000 ms ⇒ `LEASE_EXPIRED`, nothing written. |
| `ST-DEAD-CODE-SLOW` | a code dead by 100 s is refused at skew −300 s (`INVALID_OR_EXPIRED_CODE`); session **not** resurrected (`open`, `pendingOwnerId:null`, `attemptsUsed:0`). This is the security-relevant consequence GM-36 missed. |
| `ST-DISLODGE-OWN-LIVE-FAST` | `dislodgeOwnLapsedLease` (the 4th site, "previously missed by everyone") does not over-release the caller's own live lease; `ONE_DEVICE_PER_ACCOUNT` returned, second row untouched. |
| `ST-SKEW-GUARD-DEFENCE-IN-DEPTH` | guard passes in budget, fails closed out of budget with `CLOCK_SKEW_EXCEEDED`/503, the guarded write touches no row, an in-budget writer is **not** blocked. |

Evidence: `tests/device/_phase1_evidence/servertime-oracle/SERVER-TIME-RESULTS.json`.

**GM-64.5 compliance:** this oracle constructs the services with **no `predicateAnchor`** and takes its
reference timeline from the server, so it always runs in **database mode**. Its skew result is
therefore valid skew evidence under GM-64.5 and stays valid after the anchor seam lands.

### Skew fixture: the offset-writer law is clean, the control arm is not

`node tests/device/e1/skew/run-skew.cjs --fixture=all --evidence-dir=tests/device/_phase1_evidence/skew-fixed`
— **exit 5, PRODUCT_FAIL**, and honestly so:

- **Offset-writer law violations: 0.** Zero over-release, zero past-expiry renewal, across all three
  fixtures. `counterexampleReproduced: false` in all three. Every recorded first-CAS filter contains
  `$$NOW` and no writer-clock `Date`. SKEW-02's `renewAuthority` now returns `LEASE_EXPIRED`;
  SKEW-01's claim/lazy-release/ceremony all 0-match.
- **26 failed assertions, all in the offset-0 CORRECT control arm** (e.g. "CORRECT writer refused the
  claim…": observed `[1,null]`, expected `[0,'DEVICE_ALREADY_PAIRED_USE_RENEW']`; and the derived
  "no seed owner lost its active lease", which is computed from those same rows). The control arm
  asserts that the offset-0 writer **refuses** a lease that is live on the fixture's reference
  timeline (`TRUE_NOW = 1791000000000`). It does not refuse, because the fixture seeds that lease
  with `expiresAt = TRUE_NOW + 1000`, and `TRUE_NOW` is a **hard-coded epoch ~20 days in the past**.
  In database time that lease expired weeks ago, so the offset-0 writer correctly dislodges it.

**The fixture is NOT weakened.** It remains the oracle; no assertion was edited. Its premise
("live on the reference timeline" ⇔ "live in the database") is what stopped holding once predicates
moved to database time. Fixing it needs the reference timeline anchored to the server — i.e. editing
the oracle — which the task explicitly reserves for the Governor.

---

## 4. Acceptance results — exact counts

| Gate | Target | Result |
|---|---|---|
| `npx jest api/server/routes/__tests__/devices.spec.js` | 112/112 | **91/112 (21 failed)** — REGRESSED |
| `npx jest api/server/routes/__tests__/devices.hardening.spec.js` | 57/57 | **57/57 PASS** |
| `npx jest api/server/services/Device/relay` | 100/100 | **127/127 PASS** (see note) |
| `node tests/device/e1/run-e1.cjs --fixture=all` | 12/12 product + 5/5 controls | **7 product failures; 5 product PASS; controls 5/5 (0 controlFailures)** — REGRESSED |
| `run-skew.cjs --fixture=all` | zero violations | **0 offset-writer violations**; 26 control-arm assertions fail ⇒ exit 5 |
| new margin-free test | must flip to refusal | **PASS** (32/32, exit 0) |

Note on relay: the count is **127**, not 100, because a sibling agent concurrently added
`api/server/services/Device/relay/__tests__/defectFixes.spec.js` (untracked) and modified three relay
specs plus `relay/*.js` during this task. All 127 pass. I did not touch `relay/**`.

### Why the two gates regress — one root cause

Every failing test mints or reads a row relative to an **absolute injected epoch**:

- `devices.spec.js`: `BASE_NOW = 1792000000000` (**2026-10-14**, ~9 days past).
- E1: `EPOCH_BASE_MS = 1791000000000` (**2026-10-03**, ~20 days past).

With predicates on database time, a lease seeded at `BASE_NOW + 10h` is already dead. So:
`pairing/issue` refuses with `INVALID_OR_EXPIRED_CODE` instead of issuing (14 tests), the renewal
pre-checks refuse (6 tests), and E1's TTL/margin/race fixtures see "expired" where they expect "live".
This is **not** a defect in the predicates — it is the fixtures' clock contract.

Verified NOT a cardinality regression: `E2-T7` reports `winnerCount: 2`, but that is **two winners in
two different rounds** (round 0 and round 1), and `dbReadBack.activeRowsForOwner: 1`. The
`uq_owner_active` unique partial index still enforces exactly one active row per owner, exactly as
GM-44 §2 states.

Two E1 entries are `HARNESS_FAIL` rather than `PRODUCT_FAIL` (`E1-V24T04-CODE-TTL-300S`:
`TypeError: Cannot read properties of null (reading '_id')`; `E1-V24T03-CODE-COLLISION`:
`…(reading 'lookupTag')`). Cause: the fixture seeds devices with `leaseState:'never'` but calls
`issuePairingSession` **without** the `mintPairingOpenChallenge` step, so `readChallengeRecord`
(the now-`$expr` challenge TTL read) finds no row and the fixture dereferences `null`. Same epoch
root cause, surfacing as an unguarded dereference inside the fixture.

### The decision I did not take unilaterally — and how it was resolved

Making both gates green requires one of:

1. **Re-anchor the fixtures to database time** (change `BASE_NOW`/`EPOCH_BASE_MS` from constants to a
   server-derived base). Touches `tests/device/e1/**` and `api/server/routes/__tests__/devices.spec.js`
   — the latter is outside my write scope.
2. **Keep an explicit, test-only time-source seam** so a fixture can place the comparison anchor
   anywhere on the timeline.

I stopped at the boundary rather than rewrite an oracle, and flagged option 2 as needing GM sign-off
because a naively-widened seam would re-open the hole GM-44 closed.

**RESOLVED BY GM-64 / GM-65 / GM-66** (`docs/GM-RULING-GM44-TIME-ANCHOR-20261023.md`, 2026-10-23
08:33 Pacific — written after this task began and therefore not in the brief I was given). It rules
exactly option 2, under conditions:

- GM-64.1 production default stays `$$NOW`, non-negotiable;
- GM-64.2 a test-only anchor (concrete `Date`) may replace the `$$NOW` operand;
- GM-64.3 the anchor must be unreachable from request/row/session/caller data;
- GM-64.4 **a test must pin the production default** (no seam ⇒ `$$NOW`, never a caller date);
- GM-64.5 the skew oracle must run in **database mode** or its result is void as skew evidence;
- GM-65 the seam is named `predicateAnchor`, "tests only; production must omit";
- GM-66.3 `devices.spec.js` back to **112/112** and E1 to **12/12 + 5/5** with the same assertions.

The seam was subsequently implemented in `databaseTime.js` (`predicateAnchor`,
`resolvePredicateAnchor`, `expiryPredicate`, `readAnchorNowMs`) by a **concurrent sibling agent**, who
is wiring it through the services now. My conversion is the foundation that seam is being layered on;
the `$expr`/`$$NOW` shapes it produces in production are byte-identical to what §1 records.

**Concurrency note (important for the integrator):** a sibling agent is editing the same files. At
2026-10-23 08:55 it had wired `authorityService.js` for `predicateAnchor` but not yet
`pairingSessionService.js`, `pairingCompleteHttpHandler.js`, `currentDeviceRenewEnvelopeHandler.js` or
`registrationService.js`. A spec run taken during that window reports **27 failed / 85 passed** — a
mid-refactor snapshot, not a verdict. I stopped writing to these files at that point rather than
clobber in-flight work. Final acceptance must be re-measured once the sibling's wiring lands.

---

## 5. Files changed

New:
- `api/server/services/Device/databaseTime.js`
- `tests/device/servertime/run-servertime.cjs`
- `tests/device/_phase1_evidence/servertime-oracle/SERVER-TIME-RESULTS.json` (evidence)

Modified (all within `api/server/services/Device/**`):
- `authorityService.js`, `pairingSessionService.js`, `registrationService.js`,
  `currentDeviceRenewEnvelopeHandler.js`, `pairingCompleteHttpHandler.js`, `pairingHttpHandler.js`
  (guard wiring only), `errors.js` (`CLOCK_SKEW_EXCEEDED: 503`).

`node --check` passed on every changed file. Nothing committed or pushed.
