# T5 — Independent Verification of the Post-T4 DELTA (`1ed795808`)

Verifier: `delta-verifier` (did **not** write this code; wrote nothing outside `tests/device/_phase1_evidence/r3-verify/**`)
Repo: `C:\Users\Aryan\Desktop\codellm\librechat-rdc-phase1`
Branch: `agent/cbhr-rdc-phase1-local-authority-20261010`
Verified HEAD: `1ed795808d0a578cc434ebfd9e71f8471cb7bd4c` (`fix(device): honest V24T15 status and leak-free duplicate cause`)
Baseline for the delta: `03c351bea` (T4's verified HEAD)
Delta: 3 files, `+110 / −7` — `api/server/services/Device/errors.js`, `tests/device/e1/product/race.cjs`, `tests/device/e1/run-e1.cjs`
File SHA256 of the verified bytes:
- `errors.js` = `39D57C5CD244C0D095652CCBB8C2FF0658A2E1317004B692CBBED09E7C0DB47F`
- `race.cjs` = `8DFB43540A1C56D036DDFA221CE6FD4BA4CB5A5FB954FF05B50E1734258BDEB6`
- `run-e1.cjs` = `714899B202BE07D670BF120015B0F307DE58EF72D4BB9415B9D375CCBF3C3C6A`
Mongo: `mongodb://127.0.0.1:27027/?directConnection=true&replicaSet=cbhrRdcP1` — server `7.0.43`, vendored driver `6.21.0`, node `v22.19.0`, replica set `cbhrRdcP1`, writable primary
`git diff HEAD -- <the 3 files>` is empty: the bytes verified are the committed bytes.
Date: 2026-10-23

**Scope: adversarial verification only. Nothing was fixed. No product/test/config byte was modified. No commit, no push, no package install.**

---

## 1. Claim-by-claim table

| # | Claim under test | Verdict | Exact evidence |
|---|---|---|---|
| 1 | **Delta is honest** — V24T15 no longer claims a PASS it does not earn; nothing weakened, no assertion deleted/loosened, no fixture made vacuous | **CONFIRMED** | `git show 1ed795808 --stat` = 3 files +110/−7. The only deleted lines are the superseded doc-comment lines, `const cause = err !== null && typeof err === 'object' ? err : undefined;`, the old `...support.statusFromChecks(checks.checks)` (replaced by the identical `...measured`), the 3-status `PRODUCT_BLOCKED_STATUSES` literal (replaced by a 4-status literal) and `status = 'BLOCKED_PENDING_I6_I5';` (replaced by the deviation-aware assignment). **No assertion, check, or threshold was removed or loosened anywhere in the diff.** Live run (`t5-single-E2-V24T15-…json`): `status:"BLOCKED_CONTRACT_DEVIATION"`, `exitCode:2`, `productClaim:false`, `reason` present, 17/17 checks still executed and passing, `contractDeviation.measured = {rounds:25, totalMatches:50, revokeMatches:25, claimMatches:25, claimArmsThatFailedClosed:0, roundsWithTwoMatches:25, epochDeltaPerRow:2}`, and all 25 `dbReadBack.perDevice[*].epochDelta === 2` with `matches === 2`. The PASS is gone; the measured evidence is real and matches the frozen plan's contradiction. |
| 2 | **T7–T8 unaffected** — genuine PASS from real 50-attempt two-process contention, exactly one winner, one active row; the V24T15 override did not leak | **CONFIRMED** | Override is guarded at `race.cjs:449` (`if (fixture.id === 'E2-V24T15-REVOKE-VS-CLAIM-RACE')`); T7/T8 take the normal return at `race.cjs:503-542`. Single runs: **E2-T7** `status:"PASS"`, `productClaim:true`, 13/13 checks, `attempts:{rounds:25, casAttempts:50, recordedAttempts:50, shards:2}`, 2 distinct child PIDs, `realReturns.errorHistogram:{MATCHED:1, ONE_DEVICE_PER_ACCOUNT:24, PAIRING_CEREMONY_STALE:25}`, `dbReadBack:{activeRowsForOwner:1, rows:2, winnerCount:1}`, winner row `grantId` 22 chars + `expiresAt−activatedAt = 172800000`, 50 raw `E11000` observations on `{ownerId:1,tenantId:1}`. **E2-T8** `status:"PASS"`, 15/15, `errorHistogram:{MATCHED:1, PAIRING_CEREMONY_STALE:49}`, `epoch:1`, durable `ownerId` = the recorded winner, `authorize(winner)===true / authorize(loser)===false`. Neither report contains a `contractDeviation` key; both are `productClaim:true` and exit 0. Not inferred from the aggregate — read from `t5-single-E2-T7-*.json` / `t5-single-E2-T8-*.json`. |
| 3 | **Leak fully closed** — normalized pattern absent from `toJSON()`, `JSON.stringify(err)`, `Object.keys(err)`, `err.message`, and `util.inspect(err)` **including the `Error#cause` chain**; six mappings keep exact code/status/disposition/retryable | **CONFIRMED** | My own probe `probe-t5-leak.cjs` → `PROBE_RESULT CLEAN`, **0 FAIL** lines. For all six classified patterns and the three unclassified inputs: `toJSON` keys are exactly `["code","disposition","httpStatus","message","name","retryable"]`; pattern fields and `keyValue` values absent from `toJSON` text, `JSON.stringify(err)`, `Object.keys(err)`, `err.message`, `util.inspect(err,{depth:20})` **and** `util.inspect(err.cause,{depth:20})`. `err.cause` own keys are `["name","code"]` (`MongoDuplicateKeyError`, `11000`) — no `keyPattern`/`keyValue`. Six mappings exact: `challengeHash:1`→`RETRY_CHALLENGE_DUPLICATE`/500/`regenerate-challenge`/true; `deviceId:1,tenantId:1`→`RETRY_PRIOR_SESSION`/500/`supersede-session`/true; `deviceKeyId:1,tenantId:1`→`DEVICE_ALREADY_REGISTERED`/409/`terminal`/false; `grantId:1,tenantId:1`→`RETRY_GRANT_MINT_DEFECT`/500/`regenerate-grant`/true; `lookupTag:1,tenantId:1`→`RETRY_CODE_COLLISION`/500/`regenerate-code`/true; `ownerId:1,tenantId:1`→`ONE_DEVICE_PER_ACCOUNT`/409/`owner-dislodge-retry`/true. Before/after proof: on the pre-delta bytes (`errors-pre-delta.js`, extracted from `03c351bea`) the same probe shows `inspect leaks keyPattern: true` and cause own keys `["name","code","keyPattern","keyValue"]`; post-delta both are clean. `err.detail` still carries the normalized pattern server-side on the unclassified path (`"someNewField:1"`, `"absent or unusable"`) and is non-enumerable (`Object.keys` excludes it). |
| 4 | **No loophole** — namespace drift or a fabricated PASS still yields `HARNESS_FAIL`; a blocked fixture cannot be reported as product evidence (`productClaim:false`, reason present) | **PARTIAL** | Drift/fabrication halves **CONFIRMED** by dynamic injection (`probe-t5-gate.cjs`, in-memory stubs only, real `run-e1.cjs`): **B** fabricated PASS → `HARNESS_FAIL`/exit 4, `fabricatedProductPassIds:["FAKE-FABRICATED"]`; **C** failing control → `HARNESS_FAIL`/4; **D** injected namespace drift → `HARNESS_FAIL`/4 with `namespaceAudit.created` naming the injected db. **E REFUTED for `run-e1.cjs`**: a `BLOCKED_CONTRACT_DEVIATION` report with `productClaim:true` and **no `reason`** is accepted as blocked (exit 2), not flagged — `run-e1.cjs:184` only tests status membership, and `run-e1.cjs:196-206` never inspects `productClaim` or `reason` on blocked entries. The invariant *is* enforced elsewhere, by `tests/device/e1/suite.test.cjs:71-72`, which is why the Node suite passes. Today's real V24T15 report is honest (`productClaim:false`, reason present), so this is a gate-completeness gap, not a present falsehood. |
| 5 | **Namespace clean** — no fixture DB left behind; database list byte-identical before/after | **CONFIRMED** | My own probe `probe-t5-namespace.cjs` (raw driver, read-only) before and after the whole verification: `databasesBefore === databasesAfter` = `["admin","cbhr_rdc_phase1_governor_nullgrant_probe_20261010","cbhr_rdc_phase1_preflight_20261010","config","local"]` (JSON-byte-identical), `protectedDocumentCounts` identical, `nonProtectedOwnDatabases:[]`, `r3verifyDatabases:[]`, `foreignDatabases:[]`, `clean:true` both times. The "after" snapshot was re-taken as the very last action, i.e. after the full suite, the three single-fixture runs, and all five of my probes, and is still clean. Independently corroborated by the aggregate's own audit in `t5-e1-run-all.json`: `namespaceAudit.ok:true`, `created:[]`, `removed:[]`, `leftoverOwnDatabases:[]`, `foreignAfter:[]`. `git status --porcelain` at the end shows only the pre-existing untracked `s2ir/` and the evidence directory `tests/device/_phase1_evidence/` — no tracked file changed. |

---

## 2. Findings

### MAJOR-1 — the new override makes V24T15 unable to report `PRODUCT_FAIL`: a genuine assertion failure is relabelled `BLOCKED_CONTRACT_DEVIATION`
`tests/device/e1/product/race.cjs:448-501` (specifically `:481-500`). The override computes `measured = support.statusFromChecks(checks.checks)` (`:448`) — which is `PRODUCT_FAIL` when any check fails — then spreads `...measured` and **overwrites `status`** with `'BLOCKED_CONTRACT_DEVIATION'` (`:485`). `measured.failedCount` survives only as the descriptive `contractDeviation.assertionsStillHold` (`:477`), which no gate reads.

Consequence: if any of the 17 real assertions regresses, the fixture reports "blocked contract deviation" (aggregate exit 2, `counts.productFailures === 0`) instead of `PRODUCT_FAIL` (exit 5). Both `run-e1.cjs:184/196-206` and `suite.test.cjs:67-73` accept any `PRODUCT_BLOCKED_STATUSES` member that has `productClaim:false` + a non-empty `reason`, without looking at `failedCount`.

Minimal reproduction (no file edited; in-process wrapper that forces every check to fail):
```
node tests/device/_phase1_evidence/r3-verify/probe-t5-masking.cjs
```
Observed (`probe-t5-masking.log`): `fixtureStatus:"BLOCKED_CONTRACT_DEVIATION"`, `failedCount:17`, `passedCount:0`, `contractDeviation.assertionsStillHold:false`, `suiteBlockedBranchWouldAccept:true`, `maskingConfirmed:true`. End-to-end at the aggregate gate:
```
node tests/device/_phase1_evidence/r3-verify/probe-t5-gate.cjs    # scenario F
```
→ `status=BLOCKED_CONTRACT_DEVIATION exit=2`, `counts.productFailures=0`, despite a failed assertion in the blocked report.

Why MAJOR, not BLOCKING: it cannot fabricate a green result, cannot fabricate evidence, and cannot turn exit 2 into exit 0 — the run stays non-green. But it removes the fixture's ability to *distinguish* a product regression from the known contract deviation, which is precisely the signal the GM needs. Suggested guard (not applied): only take the deviation branch when `measured.failedCount === 0`; otherwise return `PRODUCT_FAIL` unchanged.

### MINOR-1 — `run-e1.cjs` does not enforce `productClaim:false` or a `reason` for blocked entries
`tests/device/e1/run-e1.cjs:184` (`productBlocked` = status membership only) and `:196-206` (gate). Repro: `probe-t5-gate.cjs` scenario E → a blocked report with `productClaim:true` and `reason:undefined` is accepted (`acceptedAsBlocked:true`, `flagged:false`), and the aggregate's `results[].productClaim` is `true` (`run-e1.cjs:176` copies it through). The task's required invariant *is* enforced, but only by `suite.test.cjs:71-72`; `run-e1.cjs --fixture=all` — the command the author quotes as evidence — does not check it. Today's real report satisfies the invariant, so no present falsehood.

### MINOR-2 — `measured.epochDeltaPerRow: 2` is a hardcoded literal inside a block labelled "measured"
`tests/device/e1/product/race.cjs:469`. It is not derived from the run. Today it is corroborated (all 25 `dbReadBack.perDevice[*].epochDelta === 2` and check `:375-379`), so the artifact is not false; but under a regression this "measured" value would still print `2` while the assertions fail — compounding MAJOR-1. Deriving it from `verdict.perDevice` would make it evidence rather than a claim.

### MINOR-3 — commit message and `errors.js:145` overclaim what `err.detail` retains
`errors.js:145` (and the commit body) state the normalized pattern "stays available server-side as the non-enumerable `err.detail`". True only for `UNCLASSIFIED_DUPLICATE` (`errors.js:264-270`); the six **classified** paths never set `detail` (`:272-276`) — probe prints `detail=null` for all six. Pre-delta the pattern was still reachable server-side on classified duplicates through `err.cause`; post-delta it is retained nowhere for them. Client-side and inspect leakage are fully closed (claim 3), so this is a small *diagnosability* regression plus an inaccurate doc/commit statement, not a leak.

### MINOR-4 — `contractDeviation.planExpected` quotes only 2 of the plan's 3 expected items
`tests/device/e1/product/race.cjs:455-461` omits the frozen plan's third item, "final row satisfies exactly one of {leaseState revoked} or {leaseState active under the new owner}" (`tests/device/e1/fixtures.cjs:153-157`). The fixture does still assert that item (`race.cjs:380-388`), so this is an incompleteness in the deviation report's self-description only.

### NOTE-1 — pre-existing uncleared 120 s timers make a standalone race take ~124 s wall for ~4 s of work
`tests/device/e1/product/race.cjs:60` (`waitFor` default 120000), `:190` (`READY_TIMEOUT`), `:217` (`RESULT_TIMEOUT`) — all three are present unchanged at `03c351bea`, so this is **not** delta-introduced. Measured (`probe-t5-timing.cjs`): fixture work completes in **4.35 s**, process exits after **124.20 s**, with **50** live `Timeout` resources. Same phenomenon inside `node --test` (subtest `duration_ms` 3.6 s for E2-T7 vs suite total 138 s). Recorded so no one reads the 124 s as a hang and so the delta is not blamed for it.

### NOTE-2 — T4's MINOR-2 is still open (pre-existing, outside this delta)
`tests/device/e1/product/race.cjs:298-303` still accepts `PAIRING_CEREMONY_STALE` as a T7 loser, beyond the frozen plan text `ONE_DEVICE_PER_ACCOUNT | DEVICE_ALREADY_PAIRED_USE_RENEW` (`fixtures.cjs:113`). Observed again this run: 25 such losers. Non-vacuous (one-winner/one-active-row assertions are independent), but unreconciled with the frozen text.

### NOTE-3 — verifier's own deviation, disclosed
During environment preflight I opened (and immediately dropped) one harness DB named `cbhr_rdc_phase1_w2b_r3verify_preflight_<stamp>` — the harness only mints `cbhr_rdc_phase1_w2b_*`, so it did not use my assigned `cbhr_rdc_phase1_r3verify_` prefix. It was dropped before my "before" snapshot and appears in neither snapshot (`nonProtectedOwnDatabases:[]` both times). No other probe DB was created by me.

---

## 3. Collateral-damage checks (negative results worth recording)

- `classifyWriteOutcome` on a `DeviceError` produced by `classifyDuplicateKey` is `'unknown'` both pre- and post-delta — the sanitized cause changed nothing. On a raw duplicate it is `'duplicate'`; on `MongoNetworkError` it is `'uncertain'`; on a duplicate carrying `RetryableWriteError` it is `'duplicate'` (label path untouched).
- No product code consumes `err.cause` for duplicates: `grep` over `api/server/services/Device` and `api/server/routes` finds `.cause` only inside `errors.js` (the constructor and `isUncertainWriteError`) — the sanitized stand-in breaks no consumer.
- `authorityService.js:414-416` still returns `classifyDuplicateKey(err)` for a raw duplicate; the raw error is still what classification sees, so classification behaviour is unchanged.
- T7/T8 payload shape is unchanged by the `measured` refactor: `...measured` is exactly what `...support.statusFromChecks(checks.checks)` produced before (`support.cjs:86-95`).

---

## 4. Suite / route results (independent runs)

| Command | Result |
|---|---|
| `node tests/device/e1/run-e1.cjs --fixture=all` | exit **2**, `status:"BLOCKED_CONTRACT_DEVIATION"`, `counts:{total:17, productFixtures:12, productBlocked:1, controls:5, controlFailures:0, fabricatedProductPasses:0, productFailures:0}`, `productBlockedIds:["E2-V24T15-REVOKE-VS-CLAIM-RACE"]`, `namespaceAudit.ok:true` (`t5-e1-run-all.log` / `.json`) |
| `node tests/device/e1/run-e1.cjs --fixture=E2-T7-…` | exit **0**, PASS, 13/13 |
| `node tests/device/e1/run-e1.cjs --fixture=E2-T8-…` | exit **0**, PASS, 15/15 |
| `node tests/device/e1/run-e1.cjs --fixture=E2-V24T15-…` | exit **2**, `BLOCKED_CONTRACT_DEVIATION`, 17/17 checks pass, `productClaim:false` |
| `node --test --experimental-test-isolation=none --test-concurrency=1 --test-timeout=900000 tests/device/e1/suite.test.cjs` | **20/20 pass**, exit 0 (`t5-node-suite.log`) |
| `npx jest api/server/routes/__tests__/devices.spec.js` | **5/5 pass**, exit 0 (`t5-jest-devices.log`) |

---

## 5. What I could NOT verify

1. **The frozen contract itself.** As in T4, my "frozen plan" reference is the `assertionPlan` text embedded in `tests/device/e1/fixtures.cjs:146-158`, not the M7/M7R frozen manifests or `PM-INTERFACE-FREEZE` in `C:\Users\Aryan\Desktop\codellm\cbhr-rdc`. I read only the test-side text; I did not open the governance manifests.
2. **Whether `BLOCKED_CONTRACT_DEVIATION` is an admissible status** to the Governor, and whether the plan should be amended or the protocol changed. That is a policy ruling, not a code fact; the delta correctly defers it.
3. **The product's real behaviour under a genuine revoke/claim overlap.** The fixture still cannot create one, and the delta does not claim it can. I did not author a new overlap race (out of scope, and doing so would be fixing rather than verifying). So "is the product actually safe in a contended window?" remains unproven by this fixture — exactly as the `residualRisk` field states.
4. **HTTP/JWT end-to-end.** Not touched by the delta; only the jest router spec (mocked) was run.
5. **Production / G0.** Everything ran against the isolated local replica set. Nothing here speaks to production.

---

## 6. Final verdict

**INCOMPLETE**

The delta's two stated goals are genuinely achieved and independently reproduced: E2-V24T15 now reports `BLOCKED_CONTRACT_DEVIATION` with real measured evidence instead of a PASS it does not earn (claim 1), E2-T7/T8 remain genuine 50-attempt two-process PASSes with one winner and one active row (claim 2), the `util.inspect`/cause-chain leak is closed across every surface while `err.detail` and the six mappings survive (claim 3), and the Mongo namespace is byte-identical with no leftover database (claim 5). No assertion was weakened and no PASS was fabricated.

It is not yet complete because of **MAJOR-1**: the override overwrites the computed `PRODUCT_FAIL` with `BLOCKED_CONTRACT_DEVIATION`, so V24T15 can no longer fail — a real regression in its 17 assertions would be reported as a contract deviation (exit 2, `productFailures:0`) instead of `PRODUCT_FAIL` (exit 5). MINOR-1 (gate does not enforce `productClaim:false`/`reason` for blocked entries) and MINOR-2 (hardcoded `epochDeltaPerRow`) compound the same theme: the new status is honest today but not failure-safe.

**To reach READY_FOR_GM_REVIEW:** in `race.cjs`, take the deviation branch only when `measured.failedCount === 0` (otherwise return the computed `PRODUCT_FAIL`); derive `epochDeltaPerRow` from `verdict.perDevice`; and add the `productClaim===false` + non-empty-`reason` invariant to `run-e1.cjs`'s blocked filter. Independently of those fixes, the GM still owes the V24-T15 ruling the delta correctly surfaces (amend the frozen plan to the realizable sequential observable, or authorise a protocol change that permits a claim ceremony to be armed while a live lease exists).

---

## 7. Reproduce everything (exact commands, from the repo root)

```powershell
cd C:\Users\Aryan\Desktop\codellm\librechat-rdc-phase1

# delta inspection
git show 1ed795808 --stat
git diff 03c351bea..1ed795808 -- api/server/services/Device/errors.js tests/device/e1/product/race.cjs tests/device/e1/run-e1.cjs

# claims 1, 2, 5 (aggregate + per-fixture)
node tests/device/e1/run-e1.cjs --fixture=all --result-out tests/device/_phase1_evidence/r3-verify/t5-e1-run-all.json
node tests/device/e1/run-e1.cjs --fixture=E2-T7-ONEPC-TWO-PC-RACE
node tests/device/e1/run-e1.cjs --fixture=E2-T8-TWO-OWNERS-ONE-PC-RACE
node tests/device/e1/run-e1.cjs --fixture=E2-V24T15-REVOKE-VS-CLAIM-RACE   # exit 2 by design

# claim 3 (verifier-authored leak probe, 0 FAIL expected)
node tests/device/_phase1_evidence/r3-verify/probe-t5-leak.cjs

# claim 4 + MAJOR-1 + MINOR-1/2 (verifier-authored, in-memory stubs, no file edited)
node tests/device/_phase1_evidence/r3-verify/probe-t5-gate.cjs       # scenarios A-F
node tests/device/_phase1_evidence/r3-verify/probe-t5-masking.cjs    # exits 1 when masking is confirmed

# claim 5 (verifier-authored namespace snapshots)
node tests/device/_phase1_evidence/r3-verify/probe-t5-namespace.cjs before
node tests/device/_phase1_evidence/r3-verify/probe-t5-namespace.cjs after

# NOTE-1 (timing)
node tests/device/_phase1_evidence/r3-verify/probe-t5-timing.cjs

# suites
node --test --experimental-test-isolation=none --test-concurrency=1 --test-timeout=900000 tests/device/e1/suite.test.cjs
npx jest api/server/routes/__tests__/devices.spec.js
```

Evidence files in `tests/device/_phase1_evidence/r3-verify/`: `t5-e1-run-all.log`, `t5-e1-run-all.json`, `t5-single-E2-T7-ONEPC-TWO-PC-RACE.{json,log}`, `t5-single-E2-T8-TWO-OWNERS-ONE-PC-RACE.{json,log}`, `t5-single-E2-V24T15-REVOKE-VS-CLAIM-RACE.{json,log}`, `t5-node-suite.log`, `t5-jest-devices.log`, `probe-t5-leak.cjs`/`.log`, `probe-t5-gate.cjs`/`.log`, `probe-t5-masking.cjs`/`.log`/`-report.json`, `probe-t5-namespace.cjs` + `probe-t5-namespace-{before,after}.json`, `probe-t5-timing.cjs`/`.log`, `errors-pre-delta.js` (read-only extraction from `03c351bea`), `T5-DELTA-VERDICT.md`.
