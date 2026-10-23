# T6 — INDEPENDENT FINAL VERDICT (R3 end state)

Verifier: `final-verifier` — **did not write any of the code under test**. Nothing was fixed.
Repo: `C:\Users\Aryan\Desktop\codellm\librechat-rdc-phase1`
Branch: `agent/cbhr-rdc-phase1-local-authority-20261010`
Verified HEAD: **`0d579b2ccaf8ef322dbc1a55d3172a56dad68b30`** (`feat(device): owner-authorized local pairing and current-device HTTP endpoints`)
Commits in scope: `ab51de5d4` (V24T15 plan amendment + failure-safety), `0d579b2cc` (T7 endpoints)
Mongo: `mongodb://127.0.0.1:27027/?directConnection=true&replicaSet=cbhrRdcP1` — server `7.0.43`, driver `6.21.0`, node `v22.19.0`, replica set `cbhrRdcP1`, writable primary
Date: 2026-10-23
Writes: only under `tests/device/_phase1_evidence/r3-final/**`. No tracked file modified (`git diff --stat HEAD` empty; `git status` shows only the pre-existing untracked `s2ir/` and the evidence tree). No package install, no commit, no push.

**Verdict: `READY_FOR_GM_REVIEW`** — see §6.

---

## 1. Claim-by-claim table

| # | Claim | Verdict | Exact evidence |
|---|---|---|---|
| 1 | `run-e1.cjs --fixture=all` exits 0: 12/12 product PASS, 5/5 controls, 0 fabricated PASSes, 0 unevidenced blocks, namespace before==after | **CONFIRMED** | `node tests/device/e1/run-e1.cjs --fixture=all --result-out tests/device/_phase1_evidence/r3-final/t6-e1-run-all.json` → exit **0** (`t6-e1-run-all.exit.txt`). Raw JSON (`t6-e1-run-all.json`, not the summary line): `status:"PASS"`, `counts:{total:17, productFixtures:12, productBlocked:0, controls:5, controlFailures:0, fabricatedProductPasses:0, unevidencedBlocked:0, productFailures:0}`, `productBlockedIds:[]`, `fabricatedProductPassIds:[]`, `unevidencedBlockedIds:[]`, `productFailureIds:[]`, `namespaceAudit:{ok:true, created:[], removed:[], leftoverOwnDatabases:[], foreignAfter:[]}`. Per-fixture read of all 12 product entries: each `status:"PASS"`, `productClaim:true`, non-empty `checks`, `failedCount:0`, real per-fixture `dbName`; controls `NC-NAIVE-NOINDEX:EXPECTED_FAIL`, `NC-NAIVE-INDEX/NC-DB-FENCE/NC-CRASH-HARNESS/NC-SWEEP-KNOB:PASS`. |
| 2 | `ab51de5d4` is honest: amendment recorded (at/authority/rationale/supersedes), fixture asserts the reachable sequenced law, unreachable contention disclosed as `residualGap.notTested`, nothing weakened | **CONFIRMED** | `git show ab51de5d4` (3 files, +100/−75). Amendment block `tests/device/e1/fixtures.cjs:164-171` — `amended:{at:'2026-10-22', authority:'owner ruling (option: amend the plan to the realizable sequential expectation)', supersedes:'exactly one CAS matches; loser matched 0, never a blind write; epoch delta exactly 1', rationale:'one-CAS contention is unreachable…'}`; `expected[]` now states the sequenced law and ends with an explicit `RESIDUAL GAP (not tested)` entry (`fixtures.cjs:184`). Runtime proof (`t6-e1-run-all.json`): the V24T15 report carries `residualGap:{planAmendedAt, authority, supersededExpectation, whyUnreachable{file,rule,observed:"0 failed-closed arming attempts across 25 rounds…"}, notTested:"A regression permitting two conflicting writes inside a contended revoke/claim window would NOT be detected by this fixture.", measuredSequence:{…epochDeltasObserved:[2], matchesPerRowObserved:[2]}}` — i.e. disclosed, **not** claimed as tested. Weakening check: `ab51de5d4` deletes only the superseded doc-comment, the old override block and the `counterexample` field (reporting code, not assertions); the 17 checks in `race.cjs:267-425` are untouched and the measured values in `residualGap.measuredSequence` are derived from `verdict.perDevice` (`race.cjs:465-474`), closing T5's MINOR-2 (hardcoded `epochDeltaPerRow`). `run-e1.cjs` only **gains** the `unevicencedBlocked` gate (`run-e1.cjs:194-201,210-218`) — strictly stronger. |
| 3 | FAILURE-SAFETY: the V24T15 fixture can actually FAIL (`PRODUCT_FAIL`/exit 5, not a blocked status); `unevidencedBlocked` gate trips `HARNESS_FAIL` on `productClaim!==false` or empty reason | **CONFIRMED** | **(a) Real failing assertion, no tracked file edited.** `node --require tests/device/_phase1_evidence/r3-final/probe-fail-inject.cjs tests/device/e1/run-e1.cjs --fixture=E2-V24T15-REVOKE-VS-CLAIM-RACE` → exit **5**, `status:"PRODUCT_FAIL"`, `productFailures:1`, `productFailureIds:["E2-V24T15-REVOKE-VS-CLAIM-RACE"]`; the report has `failedCount:1, passedCount:16`, failed check = *"no live authorization remains for any raced row"* (`t6-failinject-v24t15.json`). The preload replaces **only** the harness oracle `support.authorizePredicate` with an always-allow stub; the fixture itself still ran 25 rounds / 50 real CAS attempts against real Mongo, so this is a genuine assertion failure, not a synthetic status. **(b) Historical defect directly re-tested.** T5's own masking probe (which exited 1 confirming masking at `1ed795808`) now returns `fixtureStatus:"PRODUCT_FAIL"`, `contractDeviationPresent:false`, `maskingConfirmed:false`, `suiteBlockedBranchWouldAccept:false` and exits **0** (`t6-t5masking-rerun.log`). **(c) Gate.** `node tests/device/_phase1_evidence/r3-final/probe-gate.cjs` → exit 0, 4/4 scenarios: A blocked+`productClaim:true` → `HARNESS_FAIL`/4 with `unevidencedBlocked:1`; B blocked+empty `reason` → `HARNESS_FAIL`/4; C honest blocked (`productClaim:false`+reason) → accepted `BLOCKED_CONTRACT_DEVIATION`/2; D PASS without evidence → `HARNESS_FAIL`/4 with `fabricatedProductPasses:1` (`probe-gate.log`). |
| 4 | E2-T7 and E2-T8 still genuinely PASS from real 50-attempt two-process contention (one winner, one active row); neither carries V24T15's `residualGap` | **CONFIRMED** | `node tests/device/e1/run-e1.cjs --fixture=E2-T7-ONEPC-TWO-PC-RACE` → exit 0, `PASS`, **13/13** checks, `attempts:{rounds:25, casAttempts:50, recordedAttempts:50, shards:2}`, two distinct child PIDs `[41276,51104]`, `errorHistogram:{MATCHED:1, ONE_DEVICE_PER_ACCOUNT:24, PAIRING_CEREMONY_STALE:25}`, `dbReadBack:{activeRowsForOwner:1, rows:2, winnerCount:1}`, **48** raw duplicate-key observations on `{ownerId,tenantId}` (`t6-single-t7.json`). `--fixture=E2-T8-TWO-OWNERS-ONE-PC-RACE` → exit 0, **15/15**, `errorHistogram:{MATCHED:1, PAIRING_CEREMONY_STALE:49}`, `epoch:1`, durable `ownerId` == recorded winner, `expiresAt−activatedAt = 172800000`, `authorize(winner)===true / authorize(loser)===false` (`t6-single-t8.json`). Neither report contains a non-null `residualGap` (`residualGap:null` in both); the disclosure is guarded to V24T15 at `race.cjs:451-452,506-509`. |
| 5 | T7 endpoint work: `requireJwtAuth` before EVERY handler; no request-derived identity/tenant/owner/role/deviceId/grantId/epoch; injection → 400 before any model call; no secret/cross-user leakage; jest fully green with pre-existing cases intact | **CONFIRMED** | *Auth ordering:* `api/server/routes/devices.js:66` `router.use(requireJwtAuth)` precedes all six `router.*` registrations (`:67-72`). Independently proved from the loaded router object (`probe-router-auth.cjs`, 5/5, `t6-router-auth.json`): `stack[0]` is the auth middleware; 6 route layers, all `index > 0`; DENY mode → every endpoint 401, auth invoked exactly once, **0 model calls**; ALLOW mode → every endpoint non-401 (handler reachable). *No request identity:* the only request reads in the three new files are `req.body.{devicePublicKey,challengeHash,signatureB64u,code}` (`pairingHttpHandler.js:282,385,404,407,495`) plus `req.user` for the session (`deviceHttpTrust.js:107,235,246`); `guardRequestInput` rejects params/query/nested/identity vocabulary (`deviceHttpTrust.js:35-84,150-195`). *Injection with zero model calls:* real-registry probe (`probe-http-real.cjs`, **28/28**, `t6-http-real.json`) — 40 body injections across 4 endpoints, 5 query injections, 5 param injections → all `400 REQUEST_SUPPLIED_IDENTITY_REJECTED` with a counting proxy observing **0** model calls. *Code exactly once, never persisted/logged:* the issue response carries the 6-digit code once; the persisted row carries only a 43-char HMAC `lookupTag` which is exactly `computeLookupTag({code,tenantId,pepper})`; the code appears in **no** collection dump; approve's response does not echo it; the three handler files contain **zero** logger/console calls; `pairingSessionService.js` logs no code (`code:'READ_FAILED'` is symbolic, `:619`). *No leakage:* `GET /current` projection is exactly `["deviceId","epoch","expiresAt","identityState","leaseState","ok","tenantId"]` with none of `devicePublicKey/deviceKeyId/lookupTag/grantId/grantProof/prevGrantId/prevOwner/prevEpoch/deviceSessionId/authorizedNow`; another user's device → `404 UNKNOWN_DEVICE` indistinguishable from none. *Renew law:* 48h exactly (`expiresAt−now = 172800000`); inside the 5 s margin → `409 LEASE_EXPIRED`, `committed:false`, no write; cross-user → 404 with row untouched; two concurrent renewals → **exactly one commits** (epoch 5→6, `renewalCount 1`, one audit event, loser `409 NOT_OWNER_OR_STALE committed:false`) — the CAS is preserved end-to-end (`probe-renew-race.cjs`, 5/5). *Approve stops at LP-2:* `state:"claim_pending"`, authority row still `pending/never/null/null/0`. *Jest:* `npx jest api/server/routes/__tests__/devices.spec.js` → **68/68 pass**, 1 suite, exit 0 (`t6-jest.stderr.log`). *Pre-existing cases intact:* `0d579b2cc` is insertions-only (`git show --numstat`: 1109/50/355/359/524 added, **0 deleted**), so the original 5 cases are byte-identical. |
| 6 | `node --test … tests/device/e1/suite.test.cjs` → 20/20 | **CONFIRMED** (with a spec-text typo, NOTE-1) | `node --test --experimental-test-isolation=none --test-concurrency=1 --test-timeout=900000 tests/device/e1/suite.test.cjs` → exit **0**, `# tests 20 / # pass 20 / # fail 0 / # cancelled 0 / # skipped 0`, duration 137.7 s (`t6-node-suite.stdout.log`, `t6-node-suite.exit.txt`). The literal flag in the task text (`--experimental-isolation=none`) is rejected by node 22.19.0 (exit 9, `bad option`); the suite's own header documents the correct `--experimental-test-isolation=none`. |
| 7 | Mongo namespace unchanged, no fixture/probe DB left behind, only `cbhr_rdc_phase1_*` touched | **CONFIRMED** | My own raw-driver snapshots before and after the whole verification (`probe-namespace.cjs` → `namespace-before.json` / `namespace-after.json`): `databases` byte-identical `["admin","cbhr_rdc_phase1_governor_nullgrant_probe_20261010","cbhr_rdc_phase1_preflight_20261010","config","local"]`, `identical:true`, protected document counts identical, `ownDatabases:[]` both times, `r3finalDatabases:[]`, `foreignDatabases:[]`. Corroborated by every aggregate run's own `namespaceAudit.ok:true` with empty `created/removed/leftoverOwnDatabases/foreignAfter`. My two probe DBs (`cbhr_rdc_phase1_r3final_http_*`, `cbhr_rdc_phase1_r3final_renew_*`) were dropped by the probes themselves and appear in neither snapshot. |

---

## 2. The two historical failure modes — explicit closure

### 2.1 MASKING — **CLOSED**
The defect T5 found was that the V24T15 override overwrote the computed `PRODUCT_FAIL` with `BLOCKED_CONTRACT_DEVIATION`, so a real regression became exit 2 instead of exit 5. At HEAD:

- The override block is gone; the fixture returns `support.statusFromChecks(checks.checks)` unchanged (`race.cjs:448`, returned at `:478-482`), and the comment at `:445-446` states the invariant.
- **Direct proof it can fail**: forcing one real assertion to fail from outside the tracked tree yields `status:"PRODUCT_FAIL"`, exit **5**, `productFailures:1` — not a blocked status (`t6-failinject-v24t15.json`).
- **Regression proof**: T5's masking probe, which previously confirmed masking (exit 1), now reports `maskingConfirmed:false` / `fixtureStatus:"PRODUCT_FAIL"` and exits 0 (`t6-t5masking-rerun.log`).
- **Gate proof**: a blocked report that is not evidenced (`productClaim:true`, or an empty reason) is now `HARNESS_FAIL`/4 at the aggregate itself (`run-e1.cjs:194-201,210-218`), not only in `suite.test.cjs` — closing T5's MINOR-1.

### 2.2 HONESTY — **CLOSED**
The amended plan is recorded in the frozen fixture file (`fixtures.cjs:164-171`) with `amended.at/authority/rationale/supersedes`, the `expected[]` list asserts only the reachable sequenced law, and the unreachable one-CAS contention property is disclosed three times: as an `expected[]` line (`fixtures.cjs:184`), as `residualGap.notTested` in every run report (`race.cjs:463-464`), and as `sequenceNote` (`race.cjs:506-509`). It is **not** claimed as tested anywhere, and the measured sequence values are derived from the run rather than hardcoded.

---

## 3. Findings

No BLOCKING and no MAJOR findings. All seven claims are confirmed.

### MINOR-1 — renewal authorization is session-only (no device proof); disclosed but a real gap for any non-lab use
`api/server/services/Device/currentDeviceHttpHandler.js:35-44,77-103,258-294`. The handler injects a server-owned `createSessionRenewalAuthorization` verifier; `observe()` binds `{tenantId, ownerPrincipalId, deviceId, grantId, epoch}` from the row the handler **just read itself**, immediately before calling `renewAuthority` with the same values (`:285-294`). `checkRenewalBinding` (`authorityService.js:801-827`) therefore always agrees by construction, so the renewal's only real authorization is the authenticated session plus the resolver. The frozen law's *timing* half (48 h TTL, `expiresAt > now+5000` CAS, epoch/grant/owner conjuncts at `authorityService.js:912-921`) is genuinely enforced — but the *"manually approved"* half has no device-side proof.
**Judgment:** an **honest scope limit for the local lab** (the file header and the commit body both say it MUST be replaced by the ratified device-proof verifier before non-lab use, and production G0 is blocked), but a **real gap for any promotion past the lab** — it must not be read as a completed renewal-authorization design.
Minimal repro: `node tests/device/_phase1_evidence/r3-final/probe-http-real.cjs` — a renew succeeds with no client proof at all (200, epoch+1).

### MINOR-2 — `/pairing/approve` stops at LP-2 and cannot complete the claim; the end-to-end employee flow is not closed over HTTP
`api/server/services/Device/pairingHttpHandler.js:37-43,438-517`. Approve binds `pendingOwnerId` and returns `claim_pending`; it grants no authority (verified: the row stays `pending/never/null/null/0`). The grant-completing claim leg needs a PoP-authenticated device poll channel plus a device-local approval prompt, neither of which exists in this repo, so the builder deliberately stopped rather than inventing an unauthenticated claim path.
**Judgment:** **honest scope limit**, and the safer choice — an HTTP claim endpoint without device PoP would be a serious authority-escalation hole. Consequence to record: the E2 fixtures exercise the claim leg through the accepted services directly (`race.cjs`), not through HTTP, so "employee enters the code and the AI operates the PC" is **not** yet a closed HTTP path. That is a product-completeness gap, not a defect in what was built.
Minimal repro: `node tests/device/_phase1_evidence/r3-final/probe-http-real.cjs` — approve → `claim_pending`, authority row unchanged.

### MINOR-3 — the HTTP tests use schema-mirroring test models, not the real `@librechat/data-schemas` registry
`api/server/routes/__tests__/devices.spec.js:254-263,280-433` (disclosed in the file itself), with `mongodb-memory-server` rather than the local replica set (`:580-581`). This is forced: the workspace packages are unbuilt in this worktree, so the real registry cannot load under Jest (`node -e "require('./api/server/routes/devices.js')"` → `MODULE_NOT_FOUND librechat-data-provider/dist/index.js`).
**Does it materially weaken claim 5?** For the Jest suite alone, yes — schema drift between the mirrored models and the frozen schemas would be invisible. I therefore **compensated independently** rather than accepting it: `probe-http-real.cjs` loads the genuine `createModels(mongoose)` registry through the in-memory TS bridge, calls the real declared `syncIndexes()` on the real local replica set, and drives the same real handler bytes — **28/28 assertions pass**. With that mitigation, claim 5 is not materially weakened. Grade **MINOR (test-fidelity), mitigated**.
Minimal repro: `node tests/device/_phase1_evidence/r3-final/probe-http-real.cjs` (`models: "real frozen createModels(mongoose) registry via the w3a bridge"`).

### NOTE-1 — the task's literal suite command has a flag typo
`node --test --experimental-isolation=none …` is not a valid node 22.19.0 flag (exit 9, `bad option: --experimental-isolation=none`). The correct flag — used by the suite's own header, `tests/device/e1/suite.test.cjs:9` — is `--experimental-test-isolation=none`. Re-run with it: 20/20, exit 0. No code defect; the spec text should be corrected.

### NOTE-2 — my router probe crashed on first run; that was my harness, not the route
`probe-router-auth.cjs` initially exited 1 with `UNEXPECTED_MODEL_CALL DeviceAuthority` because my first stub threw on any model call, and in ALLOW mode the handlers legitimately reach the models. Fixed to permissive stubs; final result **5/5 pass**. Recorded so the transient failure is not misread as a route defect (also independently confirmed by the Lead's own reproduction and by `stack[0] = auth` static inspection of `devices.js:66-72`).

### NOTE-3 — T4's MINOR-2 (T7 loser allowlist wider than the frozen plan text) remains open, unchanged
`race.cjs:298-303` still accepts `PAIRING_CEREMONY_STALE` alongside the frozen `ONE_DEVICE_PER_ACCOUNT | DEVICE_ALREADY_PAIRED_USE_RENEW` (`fixtures.cjs:113`). Observed again this run: 25 such losers. Non-vacuous (the one-winner / one-active-row checks are independent), but unreconciled with the frozen text. Pre-existing; not introduced or worsened by the commits under test.

### NOTE-4 — E1 log contains the disclosed test constant `424242`
`t6-e1-run-all.stdout.log` records `"the forced code was used","observed":"424242"` — the source-visible test constant already flagged as T4 NOTE-2. Not a minted secret (no minted 6-digit code appears in any log I produced; the other 6-digit runs in the logs are hex substrings such as `…DF659613DF…` and TTL constants `299999/300000/300001`). Lab pepper never appears in any log.

### NOTE-5 — `errors.js` unchanged since the T5 leak fix; leak remains closed at HEAD
`git diff 1ed795808..HEAD -- api/server/services/Device/errors.js` → empty. Re-ran T5's leak probe at HEAD: `PROBE_RESULT CLEAN`, `Object.keys` = `["name","code","httpStatus","disposition","retryable"]`, `detail` non-enumerable (`t6-leak-rerun.log`). No regression from the endpoint work.

### NOTE-6 — unauthenticated non-POST verbs still return 401, not 404
Because `router.use(requireJwtAuth)` covers the whole prefix, an unauthenticated `GET /api/devices/pairing/issue` returns 401 before the 404. More fail-closed, not an exposure (T4 NOTE-6, still true).

---

## 4. What I could NOT verify

1. **A booted LibreChat server with a real JWT.** The route is verified at the router/Express layer (real router bytes, real handlers, real services, real Mongo). I did not start the full app, so the real passport strategy's `req.user.tenantId` and the mount in `api/server/index.js` are verified by source/`node --check`, not by an end-to-end login. If a real JWT user object lacked `tenantId`, every device endpoint would fail closed (403) — safe, but untested live.
2. **The frozen governance manifests.** My "frozen plan" reference is the `assertionPlan` text embedded in `tests/device/e1/fixtures.cjs` and the owner-ruling commit message, not the M7/M7R manifests or `PM-INTERFACE-FREEZE` in `C:\Users\Aryan\Desktop\codellm\cbhr-rdc`. I did not open the governance repo.
3. **Whether the owner ruling of 2026-10-22 and the amended V24T15 plan are admissible to the Governor.** That is a policy ruling, not a code fact. The amendment is recorded and honest; its authority is the owner, and it still needs GM ratification.
4. **The product's real behaviour under a genuine revoke/claim contention window.** No such window is constructible under the frozen protocol (0 failed-closed arming attempts in 25 rounds), so this remains unproven by design — exactly as `residualGap.notTested` states. I did not author a new overlap race, because that would be fixing rather than verifying.
5. **The device-side half of the pairing/claim ceremony** (poll channel, local approval prompt, CBHR-RENEW-V1 envelope): these do not exist in the repo, so I could not test them; I only verified that the HTTP layer refuses to fake them.
6. **Production / G0.** Everything ran against the isolated local replica set. Nothing here speaks to production readiness, and G0 remains blocked.

---

## 5. Reproduce everything (exact commands, from the repo root)

```powershell
cd C:\Users\Aryan\Desktop\codellm\librechat-rdc-phase1

# claim 1 — full fixture suite (raw JSON, not the summary line)
node tests/device/e1/run-e1.cjs --fixture=all --result-out tests/device/_phase1_evidence/r3-final/t6-e1-run-all.json   # exit 0

# claim 3a — real failing assertion, no tracked file edited
node --require ./tests/device/_phase1_evidence/r3-final/probe-fail-inject.cjs `
  tests/device/e1/run-e1.cjs --fixture=E2-V24T15-REVOKE-VS-CLAIM-RACE `
  --result-out tests/device/_phase1_evidence/r3-final/t6-failinject-v24t15.json                                        # exit 5, PRODUCT_FAIL

# claim 3b — aggregate blocked-evidence / fabrication gate
node tests/device/_phase1_evidence/r3-final/probe-gate.cjs                                                             # 4/4, exit 0

# claim 3c — T5's own masking probe at HEAD (previously confirmed masking)
node tests/device/_phase1_evidence/r3-verify/probe-t5-masking.cjs                                                      # maskingConfirmed:false, exit 0

# claim 4 — two-process races, single runs
node tests/device/e1/run-e1.cjs --fixture=E2-T7-ONEPC-TWO-PC-RACE   --result-out tests/device/_phase1_evidence/r3-final/t6-single-t7.json   # exit 0
node tests/device/e1/run-e1.cjs --fixture=E2-T8-TWO-OWNERS-ONE-PC-RACE --result-out tests/device/_phase1_evidence/r3-final/t6-single-t8.json # exit 0

# claim 5 — router auth ordering, real router bytes
node tests/device/_phase1_evidence/r3-final/probe-router-auth.cjs --out tests/device/_phase1_evidence/r3-final/t6-router-auth.json   # 5/5

# claim 5 — real frozen models + real Mongo: injection/leakage/48h/margin/LP-2
node tests/device/_phase1_evidence/r3-final/probe-http-real.cjs --out tests/device/_phase1_evidence/r3-final/t6-http-real.json        # 28/28

# claim 5 — concurrent renewal keeps the CAS
node tests/device/_phase1_evidence/r3-final/probe-renew-race.cjs --out tests/device/_phase1_evidence/r3-final/t6-renew-race.json     # 5/5

# claim 5 — Jest
npx jest api/server/routes/__tests__/devices.spec.js                                                                   # 68/68

# claim 6 — Node suite (correct flag; the task text's flag is a typo, see NOTE-1)
node --test --experimental-test-isolation=none --test-concurrency=1 --test-timeout=900000 tests/device/e1/suite.test.cjs  # 20/20

# claim 7 — namespace before/after
node tests/device/_phase1_evidence/r3-final/probe-namespace.cjs before tests/device/_phase1_evidence/r3-final/namespace-before.json
node tests/device/_phase1_evidence/r3-final/probe-namespace.cjs after  tests/device/_phase1_evidence/r3-final/namespace-after.json
```

Evidence in `tests/device/_phase1_evidence/r3-final/`: `t6-e1-run-all.json` (+ `.stdout/.stderr/.exit`), `t6-single-t7.json`, `t6-single-t8.json`, `t6-failinject-v24t15.json` (+ logs/exit), `probe-gate.cjs`/`.log`/`.exit.txt`, `t6-t5masking-rerun.log`, `t6-leak-rerun.log`, `probe-http-real.cjs`/`t6-http-real.json`/`.log`, `probe-router-auth.cjs`/`t6-router-auth.json`/`.log`, `probe-renew-race.cjs`/`t6-renew-race.json`/`.log`, `t6-jest.stdout.log`/`t6-jest.stderr.log`, `t6-node-suite.stdout.log`/`.stderr.log`/`.exit.txt`, `probe-fail-inject.cjs`, `probe-namespace.cjs`, `namespace-before.json`, `namespace-after.json`, `T6-FINAL-VERDICT.md`.

---

## 6. Final verdict

**`READY_FOR_GM_REVIEW`**

All seven claims are **CONFIRMED** from independently re-run evidence. The two historical failure modes are genuinely closed, not merely re-labelled:

- **Masking is gone.** The V24T15 fixture returns the computed status unchanged, so a real assertion failure produces `PRODUCT_FAIL` / exit 5 (proved by injecting one genuine failing assertion from outside the tracked tree, and by T5's own masking probe flipping from "masking confirmed" to "maskingConfirmed:false"). The aggregate gate now also rejects an unevidenced blocked report with `HARNESS_FAIL`.
- **The amendment is honest.** The plan records `amended.at/authority/rationale/supersedes`, asserts only the reachable sequenced law, and discloses the unreachable contention property as `residualGap.notTested` with run-derived measurements — it does not claim it as tested.
- **Nothing else broke.** 12/12 product fixtures and 5/5 controls pass from real product writes against real Mongo; E2-T7/T8 remain genuine 50-attempt two-process races with one winner and one active row and no leaked `residualGap`; the new endpoints put `requireJwtAuth` ahead of all six routes, reject every identity-injection channel with 400 before any model call, never persist or log the plaintext code, project only a whitelist status, keep the frozen 48 h/5 s-margin CAS under concurrency, and leave approve unable to escalate authority; Jest is 68/68 with the original cases byte-identical; the Node suite is 20/20; the Mongo namespace is byte-identical before and after.

The two disclosed scope limits (MINOR-1 session-only renewal authorization, MINOR-2 approve stopping at LP-2) are honest and correctly flagged in-code, and they must be treated as **open items for any promotion beyond the local lab** — they are not defects in what was built, but they are also not solved. The GM still owes the V24-T15 ratification and a decision on the renewal-envelope and claim-leg work; those are precisely the items this gate surfaces rather than hides. Production G0 remains blocked.
