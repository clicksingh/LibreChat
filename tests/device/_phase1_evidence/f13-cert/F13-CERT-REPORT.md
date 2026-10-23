# Fresh F13 two-OS-process certification (Part B)

Runner: `tests/device/e1/f13-cert/**` — **new files only** (`run-f13-cert.cjs`, `f13-law.cjs`, `f13-law-child.cjs`). No existing fixture was edited or weakened; no product byte and no `package.json` was touched.
Command: `node tests/device/e1/f13-cert/run-f13-cert.cjs` → **exit 5**, aggregate `status: PRODUCT_FAIL`, `counts: {fixtures: 5, harnessFail: 0, productFail: 1, errors: 0}`.
The single product failure is `E2-V24T15-REVOKE-VS-CLAIM-RACE` (an **intermittent** failure of that fixture's amended plan — see §5). Everything else ran clean. The run was **not** re-rolled for a green result; this artifact records what happened.
Substrate: real MongoDB `mongodb://127.0.0.1:27027/?directConnection=true&replicaSet=cbhrRdcP1` — `cbhrRdcP1`, server `7.0.43`, driver `6.21.0`, node `v22.19.0`, writable primary. HEAD `572a9875df51727b5757f5aec82797fd8de6d1fb` (in `F13-CERT-RUN-META.json`, with the SHA-256 of the 7 certified product source files).
Namespace audit: `before == after`, `created:[]`, `removed:[]`, `ownedLeftoversAfter:[]`, `foreignAfter:[]`, `ok:true`.
Runner-internal window: `startedAt 2026-10-23T12:17:11.680Z` → `finishedAt 2026-10-23T12:17:32.333Z` (20.7 s); every round/attempt below is separately durable on disk.

## 1. Outcomes per fixture (this run)

| # | fixture | runner | status | attempts | child PIDs (distinct) | per-fixture checks |
|---|---|---|---|---|---|---|
| 1 | `T0A-01-SESSION-ABA-ISSUE-VS-APPROVE` (F13/F18-A, existing row) | r2a two-process | `EXPECTED_RED` | **50** (A 25 + B 25; `productCallsAttempted: 50`) | 2 — `[61324, 30156]` | 4 `met:true`, 3 `met:false` (oracle components hardcoded `false`) |
| 2 | `F13-LAW-SESSIONVERSION-ABA-TWO-PROCESS` (**new**) | `f13-law.cjs` + `f13-law-child.cjs` | **`PASS`** | **50** (25 issue + 25 approve) | 2 — `[56944, 41604]` | **18/18 pass** |
| 3 | `E2-T7-ONEPC-TWO-PC-RACE` | `product/race.cjs` | **`PASS`** | 50 `casAttempts` / 25 rounds / 2 shards | 2 — `[24824, 50148]` | 13/13 |
| 4 | `E2-T8-TWO-OWNERS-ONE-PC-RACE` | `product/race.cjs` | **`PASS`** | 50 `casAttempts` / 25 rounds / 2 shards | 2 — `[53108, 48068]` | 15/15 |
| 5 | `E2-V24T15-REVOKE-VS-CLAIM-RACE` | `product/race.cjs` | **`PRODUCT_FAIL`** | 50 recorded / **48 `casAttempts`** / 25 rounds / 2 shards | 2 — `[60028, 24856]` | 14/17 |

PID provenance per fixture is machine-extracted into `F13-CERT-RESULTS.json` → `fixtures[].pids` (`reportedChildPids`, `spawnedChildPids`, `distinctOsPids` / `distinctChildPids`, `pidsByRole`) and cross-checked against the per-round barrier files on disk.

Observed outcome detail:

| fixture | outcome |
|---|---|
| T0A-01 | `perChild: [{role A, attempts 25, compositionFailures 0, composedInSomeFactory 25, productCallsAttempted 25, barrierReached true, peerReady true, exit 0}, {role B, …identical…}]` |
| F13 law (new) | 25/25 `issuePairingSession` real calls; 25/25 `approvePairingClaim` `ok:true`, `grantedEpoch 1`; `supersededSessionCount: 0`; all 25 armed sessions `consumed` at `armed+2`; 25/25 devices with exactly one active lease (`epoch 1`, `ttlMs 172800000`) whose `grantedByPairingSessionId` is the armed session |
| E2-T7 | `{MATCHED: 1, ONE_DEVICE_PER_ACCOUNT: 24, PAIRING_CEREMONY_STALE: 25}`, `winnerCount 1`, `activeRowsForOwner 1` |
| E2-T8 | `{MATCHED: 1, PAIRING_CEREMONY_STALE: 49}`, `winnerCount 1`, durable winner == recorded winner, `epoch 1` |
| E2-V24T15 | `{MATCHED: 48, DEVICE_ALREADY_PAIRED_USE_RENEW: 2}` — see §5 |

Per-round durability: 50 ready files + 25 go files + 50 result files for every two-process fixture, e.g. `tests/device/_phase1_evidence/w3/I11-runs/f13-cert/e2-product/E2-T7-ONEPC-TWO-PC-RACE/` and `…/f13-law/`.

## 2. The existing F13 row — reported as observed, with two explicit stale-expectation notes

The existing row runs correctly as a **two-process fixture** (2 distinct real OS PIDs, file barrier credible, 50 genuine product calls now that genuine-model factory composition is accepted) but it **does not evaluate the F13 oracle**: its `components` for `approval_consumes_observed_version_once_or_zero`, `issuance_never_flips_observed_version` and `session_version_fence_present` are hardcoded `met:false` with the text "not executed", and its hardcoded `finding` string still describes pre-repair bytes. The certification records this rather than rewriting it:

1. `sessionVersionSymbol.present = true` — **the anti-ABA fence symbol IS present in the current product bytes** (schema `packages/data-schemas/src/schema/pairingSession.ts`, service `pairingSessionService.js`), while the row's label/narrative still reads pre-repair. The row's narrative is stale relative to HEAD.
2. `productCallsAttempted: 50` — the row is no longer blocked at factory composition, but it still asserts no F13 law, so its `EXPECTED_RED` status carries no F13 information.

Both notes are emitted by the runner into `F13-CERT-RESULTS.json → f13StaleExpectationNotes` (machine-generated from the row's own fields, not hand-written). No existing fixture was edited to fix this.

## 3. New F13 law evaluation (supplements, does not replace, the row)

`F13-LAW-SESSIONVERSION-ABA-TWO-PROCESS` evaluates the frozen law with real ceremonies and a real falsification path:

> F13: sessionVersion monotonically fences transitions; issuance may supersede a state:open session only; an approval that observed version v either consumes v exactly once or 0-matches; issuance never flips the same v after approval has observed it. Two real OS processes, N>=50.

Per round (25 rounds, 2 attempts each = 50 attempts):

1. the parent seeds a claimable device with its **own round owner** (so `uq_owner_active` is never contended) and arms the **real** ceremony through product bytes only until the session is `claim_pending`: `mintPairingOpenChallenge → issuePairingSession → redeemPairingCode → mintPairingClaimChallenge`;
2. one file barrier per round releases both children inside the same window:
   * role A — `issuePairingSession` for the **same** device (a genuine supersede-capable issuance; pre-repair this matched `state $in [open, claim_pending]` and would flip the armed session),
   * role B — `approvePairingClaim` with the armed, real, version-bound claim proof;
3. both children re-read the armed session **before** acting and record `[state, sessionVersion]`; the parent re-reads every session and every authority row afterwards with the real models.

Assertions (18, all passing) include:

| assertion | observed |
|---|---|
| two distinct real OS child PIDs; recorded PIDs == spawned PIDs | 2 |
| both children exited 0 | `[0, 0]` |
| real product attempts ≥ N | 50 (25 issuance + 25 approval) |
| every child observed the armed session at `claim_pending` / the armed version before acting | 50/50 observations (`armedVersion 2`) |
| **F13: no round left a `superseded` session** (issuance never superseded a `claim_pending` session) | 0 |
| **F13: every armed session ends `consumed` with the version strictly advanced** | 25/25 |
| the consume/grant path advances the version by exactly the observed two bumps (no re-consume) | 25/25 (`armed+2`) |
| **F13: the version-bound approval succeeded in every round** (never 0-matched by an issuance) | 25/25 `ok:true` |
| every session row for every device carries a non-negative integer `sessionVersion` | 0 violations |
| every round device holds exactly one active lease owned by its round owner | 25/25 |
| every granted lease is exactly 48 h and epoch 1 (one grant, no re-grant) | 25/25 `[172800000, 1, true]` |
| each grant records the session that granted it | 25/25 |

The issuance leg genuinely creates a second, `open` session for the device in each round (visible in `dbReadBack.sessionsAfter[].sessionsForDevice`: the consumed armed session plus one `open` session at version 0) — i.e. the issuance really ran and really was fenced out of the in-flight claim.

**Falsification path (non-vacuity):** the armed claim challenge binds `boundSessionVersion = v`, so if any writer flips `v` the version-bound challenge lookup 0-matches. A pre-repair supersede therefore produces `state: 'superseded'` + a 0-matched approval, failing the "no superseded session" and "every armed session ends consumed" assertions. The fixture is therefore a genuine F13 regression detector, not a re-labelling of the stale row.

## 4. What the certification establishes about F13

* F13's fence is **present and effective at HEAD** for the evaluated interleaving: 25/25 in-flight `claim_pending` approvals survived a concurrent supersede-capable issuance and consumed exactly once; no session was superseded while non-terminal; every grant is a single epoch-1 48 h lease bound to the consumed session.
* The **existing row** still does not test this; its `EXPECTED_RED`/`met:false` shape is stale and should be re-based by its owner (a fixture change, deliberately **not** made here).
* The 2-process gate (distinct real PIDs, barrier, N ≥ 50) holds for every fixture in this run.

## 5. FINDING (new, honest): `E2-V24T15` is flaky at its amended assertion level

This certification run observed `E2-V24T15-REVOKE-VS-CLAIM-RACE` **failing** — the first time in this session's runs:

* `attempts: {requestedN: 50, rounds: 25, attemptsPerRound: 2, recordedAttempts: 50, casAttempts: 48, shards: 2}`
* `errorHistogram: {MATCHED: 48, DEVICE_ALREADY_PAIRED_USE_RENEW: 2}`
* failed assertions (3): *"real product CAS attempts total >= N"* (`casAttempts 48 < 50`), *"each row commits exactly the two legal CAS transitions in order"* (`23 != 25`), *"each raced row advanced its epoch by exactly 2"* (`23 != 25`).
* Rounds **1 and 2**: shard A `revokeLease` matched 1 (`epoch 1→2`, row now `revoked`), but shard B's `armClaimCeremony` returned `DEVICE_ALREADY_PAIRED_USE_RENEW` with `casAttempted:false` — the ceremony was armed **before** the revoke committed inside the barrier window, so the claim leg never ran for those two rows. Final state of both rows is the legal `revoked`/seed-owner end state; `revokeMatches 25`, `claimMatches 23`, no blind write, no double-grant, no live authorization left for the seeded owner.

Why this is a fixture-level flake rather than a product-law violation:

* The fixture's own plan text already discloses that the original one-CAS contention is unreachable (`residualGap.notTested`) and that the amendment asserts the **sequenced** law; the two deviating rounds are exactly the disclosed pre-revoke arming interleaving, which the amended assertion set nonetheless scores as failure.
* Immediately after the certification run, the same fixture was executed **three times standalone** and passed **17/17 with 50/50 `casAttempts` each time** (`flake/V24T15-STANDALONE-RERUN-{1,2,3}.json`). In this session's runs the fixture passed 5 times and failed once (≈1 in 6) with this exact signature.
* No authority invariant moved: cardinality and fail-closed behaviour are intact in the failing run.

Recorded here rather than fixed: the honest certification statement is **"E2-V24T15 is not a reliably green two-process fixture at its amended assertion level (observed 1 failure in 6 runs; the failing rounds are the disclosed pre-revoke arming interleaving)"**. Making it deterministic is a fixture-plan decision for its owner, not something this certification may paper over.

Post-certification regression check (`REGRESSION-E1-ALL.json`): the untouched e1 suite re-run right after this certification is fully green — `node tests/device/e1/run-e1.cjs --fixture=all` → exit 0, `PASS`, `{total: 17, productFixtures: 12, productBlocked: 0, controls: 5, controlFailures: 0, fabricatedProductPasses: 0, unevidencedBlocked: 0, productFailures: 0}`, namespace clean, with `E2-V24T15` passing 17/17 in that run. So the flake is intermittent, not a standing failure, and nothing this task did changed the existing fixtures.

## 6. Files

| file | content |
|---|---|
| `F13-CERT-RESULTS.json` | aggregate: per-fixture status, PIDs, attempts, outcomes, stale-expectation notes, namespace audit |
| `F13-CERT-REPORT.md` | this report |
| `F13-CERT-CAVEATS.md` | explicit limits of what this certification does not establish |
| `F13-CERT-RUN-META.json` | command, HEAD, node, Mongo topology, SHA-256 of the 7 certified product source files |
| `F13-CERT-NAMESPACE-BEFORE.json` / `F13-CERT-NAMESPACE-AFTER.json` | server namespace audit |
| `F13-CERT-FILE-HASHES.json` | SHA-256 of every artifact (self-excluding) |
| `F13-CERT-STDOUT.json` | raw aggregate exactly as the runner emitted it |
| `artifacts/<fixture>.json` | the fixture's own report, verbatim (5 files) |
| `flake/V24T15-STANDALONE-RERUN-{1,2,3}.json` | three immediate standalone re-runs of the flaky fixture (17/17, 50/50 each) |
| `REGRESSION-E1-ALL.json` | the untouched e1 suite re-run after the certification: `node tests/device/e1/run-e1.cjs --fixture=all` → exit 0, `PASS`, 12/12 product, 5/5 controls, 0 fabricated passes, namespace clean — the existing fixtures (including V24T15) are intact and green |
| `f13-artifacts/T0A-01-SESSION-ABA-ISSUE-VS-APPROVE.json` | the r2a row's artifact, redirected here so no previously recorded evidence file was overwritten |
| `f13-artifacts/…-barrier/{ready,out}-{A,B}.json` | the r2a row's raw barrier files with the two child PIDs |