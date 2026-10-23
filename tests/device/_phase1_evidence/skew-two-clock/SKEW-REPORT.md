# Two-clock skew fixture — observed result (Part A)

Fixture: `tests/device/e1/skew/**` — **new files only** (`skew-constants.cjs`, `writer-child.cjs`, `fixture-skew.cjs`, `run-skew.cjs`). No existing fixture, product byte or `package.json` was edited.
Reference counterexample: `C:/Users/Aryan/Desktop/codellm/cbhr-rdc/evidence/gate-closure-002/reviews/H01-authorization-concurrency.md`, finding **F-H01-4** (and the F-H01-1 claim-chain dislodge predicate).
Substrate: real MongoDB `mongodb://127.0.0.1:27027/?directConnection=true&replicaSet=cbhrRdcP1` — replica set `cbhrRdcP1`, server `7.0.43`, driver `6.21.0`, node `v22.19.0`, writable primary. HEAD `572a9875df51727b5757f5aec82797fd8de6d1fb`.
Command: `node tests/device/e1/skew/run-skew.cjs --fixture=all --evidence-dir=tests/device/_phase1_evidence/skew-two-clock` → **exit 5** (`PRODUCT_FAIL`: the asserted desired law was violated — see §6). Raw stdout is in `SKEW-STDOUT.json`.

## 1. Design

Two **real, independent OS processes** act as Mongo-side lease-state writers on the **same** database, each with a **different injected clock offset**:

| writer | injected `clock.now()` | role |
|---|---|---|
| `CORRECT` | `TRUE_NOW` (offset `0`) | reference timeline / control arm |
| `OFFSET` | `TRUE_NOW + Δ` (fast, `Δ = +300000 ms`) or `TRUE_NOW − Δ` (slow) | the skewed writer / treatment arm |

`TRUE_NOW = 1791000000000` (the harness's frozen injected-clock base). No wall-clock value enters any lease decision or assertion: both clocks are injected and deterministic, and every row is seeded with an expiry **relative to the reference timeline** (`expiresAt = TRUE_NOW + ε`, `ε = 1000 ms` for the boundary rows), so "wall-clock-live" is true by construction.

Sequence per fixture:

1. Parent seeds real `deviceauthorities` rows (raw driver, `{w:'majority', j:true}`), one active lease per seed owner (satisfies `uq_owner_active`), `epoch: 1`, `expiresAt = TRUE_NOW + ε`.
2. Parent spawns both writers (`stdio: ['ignore','ignore',logFd]`; piped child stdio is EPERM in this sandbox). Both publish `ready-<role>.json`, then wait for `go-<role>.json` — a **file barrier**, so both processes are armed before either acts.
3. `CORRECT` is released first from the pristine preimage; its refusal changes no row (asserted), so the `OFFSET` writer then acts on the **identical preimage**.
4. Each writer executes the shared plan through **product bytes only** (`createAuthorityService(...)` / `createPairingSessionService(...)` over the frozen `createModels(mongoose)` registry, `ctx.clock.set(TRUE_NOW + offset)`), and the parent independently re-reads every row with the real model.

The plan is data, not code: `{probeId, kind, expiresAtMs, seedOwnerId, claimantOwnerId, expectedEpoch, grantId}`. The probe kinds are exactly the Mongo-side write sites that decide lease state:

| probe kind | product call | predicate that consumes the writer's own clock |
|---|---|---|
| `claimAuthority` | `claimAuthority({expectedEpoch:1,…})` | `$or:[…, {leaseState:'active', expiresAt:{$lte: now − 5000}}]` — the F-H01-1 step-5 dislodge predicate |
| `releaseLapsedLease` | `releaseLapsedLease({deviceId})` | `{leaseState:'active', expiresAt:{$lte: now − 5000}}` |
| `renewAuthority` | `renewAuthority({epoch:1, grantId, proofInput})` | `{…, expiresAt:{$gt: now + 5000}}` |
| `pairingCeremony` | `mintPairingOpenChallenge → issuePairingSession → redeemPairingCode → mintPairingClaimChallenge → approvePairingClaim` | `isLiveLease` / `isLapsedLease(authority, now)` plus the claim CAS |

Two assertion ledgers are kept strictly apart:

* **GATE** (must pass, else `HARNESS_FAIL`): two distinct real OS PIDs, both barrier-armed, every probe executed, no child fatal.
* **LAW** (allowed to fail — a failure **is** the finding): a lease live on the reference timeline must not be transitioned/renewed by a skewed writer; the `CORRECT` writer must be observed refusing the same lease (proving the preimage really was live).

Fixtures: `SKEW-01-FAST-WRITER-OVER-RELEASE`, `SKEW-02-SLOW-WRITER-PAST-EXPIRY-RENEWAL`, `SKEW-03-BOUNDARY-SWEEP` (remaining-life grid `{1000, 100000, 200000, 294999, 295000, 295001, 300000, 300001}` to locate the horizon empirically).

## 2. Gate evidence (all three fixtures)

| fixture | distinct OS PIDs | barrier | clock values | probes | exits | gate |
|---|---|---|---|---|---|---|
| SKEW-01 | 2 | both `true` | `1791000000000` / `1791000300000` | 3 / 3 | 0, 0 | **8/8 PASS** |
| SKEW-02 | 2 | both `true` | `1791000000000` / `1790999700000` | 2 / 2 | 0, 0 | **8/8 PASS** |
| SKEW-03 | 2 | both `true` | `1791000000000` / `1791000300000` | 8 / 8 | 0, 0 | **8/8 PASS** |

The PIDs themselves are in each fixture's `writers.CORRECT.pid` / `writers.OFFSET.pid`, in `processEvidence.spawnCommands`, and in the raw `ready-<role>.json` barrier files; the spawned PIDs are asserted equal to the PIDs the children report. They differ per run by construction (each run spawns fresh processes).

Each fixture ran in its own database and dropped it in `finally`:

| fixture | database |
|---|---|
| SKEW-01 | `cbhr_rdc_phase1_w3_skew_s01_<rand>_<stamp>` |
| SKEW-02 | `cbhr_rdc_phase1_w3_skew_s02_<rand>_<stamp>` |
| SKEW-03 | `cbhr_rdc_phase1_w3_skew_s03_<rand>_<stamp>` |

Namespace audit: `before == after`, `created:[]`, `removed:[]`, `leftoverOwnDatabases:[]`, `foreignAfter:[]`, `ok:true` (`SKEW-NAMESPACE-BEFORE.json` / `SKEW-NAMESPACE-AFTER.json`).

## 3. Observed trace — SKEW-01 (fast writer, `Δ = +300000 ms`)

Seed preimage for all three probes: `leaseState:'active'`, `epoch:1`, `expiresAt = 1791000001000` (`2026-10-03T04:00:01.000Z`) ⇒ **live by 1000 ms** on the reference timeline.

### P1 — `claimAuthority` (the F-H01-1 step-5 dislodge predicate)

| writer | CAS filter actually sent to `deviceauthorities` | matched | outcome |
|---|---|---|---|
| CORRECT | `{_id:'skew-s01-device-1', tenantId, identityState:{$ne:'retired'}, epoch:1, $or:[{leaseState:{$in:['never','expired','revoked']}},{leaseState:'active',expiresAt:{$lte:'2026-10-03T03:59:55.000Z'}}]}` | **0** | `DEVICE_ALREADY_PAIRED_USE_RENEW` |
| OFFSET | identical filter except `expiresAt:{$lte:'2026-10-03T04:04:55.000Z'}` | **1** | claim **committed** |

Committed state: `epoch 1→2`, `ownerId 'principal-skew-seed-s01-1' → 'principal-skew-claim-s01-1'`, `prevOwner/prevEpoch = seed owner / 1`, `activatedAt = 1791000300000` (= `TRUE_NOW + Δ`), `expiresAt = 1791173100000` (48 h from the **skewed** clock), fresh 22-char `grantId`, `ttlMs = 172800000`.
Account axis: `active` rows for `principal-skew-seed-s01-1`: **1 → 0** (the `uq_owner_active` slot was freed).

### P2 — `releaseLapsedLease`

| writer | filter | matched | resulting `leaseState` |
|---|---|---|---|
| CORRECT | `{_id, tenantId, leaseState:'active', expiresAt:{$lte:'2026-10-03T03:59:55.000Z'}}` | **0** | `active` (untouched) |
| OFFSET | `{…, expiresAt:{$lte:'2026-10-03T04:04:55.000Z'}}` | **1** | `active → expired`, `epoch 1→2` |

Account axis: `active` rows for `principal-skew-seed-s01-2`: **1 → 0**.

### P3 — full real pairing ceremony on a live lease

| writer | mint-open | issue | redeem | mint-claim | approve | code minted |
|---|---|---|---|---|---|---|
| CORRECT | ok | **`DEVICE_ALREADY_PAIRED_USE_RENEW`** | — | — | — | no |
| OFFSET | ok | **ok (6-digit code issued)** | ok | ok | ok | **yes** |

The OFFSET writer's two authority writes for this probe, in order, both `matchedCount:1`:

1. `{_id:'skew-s01-device-3', tenantId, leaseState:'active', expiresAt:{$lte:'2026-10-03T04:04:55.000Z'}}` → `active → expired`, `epoch 1→2`;
2. `{_id:'skew-s01-device-3', tenantId, identityState:{$ne:'retired'}, epoch:2, $or:[…,{leaseState:'active',expiresAt:{$lte:'2026-10-03T04:04:55.000Z'}}]}` → claim, `epoch 2→3`.

Final row: `epoch 3`, `ownerId 'principal-skew-claim-s01-3'`, `prevOwner 'principal-skew-seed-s01-3'`, `expiresAt 1791173100000`. Account axis: `principal-skew-seed-s01-3` **1 → 0**.

**Net for SKEW-01: 3/3 live leases transitioned, 3/3 accounts freed.** (`SKEW-CAVEATS.md` records what this does *not* claim.)

## 4. Observed trace — SKEW-02 (slow writer, `Δ = −300000 ms`)

### P1 — `renewAuthority` on a lease expired by 1000 ms on the reference timeline (`expiresAt = 1790999999000`)

| writer | filter | matched | outcome |
|---|---|---|---|
| CORRECT | `{…, epoch:1, grantId:'skew-grant-s02-1', expiresAt:{$gt:'2026-10-03T04:00:05.000Z'}}` | **0** | `LEASE_EXPIRED` |
| OFFSET | `{…, expiresAt:{$gt:'2026-10-03T03:55:05.000Z'}}` | **1** | renewal **committed** |

Committed state: `expiresAt 1790999999000 → 1791172500000`, i.e. exactly `(TRUE_NOW − Δ) + 48 h` — 48 h measured on the **skewed** clock, which is **172 500 000 ms after `TRUE_NOW`** and **172 501 000 ms after the lease's true expiry**; `epoch 1→2`, new 22-char `grantId`. The row was re-armed as live for a further 172 500 000 ms on the reference timeline, although the renewal landed **after** true expiry — contrary to "manual approved renewal strictly before expiry".

### P2 — control: slow-writer claim on a live lease (`ε = +1000 ms`)

`CORRECT` and `OFFSET` both matched **0** (`DEVICE_ALREADY_PAIRED_USE_RENEW`): a *slow* writer does **not** over-release on the claim axis. This asymmetry confirms the treatment arm measures the clock offset, not the fixture.

## 5. Observed trace — SKEW-03 (empirical over-release horizon)

Fast writer (`Δ = +300000 ms`), claim CAS, one row per grid point:

| reference remaining life (ms) | OFFSET matched | OFFSET error | live on reference timeline | over-released |
|---|---|---|---|---|
| 1 000 | 1 | — | yes | **yes** |
| 100 000 | 1 | — | yes | **yes** |
| 200 000 | 1 | — | yes | **yes** |
| 294 999 | 1 | — | yes | **yes** |
| **295 000** | **1** | — | yes | **yes** |
| 295 001 | 0 | `PAIRING_WINDOW_TOO_EARLY` | yes | no |
| 300 000 | 0 | `PAIRING_WINDOW_TOO_EARLY` | yes | no |
| 300 001 | 0 | `DEVICE_ALREADY_PAIRED_USE_RENEW` | yes | no |

Measured horizon: **295 000 ms = Δ − SKEW_MARGIN (300000 − 5000)**, exactly as predicted; the refused side begins at horizon + 1 ms. Every over-released row was claimed by the offset writer (`epoch 1→2`, owner replaced, `activatedAt = 1791000300000`) and every corresponding seed owner lost its active row.

The two distinct refusals above the horizon are the product's own triage of the `[expiresAt, expiresAt+5000)` dead zone: the CAS `expiresAt ≤ now−5000` misses, and `classifyClaimMiss` returns `PAIRING_WINDOW_TOO_EARLY` while `expiresAt > now−5000`; once `expiresAt > now` the earlier ceremony step refuses with `DEVICE_ALREADY_PAIRED_USE_RENEW`.

Reproducibility control: the same fixture was re-run independently and produced the identical grid and horizon (`SKEW-RESULTS-S03-RERUN.json`, `measuredOverReleaseHorizonMs = 295000`; its nested bundle was pruned and its full content is embedded in that JSON file).

## 6. Finding

**The H01 counterexample reproduces.** `finding.counterexampleReproduced: true` and `status: PRODUCT_FAIL` for all three fixtures; the artifact records the exact numbers above rather than a weakened assertion.

Mechanism, precisely:

1. Every lease-state decision is evaluated **inside MongoDB** against `new Date(now ± SKEW_MARGIN_MS)`, where `now` is **the writer's own injected clock** (`authorityService.js` `buildClaimFilter`, `releaseLapsedLeaseImpl`, `renewAuthorityImpl`; `pairingSessionService.js` `isLiveLease`, `isLapsedLease`).
2. Nothing in the frozen contract pins that clock. R9/GM-16 pins endpoint ±60 s, relay ±120 s and a 5000 ms inter-host budget for the **transport** and is silent about the Mongo-side writers, so an arbitrary offset is a legal writer configuration.
3. A writer fast by `Δ` evaluates the lapsed predicate at `now + Δ`, so the dislodge/release predicate matches a still-live lease as soon as `expiresAt ≤ TRUE_NOW + Δ − 5000` — up to **Δ − SKEW_MARGIN = 295 000 ms** of remaining life early. This is **measured**, not assumed (§5).
4. Because the write is an `updateOne` on the whole row (aggregation-pipeline form: `leaseState`, `ownerId`, `epoch`, `expiresAt`, `grantId` in one commit), the over-release is a **committed** transition: the still-live lease becomes `expired`, the epoch advances, the `uq_owner_active` slot is freed, and on the claim path a different owner is installed with a fresh 48 h lease. The displaced endpoint dies on its next frame (`LEASE_EPOCH_STALE`) although its lease still had 4 m 55 s of wall-clock life.
5. Symmetrically, a writer slow by `Δ` evaluates `expiresAt > now + Δ + 5000` with `now` too small, so it accepts a renewal for a lease that expired up to `Δ − 5000` ms ago and re-arms it for a further 48 h measured from its own (slow) clock — observed expiry `1791172500000`, 172 501 000 ms past the lease's true expiry (§4).
6. Cardinality is **not** broken: never two `active` rows for one device and never two live leases for one account. The defect is over-release / over-acceptance — availability and law-conformance, not double-grant.

No product byte was changed and no assertion weakened. The corrective boundary (pin a clock authority / max acceptable skew for lease-state writers, reject writes from stale-clock writers, or derive expiry decisions from a server-asserted time) is a **GM decision**, not this fixture's.

## 7. Files

| file | content |
|---|---|
| `SKEW-RESULTS.json` | full aggregate (per-fixture reports, checks, over-releases) |
| `SKEW-REPORT.md` | this report |
| `SKEW-CAVEATS.md` | explicit limits of what the fixture does **not** claim |
| `SKEW-RUN-META.json` | command, HEAD, node, Mongo topology, product-source hashes, constants |
| `SKEW-NAMESPACE-BEFORE.json` / `SKEW-NAMESPACE-AFTER.json` | server namespace audit |
| `SKEW-FILE-HASHES.json` | SHA-256 of every artifact |
| `SKEW-STDOUT.json` | raw aggregate exactly as the runner emitted it |
| `SKEW-RESULTS-S03-RERUN.json` | independent re-run of SKEW-03 (determinism control) |
| `artifacts/SKEW-0x-….json` | one report per fixture |
| `tests/device/_phase1_evidence/w3/I11-runs/skew-cert/skew/<fixture>/barrier/` | the raw ready/go/out barrier files with the writer PIDs |