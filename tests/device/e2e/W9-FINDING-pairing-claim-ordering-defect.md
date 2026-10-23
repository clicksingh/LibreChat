# W9 finding — the local-lab ORDERING DEFECT on the pairing-claim leg

**Status: CONFIRMED, reproduced with product bytes, NOT fixed (W9 write scope excludes `api/**`).**
Production G0 remains BLOCKED. Nothing was deployed, committed or pushed.

## 1. What happens

The real local backend cannot complete the pairing ceremony's **claim leg**. Every genuine attempt
ends:

```
POST /api/devices/pairing/complete  ->  400 ENDPOINT_CONSENT_REQUIRED
  "Local-endpoint approval is stale or not bound to trusted session truth"
```

This is not a harness artefact: it reproduces with **direct calls to the accepted
`pairingSessionService`**, with no HTTP, no router and no harness fixture in the path.

## 2. The exact cause (exactly one conjunct)

`api/server/services/Device/pairingSessionService.js`, `requireLocalConsent`:

```js
const bound =
  ...
  approvedAt !== null &&
  openedAt !== null &&
  expiresAt !== null &&
  approvedAt >= openedAt &&
  approvedAt <= now &&          // <-- this one is false
  approvedAt < expiresAt;
```

* `now` is captured **at the start of the whole claim operation**
  (`approvePairingClaimImpl`: `const now = currentTime();`, i.e. *before* the device PoP is read,
  verified, and before the consent verifier runs).
* `approvedAt` is produced **later**, by the route's own consent verifier
  (`pairingCompleteHttpHandler.createEndpointSignatureConsent`: `const approvedAt = clock.now();`).

On any real wall clock, `approvedAt > now` — the operation cannot take zero or negative time. The
conjunct is therefore unsatisfiable by construction, and the claim fails closed every time.

Measured, from the repro's own inserted log line (read-only; no value or branch altered):

```
[LAW] {"nonceHashOk":true,"tenantOk":true,"ownerOk":true,"deviceOk":true,
       "sessionOk":true,"challengeOk":true,
       "approvedAt":1792797388589,"openedAt":1792797388376,"expiresAt":1792797688252,
       "now":1792797388582,
       "geOpened":true,"leNow":false,"ltExpires":true}
```

Six of six binding conjuncts pass, the two lifetime comparisons pass, and `approvedAt <= now` is the
only false one. `approvedAt - now = +7 ms`.

## 3. Why the accepted route suite does not catch it

`api/server/routes/__tests__/devices.spec.js` injects a **frozen clock**
(`clock = { now: () => currentNow }`, `BASE_NOW = 1792000000000`). Under a frozen clock
`approvedAt === now`, so `approvedAt <= now` holds and the test passes. The suite is green
(`14 passed` for the claim tests) and would stay green with the defect present. The defect exists only
**on a real clock**, which is exactly what this harness supplies.

## 4. Reproduction (two commands, real MongoDB, no writes)

```powershell
cd C:\Users\Aryan\Desktop\codellm\librechat-rdc-phase1
node tests/device/e2e/_repro-claim-law.cjs     # source-level: prints the [LAW] conjunct line
node tests/device/e2e/_repro-claim-leg.cjs     # service-level: prints the refusal envelope
```

Both create their own `cbhr_rdc_phase1_e2e_law_*` / `cbhr_rdc_phase1_e2e_repro_*` database, print
their evidence to stdout, and DROP the database before exiting. The product file is never written to:
the instrumented bytes in the source-level repro live only in memory.

## 5. Impact, stated narrowly

* **Reachability, and it is TIMING-DEPENDENT.** `POST /api/devices/pairing/complete` (the
  device-authenticated claim) succeeds only when `approvedAt` lands on the same millisecond as the
  operation's start `now`. Across the runs recorded while building this harness it mostly did not:
  the ranges observed were `+7 ms` (source-level repro) and roughly `+40…+220 ms` (real HTTP runs,
  where the device PoP and consent work take longer). It is therefore **not a deterministic
  failure** — the claim succeeds sometimes — and a green run is not evidence that the constraint is
  sound. A reviewer should treat the constraint as unsound on its face, because nothing in the
  operation bounds the elapsed time to zero.
* **Fail-closed, not fail-open.** When it does refuse, nothing is mis-granted: no lease, no grantId, no
  epoch increment. The device stays `leaseState:'never'`, and the refusal is honest.
* **Consequence for W9.** When the refusal happens, there is no `grantId`/`epoch` to sign into a
  `CBHR-RPC-V2` command frame, so the whole downstream loop (dispatch → execute → result → correlated
  outcome) is unreachable through the real pairing path.
* **Not a harness workaround.** The W9 harness does not bypass this. It records the refusal, then
  continues in a disclosed workaround mode (below) purely so the REST of the loop can be proven; the
  workaround is labelled in the evidence and in the per-step ledger.

## 6. The workaround mode, and why it is honest

With `--defect-claim-clock-freeze`, the harness freezes `Date.now()` for the duration of the single
claim request. That makes `approvedAt === now`, which is precisely the condition the accepted route
suite already relies on. Everything else is unchanged: the same route, the same service, the same
binding law, the same database-time (`$$NOW`) predicates.

This is disclosed as a workaround, it is not the default, and it is not offered as evidence that the
claim leg works. The defect is reported for whoever owns `pairingSessionService.js`. When the harness
lands on the timing window by itself, it does not use the freeze and says so
(`receivedWaiver`/`WorkaroundUsed` stay `null` in the step evidence).

## 7. The one-line shape of a fix (NOT applied here)

`now` must be read where the decision is made, not at operation start — for example by re-reading
`currentTime()` inside `requireLocalConsent` and using that value for the `approvedAt <= now`
comparison. The ruling on which timestamp is authoritative is a product decision, so W9 reports it
rather than choosing.

## 8. Run-by-run record (why "timing-dependent" is the right word)

| run | path | claim result | delta `approvedAt - now` |
|---|---|---|---|
| `_repro-claim-law.cjs` | direct service call, no HTTP | `ENDPOINT_CONSENT_REQUIRED` | `+7 ms` |
| 2026-10-23 full harness, run `…232040_c9bc9f` | real HTTP | `ENDPOINT_CONSENT_REQUIRED` | not recorded |
| 2026-10-23 full harness, run `…232335_789166` | real HTTP | `ENDPOINT_CONSENT_REQUIRED` | not recorded |
| 2026-10-23 full harness, run `…232753_a10314` | real HTTP | **`active`** — landed inside the window | `0 ms` (same millisecond) |

The last row is why this document does not say "always fails": it says the constraint is
unsatisfiable *in general* and that a green run is luck, not soundness.