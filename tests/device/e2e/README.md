# W9 — local end-to-end harness (pair → dispatch → execute → result → correlated outcome)

Commission `PHASE1-LOCAL-AUTHORITY-001` (GM-72 / GM-73 / GM-80). **LOCAL ONLY: no deploy, no Cloudflare,
no commit.** Production G0 remains BLOCKED.

## The single command

```powershell
cd C:\Users\Aryan\Desktop\codellm\librechat-rdc-phase1
node tests/device/e2e/run-e2e.cjs
```

Exit 0 = every step passed. Evidence goes to
`tests/device/_phase1_evidence/e2e/e2e-<runId>.{json,log}` and the per-step ledger is printed.

`node tests/device/e2e/run-e2e.cjs --defect-claim-clock-freeze` additionally runs the loop past the
**confirmed product defect** documented in `W9-FINDING-pairing-claim-ordering-defect.md`. Read that
file before using the flag: the flag is a disclosed workaround, not a fix, and it is not evidence that
the claim leg works.

## What is real at each step

| # | Step | What is real |
|---|---|---|
| S1 | preflight | `node.exe` process list (GM-71), MongoDB handshake and version pin, every artifact path |
| S2 | backend | the REAL `api/server/routes/devices.js` router on a real HTTP server, real `requireJwtAuth` + real passport `jwt` strategy, the real `createModels(mongoose)` registry, real MongoDB |
| S2b | auth control | an unauthenticated gated route is refused by that real chain (401), so the gate is mounted rather than bypassed |
| S3 | relay | the relay's OWN built artifact (`cbhr-rdc/apps/cbhr-relay/dist/worker.js`) in-process via Miniflare, with the compatibility config parsed from `wrangler.toml` |
| S4 | endpoint | the REAL `apps/cbhr-endpoint-agent/run-agent.js` as a child process, key store outside the repo |
| S5 | registration | a real `User` row, a real bearer JWT, the real registration ceremony (server mints the device id; the agent adopts it without regenerating its key) |
| S5b | database time | the GM-44 `$$NOW` server clock is measurable before any lease/TTL decision |
| S6 | pairing | five real HTTP legs: challenge → issue (6-digit code) → approve → complete(arm) → complete(claim), ending in a real 48 h lease |
| S7 | dispatch | the REAL `relayDispatchClient.dispatchCommand`, the real `envelopeSigner` over injected custody, the durable Mongo dispatch ledger, a transport that posts into the relay's own `/frame` admission |
| S8 | execute | the agent verifies the frame and reads a REAL file at a REAL path inside its containment root; the result frame is signed by the agent process |
| S9 | result | `{t:'result', callId, payload}` over the real device socket → the relay's outbox → `resultSink.ingestResult` → correlated outcome + ledger state |
| N1 | negative | a frame tampered after signing: refused, nothing runs, never reported as success |
| N2 | negative | a result for an unknown `callId`: refused, nothing stored |
| N3 | negative | a tool outside the server ceiling, judged by the production `deviceToolRegistry.authorizeDispatch` |
| S10 | after | a SEPARATE process re-reads the durable ledger and cannot complete the call twice |
| S11 | final ledger | the platform's own durable record of every call in the run |
| S12 | cleanup | the harness database is dropped and no harness-prefixed database remains |

## Two disclosed substitutions (both named in the evidence)

1. **`~/db/models` adapter** (`models-adapter.cjs`). The accepted `Device/**` factories require
   `typeof db.DeviceAuthority === 'object'`, while a genuine Mongoose Model is a FUNCTION. The adapter
   is a behaviour-free plain-object surface forwarding every call to the genuine model, and it wraps
   the SAME registry the router uses. Its `aggregate` goes to the driver's collection handle, because
   the tenant-isolation plugin prepends a `$match` that makes the accepted `$collStats` time read throw.
2. **pairing pepper seam** (`device-http-trust-seam.cjs`). `routes/devices.js` constructs the pairing
   handlers with no `pepperLookup`, so the ceremony fails closed. The seam supplies the server-owned
   pepper the deployment config would supply, exactly as the accepted route suite does through its own
   module mock.

## Reproductions for the finding

```powershell
node tests/device/e2e/_repro-claim-law.cjs   # source-level: prints the binding law's conjuncts
```

Creates and drops its own `cbhr_rdc_phase1_e2e_law_*` database and never writes to a product file
(the instrumented bytes live in memory only).

## Layout

```
run-e2e.cjs                       the single runner (one command, exit 0 on success)
env.cjs                           alias/model/pepper substitution, HTTP boot, namespace helpers
relay.cjs                         the real relay from the sibling checkout, booted in-process
mongo-seams.cjs                   durable dispatch-ledger and result stores over real MongoDB
models-adapter.cjs                the disclosed `~/db/models` surface
device-http-trust-seam.cjs        the disclosed server-owned pepper seam
verify-state.cjs                  the separate-process re-read of the durable ledger
_repro-claim-law.cjs              source-level reproduction of the claim-leg defect
W9-FINDING-pairing-claim-ordering-defect.md   the defect, its cause, its reproduction
```

## Environment requirements

* the frozen local MongoDB (`mongodb://127.0.0.1:27027/?directConnection=true&replicaSet=cbhrRdcP1`,
  database prefix `cbhr_rdc_phase1_`; the harness creates and drops its own `cbhr_rdc_phase1_e2e_*`)
* the sibling relay checkout at `../cbhr-rdc/apps/cbhr-relay` with `dist/worker.js` built
  (override with `CBHR_RELAY_ROOT`)
* the endpoint agent's own key store outside the repo (`~/.cbhr/e2e-<runId>`)
* **no other lane may be running** (GM-71): the harness itself refuses to start when a matching
  process is found