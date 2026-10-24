# CBHR endpoint agent (W7) — the receiver that makes "the relay cannot forge" complete

**LAB ARTIFACT (GM-73).** This is the endpoint's *logic* on the owner's own machine, built in Node
first so it is testable and so the owner can run a real end-to-end try. It is **not** the employee
deliverable: `D008` still forbids requiring Node for end users, and the Tauri 2 app that will host
this same logic is Phase 3 work. It claims **no graphical control** of any kind.

---

## 1. Why this exists

The relay is keyless by construction — `apps/cbhr-relay/src/capability-guard.js` fails the Durable
Object closed if its runtime can sign at all. That is half of the argument. The other half was missing:
**something on the employee's PC has to refuse a frame the backend did not sign.** Until that exists,
"the relay cannot forge" is a claim about the sender, not about the receiver.

This directory is that half. It receives a flat `CBHR-RPC-V2` frame, verifies it against a **pinned
backend public key**, decides whether the tool is permitted, executes it, and returns a **device-signed**
result frame.

### It does not reuse the backend's verifier

`api/server/services/Device/relay/envelopeVerifier.js` exists and is tested. It is deliberately **not**
imported. An endpoint whose admission logic *is* the sender's own module proves nothing about the
sender: a bug — or a hostile edit — inside `relay/**` would silently move the endpoint's trust
boundary along with it. So the field layout, the encodings, the freshness law, the replay window and
the args cross-check are all implemented here from the frozen contract text
(`evidence/gate-closure-002/v24/V24-C-signed-grants.md` §F-V24C-4, and the GM-29/31/32/34/35/47
rulings).

The only shared piece is the accepted crypto primitive — `canonicalEncode`, `verifyEd25519`,
`thumbprintB64u` from `api/server/services/Device/crypto.js`, reached through `src/vendoredCrypto.js`
(with a `node:crypto` fallback if that tree is absent). The task explicitly permits that reuse, and
sharing the 0x1F *join* is what keeps two implementations from disagreeing about the *bytes*.

And the layout is not taken on trust either: `test/golden.test.js` pins it against the contract's
**published worked example** — the exact 325 canonical bytes and the published Ed25519 signature under
the published fixed-seed key — so if this endpoint's field order, tag or encoding were wrong by one
byte, that signature would not verify. The tests' own frame builder shares no code with `src/layout.js`,
so a spec that passes is evidence two independent readings agree, not that a module agrees with itself.

---

## 2. The verification order — one distinct refusal code per step

Fail closed at the first failure. Nothing executes before step 10 passes.
`run-agent.js describe` prints this table from the code itself.

| # | Check | Refusal code |
|---|---|---|
| 1 | canonical string rebuild: 15 fields, exact order, 0x1F law, well-formed UTF-16, per-field encodings, `deadlineMs ≤ issuedAt + 120 000` | `ENDPOINT_ENVELOPE_SHAPE_INVALID` / `ENDPOINT_FRAME_EXTRA_FIELD` / `ENDPOINT_ENVELOPE_FIELD_NOT_CANONICAL` |
| 2 | Ed25519 signature over those exact bytes against the **pinned** backend key | `ENDPOINT_SIGNATURE_INVALID` |
| 3 | `keyId` names a pinned key (GM-31: unsigned transport metadata, never authority) | `ENDPOINT_KEY_UNPINNED` |
| 4 | `audience === 'endpoint'` (signed, field 14) | `ENDPOINT_AUDIENCE_MISMATCH` |
| 5 | freshness `\|now − issuedAt\| ≤ 60 000` in **both** directions | `ENDPOINT_FRESHNESS_EXPIRED` / `ENDPOINT_FRESHNESS_NOT_YET_VALID` |
| 6 | `now ≤ deadlineMs` (inside the signature: an attacker cannot extend it) | `ENDPOINT_DEADLINE_EXCEEDED` |
| 7 | `deviceId` and `deviceKeyId` name **this** endpoint (F-V24C-5 endpoint checks) | `ENDPOINT_DEVICE_MISMATCH` / `ENDPOINT_DEVICE_KEY_MISMATCH` |
| 8 | durable replay window on `(grantId, nonce)`, persisted before execution is allowed | `ENDPOINT_REPLAY_DETECTED` |
| 9 | **GM-47 / GM-29**: decode `argsB64u`, re-hash **those exact bytes**, require equality with the signed `argsDigestHex`. No canonicalisation anywhere. | `ENDPOINT_ARGS_DIGEST_MISMATCH` |
| 10 | `opKind` admission (this agent executes `command` only) | `ENDPOINT_OPKIND_REFUSED` |

Two ordering notes that are deliberate rather than accidental:

* **Step 3 before step 2.** GM-31 makes `keyId` selection metadata and the contract puts signature
  verification before every other check. Both hold if the label is resolved to a pinned key *first*
  (refusing an unpinned label) and the crypto then runs against that key. A frame naming an unpinned
  key never reaches the crypto call at all, so it cannot probe for a key pinned under another label,
  and a local operator can still tell a rotation mistake from a forgery.
* **Step 8 after the signature, before execution.** A forged or stale frame must not be able to burn a
  nonce and deny the genuine frame that follows. The reservation is made *only* after every earlier
  check passes, and it is written to disk *before* the caller is allowed to execute — so an execution
  can never happen with an unrecorded nonce.

### Why the replay window is durable

GM-34 assigns durable replay authority to the relay's DO ring **and the endpoint's own persisted
window**. The endpoint half matters because an attacker who captures a frame can simply wait for the
agent to restart — an update, a crash, a reboot — and replay it inside the 60 s freshness window. An
in-memory ring cannot survive that, and no in-process test can show the difference.

`test/durability.test.js` therefore spawns a **second real Node process** that verifies the same frame
bytes with a fixed clock: process 1 accepts and writes `replay-window.json`, process 2 refuses with
`ENDPOINT_REPLAY_DETECTED`. The in-memory control (same bytes, no file) accepts the replay, so the test
is not passing vacuously. `replay-window.json` is written with temp-file + fsync + rename, so a crash
leaves the old window or the new one, never a truncated one. A corrupt window **fails closed**
(`ENDPOINT_REPLAY_STORE_UNAVAILABLE`) rather than starting empty.

---

## 3. GM-72 — the device may NARROW, never WIDEN

Effective tool set = **server ceiling ∩ device floor**, in that order of authority.

| Tier | Owner | Where it lives here | Can it widen? |
|---|---|---|---|
| 1. Server ceiling | Governor / GM policy | `config/server-ceiling.json` — a snapshot of the server's own `ceilingForStage()` document (`schema: cbhr.rdc.capability-ceiling/1`, `tier: 1`, `source: 'server'`, `deviceSettable: false`) | **No.** The endpoint never re-derives it |
| 2. Device floor | The employee | `~/.cbhr/endpoint-agent/tools.json` | **No.** A name outside tier 1 makes the whole config invalid |
| 3. Per-call approval | The four approval tools | reported, never assumed | Still approval-gated |

Dispatch refuses in this order, each with its own code:

1. outside the server ceiling → `ENDPOINT_TOOL_OUTSIDE_CEILING` — **even when the device enabled it**
2. inside the ceiling but switched off in `tools.json` → `ENDPOINT_TOOL_NOT_ENABLED_ON_DEVICE`
3. permitted and enabled but not implemented here → `ENDPOINT_TOOL_NOT_IMPLEMENTED`
4. argument shape wrong → `ENDPOINT_TOOL_ARGS_INVALID`

Ceiling-before-floor is the point: a tool outside the ceiling is refused on **tier-1** grounds, so the
answer reads "the server does not permit this", not "you turned it off". The reverse order would let a
hand-edited config masquerade as a permission decision.

A config naming a tool outside the ceiling is **invalid as a whole** (`ENDPOINT_DEVICE_CONFIG_INVALID`),
not silently filtered. GM-72's UX clause requires that a refusal be explained rather than mysterious;
silently dropping an entry would leave the employee seeing a tool as "on" while the platform refuses
it, with nobody able to say which side said no. `run-agent.js tools` prints exactly which side refuses
each name.

The two GM-72 absolutes (`track_ui_event`, `give_feedback_to_desktop_commander`) are refused even if a
snapshot were hand-edited to permit them. That is not a second authority; it is a refusal to act on a
snapshot that contradicts the ruling this endpoint was built under.

`config/server-ceiling.json` is generated by `tools/generate-ceiling-snapshot.cjs` from the **server's**
policy module, and `test/dispatch.test.js` **fails when the committed snapshot and a fresh server call
disagree**, so server policy cannot reach the endpoint without a visible diff.

### The tool set implemented here (deliberately small)

| Tool | Ceiling stage | What it really does |
|---|---|---|
| `list_directory` | A | sorted, paged, truncation reported honestly |
| `read_file` | A | bounded read; UTF-8, or lossless base64 for binary; sha256 of the bytes read |
| `get_file_info` | A | stat + (for a directory) a capped entry count |

Path arguments are resolved **inside a containment root** (`<agent root>/workspace`) and anything that
escapes it — `..`, an absolute path outside, a drive change, a symlink out — is refused with
`ENDPOINT_TOOL_ARGS_INVALID`. The write scope of all three is zero: nothing in this directory creates,
modifies or deletes a file except its own config and state files.

Every other name in the ceiling (the search tools, stage B writes, the process tools, the 26 Desktop
Commander tools) is refused with `ENDPOINT_TOOL_NOT_IMPLEMENTED`. "Inside the ceiling" is not
"implemented here", and that difference must be observable rather than silent.

---

## 4. Result frames

Results are device-signed, `audience:'relay'`, and correlate by `callId`.

```
CBHR-RPC-RESULT-V2 ‖ requestId ‖ callId ‖ nonce ‖ issuedAt ‖ deadlineMs ‖ grantId ‖ epoch ‖
deviceId ‖ deviceKeyId ‖ outcome ‖ sha256(result bytes)
```

**A distinct domain tag, on purpose.** The command string is `CBHR-RPC-V2`; a result is not a command
(different audience, different subject, field 15 binds the *result* bytes). Reusing one tag for two
differently-shaped documents is exactly the "two documents, one domain" ambiguity a tag exists to
prevent, so results carry their own prefix and a result signature can never be presented as a command
signature, or vice versa. The nonce is **fresh** per result — reusing the command's would collide with
the relay's own `(grantId, nonce)` ring.

### The outcome law — the three values are inside the signature

| `outcome` | Meaning |
|---|---|
| `succeeded` | the tool ran; the payload says what it produced |
| `refused` | the endpoint can **prove** nothing ran (a verification failure, or one of the four policy gates) |
| `uncertain` | anything else — an execution whose effect the endpoint cannot prove |

`uncertain` exists so that "I do not know" is never spelled "success". Because `outcome` is inside the
signed bytes, the relay can neither re-label a refusal as a success nor forge one — the platform
verifies with the **device** public key, which the relay does not have.

A refusal raised **before** the core is authentic still carries the frame's *claimed* `requestId` and
`callId`, because the platform has to correlate the refusal with the call it dispatched. The signature
makes the refusal authentic, not the claim, so such a frame records
`correlation: 'unverified-claim'` rather than pretending the correlation was verified.

---

## 5. Key store

| Item | Location | Permission |
|---|---|---|
| Device keypair | `<agent root>/device-key.json` | owner-only (see below) |
| Device identity (`deviceId`) | `<agent root>/device.json` | owner-only |
| Pinned backend keys | `<agent root>/backend-keys.json` | owner-only |
| Device tool config | `<agent root>/tools.json` | owner-only |
| Durable replay window | `<agent root>/replay-window.json` | owner-only |
| Tool containment root | `<agent root>/workspace/` | created on first use |

Default agent root: **`%USERPROFILE%\.cbhr\endpoint-agent`** (POSIX: `$HOME/.cbhr/endpoint-agent`),
overridable with `--root` or `CBHR_ENDPOINT_AGENT_ROOT`. It is **outside any git worktree on purpose**:
a private key inside a repository is one `git add -A` away from being published.

**Permissions, stated honestly.** On POSIX the file is created `0600`, re-asserted with `fchmod`, and a
failure to apply it is a refusal. On Windows `fs` mode is advisory, so `icacls` drops inheritance and
grants one principal — but Windows then re-adds two entries of its own:

```
<owner>:(F)                                we granted this
NT AUTHORITY\SYSTEM:(F)                    Windows re-adds it to every object
NT AUTHORITY\LogonSessionId_0_<id>:(RX)    Windows re-adds the CURRENT LOGON SESSION
```

The third is a SID bound to the logged-on session, so every process in the owner's own session holds
it — including everything the owner starts. It cannot be removed durably, so a module demanding a
literal one-ACE file would simply never succeed. **On this machine it was re-added inconsistently:**
a fresh directory under `%TEMP%` showed three entries, while the real agent root under `%USERPROFILE%`
showed exactly one (`Tech\Aryan:(F)`, no inherited ACE). Because that variation is a property of the
platform rather than of this code, `src/permissions.js` handles both cases the same way: it **refuses
any other principal** (a real second account, `Users`, `Authenticated Users`, `Everyone`, any
unrecognised SID), **refuses any inherited ACE**, and returns the **raw `icacls` text as evidence** so
nobody has to take the classification on trust. The guarantee claimed is exactly: *no account other
than the owner (plus SYSTEM and the owner's own session, where Windows adds them) can read the key
file, and no inherited ACE survives.* The test suite asserts both the refusal (against a synthetic
listing containing `BUILTIN\Users`) and the classification of a real post-restriction listing.

**The real store on this machine** (created by `init`, evidence captured at creation):

```
C:\Users\Aryan\.cbhr\endpoint-agent\device-key.json Tech\Aryan:(F)

Successfully processed 1 files; Failed processing 0 files
```

One principal, no inherited entry, no foreign principal. The private key file is 319 bytes and no file
whose name matches `device-key|backend-keys|replay-window|lab-backend-key` exists anywhere under the
worktree.

**No key material anywhere it can escape.** The private key lives in a closure: `loadDeviceKeystore()`
returns an object whose only key-touching member is `sign(bytes)`, with no accessor, no `toString`, no
enumerable property and no `toJSON`. `test/keystore.test.js` runs the success path and every failure
path with console capture, then asserts that **no 20-character window** of any private-key encoding
(base64, base64url, hex, latin1, PEM body) appears in `JSON.stringify`, `util.inspect` (including
`showHidden`), a deep text flattening, own-property names, thrown errors, `stack`, or the `cause`
chain — the same standard `DeviceError` already meets.

---

## 6. Running it

Everything below runs on the owner's own machine. Nothing leaves it: there is no network call anywhere
in this directory.

```powershell
cd apps/cbhr-endpoint-agent

# 1. the whole test suite (no framework, no new dependency)
node test/run-tests.js

# 2. syntax-check every file (the npm script below is only a convenience wrapper:
#    pnpm was not on PATH in this environment, so the direct command is the one that was verified)
node -e "const fs=require('fs'),p=require('path'),{execFileSync}=require('child_process');const walk=(d)=>fs.readdirSync(d,{withFileTypes:true}).flatMap((e)=>e.name==='node_modules'?[]:e.isDirectory()?walk(p.join(d,e.name)):[p.join(d,e.name)]);const files=walk(process.cwd()).filter((f)=>/\.(js|cjs)$/.test(f));for(const f of files){execFileSync(process.execPath,['--check',f],{stdio:'inherit'});}console.log('node --check: '+files.length+' files OK');"

# 3. initialise this endpoint (device key + device id + narrowest tool config)
node run-agent.js init --device-id <the server-issued device id>

# 4. create a LAB backend signing key, and pin its public half
node tools/lab-backend.cjs keygen --out "$env:USERPROFILE\.cbhr\lab-backend"
node run-agent.js pin-backend --spki-file "$env:USERPROFILE\.cbhr\lab-backend\lab-backend-spki.txt"

# 5. read the PUBLIC state, and the effective tool set
node run-agent.js describe
node run-agent.js tools

# 6. sign a real frame and run the loop
node tools/lab-backend.cjs sign `
  --key "$env:USERPROFILE\.cbhr\lab-backend\lab-backend-key.txt" `
  --device-id <device id> --device-key-id <deviceKeyId from `describe`> `
  --tool read_file --args '{"path":"hello.txt"}' --call-id call-1 --out frame.json
node run-agent.js handle --in frame.json

# 7. prove a tampered frame does not execute. The frame must carry a FRESH nonce: reusing the one
#    already spent above is refused as a replay FIRST (which is correct — verification is ordered),
#    so a fresh frame is what isolates the args check.
node tools/lab-backend.cjs sign `
  --key "$env:USERPROFILE\.cbhr\lab-backend\lab-backend-key.txt" `
  --device-id <device id> --device-key-id <deviceKeyId> `
  --tool read_file --args '{"path":"hello.txt"}' --call-id call-2 --out frame2.json
node tools/lab-backend.cjs tamper --in frame2.json --swap-args --out tampered.json
node run-agent.js handle --in tampered.json     # -> refused, ENDPOINT_ARGS_DIGEST_MISMATCH

# 8. and replaying the first frame is refused too
node run-agent.js handle --in frame.json        # -> refused, ENDPOINT_REPLAY_DETECTED

# 9. or leave it RUNNING against a relay (W13). It stays, reconnects with backoff, and shuts down
#    cleanly on SIGINT/SIGTERM. See §7 for the handshake, the options and what it reports.
#    (Served process, not one-shot: the relay must be reachable, or it retries loudly.)
node run-agent.js serve --relay http://127.0.0.1:8787
```

`test/cli.test.js` runs this exact sequence as **real processes** and asserts the FILES the tools claim
to write, which is where two bugs in this directory were found and fixed: a pretty-printed `sign --out`
frame was not accepted by `handle --in`, and `--swap-args --out <file>` swallowed `--out` as the flag's
value so the tampered frame was never written.

`node tools/lab-backend.cjs selftest` reproduces the contract's published golden vector, so the lab
signer can be trusted before it is used to test the endpoint. `verify-only` runs the same verification
chain and **never** dispatches (it still consumes the nonce: a dry run that silently freed a nonce
would be a replay hole).

### The owner's try is already set up on this machine

`init` has been run against the real root, so the parts that need no product decision exist:

| What | Where | Value |
|---|---|---|
| Device id | `~/.cbhr/endpoint-agent/device.json` | `device-owner-lab-0001` |
| Device key id | `~/.cbhr/endpoint-agent/device-key.json` | `kJCTz4675vDTOWDejkxuq0OJCN3AR1xMvYuJT19kEvE` |
| Pinned backend key | `~/.cbhr/endpoint-agent/backend-keys.json` | `czJUlMZa137OWW8XyMV_KSX7D9wI4d3Rr2Mb7SrtTrU` (the LAB key) |
| Local tool config | `~/.cbhr/endpoint-agent/tools.json` | the three read-only tools |
| Lab signing key | `~/.cbhr/lab-backend/lab-backend-key.txt` | a lab key, **not** the deployment signer |
| Pinned key is a lab key | — | replace it with the real backend public key via `pin-backend` when custody is populated |

The lab loop was run against that store and produced `succeeded` for a real file read, then
`ENDPOINT_ARGS_DIGEST_MISMATCH` for a tampered frame, `ENDPOINT_KEY_UNPINNED` for a frame signed by an
unpinned key, and `ENDPOINT_REPLAY_DETECTED` for a replay — each with a distinct code.

**What the owner still supplies (GM-73 §5).** Two of the three items are decisions, not code:
backend signing key custody (where it lives, who rotates it) and the GM-10/R3 plaintext-relay
disclosure for a try on the owner's own machine. **The second one is not mine to accept**, and the
device was therefore initialised with a LAB key rather than the real backend key: pinning the real key
requires that decision to be made first.

---

## 7. The runtime — `serve` (W13): the agent as a LIVE participant

Everything above is one frame per process invocation. That is enough to prove the endpoint's logic and
useless for leaving an agent on a PC: nothing connects to the relay, nothing waits for frames, nothing
answers them. `serve` is that participant, and it is deliberately a **thin, transparent shell**: the
socket, the reconnect and the shutdown are new, and *verification, policy, execution and the outcome
are the existing path* (`src/agent.js` → `verify` → `dispatch` → `tools` → `resultFrame`). A runtime
that re-implemented any of those would leave two endpoint verifiers and only one of them tested.

```powershell
cd apps/cbhr-endpoint-agent
node run-agent.js serve --relay http://127.0.0.1:8787
```

| Option | Meaning |
|---|---|
| `--relay <url>` | relay base URL. Path-less URLs get `/d/<deviceId>/ws?tag=device` appended; a URL with a path is used as the device route. |
| `--no-replay-on-connect` | pass `replay=0` (do not take the frames the relay held while the agent was down) |
| `--backoff-initial-ms` / `--backoff-max-ms` | reconnect backoff (default 500 ms doubling to 30 s, no jitter, capped) |
| `--max-reconnects N` | give up after N consecutive failures and **exit 1** (default: retry forever) |
| `--verdict-timeout-ms` | how long to wait for the relay's verdict on one result (default 15 000) |
| `--drain-ms` | how long a shutdown waits for in-flight frames (default 5 000) |
| `--shutdown-on-stdin-eof` | also stop cleanly when stdin reaches EOF (a signal-free control channel) |
| `--print-url` | print the device socket URL, then serve |

### The handshake, read from the relay's own code (not invented)

1. **Connect.** The relay's Worker maps `/d/<deviceId>/...` onto `DEVICE_RELAY.idFromName(deviceId)`
   (`src/worker.js`), so the device opens a WebSocket to `<relay>/d/<deviceId>/ws`. The Durable Object
   checks the upgrade header first and reads its role from the query string:
   `acceptSocket` does `url.searchParams.get('tag') ?? 'device'`. A platform-side reader uses
   `?tag=platform`; **this runtime always sends `tag=device` and cannot be told otherwise** — claiming
   the platform role would put the endpoint's own results on the platform's reader socket.
2. **Replay on connect.** `acceptSocket` calls `resync('connect')` unless `?replay=0`, so every unacked
   frame in the DO's durable `pending` list is redelivered as `{t:'frame', seq, payload, replay:true}`
   the moment a device reconnects. That is the production path and the runtime keeps it ON.
3. **Commands.** `{t:'frame', seq, payload, replay}` — `payload` is the opaque JSON text of a flat
   `CBHR-RPC-V2` frame. `seq` is the relay's delivery number; **acking it is the only way the frame
   stops being redelivered** (GM-21: the relay is the delivery guarantee).
4. **Results.** The runtime sends `{t:'result', callId, payload}` with the `CBHR-RPC-RESULT-V2` frame as
   the opaque payload. The relay checks shape, non-emptiness, its 65 536-character bound and that
   `callId` names a call it dispatched and has not already handed on; it never decodes the payload.
5. **Verdict + ack.** `{t:'result-ok', resultSeq, callId}` or `{t:'result-refused', code, ...}` comes
   back on the same socket, and only then is `{t:'ack', seq}` sent. `RESULT_OUTBOX_SATURATED` is the one
   retryable refusal, so that frame is deliberately **left unacked** for redelivery. `{t:'error',
   reason}` is logged, never fatal.

### How results travel back, and what the runtime refuses to decide

`callId` is unsigned transport metadata (GM-31) and is the relay's ledger key, so the result envelope
correlates on the **transport** `callId` of the frame that arrived — never on a value the signed core
happens to carry. The core's own `callId` is signed and is what the platform re-verifies. (An observed
wrinkle, recorded rather than papered over: a *policy* refusal raised after verification carries the
literal `unknown` in its signed core, exactly as `src/agent.js` already did; the transport field is what
still lets the relay correlate it.)

The runtime sends the frame `agent.handleFrame` returned and nothing else. It never upgrades an outcome,
never synthesises one, and when the core cannot assemble a result frame at all it sends **nothing** and
says so loudly: an unanswered call can be released and retried, a fabricated `uncertain` cannot be taken
back.

### Reconnect and shutdown are LOUD, because a silently dead agent is the failure mode

```
2026-10-24T00:04:30.063Z ERROR relay.error          {"detail":"Received network error or non-101 status code."}
2026-10-24T00:04:30.063Z ERROR relay.socket.lost    {"via":"error", "expected":false}
2026-10-24T00:04:30.063Z WARN  relay.reconnect.scheduled {"attempt":1,"delayMs":200}
2026-10-24T00:04:30.264Z INFO  relay.connected      {"connections":2, ...}
```

Measured behaviour worth knowing: on a **refused** connection Node 22's global `WebSocket` fires `error`
and then *never fires `close`* (`readyState` stays CONNECTING forever). The runtime therefore retires the
socket from **both** events — a reconnect driven only by `close` would leave the agent dead after its
first outage. `SIGINT`/`SIGTERM` and (opt-in) stdin EOF all route to one shutdown path: stop accepting
frames, drain in-flight work with a stated ceiling, close the socket with code 1000, prune-and-persist
the replay window, report the counters, exit 0. **Shutdown deletes nothing** — the device key and the
durable replay window are left for the next start.

Windows note, measured: a Node parent cannot deliver a signal to a child at all —
`child.kill('SIGINT')` terminates it unconditionally and the handler never runs (asserted in
`test/runtime.test.js`). The end-to-end proof therefore drives the same shutdown path through
`--shutdown-on-stdin-eof`, and the signal wiring is proven separately by routing both signals to that
one handler.

### The durable replay window across a restart

`serve` never resets the window: `createEndpointAgent` loads `replay-window.json` from the agent root and
`checkAndRemember` persists a spent `(grantId, nonce)` **before** execution is allowed. The end-to-end
suite proves it with two real processes on one root: process 1 executes a frame and is stopped cleanly;
process 2 logs `replayWindowLoadedEntries: 1` at start and, when the *same signed core* is dispatched
again under a new transport `callId`, answers `refused` / `ENDPOINT_REPLAY_DETECTED` with
`executed:false` — never a second execution.

---

## 8. Layout

```
run-agent.js                 runnable entry point (init / describe / tools / pin-backend / handle / verify-only / serve)
src/errors.js                refusal taxonomy + leak-free EndpointRefusal
src/layout.js                the frozen 15-field document, read independently from the contract
src/vendoredCrypto.js        the accepted primitives (canonicalEncode / verifyEd25519 / thumbprintB64u)
src/verify.js                the verification chain, one distinct code per step
src/freshness.js             the dual freshness law, the deadline, and the GM-47 args re-hash
src/replayWindow.js          the DURABLE (grantId, nonce) window
src/pinnedKeys.js            the pinned backend key set (GM-31)
src/keystore.js              device keypair, owner-only, closure-held
src/permissions.js           real owner-only permissions + ACL classification + atomic replace
src/ceiling.js               tier 1: the server ceiling snapshot, fail closed
src/deviceConfig.js          tier 2: the device floor, which may only narrow
src/dispatch.js              ceiling -> floor -> implementation -> execution
src/tools.js                 list_directory / read_file / get_file_info, contained and bounded
src/resultFrame.js           device-signed audience:'relay' result frames
src/agent.js                 the whole loop: verify -> dispatch -> execute -> sign
src/runtime.js               the RESIDENT participant (W13): device socket, results, ack, reconnect, shutdown
config/server-ceiling.json   generated snapshot of the SERVER's ceiling document
tools/generate-ceiling-snapshot.cjs   regenerate the snapshot from the server policy module
tools/lab-backend.cjs        a lab signer/tamperer for the owner's own try (NOT the deployment signer)
test/                        golden / verification / durability / dispatch / keystore / loop / cli
                             + runtime (unit, scripted socket) and runtime-relay (real relay end to end)
test/_relay-harness.cjs      boots the REAL relay artifact (Miniflare/workerd, in process) for the e2e suite
```

### Running the end-to-end suite (it needs the relay checkout)

`test/runtime-relay.test.js` boots the audited relay artifact in-process — real HTTP, real WebSockets, a
real `run-agent.js serve` child process, a real platform reader socket — and **refuses to run without
it** (a skipped end-to-end proof reads as a passing one). It needs the sibling checkout
`../cbhr-rdc/apps/cbhr-relay` with `dist/worker.js` built and `miniflare` installed
(`CBHR_RELAY_ROOT` overrides the path).

Two host facts it encodes, both measured here rather than assumed:

* **The boot must happen from the relay root.** Miniflare's converter and worker bootstrap resolve
  relative to the process CWD, and booting this artifact from anywhere else fails with the misleading
  *"A DurableObjectNamespace in the config referenced the class DeviceRelay, but no such Durable Object
  class is exported from the worker"* — the artifact exports it; the real failure is an internal workerd
  error during module-service initialisation. The harness `chdir`s into the relay root for the boot and
  restores the directory in a `finally` (the same discipline `tests/device/e2e/relay.cjs` documents).
* **workerd's scratch must live inside this worktree.** On a sandboxed host workerd's writes are denied
  everywhere else (`CreateDirectory: #5 Access is denied`, then `SQLITE_READONLY`), which is why the
  relay's own runners call `ensureProbeTemp` and keep their state under the repository. The harness keeps
  Miniflare's persistence and temp under `apps/cbhr-endpoint-agent/.runtime-e2e-state/` (gitignored,
  removed when the relay stops) and pre-creates the two storage directories Miniflare expects.

Nothing about it can hang: `Miniflare ready` has a 90 s ceiling, every HTTP call has a 15 s ceiling
(`fetch` has no default timeout), the relay must **accept a device socket within 10 s**, and blowing any
of them is a named failure — *"the relay did not accept a DEVICE SOCKET within 10000ms"* — never a test
waiting for a socket that is not coming. All three ceilings are overridable
(`CBHR_W13_BOOT_TIMEOUT_MS`, `CBHR_W13_CALL_TIMEOUT_MS`, `CBHR_W13_SOCKET_TIMEOUT_MS`).

## 9. What this does NOT do

* **No Tauri packaging** — Phase 3 (GM-73), and no Node prerequisite for employees until then.
* **No graphical control of any kind**, and none claimed.
* **No 26-tool Desktop Commander wiring** — three read-only tools, deliberately.
* **No deployment, no Cloudflare, no production relay.** `serve` talks to whatever URL it is given; the
  only relay it has ever been proven against is the local artifact booted by the test harness.
* **No live device enrollment** — `deviceId`, the pinned backend key and the device key are all
  supplied locally by the operator, which is what makes this a lab artifact.