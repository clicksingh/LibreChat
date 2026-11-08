# CBHR PC Bridge: isolated named-tunnel staging

The frozen baseline is `d954f26bf9a1a330f4e232bb888ae625e49345a4`.
This branch adds **optional, fail-closed** staging domain selection. It does not create
or change a Cloudflare resource until the existing pairing provisioner is invoked.

## Environment and isolation

Use a **separate** staging Cloudflare account and zone, with an operator-chosen
DNS suffix that is actually inside that zone. Provide all three variables:

```ini
CBHR_PC_CF_DOMAIN=stage.example.ca
CBHR_PC_CF_ACCOUNT_ID=<32-hex nonproduction account ID>
CBHR_PC_CF_ZONE_ID=<32-hex nonproduction zone ID>
CBHR_PC_CF_API_TOKEN_FILE=<staging-only protected secret file path>
```

The example values are placeholders. Never paste a token into chat or logs.
Do not reuse the production account, zone, token, production Mongo database,
live user accounts, production tunnel IDs, or `ai.kelownarealestate.com`.
The staged account token must permit only the intended staging tunnel/DNS operations.

The default without `CBHR_PC_CF_DOMAIN` remains `kelownarealestate.com`
using the pinned production account and zone. Explicit staging IDs combined
with the production domain, or an alternate domain with production IDs,
are rejected before any Cloudflare management call.

## Runtime acceptance boundary

Use a separately hosted LibreChat API and UI with isolated JWT keys, auth users,
Mongo, CodeAPI storage and rollback image. The managed hostname is generated
under the selected suffix, e.g. `pc-<id>-<nonce>.stage.example.ca`, and must
reach the native Windows MCP server through a named tunnel and HTTPS.

The registry URL validator accepts only that suffix and `/mcp` over HTTPS.
Only `NODE_ENV=CI` retains the exact `http://127.0.0.1:8847/mcp` exception.
Keep normal SSRF protection. If existing `mcpSettings.allowedDomains` acts
as a strict allowlist, add the staging hostname pattern *without replacing
existing allowed entries*; do not add a public hostname to `allowedAddresses`.

Check anonymous `/api/mcp/pc-bridge/pair/status` returns 401 and signed-in
staging status returns disconnected. Then perform a real one-use claim; verify
DNS publication, public MCP initialize/tools/list, model-driven file read,
second-user isolation, hot Edit promotion and revocation, screenshot bytes,
first-call attachments, interrupted-write continuation, and disconnect cleanup.

A synthetic provider/DoH response, CI localhost exception, registration mock,
or read-only HTTP 401 does **not** certify the real named Cloudflare transport.

## Cleanup and rollout

Stop the disposable Windows connector, unregister MCP tools, delete only the
record/tunnel IDs returned by this staging run and verify inactive status.
Never infer a tunnel to delete from a hostname alone. Keep production and
protected tunnel IDs untouched. Preserve audit receipts without bearer values.

Only after independent runtime verification may the exact native source
`9ef96f157bdd7cd5491ff2daaaec75f89cf6d6fc` be signed, its WPF engine
digest repinned, the MSI rebuilt and an upgrade/rollback pilot performed.
