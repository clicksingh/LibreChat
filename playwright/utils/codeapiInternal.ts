/**
 * 8S3D.1 browser E2E — mints the SAME internal admin JWT
 * (mintInternalAdminToken in packages/api/src/auth/codeapi.ts) locally, for
 * one purpose only: setting a disposable, tiny quota override on a test
 * fixture project workspace directly via CodeAPI's
 * /internal/workspace/quota endpoint, so J7 can fill it via real code
 * execution in seconds instead of gigabytes. This is TEST FIXTURE SETUP,
 * not part of what J7 verifies — the actual quota enforcement is the real
 * kernel-level XFS project quota, unaffected by how the limit was set.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';

const CODEAPI_BASE = process.env.CODEAPI_BASE ?? 'http://127.0.0.1:4101';
const PRIVATE_KEY_PATH = process.env.CODEAPI_JWT_PRIVATE_KEY_PATH ?? '/opt/cbhr-ai/secrets/codeapi-jwt-private.pem';

function mintInternalAdminToken(): string {
  const priv = crypto.createPrivateKey(fs.readFileSync(PRIVATE_KEY_PATH));
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const body = {
    iss: 'librechat',
    aud: 'codeapi',
    sub: 'librechat-system',
    iat: now,
    nbf: now,
    exp: now + 60,
    admin: true,
  };
  const payload = Buffer.from(JSON.stringify(body)).toString('base64url');
  const data = `${header}.${payload}`;
  const sig = crypto.sign(null, Buffer.from(data), priv);
  return `${data}.${Buffer.from(sig).toString('base64url')}`;
}

/** Set a workspace's hard quota directly (bypasses LibreChat's admin API —
 * this test suite has no admin-role user provisioned). Server-side clamped
 * to the helper's [64MiB, 50GiB] safety bounds regardless of what's asked. */
export async function setQuotaDirect(
  workspaceId: string,
  kind: 'personal' | 'project',
  quotaBytes: number,
): Promise<void> {
  // The chat write that's supposed to have provisioned this workspace's XFS
  // project only *triggers* provisioning fire-and-forget (agents/authorization.js
  // never blocks a chat reply on a round trip to the quota helper) — so the
  // helper's mapping can still be catching up for a few seconds after the
  // chat message that caused it visibly completes. Retry, don't widen any
  // product-side wait.
  const attempts = 10;
  let lastErr: Error | undefined;
  for (let i = 0; i < attempts; i++) {
    const token = mintInternalAdminToken();
    const r = await fetch(`${CODEAPI_BASE}/internal/workspace/quota`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ workspace_id: workspaceId, kind, quota_bytes: quotaBytes }),
    });
    if (r.ok) return;
    if (r.status !== 404) {
      throw new Error(`setQuotaDirect failed: ${r.status} ${await r.text()}`);
    }
    lastErr = new Error(`setQuotaDirect failed: ${r.status} ${await r.text()}`);
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  throw lastErr;
}
