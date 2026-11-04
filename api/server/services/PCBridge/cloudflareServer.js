'use strict';

/**
 * Cloudflare management adapter for employee PC tunnels.
 * Only the API server may hold the account-scoped management token.
 * Employees receive only a single tunnel's connector credential.
 */
const crypto = require('node:crypto');
const fs = require('node:fs');

const DEFAULT_ACCOUNT = '0102f078f366b9361dde6122005cd1a9';
const DEFAULT_ZONE = '56a80216044a1ba2063982351e7aeb6b';
const DOMAIN = 'kelownarealestate.com';
const DNS_READY_TIMEOUT_MS = 30000;
const DNS_READY_INTERVAL_MS = 500;
const PROTECTED_TUNNELS = new Set([
  '75ed544f-1ab6-49c6-b6b2-3d01ea0863ef',
  '0fb007e4-de0c-4003-8f8a-2449cbbeb7ce',
  'e88ee348-1db9-4443-94f3-cd90906b9a64',
]);

function createCloudflareServer({
  token = process.env.CBHR_PC_CF_API_TOKEN ||
    (process.env.CBHR_PC_CF_API_TOKEN_FILE
      ? fs.readFileSync(process.env.CBHR_PC_CF_API_TOKEN_FILE, 'utf8').trim()
      : ''),
  accountId = process.env.CBHR_PC_CF_ACCOUNT_ID || DEFAULT_ACCOUNT,
  zoneId = process.env.CBHR_PC_CF_ZONE_ID || DEFAULT_ZONE,
  fetcher = fetch,
  dnsFetcher = fetch,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  dnsReadyTimeoutMs = DNS_READY_TIMEOUT_MS,
  dnsReadyIntervalMs = DNS_READY_INTERVAL_MS,
} = {}) {
  if (!token || token.length < 20) {
    const err = new Error('PC bridge Cloudflare service credential is not configured');
    err.code = 'CF_NOT_CONFIGURED';
    throw err;
  }
  async function api(path, method = 'GET', body) {
    let response;
    try {
      response = await fetcher('https://api.cloudflare.com/client/v4' + path, {
        method,
        headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(20000),
      });
    } catch {
      throw Object.assign(new Error('Cloudflare connection failed'), { code: 'CF_UNAVAILABLE' });
    }
    let payload;
    try {
      payload = await response.json();
    } catch {
      payload = {};
    }
    if (method === 'DELETE' && response.status === 404) return null;
    if (!response.ok || !payload.success) {
      const err = new Error('Cloudflare operation failed');
      err.code = 'CF_REQUEST_FAILED';
      err.httpStatus = response.status;
      throw err;
    }
    return payload.result;
  }
  async function waitForPublicDns(hostname) {
    const deadline = Date.now() + dnsReadyTimeoutMs;
    while (Date.now() <= deadline) {
      try {
        const response = await dnsFetcher(
          'https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(hostname) + '&type=A',
          {
            headers: { Accept: 'application/dns-json' },
            signal: AbortSignal.timeout(5000),
          },
        );
        const payload = await response.json();
        if (
          response.ok &&
          payload?.Status === 0 &&
          Array.isArray(payload.Answer) &&
          payload.Answer.some((answer) => answer?.type === 1)
        ) {
          return true;
        }
      } catch {
        // DNS visibility is eventually consistent. Retry until the bounded deadline.
      }
      if (Date.now() >= deadline) break;
      await sleep(dnsReadyIntervalMs);
    }
    const err = new Error('PC bridge hostname did not become publicly resolvable in time');
    err.code = 'CF_DNS_NOT_READY';
    throw err;
  }

  async function destroy({ tunnelId, dnsRecordId }) {
    if (!tunnelId || PROTECTED_TUNNELS.has(tunnelId)) {
      throw Object.assign(new Error('Protected or invalid tunnel ID'), {
        code: 'CF_PROTECTED_TUNNEL',
      });
    }
    const failures = [];
    if (dnsRecordId) {
      try {
        await api('/zones/' + zoneId + '/dns_records/' + dnsRecordId, 'DELETE');
      } catch (err) {
        failures.push(err);
      }
    }
    try {
      await api('/accounts/' + accountId + '/cfd_tunnel/' + tunnelId + '/connections', 'DELETE');
    } catch {
      /* Cloudflare allows deletion without an active connector */
    }
    try {
      await api('/accounts/' + accountId + '/cfd_tunnel/' + tunnelId, 'DELETE');
    } catch (err) {
      failures.push(err);
    }
    if (failures.length) throw failures[0];
  }
  async function provision({ userId, port }) {
    if (
      !/^[a-f0-9]{24}$/i.test(String(userId)) ||
      !Number.isInteger(port) ||
      port < 1024 ||
      port > 65535
    ) {
      throw Object.assign(new Error('Invalid PC bridge provision request'), {
        code: 'CF_INVALID_REQUEST',
      });
    }
    const label =
      'pc-' + userId.slice(-8).toLowerCase() + '-' + crypto.randomBytes(5).toString('hex');
    const hostname = label + '.' + DOMAIN;
    const name = 'cbhr-pc-' + label;
    const result = await api('/accounts/' + accountId + '/cfd_tunnel', 'POST', {
      name,
      config_src: 'cloudflare',
    });
    const tunnelId = result?.id;
    if (!tunnelId || PROTECTED_TUNNELS.has(tunnelId))
      throw new Error('Invalid tunnel provision response');
    let dnsRecordId = null;
    try {
      await api('/accounts/' + accountId + '/cfd_tunnel/' + tunnelId + '/configurations', 'PUT', {
        config: {
          ingress: [
            { hostname, service: 'http://127.0.0.1:' + port },
            { service: 'http_status:404' },
          ],
        },
      });
      const connectorToken = await api(
        '/accounts/' + accountId + '/cfd_tunnel/' + tunnelId + '/token',
      );
      if (typeof connectorToken !== 'string' || connectorToken.length < 20) {
        throw new Error('Cloudflare did not provide a tunnel connector token');
      }
      const dns = await api('/zones/' + zoneId + '/dns_records', 'POST', {
        type: 'CNAME',
        name: hostname,
        content: tunnelId + '.cfargotunnel.com',
        proxied: true,
        comment: 'CBHR PC Bridge employee session',
      });
      dnsRecordId = dns.id;
      // The Cloudflare API has confirmed the proxied DNS record exists.
      // Public resolver propagation is asynchronous and can exceed this request's
      // lifetime. Activation already retries the actual MCP endpoint; a session
      // that never activates is reaped and its tunnel/DNS removed.
      return {
        hostname,
        url: 'https://' + hostname,
        tunnelId,
        dnsRecordId,
        connectorToken,
      };
    } catch (err) {
      await destroy({ tunnelId, dnsRecordId }).catch(() => {});
      throw err;
    }
  }
  return { provision, destroy };
}

module.exports = { createCloudflareServer, PROTECTED_TUNNELS, DNS_READY_TIMEOUT_MS };
