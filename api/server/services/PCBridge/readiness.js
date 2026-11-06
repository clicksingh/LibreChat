'use strict';

const ACTIVATION_BACKOFF_MS = Object.freeze([0, 500, 1000, 2000, 4000]);
const wait = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function publicMCPReachable(url, fetcher = fetch) {
  try {
    const response = await fetcher(url, {
      method: 'GET',
      headers: { Accept: 'application/json, text/event-stream' },
      signal: AbortSignal.timeout(4000),
    });
    try { await response.body?.cancel?.(); } catch { /* Status remains authoritative. */ }
    return response.status >= 200 && response.status < 500 &&
      ![403, 404, 407, 408, 429].includes(response.status);
  } catch {
    return false;
  }
}

function notReady(code) {
  return Object.assign(new Error('CB Bridge public MCP endpoint is not ready'), { code });
}

/** Bounded DNS, public HTTP, MCP initialize/tools-list registration admission. */
async function registerWhenReady({
  hostname,
  endpoint,
  expiresAt,
  dnsReady,
  endpointReady = publicMCPReachable,
  register,
  now = () => new Date(),
  sleep = wait,
  backoffs = ACTIVATION_BACKOFF_MS,
}) {
  let lastError = notReady('PC_MCP_NOT_READY');
  for (let attempt = 0; attempt < backoffs.length; attempt++) {
    if (attempt > 0) await sleep(backoffs[attempt]);
    if (now() >= expiresAt) throw notReady('PC_SESSION_EXPIRED');
    if (!(await dnsReady(hostname))) {
      lastError = notReady('CF_DNS_NOT_READY');
      continue;
    }
    if (!(await endpointReady(endpoint))) {
      lastError = notReady('PC_ENDPOINT_NOT_READY');
      continue;
    }
    try {
      return await register();
    } catch (error) {
      if (error?.code !== 'PC_MCP_REGISTRATION_FAILED') throw error;
      lastError = notReady('PC_MCP_NOT_READY');
    }
  }
  throw lastError;
}

module.exports = { publicMCPReachable, registerWhenReady, ACTIVATION_BACKOFF_MS };
