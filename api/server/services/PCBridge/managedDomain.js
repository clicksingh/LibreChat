'use strict';

/**
 * One authority for the managed PC Bridge tunnel DNS suffix.
 * Production remains pinned to kelownarealestate.com unless an operator
 * explicitly selects a DIFFERENT Cloudflare account/zone configuration.
 *
 * Alternate domains are for separately scoped staging accounts/zones only.
 * No request, browser input or model tool may select/override this value.
 */
const { isIP } = require('node:net');

const PRODUCTION_DOMAIN = 'kelownarealestate.com';
const PRODUCTION_ZONE_ID = '56a80216044a1ba2063982351e7aeb6b';
const PRODUCTION_ACCOUNT_ID = '0102f078f366b9361dde6122005cd1a9';

function invalidDomain() {
  return Object.assign(new Error('Invalid managed CBHR PC tunnel domain'), {
    code: 'CF_DOMAIN_INVALID',
  });
}

function canonicalDomain(raw) {
  if (typeof raw !== 'string' || raw !== raw.trim()) throw invalidDomain();
  const name = raw.toLowerCase();
  if (name.length < 4 || name.length > 253 || isIP(name)) throw invalidDomain();
  const labels = name.split('.');
  if (
    labels.length < 2 ||
    labels.some(
      (label) =>
        label.length < 1 || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
    ) ||
    !/[a-z]/.test(labels[labels.length - 1]) ||
    labels[labels.length - 1].length < 2
  ) {
    throw invalidDomain();
  }
  return name;
}

function resolveManagedDomain({
  domain = process.env.CBHR_PC_CF_DOMAIN,
  zoneId = process.env.CBHR_PC_CF_ZONE_ID,
  accountId = process.env.CBHR_PC_CF_ACCOUNT_ID,
} = {}) {
  const name =
    domain === undefined || domain === null || domain === ''
      ? PRODUCTION_DOMAIN
      : canonicalDomain(domain);
  if (name === PRODUCTION_DOMAIN) {
    const selectedZone = zoneId || PRODUCTION_ZONE_ID;
    const selectedAccount = accountId || PRODUCTION_ACCOUNT_ID;
    if (
      String(selectedZone).toLowerCase() !== PRODUCTION_ZONE_ID ||
      String(selectedAccount).toLowerCase() !== PRODUCTION_ACCOUNT_ID
    ) {
      throw Object.assign(
        new Error(
          'Production PC Bridge domain requires the pinned production Cloudflare account and zone',
        ),
        { code: 'CF_STAGING_SCOPE_REQUIRED' },
      );
    }
    return name;
  }

  // Do not accidentally provision staged PC hostnames using the production
  // zone or an implicitly inherited production account/zone.
  if (
    !/^[a-f0-9]{32}$/i.test(String(zoneId || '')) ||
    !/^[a-f0-9]{32}$/i.test(String(accountId || '')) ||
    zoneId.toLowerCase() === PRODUCTION_ZONE_ID ||
    accountId.toLowerCase() === PRODUCTION_ACCOUNT_ID
  ) {
    throw Object.assign(
      new Error(
        'Alternate PC Bridge domains require explicit nonproduction Cloudflare zone and account IDs',
      ),
      { code: 'CF_STAGING_SCOPE_REQUIRED' },
    );
  }
  return name;
}

/**
 * Strict URL admission for the one user's managed PC MCP endpoint.
 * The explicit 127.0.0.1:8847 exception is only for the existing isolated CI
 * integration harness; it must never authorize arbitrary loopback addresses.
 */
function normalizeManagedPCBridgeUrl(
  value,
  { domain = resolveManagedDomain(), allowCI = process.env.NODE_ENV === 'CI' } = {},
) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error('PC bridge URL is required');
  }
  let url;
  try {
    url = new URL(value.trim());
  } catch {
    throw new Error('PC bridge URL is invalid');
  }
  const isLocalCi =
    allowCI && url.protocol === 'http:' && url.hostname === '127.0.0.1' && url.port === '8847';
  const suffix = '.' + domain;
  const hostname = url.hostname.toLowerCase();
  const isManagedTunnel =
    url.protocol === 'https:' &&
    url.port === '' &&
    hostname.endsWith(suffix) &&
    hostname !== domain;
  if (!isLocalCi && !isManagedTunnel) {
    throw new Error('PC bridge URL must use a managed CBHR tunnel hostname');
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error('PC bridge URL must not contain credentials, query parameters, or fragments');
  }
  const pathname = url.pathname.replace(/\/+$/, '') || '/';
  if (pathname !== '/mcp') {
    throw new Error('PC bridge URL must end with /mcp');
  }
  url.pathname = '/mcp';
  return url.toString();
}

module.exports = {
  PRODUCTION_DOMAIN,
  PRODUCTION_ZONE_ID,
  PRODUCTION_ACCOUNT_ID,
  canonicalDomain,
  resolveManagedDomain,
  normalizeManagedPCBridgeUrl,
};
