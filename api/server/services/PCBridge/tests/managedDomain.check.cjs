'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {
  PRODUCTION_DOMAIN,
  PRODUCTION_ZONE_ID,
  PRODUCTION_ACCOUNT_ID,
  canonicalDomain,
  resolveManagedDomain,
} = require('../managedDomain');

const STAGING_ZONE = 'a'.repeat(32);
const STAGING_ACCOUNT = 'b'.repeat(32);

test('production domain remains the default without any explicit staging scope', () => {
  assert.equal(
    resolveManagedDomain({ domain: undefined, zoneId: undefined, accountId: undefined }),
    PRODUCTION_DOMAIN,
  );
  assert.equal(resolveManagedDomain({ domain: PRODUCTION_DOMAIN }), PRODUCTION_DOMAIN);
});

test('separate staging account plus zone can select an alternate managed hostname suffix', () => {
  assert.equal(
    resolveManagedDomain({
      domain: 'STAGE.EXAMPLE.CA',
      zoneId: STAGING_ZONE,
      accountId: STAGING_ACCOUNT,
    }),
    'stage.example.ca',
  );
});

test('alternate domain rejects inherited, missing or production Cloudflare authority', () => {
  const stage = 'stage.example.ca';
  for (const [zoneId, accountId] of [
    [undefined, undefined],
    [STAGING_ZONE, undefined],
    [undefined, STAGING_ACCOUNT],
    [PRODUCTION_ZONE_ID, STAGING_ACCOUNT],
    [STAGING_ZONE, PRODUCTION_ACCOUNT_ID],
    ['not-a-zone', STAGING_ACCOUNT],
    [STAGING_ZONE, 'invalid-account'],
  ]) {
    assert.throws(() => resolveManagedDomain({ domain: stage, zoneId, accountId }), {
      code: 'CF_STAGING_SCOPE_REQUIRED',
    });
  }
});

test('invalid host suffixes never become a tunnel DNS name', () => {
  for (const bad of [
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    '-stage.example.com',
    'stage.example.com-',
    'stage..com',
    'stage.example.com.',
    '.example.com',
    'https://stage.example.com',
    'stage.example.com/path',
    'foo*.example.com',
    'stage.example.com:443',
    'a.com ',
    'a.com\\n',
    'example.c',
    '🚀.example.com',
  ]) {
    assert.throws(() => canonicalDomain(bad), { code: 'CF_DOMAIN_INVALID' }, bad);
  }
});

test('provider creates and deletes only a tunnel and DNS under the selected staging account and zone', async () => {
  const { createCloudflareServer } = require('../cloudflareServer');
  const calls = [];
  const tunnelId = '11111111-1111-4111-8111-111111111111';
  const provider = createCloudflareServer({
    token: 'staging-token-12345678901234567890',
    accountId: STAGING_ACCOUNT,
    zoneId: STAGING_ZONE,
    domain: 'stage.example.ca',
    fetcher: async (url, init) => {
      const route = new URL(url).pathname;
      calls.push({ route, method: init.method, body: init.body });
      let result = {};
      if (route.endsWith('/cfd_tunnel') && init.method === 'POST') result = { id: tunnelId };
      if (route.endsWith('/token')) result = 'staging-connector-token-1234567890123';
      if (route.endsWith('/dns_records') && init.method === 'POST') result = { id: 'dns-stage-1' };
      return { ok: true, status: 200, json: async () => ({ success: true, result }) };
    },
  });
  const result = await provider.provision({ userId: '6a31557594ab025c7537576e', port: 8847 });
  assert.match(result.hostname, /^pc-[a-f0-9-]+\.stage\.example\.ca$/);
  assert.equal(result.url, 'https://' + result.hostname);
  const dnsCall = calls.find((c) => c.route.endsWith('/dns_records') && c.method === 'POST');
  assert.ok(dnsCall);
  assert.equal(JSON.parse(dnsCall.body).name, result.hostname);
  assert.ok(dnsCall.route.includes('/zones/' + STAGING_ZONE + '/dns_records'));
  assert.ok(calls.some((c) => c.route.includes('/accounts/' + STAGING_ACCOUNT + '/cfd_tunnel')));
  await provider.destroy(result);
  assert.ok(
    calls.some(
      (c) =>
        c.route.includes('/zones/' + STAGING_ZONE + '/dns_records/dns-stage-1') &&
        c.method === 'DELETE',
    ),
  );
  assert.ok(
    calls.some(
      (c) =>
        c.route.includes('/accounts/' + STAGING_ACCOUNT + '/cfd_tunnel/' + tunnelId) &&
        c.method === 'DELETE',
    ),
  );
});

test('invalid staging DNS scope fails before a Cloudflare management API request', () => {
  let calls = 0;
  const { createCloudflareServer } = require('../cloudflareServer');
  const fakeFetch = () => {
    calls++;
    throw Error('must not be called');
  };
  assert.throws(
    () =>
      createCloudflareServer({
        token: 'staging-token-12345678901234567890',
        zoneId: PRODUCTION_ZONE_ID,
        accountId: STAGING_ACCOUNT,
        domain: 'stage.example.ca',
        fetcher: fakeFetch,
      }),
    { code: 'CF_STAGING_SCOPE_REQUIRED' },
  );
  assert.equal(calls, 0);
});

test('PC registration URL admits only a managed HTTPS child hostname', () => {
  const { normalizeManagedPCBridgeUrl } = require('../managedDomain');
  assert.equal(
    normalizeManagedPCBridgeUrl('https://pc-proof.kelownarealestate.com/mcp', { allowCI: false }),
    'https://pc-proof.kelownarealestate.com/mcp',
  );
  assert.equal(
    normalizeManagedPCBridgeUrl('https://pc-stage.stage.example.ca/mcp', {
      domain: 'stage.example.ca',
      allowCI: false,
    }),
    'https://pc-stage.stage.example.ca/mcp',
  );
  for (const denied of [
    'https://pc-proof.kelownarealestate.com/mcp',
    'https://stage.example.ca/mcp',
    'https://pc-qa.stage.example.ca.evil.com/mcp',
    'http://pc-qa.stage.example.ca/mcp',
    'https://pc-qa.stage.example.ca:8443/mcp',
    'https://pc-qa.stage.example.ca/foo',
    'https://pc-qa.stage.example.ca/mcp?token=x',
    'https://user:pass@pc-qa.stage.example.ca/mcp',
    'http://127.0.0.1:8847/mcp',
    'http://127.0.0.1:8848/mcp',
  ]) {
    assert.throws(
      () => normalizeManagedPCBridgeUrl(denied, { domain: 'stage.example.ca', allowCI: false }),
      /PC bridge URL/,
      denied,
    );
  }
  assert.equal(
    normalizeManagedPCBridgeUrl('http://127.0.0.1:8847/mcp', {
      domain: 'stage.example.ca',
      allowCI: true,
    }),
    'http://127.0.0.1:8847/mcp',
  );
  assert.throws(
    () =>
      normalizeManagedPCBridgeUrl('http://127.0.0.1:8848/mcp', {
        domain: 'stage.example.ca',
        allowCI: true,
      }),
    /PC bridge URL must use/,
  );
});

test('managed bridge URL rejects invalid alternate-stage operator scope before URL evaluation', () => {
  const { normalizeManagedPCBridgeUrl } = require('../managedDomain');
  const env = process.env;
  const saved = {
    CBHR_PC_CF_DOMAIN: env.CBHR_PC_CF_DOMAIN,
    CBHR_PC_CF_ZONE_ID: env.CBHR_PC_CF_ZONE_ID,
    CBHR_PC_CF_ACCOUNT_ID: env.CBHR_PC_CF_ACCOUNT_ID,
  };
  try {
    env.CBHR_PC_CF_DOMAIN = 'stage.example.ca';
    env.CBHR_PC_CF_ZONE_ID = PRODUCTION_ZONE_ID;
    env.CBHR_PC_CF_ACCOUNT_ID = STAGING_ACCOUNT;
    assert.throws(
      () =>
        normalizeManagedPCBridgeUrl('https://pc-proof.stage.example.ca/mcp', { allowCI: false }),
      { code: 'CF_STAGING_SCOPE_REQUIRED' },
    );
    env.CBHR_PC_CF_ZONE_ID = STAGING_ZONE;
    env.CBHR_PC_CF_ACCOUNT_ID = STAGING_ACCOUNT;
    assert.equal(
      normalizeManagedPCBridgeUrl('https://pc-proof.stage.example.ca/mcp', { allowCI: false }),
      'https://pc-proof.stage.example.ca/mcp',
    );
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete env[key];
      else env[key] = value;
    }
  }
});

test('production hostname cannot be paired with staging Cloudflare account or zone settings', () => {
  for (const domain of [undefined, null, '', PRODUCTION_DOMAIN, 'KELOWNAREALESTATE.COM']) {
    for (const [zoneId, accountId] of [
      [STAGING_ZONE, STAGING_ACCOUNT],
      [STAGING_ZONE, PRODUCTION_ACCOUNT_ID],
      [PRODUCTION_ZONE_ID, STAGING_ACCOUNT],
    ]) {
      assert.throws(() => resolveManagedDomain({ domain, zoneId, accountId }), {
        code: 'CF_STAGING_SCOPE_REQUIRED',
      });
    }
  }
});

test('production hostname with matching explicitly selected account and zone is allowed', () => {
  assert.equal(
    resolveManagedDomain({
      domain: PRODUCTION_DOMAIN,
      zoneId: PRODUCTION_ZONE_ID,
      accountId: PRODUCTION_ACCOUNT_ID,
    }),
    PRODUCTION_DOMAIN,
  );
});
