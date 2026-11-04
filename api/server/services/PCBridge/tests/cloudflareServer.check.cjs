'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createCloudflareServer, PROTECTED_TUNNELS } = require('../cloudflareServer');

const TUNNEL_ID = '11111111-1111-4111-8111-111111111111';
function fixture({ failDns = false, dnsVisibleAfter = 1, dnsNeverReady = false } = {}) {
  const calls = [];
  const adminToken = 'admin-token-secret-kept-exclusively-on-server';
  let dnsChecks = 0;
  const fakeDnsFetch = async () => {
    dnsChecks += 1;
    const ready = !dnsNeverReady && dnsChecks >= dnsVisibleAfter;
    return {
      status: 200,
      ok: true,
      async json() {
        return ready
          ? { Status: 0, Answer: [{ type: 1, data: '104.21.35.185' }] }
          : { Status: 3 };
      },
    };
  };
  const fakeFetch = async (url, options) => {
    const path = new URL(url).pathname;
    calls.push({ path, method: options.method, headers: options.headers, body: options.body });
    if (failDns && path.endsWith('/dns_records') && options.method === 'POST') {
      return {
        status: 500,
        ok: false,
        async json() {
          return { success: false };
        },
      };
    }
    let result = {};
    if (path.endsWith('/cfd_tunnel') && options.method === 'POST') result = { id: TUNNEL_ID };
    if (path.endsWith('/token')) result = 'single-tunnel-connector-credential-1234567';
    if (path.endsWith('/dns_records') && options.method === 'POST') result = { id: 'dns-123' };
    return {
      status: 200,
      ok: true,
      async json() {
        return { success: true, result };
      },
    };
  };
  return {
    service: createCloudflareServer({
      token: adminToken,
      fetcher: fakeFetch,
      dnsFetcher: fakeDnsFetch,
      sleep: async () => {},
      dnsReadyTimeoutMs: dnsNeverReady ? 0 : 30000,
      dnsReadyIntervalMs: 0,
    }),
    calls,
    adminToken,
    dnsChecks: () => dnsChecks,
  };
}

test('central provider provisions scoped named tunnel and cleans it without exposing admin token', async () => {
  const { service, calls, adminToken } = fixture();
  const tunnel = await service.provision({ userId: '6a31557594ab025c7537576e', port: 8845 });
  assert.match(tunnel.hostname, /^pc-[a-f0-9]{8}-[a-f0-9]{10}\.kelownarealestate\.com$/);
  assert.equal(tunnel.tunnelId, TUNNEL_ID);
  assert.ok(!JSON.stringify(tunnel).includes(adminToken));
  assert.ok(calls.find((x) => x.path.endsWith('/configurations')).body.includes('127.0.0.1:8845'));
  await service.destroy(tunnel);
  assert.ok(calls.some((x) => x.path.endsWith('/dns_records/dns-123') && x.method === 'DELETE'));
  assert.ok(
    calls.some((x) => x.path.endsWith('/cfd_tunnel/' + TUNNEL_ID) && x.method === 'DELETE'),
  );
});

test('failed DNS provisioning revokes created tunnel', async () => {
  const { service, calls } = fixture({ failDns: true });
  await assert.rejects(service.provision({ userId: '6a31557594ab025c7537576e', port: 8845 }), {
    code: 'CF_REQUEST_FAILED',
  });
  assert.ok(
    calls.some((x) => x.path.endsWith('/cfd_tunnel/' + TUNNEL_ID) && x.method === 'DELETE'),
  );
});

test('invalid port and protected tunnel IDs are rejected before API calls', async () => {
  const { service, calls } = fixture();
  await assert.rejects(service.provision({ userId: 'bad-id', port: 8845 }), {
    code: 'CF_INVALID_REQUEST',
  });
  await assert.rejects(service.provision({ userId: '6a31557594ab025c7537576e', port: 1 }), {
    code: 'CF_INVALID_REQUEST',
  });
  await assert.rejects(service.destroy({ tunnelId: [...PROTECTED_TUNNELS][0] }), {
    code: 'CF_PROTECTED_TUNNEL',
  });
  assert.equal(calls.length, 0);
});

test('missing central Cloudflare token fails closed', () => {
  assert.throws(() => createCloudflareServer({ token: '' }), { code: 'CF_NOT_CONFIGURED' });
});


test('provision returns after DNS record creation without waiting for external resolver propagation', async () => {
  const { service, dnsChecks, calls } = fixture({ dnsVisibleAfter: 3 });
  const tunnel = await service.provision({ userId: '6a31557594ab025c7537576e', port: 8845 });
  assert.equal(tunnel.tunnelId, TUNNEL_ID);
  assert.equal(dnsChecks(), 0);
  assert.ok(calls.some((x) => x.path.endsWith('/dns_records') && x.method === 'POST'));
});

test('unavailable public DNS resolver does not consume a valid provisioning attempt', async () => {
  const { service, calls } = fixture({ dnsNeverReady: true });
  const tunnel = await service.provision({ userId: '6a31557594ab025c7537576e', port: 8845 });
  assert.equal(tunnel.tunnelId, TUNNEL_ID);
  await service.destroy(tunnel);
  assert.ok(calls.some((x) => x.path.endsWith('/dns_records/dns-123') && x.method === 'DELETE'));
  assert.ok(calls.some((x) => x.path.endsWith('/cfd_tunnel/' + TUNNEL_ID) && x.method === 'DELETE'));
});
