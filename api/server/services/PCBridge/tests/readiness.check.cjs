'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { publicMCPReachable, registerWhenReady, ACTIVATION_BACKOFF_MS } = require('../readiness');

const endpoint = 'https://pc-test.kelownarealestate.com/mcp';
const expiresAt = new Date('2026-11-07');
const now = () => new Date('2026-11-06');
const noop = async () => {};

test('Cloudflare 1033 / HTTP 530 is not a reachable MCP endpoint', async () => {
  assert.equal(await publicMCPReachable(endpoint, async () => ({ status: 530 })), false);
  assert.equal(await publicMCPReachable(endpoint, async () => ({ status: 503 })), false);
  assert.equal(await publicMCPReachable(endpoint, async () => ({ status: 502 })), false);
  assert.equal(await publicMCPReachable(endpoint, async () => ({ status: 404 })), false);
});
test('MCP request-level 401 / 406 proves origin reachability, not registration', async () => {
  assert.equal(await publicMCPReachable(endpoint, async () => ({ status: 401 })), true);
  assert.equal(await publicMCPReachable(endpoint, async () => ({ status: 406 })), true);
});
test('DNS resolves, 1033 warms up, bounded retry then MCP registers', async () => {
  const states = [false, false, true];
  const sleeps = [];
  let registered = 0;
  const result = await registerWhenReady({
    hostname: 'pc-test.kelownarealestate.com',
    endpoint,
    expiresAt,
    now,
    dnsReady: async () => true,
    endpointReady: async () => states.shift(),
    sleep: async (ms) => sleeps.push(ms),
    register: async () => {
      registered++;
      return { tools: ['read_file'], serverName: 'pc' };
    },
  });
  assert.equal(result.serverName, 'pc');
  assert.equal(registered, 1);
  assert.deepEqual(sleeps, [500, 1000]);
});
test('DNS alone cannot activate when origin never becomes reachable', async () => {
  let registered = 0;
  await assert.rejects(
    registerWhenReady({
      endpoint,
      expiresAt,
      now,
      dnsReady: async () => true,
      endpointReady: async () => false,
      sleep: noop,
      register: async () => {
        registered++;
      },
    }),
    { code: 'PC_ENDPOINT_NOT_READY' },
  );
  assert.equal(registered, 0);
});
test('successful HTTP reachability alone cannot activate without MCP initialize and tools/list', async () => {
  let attempts = 0;
  await assert.rejects(
    registerWhenReady({
      endpoint,
      expiresAt,
      now,
      dnsReady: async () => true,
      endpointReady: async () => true,
      sleep: noop,
      register: async () => {
        attempts++;
        throw Object.assign(new Error('MCP initialize failed'), {
          code: 'PC_MCP_REGISTRATION_FAILED',
        });
      },
    }),
    { code: 'PC_MCP_NOT_READY' },
  );
  assert.equal(attempts, ACTIVATION_BACKOFF_MS.length);
});
test('permanent DNS failure cannot reach registration', async () => {
  await assert.rejects(
    registerWhenReady({
      endpoint,
      expiresAt,
      now,
      dnsReady: async () => false,
      endpointReady: async () => true,
      sleep: noop,
      register: async () => {
        throw new Error('must not run');
      },
    }),
    { code: 'CF_DNS_NOT_READY' },
  );
});
test('expired claim never tries activation', async () => {
  await assert.rejects(
    registerWhenReady({
      endpoint,
      expiresAt: new Date('2026-11-05'),
      now,
      dnsReady: async () => true,
      endpointReady: async () => true,
      sleep: noop,
      register: async () => {
        throw new Error('must not run');
      },
    }),
    { code: 'PC_SESSION_EXPIRED' },
  );
});
