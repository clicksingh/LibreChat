import { expect, test } from '@playwright/test';
// @ts-expect-error standalone CommonJS bridge outside this TS workspace
import bridge from '../../../../cbhr-pc-bridge/app/mcpServer.js';
// @ts-expect-error standalone CommonJS bridge client outside this TS workspace
import lc from '../../../../cbhr-pc-bridge/control/librechat.js';

const PORT = 8847;
const BEARER = 'rdc-native-proof-bearer-0123456789abcdef0123456789';
const EMAIL = 'rdc-native-proof@example.com';
const PASSWORD = 'RdcNativeProof123!';
const NAME = 'RDC Native Proof';

test('CBHR bridge registers through LibreChat native MCP API and disappears on delete', async ({
  request,
  baseURL,
}) => {
  test.setTimeout(60_000);
  if (!baseURL) throw new Error('baseURL missing');
  const nativeBaseUrl = baseURL.replace(/^http:\/\/localhost(?=[:/]|$)/, 'http://[::1]');

  const server = bridge.createBridgeServer({
    port: PORT,
    token: BEARER,
    scope: 'read_file,list_directory',
    workspaceRoot: process.cwd(),
  });
  await server.listen();

  let token = '';
  let serverName = '';
  try {
    const register = await request.post('/api/auth/register', {
      data: {
        email: EMAIL,
        name: NAME,
        password: PASSWORD,
        confirm_password: PASSWORD,
      },
    });
    if (!register.ok() && register.status() !== 409) {
      throw new Error(`user registration failed: ${register.status()} ${await register.text()}`);
    }

    const login = await request.post('/api/auth/login', {
      data: { email: EMAIL, password: PASSWORD },
    });
    expect(login.ok()).toBeTruthy();
    const loginBody = await login.json();
    token = String(loginBody.token || '');
    expect(token.length).toBeGreaterThan(20);

    const created = await lc.register({
      baseUrl: nativeBaseUrl,
      token,
      tunnelUrl: `http://127.0.0.1:${PORT}`,
      bearerToken: BEARER,
      title: 'CBHR PC Proof',
    });
    serverName = created.serverName;
    expect(serverName).toBeTruthy();
    const headers = { Authorization: `Bearer ${token}` };
    const serversResponse = await request.get('/api/mcp/servers', { headers });
    expect(serversResponse.ok()).toBeTruthy();
    const servers = await serversResponse.json();
    const serialized = JSON.stringify(servers);
    expect(serialized).toContain(serverName);
    expect(serialized).not.toContain(BEARER);

    const toolsResponse = await request.get('/api/mcp/tools', { headers });
    expect(toolsResponse.ok()).toBeTruthy();
    const tools = await toolsResponse.json();
    const toolText = JSON.stringify(tools);
    expect(toolText).toContain('read_file');
    expect(toolText).toContain('list_directory');

    const removed = await lc.unregister({
      baseUrl: nativeBaseUrl,
      token,
      serverName,
    });
    expect(removed.removed || removed.alreadyGone).toBeTruthy();

    const afterResponse = await request.get('/api/mcp/servers', { headers });
    expect(afterResponse.ok()).toBeTruthy();
    expect(JSON.stringify(await afterResponse.json())).not.toContain(serverName);
  } finally {
    if (serverName && token) {
      await lc
        .unregister({
          baseUrl: nativeBaseUrl,
          token,
          serverName,
        })
        .catch(() => undefined);
    }
    await server.close().catch(() => undefined);
  }
});
