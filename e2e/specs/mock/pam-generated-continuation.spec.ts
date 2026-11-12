import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { expect, test } from '@playwright/test';
import { getPrimaryE2EUser } from '../../setup/users.mock';
import { cleanupAgent, uniqueAgentName } from './agents.helpers';
import { withMongo } from './db';
import {
  MOCK_ENDPOINTS,
  getAccessToken,
  requestJson,
  sendMessageAndWaitForCompletion,
  replyText,
} from './helpers';

const CODE_PORT = 8897;
const CODE_URL = 'http://127.0.0.1:' + CODE_PORT;

test('persisted generated CSV/XLSX survive authenticated agent continuation', async ({ page }) => {
  test.skip(
    process.env.PAM_CSV_CONTINUATION_E2E !== '1',
    'Requires isolated Mongo, fake CodeAPI, authenticated E2E user, and enabled B1 conversation sessions',
  );
  test.setTimeout(150000);
  expect(process.env.LIBRECHAT_CODE_BASEURL).toBe(CODE_URL);
  expect(process.env.CBHR_CONVERSATION_EXECUTION_SESSIONS).toBe('1');
  const suffix = Date.now() + '-' + randomUUID().slice(0, 8);
  const conversationId = randomUUID();
  const userMessageId = randomUUID();
  const assistantMessageId = randomUUID();
  const name = uniqueAgentName('Pam generated CSV continuation');
  const fileSpecs = [
    { name: 'bank-mapping.csv', contents: Buffer.from('source,target\n1000,4100\n') },
    { name: 'reverse-mapping.csv', contents: Buffer.from('target,source\n4100,1000\n') },
    { name: 'account-index.xlsx', contents: Buffer.from('PK\x03\x04synthetic-xlsx-data') },
  ];
  const files = fileSpecs.map((f, index) => ({
    ...f,
    logicalId: 'logical-' + index + '-' + suffix,
    storageId: 'storage-' + index + '-' + suffix,
    diskPath: path.join(
      process.cwd(),
      'e2e',
      'specs',
      '.test-results',
      'pam-' + index + '-' + suffix + path.extname(f.name),
    ),
  }));
  let agentId: string | undefined;
  let lookups = 0;
  const codeApi = http.createServer((req, res) => {
    if (req.method === 'GET' && req.url?.startsWith('/sessions/')) {
      lookups += 1;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ lastModified: new Date().toISOString() }));
      return;
    }
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'fake CodeAPI only supports session reads' }));
  });
  await new Promise<void>((resolve, reject) => {
    codeApi.once('error', reject);
    codeApi.listen(CODE_PORT, '127.0.0.1', resolve);
  });
  try {
    fs.mkdirSync(path.dirname(files[0].diskPath), { recursive: true });
    for (const f of files) fs.writeFileSync(f.diskPath, f.contents);
    await page.goto('/c/new');
    const token = await getAccessToken(page);
    const agent = await requestJson<{ id: string; model: string; tools?: string[] }>(page, {
      path: '/api/agents',
      token,
      method: 'POST',
      body: {
        name,
        description: 'Synthetic CSV/XLSX continuation only',
        instructions: 'Reply to E2E_REPLY requests without invoking tools.',
        provider: MOCK_ENDPOINTS[0].label,
        model: MOCK_ENDPOINTS[0].model,
        tools: ['execute_code'],
      },
    });
    agentId = agent.id;
    expect(agent.tools).toContain('execute_code');

    const identity = await withMongo(async (db) => {
      const user = await db.collection('users').findOne({
        email: getPrimaryE2EUser().email,
      });
      if (!user) throw new Error('E2E authenticated user not found');
      return { oid: user._id, id: user._id.toString(), tenantId: user.tenantId };
    });
    const now = new Date();
    const sessionId = 'session-' + suffix;
    await withMongo(async (db) => {
      await db.collection('conversations').insertOne({
        conversationId,
        title: 'Synthetic generated CSV continuation',
        user: identity.id,
        endpoint: 'agents',
        model: agent.model,
        agent_id: agent.id,
        agentVersion: null,
        isTemporary: false,
        workspaceId: null,
        ...(identity.tenantId ? { tenantId: identity.tenantId } : {}),
        createdAt: now,
        updatedAt: now,
      });
      await db.collection('files').insertMany(
        files.map((f) => ({
          user: identity.oid,
          ...(identity.tenantId ? { tenantId: identity.tenantId } : {}),
          file_id: f.logicalId,
          filename: f.name,
          filepath: f.diskPath,
          source: 'local',
          context: 'execute_code',
          conversationId,
          messageId: assistantMessageId,
          type: f.name.endsWith('.csv')
            ? 'text/csv'
            : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
          bytes: f.contents.length,
          status: 'ready',
          usage: 0,
          metadata: {
            codeEnvRef: {
              kind: 'user',
              id: identity.id,
              storage_session_id: sessionId,
              file_id: f.storageId,
            },
          },
          createdAt: now,
          updatedAt: now,
        })),
      );
      await db.collection('messages').insertMany([
        {
          user: identity.id,
          conversationId,
          endpoint: 'agents',
          agent_id: agent.id,
          model: agent.model,
          messageId: userMessageId,
          parentMessageId: '00000000-0000-0000-0000-000000000000',
          isCreatedByUser: true,
          sender: 'User',
          text: 'Synthetic CSV and XLSX generated.',
          error: false,
          unfinished: false,
          createdAt: new Date(+now + 1),
          updatedAt: new Date(+now + 1),
        },
        {
          user: identity.id,
          conversationId,
          endpoint: 'agents',
          agent_id: agent.id,
          model: agent.model,
          messageId: assistantMessageId,
          parentMessageId: userMessageId,
          isCreatedByUser: false,
          sender: name,
          text: 'Three generated reports are ready.',
          attachments: files.map((f) => ({
            file_id: f.logicalId,
            filename: f.name,
            type: 'execute_code',
            source: 'local',
            bytes: f.contents.length,
          })),
          error: false,
          unfinished: false,
          createdAt: new Date(+now + 2),
          updatedAt: new Date(+now + 2),
        },
      ]);
    });
    await page.goto('/c/' + conversationId);
    await expect(page.getByRole('textbox', { name: 'Message input' })).toBeVisible();
    const label = 'pam-continued-' + suffix;
    const response = await sendMessageAndWaitForCompletion(page, 'E2E_REPLY:' + label, {
      timeout: 40000,
    });
    expect(response.ok()).toBeTruthy();
    await expect(
      page.getByTestId('screenshot-target').getByText(replyText(label), { exact: true }),
    ).toBeVisible({ timeout: 40000 });
    // All outputs share one CodeAPI storage session; freshness lookup is session-cached.
    expect(lookups).toBeGreaterThanOrEqual(1);
    const receipt = await withMongo(async (db) => ({
      session: await db.collection('code_execution_sessions').findOne({ conversationId }),
      errors: await db.collection('messages').countDocuments({
        conversationId,
        isCreatedByUser: false,
        error: true,
      }),
    }));
    expect(receipt.session).not.toBeNull();
    expect(receipt.errors).toBe(0);
  } finally {
    await withMongo(async (db) => {
      await db.collection('files').deleteMany({
        file_id: { $in: files.map((f) => f.logicalId) },
      });
      await db.collection('code_execution_sessions').deleteMany({ conversationId });
      await db.collection('messages').deleteMany({ conversationId });
      await db.collection('conversations').deleteMany({ conversationId });
    }).catch(() => undefined);
    await cleanupAgent(page, agentId).catch(() => undefined);
    for (const f of files) fs.rmSync(f.diskPath, { force: true });
    await new Promise<void>((resolve) => codeApi.close(() => resolve()));
  }
});
