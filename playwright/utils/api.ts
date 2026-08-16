/**
 * 8S3C.1 browser E2E — host-side agent-chat API helpers.
 *
 * The forged-flag and malformed-coupling cases are, by definition, requests the
 * normal UI cannot produce — they are only expressible at the request layer.
 * These helpers drive them through the SAME `/api/agents/chat/:endpoint`
 * surface the deployed client uses, with a real browser User-Agent and a
 * server-minted access token (identical to the accepted verify-doc-workstation
 * E2E). They NEVER call /api/auth/login, so the login rate-limiter ban is never
 * tripped.
 */

import { randomUUID } from 'node:crypto';
import { MongoClient } from 'mongodb';
import { BASE, CHAT_ENDPOINT } from './constants';
import { accessToken, MONGO_URI } from './auth';
import { parseStream, type ParsedStream } from './stream';

const UA =
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36';

export interface ChatOutcome extends ParsedStream {
  postStatus: number;
  streamStatus: number | null;
  postBody: string;
}

/**
 * POST a chat request as `userId` with an explicit ephemeralAgent and read the
 * full SSE stream. This is the "request state" surface the client uses.
 */
export async function chatRequest(
  userId: string,
  ephemeralAgent: Record<string, unknown>,
  text = 'Reply with the single word ok.',
): Promise<ChatOutcome> {
  const token = accessToken(userId);
  const body = {
    endpoint: CHAT_ENDPOINT,
    endpointType: 'custom',
    model: 'deepseek-v4-flash',
    text,
    messageId: randomUUID(),
    parentMessageId: '00000000-0000-0000-0000-000000000000',
    sender: 'User',
    isCreatedByUser: true,
    conversationId: null,
    ephemeralAgent,
  };
  const ep = encodeURIComponent(CHAT_ENDPOINT);
  const r = await fetch(`${BASE}/api/agents/chat/${ep}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', 'User-Agent': UA },
    body: JSON.stringify(body),
  });
  const j = await r.json().catch(() => ({}));
  if (r.status !== 200 || !j.streamId) {
    return { postStatus: r.status, streamStatus: null, postBody: JSON.stringify(j).slice(0, 300), toolTokenCounts: [], toolCalls: [], finalText: '', conversationId: null, bytes: 0 };
  }
  const s = await fetch(`${BASE}/api/agents/chat/stream/${j.streamId}`, {
    headers: { Authorization: `Bearer ${token}`, 'User-Agent': UA },
  });
  const raw = await s.text();
  return {
    postStatus: r.status,
    streamStatus: s.status,
    postBody: '',
    ...parseStream(raw),
  };
}

/**
 * Insert a message doc owned by `userId` so the direct tool-call endpoint can
 * satisfy its messageId-ownership lookup (messages.user is a hex string, not an
 * ObjectId). Cleaned up after the test. Mirrors /tmp/insert-probe-msg.js.
 */
export async function insertMessage(
  userId: string,
  messageId: string,
  conversationId = '8s3c1-e2e-probe-convo',
): Promise<void> {
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  try {
    const col = client.db('LibreChat').collection('messages');
    await col.deleteMany({ messageId });
    await col.insertOne({
      messageId,
      user: userId,
      conversationId,
      parentMessageId: '00000000-0000-0000-0000-000000000000',
      sender: 'User',
      role: 'user',
      isCreatedByUser: true,
      text: '8S3C.1 direct tool-call probe message',
      createdAt: new Date(),
      updatedAt: new Date(),
    });
  } finally {
    await client.close();
  }
}

export async function deleteMessage(messageId: string): Promise<void> {
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  try {
    await client.db('LibreChat').collection('messages').deleteMany({ messageId });
  } finally {
    await client.close();
  }
}

/** Direct tool-call endpoint (the RUN_CODE-gated surface). */
export async function directToolCall(
  userId: string,
  messageId: string,
  conversationId: string | null,
  args: Record<string, unknown> = { code: 'print(1)' },
): Promise<{ status: number; body: string }> {
  const token = accessToken(userId);
  const r = await fetch(`${BASE}/api/agents/tools/execute_code/call`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', 'User-Agent': UA },
    body: JSON.stringify({ messageId, conversationId, ...args }),
  });
  return { status: r.status, body: (await r.text()).slice(0, 300) };
}
