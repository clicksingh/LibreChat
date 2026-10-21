import { Constants } from '@librechat/agents';
import type { CodeSessionContext, ToolSessionMap } from '@librechat/agents';
import {
  bindExecutionSession,
  executionSessionKey,
  resolveExecutionSession,
} from './sessionRegistry';

const scope = {
  tenantId: 'tenant-1',
  userId: 'alice',
  conversationId: 'chat-1',
  workspaceKind: 'personal' as const,
  workspaceId: 'alice',
};
const makeStore = () => {
  const rows = new Map<string, object>();
  return {
    findOneAndUpdate: jest.fn(async ({ _id }, { $setOnInsert }) => {
      if (!rows.has(_id)) rows.set(_id, $setOnInsert);
      return rows.get(_id);
    }),
    findOne: jest.fn(async ({ _id }) => rows.get(_id) ?? null),
  };
};

describe('conversation execution session registry', () => {
  it('reuses the persisted mapping across independent turns and SSE replays', async () => {
    const store = makeStore();
    const original = await resolveExecutionSession(store, scope);
    expect(original).toMatch(/^conv-[0-9a-f-]{36}$/);
    expect(await resolveExecutionSession(store, scope)).toBe(original);
    expect(store.findOneAndUpdate).toHaveBeenCalledTimes(2);
  });

  it('isolates new chats, siblings, users, tenants and project workspaces', async () => {
    const store = makeStore();
    const first = await resolveExecutionSession(store, scope);
    const changed = [
      { ...scope, conversationId: 'chat-2' },
      { ...scope, userId: 'bob', workspaceId: 'bob' },
      { ...scope, tenantId: 'tenant-2' },
      { ...scope, workspaceKind: 'project' as const, workspaceId: 'project-1' },
      { ...scope, workspaceKind: 'project' as const, workspaceId: 'project-2' },
    ];
    const seen = new Set([first]);
    for (const variant of changed) seen.add(await resolveExecutionSession(store, variant));
    expect(seen.size).toBe(changed.length + 1);
  });

  it('refuses implicit legacy migration and resumes only a pre-bound conversation', async () => {
    const store = makeStore();
    await expect(resolveExecutionSession(store, scope, { allowCreate: false })).rejects.toThrow(
      'migration',
    );
    expect(store.findOneAndUpdate).not.toHaveBeenCalled();
    const id = await resolveExecutionSession(store, scope);
    expect(await resolveExecutionSession(store, scope, { allowCreate: false })).toBe(id);
  });

  it('resolves a concurrent upsert collision from the durable row', async () => {
    const store = makeStore();
    const original = await resolveExecutionSession(store, scope);
    store.findOneAndUpdate.mockImplementationOnce(async () => {
      throw { code: 11000 };
    });
    expect(await resolveExecutionSession(store, scope)).toBe(original);
    expect(store.findOne).toHaveBeenCalledWith({ _id: executionSessionKey(scope) });
  });

  it('fails closed on invalid or corrupt records', async () => {
    const store = makeStore();
    await expect(
      resolveExecutionSession(store, { ...scope, conversationId: 'new' }),
    ).rejects.toThrow();
    await expect(resolveExecutionSession(store, { ...scope, workspaceId: '' })).rejects.toThrow();
    const corrupt = {
      ...makeStore(),
      findOneAndUpdate: jest.fn(async () => ({ sessionId: 'legacy' })),
    };
    await expect(resolveExecutionSession(corrupt, scope)).rejects.toThrow('inconsistent');
  });

  it('pins execution scratch while retaining approved explicit input storage refs', () => {
    const ref = {
      id: 'doc1',
      resource_id: 'alice',
      storage_session_id: 'input-upload',
      name: 'manual.docx',
      kind: 'user' as const,
    };
    const existing: ToolSessionMap = new Map();
    existing.set(Constants.EXECUTE_CODE, {
      session_id: 'legacy-user-session',
      files: [ref],
      lastUpdated: 1,
    } satisfies CodeSessionContext);
    const sessionId = 'conv-11111111-1111-4111-8111-111111111111';
    const sessions = bindExecutionSession(existing, sessionId);
    const code = sessions.get(Constants.EXECUTE_CODE) as CodeSessionContext;
    expect(code.session_id).toBe(sessionId);
    expect(code.files).toEqual([ref]);
    expect(bindExecutionSession(undefined, sessionId).get(Constants.EXECUTE_CODE)).toBeDefined();
    expect(() => bindExecutionSession(undefined, 'legacy-user-session')).toThrow();
  });
});
