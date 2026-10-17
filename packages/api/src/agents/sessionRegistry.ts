import { createHash, randomUUID } from 'crypto';
import { Constants } from '@librechat/agents';
import type { CodeSessionContext, ToolSessionMap } from '@librechat/agents';

export interface ExecutionScope {
  tenantId: string;
  userId: string;
  conversationId: string;
  workspaceKind: 'personal' | 'project';
  workspaceId: string;
}

interface StoredSession extends ExecutionScope {
  _id: string;
  sessionId: string;
  createdAt: Date;
}

interface SessionCollection {
  findOneAndUpdate(
    filter: { _id: string },
    update: { $setOnInsert: StoredSession },
    options: { upsert: true; returnDocument: 'after' },
  ): Promise<StoredSession | { value: StoredSession | null } | null>;
  findOne(filter: { _id: string }): Promise<StoredSession | null>;
}

function validateScope(scope: ExecutionScope): void {
  for (const field of [scope.tenantId, scope.userId, scope.conversationId, scope.workspaceId]) {
    if (typeof field !== 'string' || field.length < 1 || field.length > 200) {
      throw new Error('Invalid execution session scope');
    }
  }
  if (scope.conversationId === 'new') {
    throw new Error('Execution session requires a persisted conversation identity');
  }
  if (scope.workspaceKind !== 'personal' && scope.workspaceKind !== 'project') {
    throw new Error('Invalid execution workspace kind');
  }
}

export function executionSessionKey(scope: ExecutionScope): string {
  validateScope(scope);
  const parts = [scope.tenantId, scope.userId, scope.workspaceKind, scope.workspaceId, scope.conversationId];
  return `b1-${createHash('sha256').update(JSON.stringify(parts)).digest('hex')}`;
}

/** One unique Mongo _id per authenticated conversation/workspace scope; no TTL or cleanup. */
export async function resolveExecutionSession(
  collection: SessionCollection,
  scope: ExecutionScope,
  options: { allowCreate?: boolean } = {},
): Promise<string> {
  const _id = executionSessionKey(scope);
  const record: StoredSession = {
    _id,
    ...scope,
    sessionId: `conv-${randomUUID()}`,
    createdAt: new Date(),
  };
  // Existing conversations must keep their legacy workspace until an
  // explicit migration mapping is reviewed. A global flag cannot silently
  // strand an old user's shared lc-* work directory.
  if (options.allowCreate === false) {
    const existing = await collection.findOne({ _id });
    if (!existing) throw new Error('Legacy conversation requires execution session migration');
    if (existing._id !== _id || !/^conv-[0-9a-f-]{36}$/.test(existing.sessionId)) {
      throw new Error('Execution session registry is inconsistent');
    }
    return existing.sessionId;
  }
  let result: StoredSession | { value: StoredSession | null } | null;
  try {
    result = await collection.findOneAndUpdate(
      { _id },
      { $setOnInsert: record },
      { upsert: true, returnDocument: 'after' },
    );
  } catch (error) {
    // A concurrent first-turn upsert may lose the unique _id insert race.
    if ((error as { code?: number }).code !== 11000) throw error;
    result = await collection.findOne({ _id });
  }
  const resolved = result && 'value' in result ? result.value : result;
  if (!resolved || resolved._id !== _id || !/^conv-[0-9a-f-]{36}$/.test(resolved.sessionId)) {
    throw new Error('Execution session registry is inconsistent');
  }
  return resolved.sessionId;
}

/** Preserve per-file source bucket refs while pinning the run to its own scratch. */
export function bindExecutionSession(
  original: ToolSessionMap | undefined,
  sessionId: string,
): ToolSessionMap {
  if (!/^conv-[0-9a-f-]{36}$/.test(sessionId)) throw new Error('Invalid execution session ID');
  const sessions = original ?? new Map();
  const prior = sessions.get(Constants.EXECUTE_CODE) as CodeSessionContext | undefined;
  sessions.set(Constants.EXECUTE_CODE, {
    session_id: sessionId,
    files: prior?.files ?? [],
    lastUpdated: Date.now(),
  } satisfies CodeSessionContext);
  return sessions;
}
