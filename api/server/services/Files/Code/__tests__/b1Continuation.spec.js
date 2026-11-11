'use strict';

const { getThreadData, buildInitialToolSessions } = require('@librechat/api');
const { Constants } = require('@librechat/agents');
const { resolveAuthorizedFileGrants } = require('../b1Grants');

describe('B1 generated-file continuation across persisted conversation turns', () => {
  const owner = 'synthetic-owner';
  const session = 'synthetic-storage-session';
  const filenameTypes = ['bank-map.csv', 'reverse-map.csv', 'account-index.xlsx'];
  const records = filenameTypes.map((filename, i) => {
    const fileId = `logical-file-${i}`;
    const codeId = `storage-file-${i}`;
    return {
      user: owner,
      tenantId: null,
      file_id: fileId,
      conversationId: 'synthetic-conversation',
      context: 'execute_code',
      filename,
      bytes: 50 + i,
      metadata: {
        codeEnvRef: { kind: 'user', id: owner, storage_session_id: session, file_id: codeId },
      },
    };
  });
  const firstAssistant = {
    messageId: 'assistant-healthy',
    parentMessageId: 'user-original',
    attachments: records.map((r) => ({ file_id: r.file_id })),
  };
  const messages = [
    { messageId: 'user-original', parentMessageId: Constants.NO_PARENT },
    firstAssistant,
    { messageId: 'user-continue', parentMessageId: 'assistant-healthy' },
    {
      messageId: 'assistant-sibling',
      parentMessageId: 'user-original',
      attachments: [{ file_id: 'sibling-unrelated' }],
    },
  ];

  async function hydrateTurn(parentMessageId) {
    const thread = getThreadData(messages, parentMessageId);
    const primed = records
      .filter((r) => thread.fileIds.includes(r.file_id))
      .map((r) => ({
        kind: r.metadata.codeEnvRef.kind,
        resource_id: r.metadata.codeEnvRef.id,
        storage_session_id: r.metadata.codeEnvRef.storage_session_id,
        id: r.metadata.codeEnvRef.file_id,
        name: r.filename,
      }));
    const initialSessions = buildInitialToolSessions({ agents: [{ primedCodeFiles: primed }] });
    const seen = [];
    const grants = await resolveAuthorizedFileGrants({
      req: { user: { id: owner, tenantId: null } },
      initialSessions,
      getFiles: async (query) => {
        seen.push(query);
        return records.filter((r) =>
          query['metadata.codeEnvRef.file_id'].$in.includes(r.metadata.codeEnvRef.file_id),
        );
      },
      hashFile: async () => 'a'.repeat(64),
    });
    return { thread, initialSessions, seen, grants };
  }

  it('preserves both CSV outputs and XLSX on turn two without importing a sibling branch', async () => {
    const result = await hydrateTurn('user-continue');
    expect(result.thread.fileIds).toEqual(records.map((r) => r.file_id));
    expect(result.initialSessions.get(Constants.EXECUTE_CODE).files).toHaveLength(3);
    expect(result.grants.map((g) => g.name)).toEqual(filenameTypes);
    expect(result.seen[0]).toEqual({
      user: owner,
      'metadata.codeEnvRef.file_id': { $in: records.map((r) => r.metadata.codeEnvRef.file_id) },
    });
    expect(result.grants.every((g) => g.sha256 === 'a'.repeat(64))).toBe(true);
    expect(result.thread.fileIds).not.toContain('sibling-unrelated');
  });

  it('retains the same output grants on turn three after traversing persisted ancestors', async () => {
    messages.push({ messageId: 'assistant-second', parentMessageId: 'user-continue' });
    messages.push({ messageId: 'user-third', parentMessageId: 'assistant-second' });
    try {
      const result = await hydrateTurn('user-third');
      expect(result.grants.map((g) => g.name)).toEqual(filenameTypes);
      expect(result.grants.every((g) => g.owner === owner && g.session_id === session)).toBe(true);
    } finally {
      messages.splice(-2);
    }
  });
});
