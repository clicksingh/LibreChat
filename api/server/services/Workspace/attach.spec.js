const mockListFiles = jest.fn();
const mockRead = jest.fn();
const mockCreateFile = jest.fn();
const mockGetConvo = jest.fn();
const mockSaveBuffer = jest.fn();
jest.mock('./proxy', () => ({
  listFiles: (...args) => mockListFiles(...args),
  readWorkspaceFile: (...args) => mockRead(...args),
}));
jest.mock('~/models', () => ({
  createFile: (...args) => mockCreateFile(...args),
  getConvo: (...args) => mockGetConvo(...args),
}));
jest.mock('~/server/services/Files/strategies', () => ({
  getStrategyFunctions: () => ({ saveBuffer: (...args) => mockSaveBuffer(...args) }),
}));
jest.mock('~/server/services/Files/retention', () => ({
  getRetentionExpiry: jest.fn().mockResolvedValue({}),
}));
jest.mock(
  '@librechat/api',
  () => ({
    getStorageMetadata: jest.fn(() => ({})),
  }),
  { virtual: true },
);
const {
  attachWorkspaceFile,
  resolveListedArtifact,
  verifyChatScope,
  MAX_ATTACH_BYTES,
  workspaceMimeType,
} = require('./attach');

const req = {
  user: { id: 'user-owner', tenantId: 'tenant-a' },
  config: { fileStrategy: 'local' },
};
const source = {
  path: 'session-a/published-id',
  sessionId: 'session-a',
  fileId: 'published-id',
  name: 'Objective.docx',
  size: 7,
  role: 'output',
};

describe('Reuse CodeAPI workspace files in a chat (server-boundary)', () => {
  it('classifies DOCX and PDF with real MIME instead of octet-stream', () => {
    expect(workspaceMimeType('Objective.docx')).toBe(
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    );
    expect(workspaceMimeType('Objective.pdf')).toBe('application/pdf');
  });

  beforeEach(() => {
    jest.clearAllMocks();
    mockListFiles.mockResolvedValue({ items: [source], nextCursor: null });
    mockRead.mockResolvedValue(Buffer.from('test123'));
    mockSaveBuffer.mockResolvedValue('/uploads/user/new__Objective.docx');
    mockGetConvo.mockResolvedValue({ workspaceId: null });
  });

  it('creates a per-chat metadata-only pointer without moving file bytes', async () => {
    const result = await attachWorkspaceFile(req, {
      kind: 'user',
      sessionId: 'session-a',
      fileId: 'published-id',
      conversationId: 'conversation-1',
    });
    expect(mockGetConvo).toHaveBeenCalledWith('user-owner', 'conversation-1');
    expect(mockListFiles).toHaveBeenCalledWith(req, 'user', undefined, undefined, 500);
    expect(mockRead).not.toHaveBeenCalled();
    expect(mockSaveBuffer).not.toHaveBeenCalled();
    expect(mockCreateFile).toHaveBeenCalledWith(
      expect.objectContaining({
        user: 'user-owner',
        source: 'local',
        filepath: 'cbhrwsref://user/user-owner/session-a/published-id',
        bytes: 7,
        conversationId: 'conversation-1',
        metadata: expect.objectContaining({
          workspaceFileAttachment: true,
          codeEnvRef: {
            kind: 'user',
            id: 'user-owner',
            storage_session_id: 'session-a',
            file_id: 'published-id',
          },
        }),
      }),
      true,
    );
    expect(result).toMatchObject({
      filename: 'Objective.docx',
      bytes: 7,
      filepath: 'cbhrwsref://user/user-owner/session-a/published-id',
    });
  });

  it('attaches a role-less legacy file only after authorized CodeAPI list and read', async () => {
    mockListFiles.mockResolvedValue({
      items: [{ ...source, role: undefined }],
      nextCursor: null,
    });
    const result = await attachWorkspaceFile(req, {
      kind: 'user',
      sessionId: 'session-a',
      fileId: 'published-id',
    });
    expect(result).toMatchObject({ filename: 'Objective.docx', bytes: 7 });
    expect(mockRead).not.toHaveBeenCalled();
    expect(mockSaveBuffer).not.toHaveBeenCalled();
    expect(mockCreateFile).toHaveBeenCalledWith(
      expect.objectContaining({
        metadata: expect.objectContaining({
          codeEnvRef: expect.objectContaining({
            storage_session_id: 'session-a',
            file_id: 'published-id',
          }),
        }),
      }),
      true,
    );
  });

  it('enforces the exact project scope from the current chat', async () => {
    mockGetConvo.mockResolvedValue({ workspaceId: 'another-project' });
    await expect(
      verifyChatScope(req, 'project', 'project-a', 'conversation-1'),
    ).rejects.toMatchObject({ status: 409 });
    expect(mockRead).not.toHaveBeenCalled();
    mockGetConvo.mockResolvedValue({ workspaceId: 'project-a' });
    await attachWorkspaceFile(req, {
      kind: 'project',
      projectId: 'project-a',
      sessionId: 'session-a',
      fileId: 'published-id',
      conversationId: 'conversation-1',
    });
    expect(mockRead).not.toHaveBeenCalled();
    expect(mockSaveBuffer).not.toHaveBeenCalled();
    expect(mockCreateFile).toHaveBeenCalledWith(
      expect.objectContaining({
        metadata: expect.objectContaining({
          codeEnvRef: {
            kind: 'project',
            id: 'project-a',
            storage_session_id: 'session-a',
            file_id: 'published-id',
          },
        }),
      }),
      true,
    );
  });

  it('denies invented/traversal keys and non-published raw files before reading bytes', async () => {
    await expect(
      resolveListedArtifact(req, 'user', undefined, '../etc', 'x'),
    ).rejects.toMatchObject({ status: 400 });
    mockListFiles.mockResolvedValue({ items: [{ ...source, role: 'scratch' }], nextCursor: null });
    await expect(
      resolveListedArtifact(req, 'user', undefined, 'session-a', 'published-id'),
    ).rejects.toMatchObject({ status: 403 });
    expect(mockRead).not.toHaveBeenCalled();
  });

  it('denies not-found/trashed or oversized files', async () => {
    mockListFiles.mockResolvedValueOnce({ items: [], nextCursor: null });
    await expect(
      resolveListedArtifact(req, 'user', undefined, 'session-a', 'published-id'),
    ).rejects.toMatchObject({ status: 404 });
    mockListFiles.mockResolvedValueOnce({
      items: [{ ...source, size: MAX_ATTACH_BYTES + 1 }],
      nextCursor: null,
    });
    await expect(
      resolveListedArtifact(req, 'user', undefined, 'session-a', 'published-id'),
    ).rejects.toMatchObject({ status: 413 });
  });

  it('refuses removed files without ever storing a new copy', async () => {
    mockListFiles.mockResolvedValue({ items: [], nextCursor: null });
    await expect(
      attachWorkspaceFile(req, {
        kind: 'user',
        sessionId: 'session-a',
        fileId: 'published-id',
      }),
    ).rejects.toMatchObject({ status: 404 });
    expect(mockSaveBuffer).not.toHaveBeenCalled();
    expect(mockCreateFile).not.toHaveBeenCalled();
  });
});
