import {
  WORKSPACE_FILE_DRAG_TYPE,
  makeWorkspaceAttachRequest,
  readWorkspaceFileDrop,
  isWorkspaceFileDrag,
  matchesWorkspaceChatScope,
  isWorkspaceAttachRequest,
  beginWorkspaceFileAttach,
  requestWorkspaceFileAttach,
  WORKSPACE_ATTACH_EVENT,
} from '../workspaceAttachment';

const item = {
  sessionId: 'lc-session',
  fileId: 'code-file',
  path: 'lc-session/code-file',
  name: 'report.docx',
  role: 'output' as const,
  size: 125298,
  modified: '2026-10-16T21:00:00Z',
};

describe('Workspace ? composer drag identity', () => {
  it('preserves only opaque keys and scope, not a host file path', () => {
    expect(makeWorkspaceAttachRequest(item, { kind: 'project', id: 'project-id' })).toEqual({
      kind: 'project',
      projectId: 'project-id',
      sessionId: 'lc-session',
      fileId: 'code-file',
      name: 'report.docx',
      size: 125298,
    });
  });

  it('distinguishes workspace identity drags from OS file drops', () => {
    expect(isWorkspaceFileDrag({ types: [WORKSPACE_FILE_DRAG_TYPE] })).toBe(true);
    expect(isWorkspaceFileDrag({ types: ['Files'] })).toBe(false);
  });

  it('accepts CBHR AI custom endpoint with matching workspace just like agents', () => {
    const personal = makeWorkspaceAttachRequest(item, { kind: 'personal' });
    const project = makeWorkspaceAttachRequest(item, { kind: 'project', id: 'ws-1' });
    expect(matchesWorkspaceChatScope(personal, { endpoint: 'CBHR AI' })).toBe(true);
    expect(matchesWorkspaceChatScope(project, { endpoint: 'CBHR AI', workspaceId: 'ws-1' })).toBe(
      true,
    );
    expect(matchesWorkspaceChatScope(project, { endpoint: 'agents', workspaceId: 'ws-2' })).toBe(
      false,
    );
    expect(matchesWorkspaceChatScope(personal, { endpoint: 'CBHR AI', workspaceId: 'ws-1' })).toBe(
      false,
    );
  });

  it('preserves personal and project scope in actual drag payloads and rejects untrusted keys', () => {
    const data = (value: unknown) => ({ getData: () => JSON.stringify(value) });
    const personal = makeWorkspaceAttachRequest(item, { kind: 'personal' });
    const project = makeWorkspaceAttachRequest(item, { kind: 'project', id: 'ws-1' });
    expect(readWorkspaceFileDrop(data(personal))).toEqual(personal);
    expect(readWorkspaceFileDrop(data(project))).toEqual(project);
    for (const forged of [
      { ...personal, sessionId: '../escape' },
      { ...personal, fileId: '.pending' },
      { ...personal, sessionId: '' },
      { ...personal, projectId: 'unexpected-project' },
      { ...personal, name: '' },
      { ...personal, size: NaN },
      { ...project, projectId: '../wrong' },
      { ...project, projectId: '' },
    ]) {
      expect(readWorkspaceFileDrop(data(forged))).toBeNull();
      expect(isWorkspaceAttachRequest(forged)).toBe(false);
    }
  });

  it('routes paperclip attach through the same scoped event as workspace drops', () => {
    const project = makeWorkspaceAttachRequest(item, { kind: 'project', id: 'project-1' });
    const listener = jest.fn();
    window.addEventListener(WORKSPACE_ATTACH_EVENT, listener);
    try {
      requestWorkspaceFileAttach(project);
      expect(listener).toHaveBeenCalledTimes(1);
      expect((listener.mock.calls[0][0] as CustomEvent).detail).toEqual(project);
    } finally {
      window.removeEventListener(WORKSPACE_ATTACH_EVENT, listener);
    }
  });

  it('blocks same-tick duplicate drops and always releases composer loading', () => {
    const lock = { current: false };
    const loading = jest.fn();
    const finish = beginWorkspaceFileAttach(lock, loading);
    expect(finish).not.toBeNull();
    expect(lock.current).toBe(true);
    expect(loading).toHaveBeenCalledWith(true);
    expect(beginWorkspaceFileAttach(lock, loading)).toBeNull();
    expect(loading).toHaveBeenCalledTimes(1);
    finish?.();
    finish?.();
    expect(lock.current).toBe(false);
    expect(loading.mock.calls).toEqual([[true], [false]]);
    const failedRetryFinish = beginWorkspaceFileAttach(lock, loading);
    expect(failedRetryFinish).not.toBeNull();
    failedRetryFinish?.();
    expect(lock.current).toBe(false);
    expect(loading.mock.calls).toEqual([[true], [false], [true], [false]]);
  });

  it('ignores tampered/incomplete drag metadata instead of invoking upload', () => {
    const data = (value: unknown) => ({ getData: () => JSON.stringify(value) });
    expect(readWorkspaceFileDrop(data({ kind: 'project', fileId: 'f' }))).toBeNull();
    expect(
      readWorkspaceFileDrop(
        data({ kind: 'personal', sessionId: 's', fileId: 'f', name: 'x', size: -1 }),
      ),
    ).toBeNull();
    expect(readWorkspaceFileDrop({ getData: () => 'not-json' })).toBeNull();
    expect(
      readWorkspaceFileDrop(data(makeWorkspaceAttachRequest(item, { kind: 'personal' }))),
    ).toMatchObject({
      kind: 'personal',
      sessionId: 'lc-session',
      fileId: 'code-file',
    });
  });
});
