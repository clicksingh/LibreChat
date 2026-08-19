import { useState, useMemo } from 'react';
import { useToastContext } from '@librechat/client';
import { Constants } from 'librechat-data-provider';
import type {
  TWorkspaceFileEntry,
  TWorkspaceTrashEntry,
  TWorkspace,
} from 'librechat-data-provider';
import {
  useListWorkspacesQuery,
  usePersonalWorkspaceUsageQuery,
  useProjectWorkspaceUsageQuery,
  usePersonalWorkspaceFilesQuery,
  useProjectWorkspaceFilesQuery,
  usePersonalWorkspaceTrashQuery,
  useProjectWorkspaceTrashQuery,
  useTrashPersonalFileMutation,
  useRestorePersonalFileMutation,
  usePurgePersonalFileMutation,
  useTrashProjectFileMutation,
  useRestoreProjectFileMutation,
  usePurgeProjectFileMutation,
} from '~/data-provider';
import { useSetIndexOptions } from '~/hooks';
import { useChatContext } from '~/Providers';
import QuotaBar from './QuotaBar';
import FileTable from './FileTable';
import TrashTable from './TrashTable';
import CreateProjectDialog from './CreateProjectDialog';
import AdminQuotaPolicies from './AdminQuotaPolicies';

type Selection = { kind: 'personal' } | { kind: 'project'; id: string; name: string };
type View = 'files' | 'trash';

export default function WorkspacePanel() {
  const { showToast } = useToastContext();
  const { conversation } = useChatContext();
  const { setOption } = useSetIndexOptions();
  const [selection, setSelection] = useState<Selection>({ kind: 'personal' });
  const [view, setView] = useState<View>('files');

  const { data: workspaceList } = useListWorkspacesQuery();
  const projects: TWorkspace[] = workspaceList?.projects ?? [];

  const isPersonal = selection.kind === 'personal';
  const projectId = selection.kind === 'project' ? selection.id : undefined;

  const personalUsage = usePersonalWorkspaceUsageQuery({ enabled: isPersonal });
  const projectUsage = useProjectWorkspaceUsageQuery(projectId);
  const usage = isPersonal ? personalUsage.data : projectUsage.data;

  const personalFiles = usePersonalWorkspaceFilesQuery();
  const projectFiles = useProjectWorkspaceFilesQuery(projectId);
  const filesQuery = isPersonal ? personalFiles : projectFiles;
  const fileItems: TWorkspaceFileEntry[] = useMemo(
    () => filesQuery.data?.pages.flatMap((p) => p.items) ?? [],
    [filesQuery.data],
  );

  const personalTrash = usePersonalWorkspaceTrashQuery();
  const projectTrash = useProjectWorkspaceTrashQuery(projectId);
  const trashQuery = isPersonal ? personalTrash : projectTrash;
  const trashItems: TWorkspaceTrashEntry[] = useMemo(
    () => trashQuery.data?.pages.flatMap((p) => p.items) ?? [],
    [trashQuery.data],
  );

  const trashPersonal = useTrashPersonalFileMutation();
  const restorePersonal = useRestorePersonalFileMutation();
  const purgePersonal = usePurgePersonalFileMutation();
  const trashProject = useTrashProjectFileMutation(projectId ?? '');
  const restoreProject = useRestoreProjectFileMutation(projectId ?? '');
  const purgeProject = usePurgeProjectFileMutation(projectId ?? '');

  const handleTrash = (item: TWorkspaceFileEntry) => {
    const payload = { session_id: item.sessionId, file_id: item.fileId };
    (isPersonal ? trashPersonal : trashProject).mutate(payload, {
      onSuccess: () => showToast({ message: `${item.name} moved to trash` }),
      onError: () => showToast({ message: 'Failed to trash file', status: 'error' }),
    });
  };

  const handleRestore = (item: TWorkspaceTrashEntry) => {
    (isPersonal ? restorePersonal : restoreProject).mutate(
      { trash_id: item.trashId },
      {
        onSuccess: () => showToast({ message: `${item.name} restored` }),
        onError: () =>
          showToast({ message: 'Restore failed — a file may already exist there', status: 'error' }),
      },
    );
  };

  const handlePurge = (item: TWorkspaceTrashEntry) => {
    (isPersonal ? purgePersonal : purgeProject).mutate(
      { trash_id: item.trashId },
      {
        onSuccess: () => showToast({ message: `${item.name} permanently deleted` }),
        onError: () => showToast({ message: 'Purge failed', status: 'error' }),
      },
    );
  };

  const activeForNewChat =
    (conversation?.conversationId == null || conversation?.conversationId === Constants.NEW_CONVO) &&
    (isPersonal ? !conversation?.workspaceId : conversation?.workspaceId === projectId);

  const useForNewChat = () => {
    // '' (not null) — TSetOption's value union has no null variant; the
    // server treats a falsy workspaceId the same as unset (personal).
    setOption('workspaceId')(isPersonal ? '' : (projectId as string));
    showToast({
      message: isPersonal
        ? 'New chats will use your personal workspace'
        : `New chats will use "${(selection as { name: string }).name}"`,
    });
  };

  return (
    <div data-testid="workspace-panel" className="flex h-auto w-full flex-col gap-2 px-3 pb-3 pt-2">
      <div className="flex flex-wrap items-center gap-2">
        <select
          className="rounded-md border border-border-light bg-surface-primary px-2 py-1 text-sm"
          value={isPersonal ? 'personal' : (projectId as string)}
          onChange={(e) => {
            if (e.target.value === 'personal') {
              setSelection({ kind: 'personal' });
            } else {
              const proj = projects.find((p) => p._id === e.target.value);
              if (proj) setSelection({ kind: 'project', id: proj._id, name: proj.name });
            }
          }}
        >
          <option value="personal">Personal</option>
          {projects.map((p) => (
            <option key={p._id} value={p._id}>
              {p.name}
            </option>
          ))}
        </select>
        <CreateProjectDialog
          onCreated={(id) => {
            const created = projects.find((p) => p._id === id);
            setSelection({ kind: 'project', id, name: created?.name ?? 'New project' });
          }}
        />
        {!activeForNewChat && (
          <button
            type="button"
            className="text-xs text-blue-500 underline hover:text-blue-600"
            onClick={useForNewChat}
          >
            Use for new chat
          </button>
        )}
        {activeForNewChat && (
          <span className="text-xs text-text-secondary">Active for new chats</span>
        )}
      </div>

      <QuotaBar usage={usage} />

      <div className="flex gap-1 border-b border-border-light text-sm">
        <button
          type="button"
          className={`px-2 py-1 ${view === 'files' ? 'border-b-2 border-blue-500 font-medium' : 'text-text-secondary'}`}
          onClick={() => setView('files')}
        >
          Files
        </button>
        <button
          type="button"
          className={`px-2 py-1 ${view === 'trash' ? 'border-b-2 border-blue-500 font-medium' : 'text-text-secondary'}`}
          onClick={() => setView('trash')}
        >
          Trash
        </button>
      </div>

      {view === 'files' ? (
        <FileTable
          items={fileItems}
          onTrash={handleTrash}
          hasMore={!!filesQuery.hasNextPage}
          onLoadMore={() => filesQuery.fetchNextPage()}
          isLoadingMore={!!filesQuery.isFetchingNextPage}
        />
      ) : (
        <TrashTable
          items={trashItems}
          onRestore={handleRestore}
          onPurge={handlePurge}
          hasMore={!!trashQuery.hasNextPage}
          onLoadMore={() => trashQuery.fetchNextPage()}
          isLoadingMore={!!trashQuery.isFetchingNextPage}
        />
      )}

      <AdminQuotaPolicies />
    </div>
  );
}
