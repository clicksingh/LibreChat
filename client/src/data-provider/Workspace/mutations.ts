import { useMutation, useQueryClient } from '@tanstack/react-query';
import { QueryKeys, dataService } from 'librechat-data-provider';
import type { UseMutationResult } from '@tanstack/react-query';
import type {
  TWorkspace,
  TCreateWorkspaceRequest,
  TWorkspaceMemberGrantRequest,
} from 'librechat-data-provider';

export const useCreateWorkspaceMutation = (): UseMutationResult<
  TWorkspace,
  unknown,
  TCreateWorkspaceRequest
> => {
  const queryClient = useQueryClient();
  return useMutation((payload) => dataService.createWorkspace(payload), {
    onSuccess: () => queryClient.invalidateQueries([QueryKeys.workspaces]),
  });
};

export const useRenameWorkspaceMutation = (): UseMutationResult<
  TWorkspace,
  unknown,
  { id: string; name: string }
> => {
  const queryClient = useQueryClient();
  return useMutation(({ id, name }) => dataService.renameWorkspace(id, name), {
    onSuccess: () => queryClient.invalidateQueries([QueryKeys.workspaces]),
  });
};

export const useArchiveWorkspaceMutation = (): UseMutationResult<TWorkspace, unknown, string> => {
  const queryClient = useQueryClient();
  return useMutation((id) => dataService.archiveWorkspace(id), {
    onSuccess: () => queryClient.invalidateQueries([QueryKeys.workspaces]),
  });
};

export const useAddWorkspaceMemberMutation = (
  workspaceId: string,
): UseMutationResult<unknown, unknown, TWorkspaceMemberGrantRequest> => {
  return useMutation((payload) => dataService.addWorkspaceMember(workspaceId, payload));
};

export const useRemoveWorkspaceMemberMutation = (
  workspaceId: string,
): UseMutationResult<unknown, unknown, { principalType: string; principalId: string }> => {
  return useMutation(({ principalType, principalId }) =>
    dataService.removeWorkspaceMember(workspaceId, principalType, principalId),
  );
};

/* ---- personal workspace trash lifecycle ---- */

export const useTrashPersonalFileMutation = (): UseMutationResult<
  unknown,
  unknown,
  { session_id: string; file_id: string }
> => {
  const queryClient = useQueryClient();
  return useMutation((payload) => dataService.trashPersonalWorkspaceFile(payload), {
    onSuccess: () => {
      queryClient.invalidateQueries([QueryKeys.workspaceFiles, 'personal']);
      queryClient.invalidateQueries([QueryKeys.workspaceTrash, 'personal']);
      queryClient.invalidateQueries([QueryKeys.workspaceUsage, 'personal']);
    },
  });
};

export const useRestorePersonalFileMutation = (): UseMutationResult<
  unknown,
  unknown,
  { trash_id: string; newName?: string }
> => {
  const queryClient = useQueryClient();
  return useMutation((payload) => dataService.restorePersonalWorkspaceFile(payload), {
    onSuccess: () => {
      queryClient.invalidateQueries([QueryKeys.workspaceFiles, 'personal']);
      queryClient.invalidateQueries([QueryKeys.workspaceTrash, 'personal']);
    },
  });
};

export const usePurgePersonalFileMutation = (): UseMutationResult<
  unknown,
  unknown,
  { trash_id: string }
> => {
  const queryClient = useQueryClient();
  return useMutation((payload) => dataService.purgePersonalWorkspaceFile(payload), {
    onSuccess: () => {
      queryClient.invalidateQueries([QueryKeys.workspaceTrash, 'personal']);
      queryClient.invalidateQueries([QueryKeys.workspaceUsage, 'personal']);
    },
  });
};

/* ---- project workspace trash lifecycle ---- */

export const useTrashProjectFileMutation = (
  workspaceId: string,
): UseMutationResult<unknown, unknown, { session_id: string; file_id: string }> => {
  const queryClient = useQueryClient();
  return useMutation((payload) => dataService.trashProjectWorkspaceFile(workspaceId, payload), {
    onSuccess: () => {
      queryClient.invalidateQueries([QueryKeys.workspaceFiles, 'project', workspaceId]);
      queryClient.invalidateQueries([QueryKeys.workspaceTrash, 'project', workspaceId]);
      queryClient.invalidateQueries([QueryKeys.workspaceUsage, 'project', workspaceId]);
    },
  });
};

export const useRestoreProjectFileMutation = (
  workspaceId: string,
): UseMutationResult<unknown, unknown, { trash_id: string; newName?: string }> => {
  const queryClient = useQueryClient();
  return useMutation((payload) => dataService.restoreProjectWorkspaceFile(workspaceId, payload), {
    onSuccess: () => {
      queryClient.invalidateQueries([QueryKeys.workspaceFiles, 'project', workspaceId]);
      queryClient.invalidateQueries([QueryKeys.workspaceTrash, 'project', workspaceId]);
    },
  });
};

export const usePurgeProjectFileMutation = (
  workspaceId: string,
): UseMutationResult<unknown, unknown, { trash_id: string }> => {
  const queryClient = useQueryClient();
  return useMutation((payload) => dataService.purgeProjectWorkspaceFile(workspaceId, payload), {
    onSuccess: () => {
      queryClient.invalidateQueries([QueryKeys.workspaceTrash, 'project', workspaceId]);
      queryClient.invalidateQueries([QueryKeys.workspaceUsage, 'project', workspaceId]);
    },
  });
};
