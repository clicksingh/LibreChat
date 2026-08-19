import { useQuery, useInfiniteQuery } from '@tanstack/react-query';
import { QueryKeys, dataService } from 'librechat-data-provider';
import type { QueryObserverResult, UseQueryOptions } from '@tanstack/react-query';
import type {
  TWorkspaceListResponse,
  TWorkspaceUsage,
  TWorkspaceFileListResponse,
  TWorkspaceTrashListResponse,
} from 'librechat-data-provider';

export const useListWorkspacesQuery = (
  config?: UseQueryOptions<TWorkspaceListResponse>,
): QueryObserverResult<TWorkspaceListResponse> => {
  return useQuery<TWorkspaceListResponse>([QueryKeys.workspaces], () => dataService.listWorkspaces(), {
    refetchOnWindowFocus: false,
    ...config,
  });
};

export const usePersonalWorkspaceUsageQuery = (
  config?: UseQueryOptions<TWorkspaceUsage>,
): QueryObserverResult<TWorkspaceUsage> => {
  return useQuery<TWorkspaceUsage>(
    [QueryKeys.workspaceUsage, 'personal'],
    () => dataService.getPersonalWorkspaceUsage(),
    { refetchOnWindowFocus: true, staleTime: 15_000, ...config },
  );
};

export const useProjectWorkspaceUsageQuery = (
  workspaceId: string | undefined,
  config?: UseQueryOptions<TWorkspaceUsage>,
): QueryObserverResult<TWorkspaceUsage> => {
  return useQuery<TWorkspaceUsage>(
    [QueryKeys.workspaceUsage, 'project', workspaceId],
    () => dataService.getProjectWorkspaceUsage(workspaceId as string),
    { enabled: !!workspaceId, refetchOnWindowFocus: true, staleTime: 15_000, ...config },
  );
};

/** Personal workspace file browser — cursor-paginated, bounded per page (never a full recursive tree in one response). */
export const usePersonalWorkspaceFilesQuery = () => {
  return useInfiniteQuery<TWorkspaceFileListResponse>(
    [QueryKeys.workspaceFiles, 'personal'],
    ({ pageParam }) => dataService.listPersonalWorkspaceFiles({ cursor: pageParam, limit: 100 }),
    {
      getNextPageParam: (lastPage) => lastPage.nextCursor ?? undefined,
      refetchOnWindowFocus: false,
    },
  );
};

export const useProjectWorkspaceFilesQuery = (workspaceId: string | undefined) => {
  return useInfiniteQuery<TWorkspaceFileListResponse>(
    [QueryKeys.workspaceFiles, 'project', workspaceId],
    ({ pageParam }) =>
      dataService.listProjectWorkspaceFiles(workspaceId as string, { cursor: pageParam, limit: 100 }),
    {
      enabled: !!workspaceId,
      getNextPageParam: (lastPage) => lastPage.nextCursor ?? undefined,
      refetchOnWindowFocus: false,
    },
  );
};

export const usePersonalWorkspaceTrashQuery = () => {
  return useInfiniteQuery<TWorkspaceTrashListResponse>(
    [QueryKeys.workspaceTrash, 'personal'],
    ({ pageParam }) => dataService.listPersonalWorkspaceTrash({ cursor: pageParam, limit: 100 }),
    {
      getNextPageParam: (lastPage) => lastPage.nextCursor ?? undefined,
      refetchOnWindowFocus: false,
    },
  );
};

export const useProjectWorkspaceTrashQuery = (workspaceId: string | undefined) => {
  return useInfiniteQuery<TWorkspaceTrashListResponse>(
    [QueryKeys.workspaceTrash, 'project', workspaceId],
    ({ pageParam }) =>
      dataService.listProjectWorkspaceTrash(workspaceId as string, { cursor: pageParam, limit: 100 }),
    {
      enabled: !!workspaceId,
      getNextPageParam: (lastPage) => lastPage.nextCursor ?? undefined,
      refetchOnWindowFocus: false,
    },
  );
};
