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
    {
      refetchOnWindowFocus: true,
      staleTime: 15_000,
      // Same reasoning as the files/trash polling: code execution changes
      // usage server-side outside any client mutation, so a bar that only
      // refetches on focus/mount can sit stale (e.g. still "0%") for a full
      // panel session after a quota-exceeding write.
      refetchInterval: WORKSPACE_LISTING_POLL_MS,
      ...config,
    },
  );
};

export const useProjectWorkspaceUsageQuery = (
  workspaceId: string | undefined,
  config?: UseQueryOptions<TWorkspaceUsage>,
): QueryObserverResult<TWorkspaceUsage> => {
  return useQuery<TWorkspaceUsage>(
    [QueryKeys.workspaceUsage, 'project', workspaceId],
    () => dataService.getProjectWorkspaceUsage(workspaceId as string),
    {
      enabled: !!workspaceId,
      refetchOnWindowFocus: true,
      staleTime: 15_000,
      refetchInterval: WORKSPACE_LISTING_POLL_MS,
      ...config,
    },
  );
};

/** Personal workspace file browser — cursor-paginated, bounded per page (never a full recursive tree in one response). */
// Chat-driven code execution writes files server-side outside of any
// mutation this panel knows about, so a plain fetch-once-on-mount query can
// permanently miss a file created moments after the panel opened. Polling
// while the panel is open (react-query pauses this automatically once the
// observer unmounts) keeps the browser's view converging on server state
// without requiring a manual refresh.
const WORKSPACE_LISTING_POLL_MS = 5_000;

export const usePersonalWorkspaceFilesQuery = () => {
  return useInfiniteQuery<TWorkspaceFileListResponse>(
    [QueryKeys.workspaceFiles, 'personal'],
    ({ pageParam }) => dataService.listPersonalWorkspaceFiles({ cursor: pageParam, limit: 100 }),
    {
      getNextPageParam: (lastPage) => lastPage.nextCursor ?? undefined,
      refetchOnWindowFocus: false,
      refetchInterval: WORKSPACE_LISTING_POLL_MS,
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
      refetchInterval: WORKSPACE_LISTING_POLL_MS,
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
      refetchInterval: WORKSPACE_LISTING_POLL_MS,
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
      refetchInterval: WORKSPACE_LISTING_POLL_MS,
    },
  );
};
