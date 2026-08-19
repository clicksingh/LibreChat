import { Button } from '@librechat/client';
import { formatDate } from '~/utils';
import { formatWorkspaceBytes } from './formatBytes';
import PurgeConfirmDialog from './PurgeConfirmDialog';
import type { TWorkspaceTrashEntry } from 'librechat-data-provider';

export default function TrashTable({
  items,
  onRestore,
  onPurge,
  hasMore,
  onLoadMore,
  isLoadingMore,
}: {
  items: TWorkspaceTrashEntry[];
  onRestore: (item: TWorkspaceTrashEntry) => void;
  onPurge: (item: TWorkspaceTrashEntry) => void;
  hasMore: boolean;
  onLoadMore: () => void;
  isLoadingMore: boolean;
}) {
  if (items.length === 0) {
    return <div className="px-2 py-6 text-center text-sm text-text-secondary">Trash is empty.</div>;
  }
  return (
    <div className="w-full">
      <div className="mb-2 text-xs text-text-secondary">
        Trashed files still count against your quota until purged.
      </div>
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border-light text-left text-xs text-text-secondary">
            <th className="py-1 font-medium">Name</th>
            <th className="py-1 text-right font-medium">Size</th>
            <th className="py-1 text-right font-medium">Trashed</th>
            <th className="py-1"></th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr
              key={item.trashId}
              className="border-b border-border-light/50 hover:bg-surface-hover"
            >
              <td className="max-w-[160px] truncate py-1.5" title={item.originalRelPath}>
                {item.name}
              </td>
              <td className="py-1.5 text-right text-xs text-text-secondary">
                {formatWorkspaceBytes(item.size)}
              </td>
              <td className="py-1.5 text-right text-xs text-text-secondary">
                {formatDate(item.trashedAt)}
              </td>
              <td className="py-1.5 text-right">
                <div className="flex justify-end gap-1">
                  <Button size="sm" variant="outline" onClick={() => onRestore(item)}>
                    Restore
                  </Button>
                  <PurgeConfirmDialog fileName={item.name} onConfirm={() => onPurge(item)} />
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {hasMore && (
        <div className="mt-2 flex justify-center">
          <Button size="sm" variant="outline" onClick={onLoadMore} disabled={isLoadingMore}>
            {isLoadingMore ? 'Loading…' : 'Load more'}
          </Button>
        </div>
      )}
    </div>
  );
}
