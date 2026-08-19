import { Button, TrashIcon } from '@librechat/client';
import { formatBytes, formatDate } from '~/utils';
import type { TWorkspaceFileEntry } from 'librechat-data-provider';

/**
 * 8S3D.1 file browser table. Deliberately NOT the whole recursive tree in
 * one shot — `items` is always one bounded page from the server
 * (workspace/files?cursor=&limit=); "Load more" fetches the next page.
 */
export default function FileTable({
  items,
  onTrash,
  hasMore,
  onLoadMore,
  isLoadingMore,
}: {
  items: TWorkspaceFileEntry[];
  onTrash: (item: TWorkspaceFileEntry) => void;
  hasMore: boolean;
  onLoadMore: () => void;
  isLoadingMore: boolean;
}) {
  if (items.length === 0) {
    return <div className="px-2 py-6 text-center text-sm text-text-secondary">No files yet.</div>;
  }
  return (
    <div className="w-full">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border-light text-left text-xs text-text-secondary">
            <th className="py-1 font-medium">Name</th>
            <th className="py-1 text-right font-medium">Size</th>
            <th className="py-1 text-right font-medium">Modified</th>
            <th className="py-1"></th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.path} className="border-b border-border-light/50 hover:bg-surface-hover">
              <td className="max-w-[200px] truncate py-1.5" title={item.path}>
                {item.name}
              </td>
              <td className="py-1.5 text-right text-xs text-text-secondary">
                {formatBytes(item.size)}
              </td>
              <td className="py-1.5 text-right text-xs text-text-secondary">
                {formatDate(item.modified)}
              </td>
              <td className="py-1.5 text-right">
                <Button
                  size="sm"
                  variant="outline"
                  aria-label={`Move ${item.name} to trash`}
                  title="Move to trash"
                  onClick={() => onTrash(item)}
                >
                  <TrashIcon />
                </Button>
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
