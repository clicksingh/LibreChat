import { Button, TrashIcon } from '@librechat/client';
import { Download, Paperclip } from 'lucide-react';
import {
  WORKSPACE_FILE_DRAG_TYPE,
  type WorkspaceAttachRequest,
} from '../../../utils/workspaceAttachment';
import { formatDate } from '../../../utils/files';
import { useLocalize } from '~/hooks';
import { formatWorkspaceBytes } from './formatBytes';
import type { TWorkspaceFileEntry } from 'librechat-data-provider';

/**
 * 8S3D.1 file browser table. Deliberately NOT the whole recursive tree in
 * one shot — `items` is always one bounded page from the server
 * (workspace/files?cursor=&limit=); "Load more" fetches the next page.
 */
export default function FileTable({
  items,
  onTrash,
  onDownload,
  onAttach,
  makeAttachRequest,
  attachingPath,
  downloadingPath,
  hasMore,
  onLoadMore,
  isLoadingMore,
}: {
  items: TWorkspaceFileEntry[];
  onTrash: (item: TWorkspaceFileEntry) => void;
  onDownload: (item: TWorkspaceFileEntry) => void;
  onAttach: (item: TWorkspaceFileEntry) => void;
  makeAttachRequest: (item: TWorkspaceFileEntry) => WorkspaceAttachRequest;
  attachingPath: string | null;
  downloadingPath: string | null;
  hasMore: boolean;
  onLoadMore: () => void;
  isLoadingMore: boolean;
}) {
  const localize = useLocalize();
  if (items.length === 0) {
    return (
      <div className="px-2 py-6 text-center text-sm text-text-secondary">
        {localize('com_cbhr_workspace_files_empty')}
      </div>
    );
  }
  return (
    <div className="w-full">
      <p className="pb-2 text-xs text-text-secondary">{localize('com_cbhr_workspace_drag_help')}</p>
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border-light text-left text-xs text-text-secondary">
            <th className="py-1 font-medium">{localize('com_cbhr_workspace_name')}</th>
            <th className="py-1 text-right font-medium">{localize('com_cbhr_workspace_size')}</th>
            <th className="py-1 text-right font-medium">
              {localize('com_cbhr_workspace_modified')}
            </th>
            <th className="py-1"></th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr
              key={item.path}
              draggable
              title={'Drag ' + item.name + ' into the chat composer'}
              onDragStart={(event) => {
                event.dataTransfer.effectAllowed = 'copy';
                event.dataTransfer.setData(
                  WORKSPACE_FILE_DRAG_TYPE,
                  JSON.stringify(makeAttachRequest(item)),
                );
              }}
              className="cursor-grab border-b border-border-light/50 hover:bg-surface-hover active:cursor-grabbing"
            >
              <td className="max-w-[200px] py-1.5" title={item.path}>
                <div className="truncate">{item.name}</div>
                {item.role && (
                  <div className="mt-0.5 text-[11px] text-text-secondary">
                    {item.role === 'output' ? 'Created by ChatGPT' : 'Uploaded'}
                  </div>
                )}
              </td>
              <td className="py-1.5 text-right text-xs text-text-secondary">
                {formatWorkspaceBytes(item.size)}
              </td>
              <td className="py-1.5 text-right text-xs text-text-secondary">
                {formatDate(item.modified)}
              </td>
              <td className="py-1.5 text-right">
                <div className="flex items-center justify-end gap-1">
                  <Button
                    size="sm"
                    variant="outline"
                    aria-label={'Attach ' + item.name + ' to chat'}
                    title="Attach to chat"
                    disabled={attachingPath !== null}
                    onClick={() => onAttach(item)}
                  >
                    <Paperclip className="h-4 w-4" aria-hidden="true" />
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    aria-label={'Download ' + item.name}
                    title="Download"
                    disabled={downloadingPath !== null}
                    onClick={() => onDownload(item)}
                  >
                    <Download className="h-4 w-4" aria-hidden="true" />
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    aria-label={'Move ' + item.name + ' to trash'}
                    title="Move to trash"
                    onClick={() => onTrash(item)}
                  >
                    <TrashIcon />
                  </Button>
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
