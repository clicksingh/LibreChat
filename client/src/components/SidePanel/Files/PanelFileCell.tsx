import { Download } from 'lucide-react';
import type { Row } from '@tanstack/react-table';
import type { TFile } from 'librechat-data-provider';
import ImagePreview from '~/components/Chat/Input/Files/ImagePreview';
import FilePreview from '~/components/Chat/Input/Files/FilePreview';
import { getFileType } from '~/utils';
import { useAttachmentLink } from '~/components/Chat/Messages/Content/Parts/LogLink';
import { useLocalize } from '~/hooks';

export default function PanelFileCell({ row }: { row: Row<TFile | undefined> }) {
  const file = row.original;
  const localize = useLocalize();
  const { handleDownload } = useAttachmentLink({
    href: file?.filepath ?? '',
    filename: file?.filename ?? '',
    file_id: file?.file_id,
    user: file?.user,
    source: file?.source,
  });
  return (
    <div className="flex w-full items-center gap-2">
      {file?.type?.startsWith('image') === true ? (
        <ImagePreview
          url={file.filepath}
          className="h-8 w-8 flex-shrink-0"
          source={file.source}
          alt={file.filename}
        />
      ) : (
        <FilePreview fileType={getFileType(file?.type)} file={file} />
      )}
      <div className="min-w-0 flex-1 overflow-hidden">
        <span className="block w-full overflow-hidden truncate text-ellipsis whitespace-nowrap text-xs">
          {file?.filename}
        </span>
      </div>
      {file?.filepath && (
        <button
          type="button"
          onClick={handleDownload}
          aria-label={localize('com_ui_download') + ' ' + file.filename}
          title={localize('com_ui_download')}
          className="flex shrink-0 items-center gap-1 rounded-md px-2 py-1 text-xs text-text-secondary hover:bg-surface-hover hover:text-text-primary focus-visible:outline-2 focus-visible:outline-text-primary"
        >
          <Download className="h-3.5 w-3.5" aria-hidden="true" />
          <span>{localize('com_ui_download')}</span>
        </button>
      )}
    </div>
  );
}
