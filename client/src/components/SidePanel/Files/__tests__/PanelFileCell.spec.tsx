import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import type { Row } from '@tanstack/react-table';
import { FileSources } from 'librechat-data-provider';
import type { TFile } from 'librechat-data-provider';
import PanelFileCell from '../PanelFileCell';

const mockDownload = jest.fn();
const mockAttachmentLink = jest.fn((_options: object) => ({ handleDownload: mockDownload }));

jest.mock('~/components/Chat/Messages/Content/Parts/LogLink', () => ({
  useAttachmentLink: (args: object) => mockAttachmentLink(args),
}));
jest.mock('~/components/Chat/Input/Files/ImagePreview', () => () => (
  <span data-testid="image-preview" />
));
jest.mock('~/components/Chat/Input/Files/FilePreview', () => () => (
  <span data-testid="file-preview" />
));
jest.mock('~/hooks', () => ({ useLocalize: () => (key: string) => key }));
jest.mock('~/utils', () => ({ getFileType: () => ({ paths: [], color: '', title: '' }) }));

const file: TFile = {
  file_id: 'file-id',
  user: 'user-id',
  filename: 'report.docx',
  filepath: '/api/files/download/user-id/file-id',
  object: 'file',
  type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  source: FileSources.local,
  embedded: false,
  usage: 0,
  bytes: 124,
};

describe('Files panel download control', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('uses the existing authenticated download link with file identity', () => {
    render(<PanelFileCell row={{ original: file } as Row<TFile>} />);

    expect(mockAttachmentLink).toHaveBeenCalledWith({
      href: file.filepath,
      filename: file.filename,
      file_id: file.file_id,
      user: file.user,
      source: file.source,
    });
    fireEvent.click(screen.getByRole('button', { name: 'com_ui_download report.docx' }));
    expect(mockDownload).toHaveBeenCalledTimes(1);
  });

  it('omits download when no target exists', () => {
    render(<PanelFileCell row={{ original: { ...file, filepath: '' } } as Row<TFile>} />);
    expect(screen.queryByRole('button', { name: /com_ui_download/ })).not.toBeInTheDocument();
  });
});
