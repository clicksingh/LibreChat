import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import type { TWorkspaceFileEntry } from 'librechat-data-provider';
import FileTable from '../FileTable';

const file: TWorkspaceFileEntry = {
  sessionId: 'session-1',
  fileId: 'f-123',
  path: 'session-1/f-123',
  name: 'CBHR_Policies_and_Procedures_Manual_v1.0.docx',
  role: 'output',
  size: 125298,
  modified: '2026-10-16T21:00:00Z',
};

describe('Workspace Files table - download and trash actions', () => {
  const onDownload = jest.fn();
  const onTrash = jest.fn();
  const defaults = {
    items: [file],
    onTrash,
    onDownload,
    downloadingPath: null,
    hasMore: false,
    onLoadMore: jest.fn(),
    isLoadingMore: false,
  };

  beforeEach(() => jest.clearAllMocks());

  it('offers Download next to Trash and targets the selected file identity', () => {
    render(<FileTable {...defaults} />);
    expect(screen.getByText('Created by ChatGPT')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Download ' + file.name }));
    expect(onDownload).toHaveBeenCalledWith(file);
    expect(onTrash).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Move ' + file.name + ' to trash' }));
    expect(onTrash).toHaveBeenCalledWith(file);
  });

  it('disables Download while a download is underway', () => {
    render(<FileTable {...defaults} downloadingPath={file.path} />);
    expect(screen.getByRole('button', { name: 'Download ' + file.name })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Move ' + file.name + ' to trash' })).toBeEnabled();
  });
});
