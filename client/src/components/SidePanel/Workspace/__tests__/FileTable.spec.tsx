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
  const onAttach = jest.fn();
  const makeAttachRequest = jest.fn((item: TWorkspaceFileEntry) => ({
    kind: 'personal' as const,
    sessionId: item.sessionId,
    fileId: item.fileId,
    name: item.name,
    size: item.size,
  }));
  const onTrash = jest.fn();
  const defaults = {
    items: [file],
    onTrash,
    onDownload,
    onAttach,
    makeAttachRequest,
    attachingPath: null,
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

  it('makes the workspace row draggable without creating a browser File upload', () => {
    render(<FileTable {...defaults} />);
    const setData = jest.fn();
    const row = screen.getByText(file.name).closest('tr');
    expect(row).toHaveAttribute('draggable', 'true');
    fireEvent.dragStart(row!, { dataTransfer: { setData, effectAllowed: 'copy' } });
    expect(setData).toHaveBeenCalledWith(
      'application/x-cbhr-workspace-file',
      JSON.stringify(makeAttachRequest(file)),
    );
  });

  it('offers a click-to-attach fallback, independently of Download/Trash', () => {
    render(<FileTable {...defaults} />);
    fireEvent.click(screen.getByRole('button', { name: 'Attach ' + file.name + ' to chat' }));
    expect(onAttach).toHaveBeenCalledWith(file);
    expect(onDownload).not.toHaveBeenCalled();
    expect(onTrash).not.toHaveBeenCalled();
  });

  it('disables Download while a download is underway', () => {
    render(<FileTable {...defaults} downloadingPath={file.path} />);
    expect(screen.getByRole('button', { name: 'Download ' + file.name })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Move ' + file.name + ' to trash' })).toBeEnabled();
  });
});
