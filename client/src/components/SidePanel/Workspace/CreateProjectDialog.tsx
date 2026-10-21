import { useState } from 'react';
import {
  Label,
  Input,
  Button,
  OGDialog,
  OGDialogTrigger,
  OGDialogTemplate,
  useToastContext,
} from '@librechat/client';
import { useCreateWorkspaceMutation } from '~/data-provider';
import { useLocalize } from '~/hooks';

export default function CreateProjectDialog({ onCreated }: { onCreated: (id: string) => void }) {
  const localize = useLocalize();
  const [name, setName] = useState('');
  const [open, setOpen] = useState(false);
  const { showToast } = useToastContext();
  const createWorkspace = useCreateWorkspaceMutation();

  const handleCreate = () => {
    const trimmed = name.trim();
    if (!trimmed) {
      return;
    }
    createWorkspace.mutate(
      { name: trimmed },
      {
        onSuccess: (workspace) => {
          showToast({ message: `Project "${workspace.name}" created` });
          setName('');
          setOpen(false);
          onCreated(workspace._id);
        },
        onError: () => showToast({ message: 'Failed to create project', status: 'error' }),
      },
    );
  };

  return (
    <OGDialog open={open} onOpenChange={setOpen}>
      <OGDialogTrigger asChild>
        <Button size="sm" variant="outline">
          {localize('com_cbhr_workspace_new_project')}
        </Button>
      </OGDialogTrigger>
      <OGDialogTemplate
        title="Create a project workspace"
        className="max-w-[450px]"
        main={
          <div className="flex w-full flex-col gap-2">
            <Label htmlFor="workspace-name" className="text-left text-sm font-medium">
              {localize('com_cbhr_workspace_name')}
            </Label>
            <Input
              id="workspace-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={100}
              placeholder="e.g. Q3 Listings"
            />
            <p className="text-xs text-text-secondary">
              {localize('com_cbhr_workspace_project_help')}
            </p>
          </div>
        }
        selection={{
          selectHandler: handleCreate,
          selectText: createWorkspace.isLoading ? 'Creating…' : 'Create',
        }}
      />
    </OGDialog>
  );
}
