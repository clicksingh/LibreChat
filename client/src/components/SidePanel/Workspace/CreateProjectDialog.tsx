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

export default function CreateProjectDialog({ onCreated }: { onCreated: (id: string) => void }) {
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
          + New project
        </Button>
      </OGDialogTrigger>
      <OGDialogTemplate
        title="Create a project workspace"
        className="max-w-[450px]"
        main={
          <div className="flex w-full flex-col gap-2">
            <Label htmlFor="workspace-name" className="text-left text-sm font-medium">
              Name
            </Label>
            <Input
              id="workspace-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={100}
              placeholder="e.g. Q3 Listings"
              autoFocus
            />
            <p className="text-xs text-text-secondary">
              A shared, quota-enforced storage boundary. You can add members after creating it.
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
