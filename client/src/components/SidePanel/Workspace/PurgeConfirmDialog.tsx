import { Label, Button, OGDialog, TrashIcon, OGDialogTrigger, OGDialogTemplate } from '@librechat/client';

/**
 * 8S3D.1 — the ONLY way a workspace file is ever irreversibly destroyed.
 * Requires an explicit human click through this dialog every time (ADR 005
 * destructive-action approval boundary) — there is no model/agent tool that
 * can reach purge, and no "select all + purge" bulk shortcut that could be
 * misclicked into losing everything at once.
 */
export default function PurgeConfirmDialog({
  fileName,
  onConfirm,
  disabled,
}: {
  fileName: string;
  onConfirm: () => void;
  disabled?: boolean;
}) {
  return (
    <OGDialog>
      <OGDialogTrigger asChild>
        <Button
          size="sm"
          variant="outline"
          aria-label={`Permanently delete ${fileName}`}
          title="Purge (permanent)"
          type="button"
          disabled={disabled}
        >
          <div className="flex items-center justify-center gap-1 text-red-500">
            <TrashIcon />
          </div>
        </Button>
      </OGDialogTrigger>
      <OGDialogTemplate
        title="Permanently delete this file?"
        className="max-w-[450px]"
        main={
          <div className="flex w-full flex-col items-center gap-2">
            <div className="grid w-full items-center gap-2">
              <Label className="text-left text-sm font-medium">
                <span className="font-semibold">{fileName}</span> will be permanently deleted and
                cannot be recovered. This frees up your workspace quota.
              </Label>
            </div>
          </div>
        }
        selection={{
          selectHandler: onConfirm,
          selectClasses: 'bg-red-600 hover:bg-red-700 dark:hover:bg-red-800 text-white',
          selectText: 'Permanently delete',
        }}
      />
    </OGDialog>
  );
}
