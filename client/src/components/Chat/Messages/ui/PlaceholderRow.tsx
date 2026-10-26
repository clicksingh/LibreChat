import { memo } from 'react';
import { Spinner } from '@librechat/client';
import { useLocalize } from '~/hooks';

/** Height matches the SubRow action buttons row (31px) — keep in sync with HoverButtons. */
const PlaceholderRow = memo(function PlaceholderRow() {
  const localize = useLocalize();

  return (
    <div
      className="mt-1 flex h-[31px] items-center gap-2 text-xs text-text-secondary"
      role="status"
      aria-live="polite"
      data-testid="generation-working-indicator"
    >
      <Spinner className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
      <span>{localize('com_ui_working')}</span>
    </div>
  );
});
PlaceholderRow.displayName = 'PlaceholderRow';

export default PlaceholderRow;
