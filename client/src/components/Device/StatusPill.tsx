import type { LucideIcon } from 'lucide-react';
import { cn } from '~/utils';

/** Tones match the status-badge palette used by the MCP panel in this client. */
export type StatusTone = 'connected' | 'pending' | 'warning' | 'error' | 'neutral';

const TONE_PILL: Record<StatusTone, string> = {
  connected: 'bg-green-50 text-green-600 dark:bg-green-950 dark:text-green-400',
  pending: 'bg-blue-50 text-blue-600 dark:bg-blue-950 dark:text-blue-400',
  warning: 'bg-amber-50 text-amber-600 dark:bg-amber-950 dark:text-amber-400',
  error: 'bg-red-50 text-red-600 dark:bg-red-950 dark:text-red-400',
  neutral: 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400',
};

const TONE_DOT: Record<StatusTone, string> = {
  connected: 'bg-green-500',
  pending: 'bg-blue-500',
  warning: 'bg-amber-500',
  error: 'bg-red-500',
  neutral: 'bg-gray-400',
};

interface StatusPillProps {
  tone: StatusTone;
  label: string;
  icon?: LucideIcon;
  testId?: string;
}

export default function StatusPill({ tone, label, icon: Icon, testId }: StatusPillProps) {
  return (
    <div
      className={cn(
        'flex items-center gap-2 rounded-full px-2 py-0.5 text-xs font-medium',
        TONE_PILL[tone],
      )}
      data-testid={testId}
      data-status-tone={tone}
    >
      {Icon ? (
        <Icon className="size-3" aria-hidden="true" />
      ) : (
        <div className={cn('size-1.5 rounded-full', TONE_DOT[tone])} aria-hidden="true" />
      )}
      <span>{label}</span>
    </div>
  );
}
