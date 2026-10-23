import { AlertTriangle, Info } from 'lucide-react';
import { cn } from '~/utils';

export type NoticeTone = 'error' | 'warning';

interface ErrorNoticeProps {
  tone: NoticeTone;
  title: string;
  body: string;
  /** Optional machine detail (an HTTP status, for example). Never an identity value. */
  detail?: string | null;
  testId?: string;
}

/**
 * One notice component for every failure the panel can show. It is deliberately impossible for
 * a notice to render a success badge: notices only ever explain what is NOT confirmed.
 */
export default function ErrorNotice({ tone, title, body, detail, testId }: ErrorNoticeProps) {
  const Icon = tone === 'error' ? AlertTriangle : Info;
  const isAlert = tone === 'error';

  return (
    <div
      role={isAlert ? 'alert' : 'status'}
      className={cn(
        'flex gap-3 rounded-lg border p-3 text-sm',
        isAlert
          ? 'border-red-300/60 bg-red-50 text-red-900 dark:border-red-900 dark:bg-red-950/60 dark:text-red-200'
          : 'border-amber-300/60 bg-amber-50 text-amber-900 dark:border-amber-900 dark:bg-amber-950/60 dark:text-amber-200',
      )}
      data-testid={testId}
      data-notice-tone={tone}
    >
      <Icon className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      <div className="space-y-1">
        <p className="font-medium">{title}</p>
        <p className="text-xs leading-relaxed">{body}</p>
        {detail ? <p className="text-xs opacity-80">{detail}</p> : null}
      </div>
    </div>
  );
}
