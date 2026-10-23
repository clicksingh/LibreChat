import { Progress } from '@librechat/client';
import { formatDuration } from './deriveView';
import { deviceCopy } from './copy';

interface PairingCountdownProps {
  remainingMs: number;
  /** Length of the window being counted down, used for the progress bar. */
  totalMs: number;
  label: string;
  testId?: string;
}

/**
 * The 300-second code-related countdown (entry window, and the approval window after a code is
 * accepted). The bar is a convenience: the server owns the real expiry, and the panel says so.
 */
export default function PairingCountdown({
  remainingMs,
  totalMs,
  label,
  testId,
}: PairingCountdownProps) {
  const clamped = Math.max(0, Math.min(remainingMs, totalMs));
  const value = totalMs > 0 ? Math.round((clamped / totalMs) * 100) : 0;

  return (
    <div className="space-y-1.5" data-testid={testId}>
      <div className="flex items-center justify-between text-xs text-text-secondary">
        <span>{label}</span>
        <span className="tabular-nums text-text-primary">
          {formatDuration(clamped, deviceCopy.units)}
        </span>
      </div>
      <Progress value={value} aria-label={label} />
    </div>
  );
}
