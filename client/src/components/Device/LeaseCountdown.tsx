import { formatDuration } from './deriveView';
import { deviceCopy } from './copy';

interface LeaseCountdownProps {
  /** Server-reported lease expiry in epoch millis. */
  expiresAt: number;
  /** Current tick from `useNow`. */
  now: number;
  label: string;
}

/**
 * Live countdown to the server-reported lease expiry. Display only: nothing in this component
 * can extend the lease, and reaching zero simply flips the status card to the expired state on
 * the next render.
 */
export default function LeaseCountdown({ expiresAt, now, label }: LeaseCountdownProps) {
  const remainingMs = Math.max(0, expiresAt - now);

  return (
    <span className="flex items-baseline gap-1.5">
      <span className="text-xs text-text-secondary">{label}</span>
      <span
        className="text-sm font-medium tabular-nums text-text-primary"
        data-testid="device-lease-countdown"
      >
        {formatDuration(remainingMs, deviceCopy.units)}
      </span>
    </span>
  );
}
