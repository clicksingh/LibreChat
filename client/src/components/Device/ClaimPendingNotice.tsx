import { Button } from '@librechat/client';
import { deviceCopy } from './copy';
import ErrorNotice from './ErrorNotice';
import PairingCountdown from './PairingCountdown';
import StatusPill from './StatusPill';

interface ClaimPendingNoticeProps {
  /** Remaining milliseconds in the approval window, or null when it cannot be computed. */
  remainingMs: number | null;
  /** Length of the approval window, for the progress bar. */
  totalMs: number;
  /** True once the window has passed without the lease landing. */
  expired: boolean;
  onReset: () => void;
}

/**
 * Shown after the server accepts a code.
 *
 * This state exists because the panel's job truly ends at `pairing/approve` (GM-2): the code is
 * spent, and the PC's own poll of `pairing/complete` is what lands the lease. The panel says
 * exactly that — "waiting for your PC" — and never claims access in the meantime. If the window
 * closes first, it says so and offers a fresh start rather than a false success.
 */
export default function ClaimPendingNotice({
  remainingMs,
  totalMs,
  expired,
  onReset,
}: ClaimPendingNoticeProps) {
  return (
    <div
      className="rounded-xl border border-border-light bg-surface-primary p-4 shadow-sm"
      data-testid="device-claim-pending"
      data-claim-state={expired ? 'expired' : 'pending'}
    >
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-sm font-semibold text-text-primary">
          {deviceCopy.pairing.approvedTitle}
        </h2>
        <StatusPill
          tone={expired ? 'warning' : 'pending'}
          label={deviceCopy.pairing.approvedPendingBadge}
          testId="device-claim-pending-pill"
        />
      </div>
      <p className="mt-1 text-xs leading-relaxed text-text-secondary">
        {deviceCopy.pairing.approvedBody}
      </p>

      {expired || remainingMs === null ? null : (
        <div className="mt-3">
          <PairingCountdown
            remainingMs={remainingMs}
            totalMs={totalMs}
            label={deviceCopy.pairing.approvedWindowLabel}
            testId="device-claim-countdown"
          />
        </div>
      )}

      {expired ? (
        <div className="mt-3">
          <ErrorNotice
            tone="warning"
            title={deviceCopy.pairing.approvedWindowExpired}
            body={deviceCopy.pairing.singleUseNote}
            testId="device-claim-expired"
          />
        </div>
      ) : null}

      <div className="mt-3">
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={onReset}
          data-testid="device-claim-reset-button"
        >
          {deviceCopy.pairing.startOver}
        </Button>
      </div>
    </div>
  );
}
