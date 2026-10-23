import { BellRing, ShieldCheck } from 'lucide-react';
import { interpolate, deviceCopy } from './copy';
import { formatDuration } from './deriveView';

interface RenewalNudgeProps {
  /** True when the lease expires inside the T-2h window the tray app also uses (GM-3). */
  renewalDue: boolean;
  /** Live remaining milliseconds on the lease, or null when unknown. */
  remainingMs: number | null;
}

/**
 * RENEWAL IS A NUDGE, NOT AN APPROVAL — and this component is the whole of the panel's renewal
 * surface.
 *
 * There is intentionally no renew button, no renew handler, and no import of anything that could
 * renew: `api.ts` does not allow the renew path, so there is no function to call. Renewal needs
 * fresh LOCAL confirmation on the PC (docs/ARCHITECTURE.md boundary 7) and owner identity is
 * confined to the backend (D007), so a stolen browser session must never be able to extend
 * device access. The panel's only renewal action is to tell the employee to use the tray prompt
 * on their own PC (GM-12 / GM-3).
 */
export default function RenewalNudge({ renewalDue, remainingMs }: RenewalNudgeProps) {
  const remaining =
    remainingMs === null
      ? deviceCopy.status.unknown
      : formatDuration(remainingMs, deviceCopy.units);

  if (!renewalDue) {
    return (
      <div
        className="rounded-lg border border-border-light bg-surface-secondary px-3 py-2 text-xs leading-relaxed text-text-secondary"
        data-testid="device-renewal-nudge"
      >
        <span className="font-medium text-text-primary">{deviceCopy.renew.heading}: </span>
        {deviceCopy.renew.alwaysNote}
      </div>
    );
  }

  return (
    <div
      role="status"
      aria-live="polite"
      className="rounded-lg border border-amber-300/60 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-900 dark:bg-amber-950/60 dark:text-amber-200"
      data-testid="device-renewal-due"
    >
      <div className="flex items-center gap-2 font-medium">
        <BellRing className="size-4 shrink-0" aria-hidden="true" />
        {deviceCopy.renew.dueTitle}
      </div>
      <p className="mt-1 text-xs leading-relaxed">
        {interpolate(deviceCopy.renew.dueBody, { remaining })}
      </p>
      <ol className="mt-2 list-decimal space-y-1 pl-5 text-xs leading-relaxed">
        {deviceCopy.renew.dueSteps.map((step) => (
          <li key={step}>{step}</li>
        ))}
      </ol>
      <p className="mt-2 flex items-start gap-1.5 text-xs leading-relaxed">
        <ShieldCheck className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
        <span>{deviceCopy.renew.securityNote}</span>
      </p>
    </div>
  );
}
