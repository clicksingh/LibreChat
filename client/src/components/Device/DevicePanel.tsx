import { useCallback, useEffect, useState } from 'react';
import { PAIRING_CODE_TTL_MS, SIX_DIGIT_CODE_PATTERN } from './constants';
import { deriveStatusView, parseInstant, remainingUntil } from './deriveView';
import { useDeviceStatusQuery, usePairingApprovalMutation } from './useDeviceStatus';
import ClaimPendingNotice from './ClaimPendingNotice';
import DeviceStatusCard from './DeviceStatusCard';
import PairingCodeForm from './PairingCodeForm';
import { toDeviceApiError } from './api';
import { deviceCopy } from './copy';
import { useNow } from './useNow';
import type { ClaimWindow, DeviceApiError } from './types';

/**
 * The "My Computer" panel — a read-and-approve surface for the CBHR device bridge.
 *
 * WHAT THIS COMPONENT MAY DO
 * - read `GET /api/devices/current` and show what the server says;
 * - redeem a six-digit code with `POST /api/devices/pairing/approve`.
 *
 * WHAT IT MAY NEVER DO (enforced in `api.ts`, not by convention here)
 * - renew: renewal is a NUDGE to the tray prompt on the PC (GM-12/GM-3, ARCHITECTURE.md
 *   boundary 7, D007). There is no renew function to call;
 * - complete pairing: `/pairing/complete` is device-authenticated and belongs to the PC;
 * - mint or issue a code: `challenge`/`issue` need the PC's private key, which never exists in a
 *   browser. The PC shows the digits; the employee types them here.
 *
 * The state machine below is deliberately small: server truth comes from the query, and the only
 * local state is the code being typed and the approval window that follows a successful redeem.
 */
export default function DevicePanel() {
  const now = useNow();
  const [code, setCode] = useState('');
  const [entryStartedAt, setEntryStartedAt] = useState<number | null>(null);
  const [claim, setClaim] = useState<ClaimWindow | null>(null);
  const [approveError, setApproveError] = useState<DeviceApiError | null>(null);

  const claimActive = claim !== null && claim.deadline > now;
  const statusQuery = useDeviceStatusQuery({ claimPending: claimActive });
  const approval = usePairingApprovalMutation();

  const view = deriveStatusView({ error: statusQuery.error, payload: statusQuery.data, now });

  /** The lease landing is the end of the ceremony: drop the local approval window. */
  useEffect(() => {
    if (view.kind === 'connected' && claim !== null) {
      setClaim(null);
    }
  }, [view.kind, claim]);

  const entryDeadline = entryStartedAt === null ? null : entryStartedAt + PAIRING_CODE_TTL_MS;
  const entryRemainingMs = remainingUntil(entryDeadline, now);
  const entryExpired = entryRemainingMs !== null && entryRemainingMs <= 0;

  const handleCodeChange = useCallback((next: string) => {
    setApproveError(null);
    setCode(next);
    if (next.length > 0) {
      const startedAt = Date.now();
      setEntryStartedAt((current) => current ?? startedAt);
    }
  }, []);

  const handleSubmit = useCallback(() => {
    if (!SIX_DIGIT_CODE_PATTERN.test(code)) {
      return;
    }
    setApproveError(null);
    approval.mutate(code, {
      onSuccess: (payload) => {
        const approvedAt = Date.now();
        const serverDeadline = parseInstant(payload?.expiresAt ?? null);
        /** The code is spent: drop it from state and never resend it. */
        setCode('');
        setEntryStartedAt(null);
        setClaim({
          approvedAt,
          deadline: serverDeadline ?? approvedAt + PAIRING_CODE_TTL_MS,
        });
      },
      onError: (mutationError) => {
        setApproveError(toDeviceApiError(mutationError));
      },
    });
  }, [approval, code]);

  const handleReset = useCallback(() => {
    setCode('');
    setEntryStartedAt(null);
    setApproveError(null);
    setClaim(null);
    approval.reset();
  }, [approval]);

  const isConnected = view.kind === 'connected';
  const showPairingForm = !claimActive && !isConnected;
  const claimTotalMs =
    claim === null ? PAIRING_CODE_TTL_MS : Math.max(1, claim.deadline - claim.approvedAt);

  /**
   * While a freshly approved code is landing, `GET /current` legitimately 404s until the PC's
   * next `pairing/complete` poll creates the row. Rendering "no PC is paired" next to "code
   * approved" would contradict itself, so the claim card speaks for that window on its own.
   */
  const showStatusCard = !(claimActive && view.kind === 'no-device');

  return (
    <section
      className="mx-auto flex w-full max-w-3xl flex-col gap-4 px-4 py-6"
      data-testid="device-panel"
    >
      <header className="space-y-1">
        <h1 className="text-lg font-semibold text-text-primary">{deviceCopy.panel.title}</h1>
        <p className="text-sm text-text-secondary">{deviceCopy.panel.subtitle}</p>
      </header>

      {showStatusCard ? <DeviceStatusCard view={view} now={now} /> : null}

      {claim === null ? null : (
        <ClaimPendingNotice
          remainingMs={remainingUntil(claim.deadline, now)}
          totalMs={claimTotalMs}
          expired={!claimActive}
          onReset={handleReset}
        />
      )}

      {!claimActive && isConnected ? (
        <div
          className="rounded-xl border border-border-light bg-surface-primary p-4 shadow-sm"
          data-testid="device-already-paired"
        >
          <h2 className="text-sm font-semibold text-text-primary">
            {deviceCopy.pairing.alreadyPairedTitle}
          </h2>
          <p className="mt-1 text-xs leading-relaxed text-text-secondary">
            {deviceCopy.pairing.alreadyPairedBody}
          </p>
        </div>
      ) : null}

      {showPairingForm ? (
        <PairingCodeForm
          code={code}
          onChangeCode={handleCodeChange}
          onSubmit={handleSubmit}
          isSubmitting={approval.isLoading}
          error={approveError}
          entryRemainingMs={entryRemainingMs}
          windowExpired={entryExpired}
          onReset={handleReset}
        />
      ) : null}

      <footer
        className="rounded-lg border border-border-light bg-surface-secondary p-3 text-xs leading-relaxed text-text-secondary"
        data-testid="device-authority-note"
      >
        {deviceCopy.panel.authorityNote}
      </footer>
    </section>
  );
}
