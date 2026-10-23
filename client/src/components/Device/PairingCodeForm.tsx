import { useId } from 'react';
import { Button, Input } from '@librechat/client';
import { KeyRound } from 'lucide-react';
import { PAIRING_CODE_LENGTH, PAIRING_CODE_TTL_MS, SIX_DIGIT_CODE_PATTERN } from './constants';
import { filterCodeInput } from './deriveView';
import { deviceCopy } from './copy';
import ErrorNotice from './ErrorNotice';
import PairingCountdown from './PairingCountdown';
import type { FormEvent } from 'react';
import type { DeviceApiError } from './types';

interface PairingCodeFormProps {
  code: string;
  onChangeCode: (next: string) => void;
  onSubmit: () => void;
  isSubmitting: boolean;
  error: DeviceApiError | null;
  /** Remaining milliseconds in the 300 s entry window, or null before typing starts. */
  entryRemainingMs: number | null;
  windowExpired: boolean;
  onReset: () => void;
}

interface ApproveErrorCopy {
  tone: 'error' | 'warning';
  title: string;
  body: string;
}

/**
 * Maps a failed approval onto plain words. The backend's uniform `INVALID_OR_EXPIRED_CODE` miss
 * deliberately does not say WHICH of used/expired/mistyped happened, so this copy must not
 * pretend to know — and must never suggest that anything was approved.
 */
function presentApproveError(error: DeviceApiError): ApproveErrorCopy {
  if (error.kind === 'network') {
    return {
      tone: 'error',
      title: deviceCopy.errors.networkTitle,
      body: deviceCopy.errors.networkBody,
    };
  }
  if (error.kind === 'malformed') {
    return {
      tone: 'error',
      title: deviceCopy.errors.unknownTitle,
      body: deviceCopy.errors.unknownBody,
    };
  }
  if (error.status === 401) {
    return {
      tone: 'warning',
      title: deviceCopy.status.sessionExpiredTitle,
      body: deviceCopy.status.sessionExpiredBody,
    };
  }
  if (error.status === 429) {
    return {
      tone: 'warning',
      title: deviceCopy.errors.rateLimitedTitle,
      body: deviceCopy.errors.rateLimitedBody,
    };
  }
  if (error.status === 400 && error.code === 'INVALID_OR_EXPIRED_CODE') {
    return {
      tone: 'error',
      title: deviceCopy.errors.invalidCodeTitle,
      body: deviceCopy.errors.invalidCodeBody,
    };
  }
  return {
    tone: 'error',
    title: deviceCopy.errors.serverTitle,
    body: deviceCopy.errors.serverBody,
  };
}

/**
 * Six-digit code entry — the employee's only action in the whole pairing ceremony.
 *
 * `inputMode="numeric"` + `maxLength=6` + digits-only filtering keep the field to exactly the
 * shape the backend accepts; anything else never reaches the network (`api.ts` re-validates).
 * The 300 s countdown is code-related and honest about its own limits: the server owns the real
 * expiry. The panel has no challenge step, no issue step and no signing key — those legs belong
 * to the PC, which shows the code this form consumes.
 */
export default function PairingCodeForm({
  code,
  onChangeCode,
  onSubmit,
  isSubmitting,
  error,
  entryRemainingMs,
  windowExpired,
  onReset,
}: PairingCodeFormProps) {
  const inputId = useId();
  const hintId = useId();
  const errorId = useId();
  const isComplete = SIX_DIGIT_CODE_PATTERN.test(code);
  const canSubmit = isComplete && !isSubmitting && !windowExpired;
  const errorCopy = error === null ? null : presentApproveError(error);

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!canSubmit) {
      return;
    }
    onSubmit();
  };

  return (
    <form
      className="rounded-xl border border-border-light bg-surface-primary p-4 shadow-sm"
      onSubmit={handleSubmit}
      data-testid="device-pairing-form"
    >
      <div className="flex items-center gap-2">
        <KeyRound className="size-4 text-text-secondary" aria-hidden="true" />
        <h2 className="text-sm font-semibold text-text-primary">{deviceCopy.pairing.heading}</h2>
      </div>

      <p className="mt-2 text-xs font-medium text-text-secondary">{deviceCopy.panel.stepsTitle}</p>
      <ol className="mt-1 list-decimal space-y-1 pl-5 text-xs leading-relaxed text-text-secondary">
        {deviceCopy.pairing.steps.map((step) => (
          <li key={step}>{step}</li>
        ))}
      </ol>

      <div className="mt-4 space-y-2">
        <label htmlFor={inputId} className="block text-xs font-medium text-text-primary">
          {deviceCopy.pairing.label}
        </label>
        <Input
          id={inputId}
          value={code}
          onChange={(event) =>
            onChangeCode(filterCodeInput(event.target.value, PAIRING_CODE_LENGTH))
          }
          inputMode="numeric"
          pattern="[0-9]*"
          maxLength={PAIRING_CODE_LENGTH}
          autoComplete="one-time-code"
          placeholder={deviceCopy.pairing.inputPlaceholder}
          aria-describedby={errorCopy === null ? hintId : `${hintId} ${errorId}`}
          disabled={isSubmitting || windowExpired}
          className="max-w-56 text-center text-lg font-semibold tracking-[0.4em]"
          data-testid="device-code-input"
        />
        <p id={hintId} className="text-xs leading-relaxed text-text-secondary">
          {deviceCopy.pairing.hint}
        </p>

        {entryRemainingMs === null ? null : (
          <PairingCountdown
            remainingMs={entryRemainingMs}
            totalMs={PAIRING_CODE_TTL_MS}
            label={deviceCopy.pairing.entryWindowLabel}
            testId="device-entry-countdown"
          />
        )}
        <p className="text-xs leading-relaxed text-text-secondary">
          {deviceCopy.pairing.entryWindowNote}
        </p>

        {windowExpired ? (
          <ErrorNotice
            tone="warning"
            title={deviceCopy.pairing.entryWindowExpired}
            body={deviceCopy.pairing.singleUseNote}
            testId="device-entry-expired"
          />
        ) : null}

        {errorCopy === null ? null : (
          <div id={errorId}>
            <ErrorNotice
              tone={errorCopy.tone}
              title={errorCopy.title}
              body={errorCopy.body}
              detail={
                error === null || error.status === null
                  ? null
                  : `HTTP ${error.status}${error.code === null ? '' : ` ${error.code}`}`
              }
              testId="device-approve-error"
            />
          </div>
        )}

        <div className="flex flex-wrap items-center gap-2 pt-1">
          <Button
            type="submit"
            variant="submit"
            disabled={!canSubmit}
            data-testid="device-approve-button"
          >
            {isSubmitting ? deviceCopy.pairing.submitting : deviceCopy.pairing.submit}
          </Button>
          <Button type="button" variant="ghost" onClick={onReset} data-testid="device-reset-button">
            {deviceCopy.pairing.startOver}
          </Button>
        </div>

        <p className="text-xs leading-relaxed text-text-secondary">
          {deviceCopy.pairing.singleUseNote}
        </p>
      </div>
    </form>
  );
}
