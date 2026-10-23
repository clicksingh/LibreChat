import { Spinner } from '@librechat/client';
import { Clock, CheckCircle2, ShieldOff, ShieldAlert, ShieldQuestion } from 'lucide-react';
import { interpolate, deviceCopy } from './copy';
import { describeState, remainingUntil } from './deriveView';
import StatusPill from './StatusPill';
import ErrorNotice from './ErrorNotice';
import LeaseCountdown from './LeaseCountdown';
import RenewalNudge from './RenewalNudge';
import type { NoticeTone } from './ErrorNotice';
import type { StatusTone } from './StatusPill';
import type { DeviceApiError, LeaseSnapshot, StatusView } from './types';

/** The status kinds that carry a lease snapshot (everything except loading, notices, no-device). */
type LeaseStatusView = Extract<StatusView, { lease: LeaseSnapshot }>;

/** Transport, session and request problems — rendered as notices, never as a lease state. */
type AlertStatusView = Extract<
  StatusView,
  { kind: 'relay-error' | 'session-expired' | 'request-rejected' }
>;

interface DeviceStatusCardProps {
  view: StatusView;
  /** Current tick from `useNow`, so the countdown is live. */
  now: number;
}

interface CardPresentation {
  tone: StatusTone;
  badge: string;
  title: string;
  body: string;
}

const BADGE_ICONS = {
  connected: CheckCircle2,
  expired: Clock,
  revoked: ShieldOff,
  'paired-incomplete': ShieldAlert,
  unverified: ShieldQuestion,
} as const;

function presentLeaseView(view: LeaseStatusView): CardPresentation {
  switch (view.kind) {
    case 'connected':
      return {
        tone: 'connected',
        badge: deviceCopy.status.connectedBadge,
        title: deviceCopy.status.connectedTitle,
        body: deviceCopy.status.connectedBody,
      };
    case 'expired':
      return {
        tone: 'warning',
        badge: deviceCopy.status.expiredBadge,
        title: deviceCopy.status.expiredTitle,
        body: deviceCopy.status.expiredBody,
      };
    case 'revoked':
      return {
        tone: 'error',
        badge: deviceCopy.status.revokedBadge,
        title: deviceCopy.status.revokedTitle,
        body: deviceCopy.status.revokedBody,
      };
    case 'unverified':
      return {
        tone: 'warning',
        badge: deviceCopy.status.unverifiedBadge,
        title: deviceCopy.status.unverifiedTitle,
        body: deviceCopy.status.unverifiedBody,
      };
    case 'paired-incomplete':
    default:
      return {
        tone: 'pending',
        badge: deviceCopy.status.pairedIncompleteBadge,
        title: deviceCopy.status.pairedIncompleteTitle,
        body: deviceCopy.status.pairedIncompleteBody,
      };
  }
}

function relayDetail(error: DeviceApiError): string {
  if (error.kind === 'http' && error.status !== null) {
    return interpolate(deviceCopy.status.relayErrorDetailHttp, { status: String(error.status) });
  }
  if (error.kind === 'malformed') {
    return deviceCopy.status.relayErrorDetailMalformed;
  }
  return deviceCopy.status.relayErrorDetailNetwork;
}

function presentAlert(view: AlertStatusView): {
  tone: NoticeTone;
  title: string;
  body: string;
  detail: string | null;
} {
  if (view.kind === 'session-expired') {
    return {
      tone: 'warning',
      title: deviceCopy.status.sessionExpiredTitle,
      body: deviceCopy.status.sessionExpiredBody,
      detail: null,
    };
  }
  if (view.kind === 'request-rejected') {
    return {
      tone: 'error',
      title: deviceCopy.status.requestRejectedTitle,
      body: deviceCopy.status.requestRejectedBody,
      detail: null,
    };
  }
  return {
    tone: 'error',
    title: deviceCopy.status.relayErrorTitle,
    body: deviceCopy.status.relayErrorBody,
    detail: relayDetail(view.error),
  };
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-border-light py-1 last:border-b-0">
      <dt className="text-xs text-text-secondary">{label}</dt>
      <dd className="text-sm font-medium text-text-primary">{value}</dd>
    </div>
  );
}

/**
 * What the server says about this account's PC.
 *
 * The "Connected" pill is rendered only for `view.kind === 'connected'`, which `classifyLease`
 * produces only from an active identity, an active lease and an expiry that is still in the future
 * ON THE SERVER'S CLOCK. Every other state renders a different pill or a notice, so no failure mode
 * can leave a success badge on screen — and a browser whose local clock is wrong cannot manufacture
 * one either, because the countdown and the expiry test are both anchored to `serverTime`.
 */
export default function DeviceStatusCard({ view, now }: DeviceStatusCardProps) {
  if (view.kind === 'loading') {
    return (
      <div
        className="flex items-center gap-3 rounded-xl border border-border-light bg-surface-primary p-4 shadow-sm"
        data-testid="device-status-card"
        data-status-kind="loading"
      >
        <Spinner className="size-4 text-text-secondary" aria-label={deviceCopy.status.loading} />
        <span className="text-sm text-text-secondary">{deviceCopy.status.loading}</span>
      </div>
    );
  }

  if (
    view.kind === 'relay-error' ||
    view.kind === 'session-expired' ||
    view.kind === 'request-rejected'
  ) {
    const alert = presentAlert(view);
    return (
      <div data-testid="device-status-card" data-status-kind={view.kind}>
        <ErrorNotice
          tone={alert.tone}
          title={alert.title}
          body={alert.body}
          detail={alert.detail}
          testId="device-status-alert"
        />
      </div>
    );
  }

  if (view.kind === 'no-device') {
    return (
      <div
        className="rounded-xl border border-border-light bg-surface-primary p-4 shadow-sm"
        data-testid="device-status-card"
        data-status-kind="no-device"
      >
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-sm font-semibold text-text-primary">
            {deviceCopy.status.noDeviceTitle}
          </h2>
          <StatusPill
            tone="neutral"
            label={deviceCopy.status.noDeviceBadge}
            icon={ShieldAlert}
            testId="device-status-pill"
          />
        </div>
        <p className="mt-1 text-xs leading-relaxed text-text-secondary">
          {deviceCopy.status.noDeviceBody}
        </p>
      </div>
    );
  }

  const presentation = presentLeaseView(view);
  const Icon = BADGE_ICONS[view.kind];
  const { lease } = view;
  const epochLabel = lease.epoch === null ? deviceCopy.status.unknown : String(lease.epoch);
  const identityLabel = describeState(
    deviceCopy.status.identityStates,
    lease.identityState,
    deviceCopy.status.unknown,
  );
  const leaseLabel = describeState(
    deviceCopy.status.leaseStates,
    lease.leaseState,
    deviceCopy.status.unknown,
  );

  return (
    <div
      className="rounded-xl border border-border-light bg-surface-primary p-4 shadow-sm"
      data-testid="device-status-card"
      data-status-kind={view.kind}
    >
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-sm font-semibold text-text-primary">{presentation.title}</h2>
        <StatusPill
          tone={presentation.tone}
          label={presentation.badge}
          icon={Icon}
          testId="device-status-pill"
        />
      </div>
      <p className="mt-1 text-xs leading-relaxed text-text-secondary">{presentation.body}</p>

      <dl className="mt-3 space-y-1">
        <DetailRow label={deviceCopy.status.identityLabel} value={identityLabel} />
        <DetailRow label={deviceCopy.status.leaseLabel} value={leaseLabel} />
        <DetailRow label={deviceCopy.status.epochLabel} value={epochLabel} />
      </dl>

      {view.kind === 'connected' && lease.expiresAt !== null ? (
        <div className="mt-3 space-y-3">
          <LeaseCountdown
            expiresAt={lease.expiresAt}
            now={now + view.serverNowOffsetMs}
            label={deviceCopy.status.expiresLabel}
          />
          <RenewalNudge
            renewalDue={view.renewalDue}
            remainingMs={remainingUntil(lease.expiresAt, now + view.serverNowOffsetMs)}
          />
        </div>
      ) : null}
    </div>
  );
}
