/**
 * Copy for the "My Computer" panel.
 *
 * TRANSLATION STATUS: every string is collected here, one place, so it can move to
 * `client/src/locales/en/translation.json` as `com_ui_device_*` keys without touching component
 * logic. It is not wired to `useLocalize` yet because this workstream's write scope is
 * `client/src/components/Device/**` plus a single registration edit; adding locale keys is a
 * separate, reviewed edit. Components never contain inline user-facing literals, so the move is
 * mechanical.
 *
 * TONE RULE: no string may imply that this page grants, renews or extends access. The only
 * state that says "connected" is the one derived from an active identity, an active lease and
 * an unexpired expiry.
 */

export const deviceCopy = {
  panel: {
    title: 'My Computer',
    subtitle: 'The assistant can work on one PC at a time — the one you pair here.',
    authorityNote:
      'Access is decided by the server and by a confirmation on your PC. This page never grants or extends it; it only shows what the server reports.',
    stepsTitle: 'How pairing works',
  },
  pairing: {
    heading: 'Pair this PC',
    steps: [
      'Your PC registers itself and shows six digits.',
      'You type those six digits here and approve them.',
      'Your PC collects the 48-hour lease on its next check-in.',
      'This page shows Connected only when the server reports an active, unexpired lease.',
    ],
    label: 'Six-digit code',
    hint: 'Your PC shows six digits. Each code works once and expires five minutes after it appears.',
    inputPlaceholder: '123456',
    entryWindowLabel: 'Code entry window',
    entryWindowNote:
      'This timer is a convenience. The server decides whether a code is still valid.',
    entryWindowExpired: 'The entry window closed. Ask your PC for a fresh code, then start again.',
    submit: 'Approve code',
    submitting: 'Approving…',
    startOver: 'Start over',
    singleUseNote:
      'A code can be used once. After it is approved, this page will not send it again.',
    alreadyPairedTitle: 'This account already has a PC',
    alreadyPairedBody:
      'One account can hold one PC. Pairing a different PC needs the current one removed first, and this page cannot remove it.',
    approvedTitle: 'Code approved',
    approvedBody:
      'Your PC finishes the handshake on its next check-in, usually within a few seconds. Access is confirmed only when the server reports an active lease.',
    approvedWindowLabel: 'Approval window',
    approvedWindowExpired:
      'The approval window closed before your PC checked in. Ask your PC for a fresh code.',
    approvedPendingBadge: 'Waiting for your PC',
  },
  renew: {
    heading: 'Renewal',
    alwaysNote: 'approved on your PC, never on this page.',
    dueTitle: 'Renewal due',
    dueBody:
      'Access ends in {remaining}. To continue, open the CBHR tray app on your PC and approve the local prompt.',
    dueSteps: [
      'Open the CBHR tray icon on your PC.',
      'Choose the renewal prompt and approve it there.',
      'This page updates on its own once the server records the renewal.',
    ],
    securityNote:
      'This page cannot renew access. That is deliberate: a stolen browser session must not be able to extend it.',
  },
  status: {
    loading: 'Checking this account’s PC…',
    unknown: 'Not reported',
    connectedBadge: 'Connected',
    connectedTitle: 'Your PC is connected',
    connectedBody:
      'The server reports an active identity and an active lease that has not expired.',
    identityLabel: 'Identity',
    leaseLabel: 'Lease',
    epochLabel: 'Lease generation',
    expiresLabel: 'Access ends in',
    noDeviceBadge: 'Not paired',
    noDeviceTitle: 'No PC is paired to this account yet',
    noDeviceBody:
      'Install the CBHR app on your PC, then type the six digits it shows into the form below.',
    pairedIncompleteBadge: 'Not connected',
    pairedIncompleteTitle: 'Your PC is registered but not connected',
    pairedIncompleteBody:
      'The server does not report an active, unexpired lease for it yet. Finish pairing with a fresh six-digit code from your PC.',
    expiredBadge: 'Expired',
    expiredTitle: 'Access expired',
    expiredBody:
      'The 48-hour lease ended. An expired lease cannot be renewed; pair again with a fresh six-digit code from your PC.',
    revokedBadge: 'Removed',
    revokedTitle: 'This PC was removed',
    revokedBody:
      'Access for this PC was revoked. Pair again with a fresh six-digit code from your PC.',
    unverifiedBadge: 'Unconfirmed',
    unverifiedTitle: 'Access cannot be confirmed',
    unverifiedBody:
      'The server did not report a readable expiry, so this page will not show Connected.',
    relayErrorBadge: 'Service unreachable',
    relayErrorTitle: 'This page cannot reach the device service',
    relayErrorBody:
      'That says nothing about your PC’s access — only that this page cannot see it right now. It will keep retrying.',
    relayErrorDetailHttp: 'HTTP {status}',
    relayErrorDetailNetwork: 'The request did not reach the server',
    relayErrorDetailMalformed: 'The server response was not readable',
    sessionExpiredBadge: 'Signed out',
    sessionExpiredTitle: 'Your sign-in expired',
    sessionExpiredBody: 'Sign in again, then reopen My Computer.',
    requestRejectedBadge: 'Rejected',
    requestRejectedTitle: 'The server rejected a request from this page',
    requestRejectedBody:
      'Nothing was changed. If this keeps happening, report it — this page should never send identity values.',
    identityStates: {
      active: 'Active',
      pending: 'Registered, not finished',
      retired: 'Removed',
    },
    leaseStates: {
      active: 'Active',
      never: 'Never issued',
      expired: 'Expired',
      revoked: 'Revoked',
    },
  },
  errors: {
    invalidCodeTitle: 'That code was not accepted',
    invalidCodeBody:
      'A code can fail because it was already used, because it expired, or because it was mistyped. Ask your PC for a fresh code.',
    rateLimitedTitle: 'Too many attempts',
    rateLimitedBody: 'Wait a moment, then try again with a fresh code from your PC.',
    networkTitle: 'The request did not reach the server',
    networkBody: 'Check your connection and try again. Nothing was approved.',
    serverTitle: 'The server could not confirm that',
    serverBody: 'Nothing is confirmed. Check the status above before trying again.',
    unknownTitle: 'Something went wrong',
    unknownBody: 'Nothing is confirmed. Check the status above before trying again.',
  },
  units: {
    hour: 'h',
    minute: 'm',
    second: 's',
  },
} as const;

export type DeviceCopy = typeof deviceCopy;

/** Fills `{placeholders}` in a copy string. Kept tiny so the copy can move to i18n later. */
export function interpolate(template: string, values: Record<string, string>): string {
  return template.replace(/\{(\w+)\}/g, (match: string, key: string) => values[key] ?? match);
}
