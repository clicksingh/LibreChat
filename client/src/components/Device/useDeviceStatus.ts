import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { CLAIM_POLL_INTERVAL_MS, STATUS_POLL_INTERVAL_MS } from './constants';
import { approvePairingCode, fetchCurrentDevice } from './api';
import type { DeviceStatusPayload, PairingApprovePayload } from './types';

/** One key for the panel's single read. Nothing else in the app reads device state today. */
export const deviceStatusQueryKey = ['deviceCurrentStatus'] as const;

/**
 * Polls `GET /api/devices/current`.
 *
 * Brisk while a claim is landing (the PC's next `pairing/complete` poll flips the lease), calm
 * otherwise. `retry: false` is deliberate: a failed poll must surface as the relay-error state
 * instead of being silently retried into a stale "connected" picture.
 */
export function useDeviceStatusQuery({ claimPending }: { claimPending: boolean }) {
  return useQuery<DeviceStatusPayload, unknown>(
    deviceStatusQueryKey,
    ({ signal }) => fetchCurrentDevice(signal),
    {
      refetchInterval: claimPending ? CLAIM_POLL_INTERVAL_MS : STATUS_POLL_INTERVAL_MS,
      refetchIntervalInBackground: false,
      refetchOnWindowFocus: true,
      refetchOnReconnect: true,
      retry: false,
      staleTime: 0,
    },
  );
}

/**
 * Redeems a six-digit code via `POST /api/devices/pairing/approve`.
 *
 * `retry: false` matters for single-use semantics: a code is consumed by the first successful
 * redemption, so the panel never resends one on its own. A failure is surfaced to the employee,
 * who decides whether to ask the PC for a fresh code.
 */
export function usePairingApprovalMutation() {
  const queryClient = useQueryClient();

  return useMutation<PairingApprovePayload, unknown, string>(
    (code: string) => approvePairingCode(code),
    {
      retry: false,
      onSuccess: () => {
        void queryClient.invalidateQueries(deviceStatusQueryKey);
      },
    },
  );
}
