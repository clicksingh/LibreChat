import { useMutation } from '@tanstack/react-query';
import { dataService, MutationKeys } from 'librechat-data-provider';
import type { TXposeDeviceClaimRequest, TXposeDeviceClaimResponse } from 'librechat-data-provider';
import type { UseMutationResult } from '@tanstack/react-query';

export const useClaimXposeDeviceMutation = (): UseMutationResult<
  TXposeDeviceClaimResponse,
  unknown,
  TXposeDeviceClaimRequest
> =>
  useMutation((payload: TXposeDeviceClaimRequest) => dataService.claimXposeDevice(payload), {
    mutationKey: [MutationKeys.claimXposeDevice],
  });
