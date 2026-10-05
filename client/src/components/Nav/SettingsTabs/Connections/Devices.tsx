import { useState } from 'react';
import { Button, Input, Label, Spinner, useToastContext } from '@librechat/client';
import type { TranslationKeys } from '~/hooks';
import { useClaimXposeDeviceMutation } from '~/data-provider';
import { useLocalize } from '~/hooks';

function errorLabel(error: unknown): TranslationKeys {
  const code = (
    error as {
      response?: {
        data?: {
          code?: unknown;
        };
      };
    }
  )?.response?.data?.code;

  switch (code) {
    case 'pairing_not_activated':
    case 'pairing_not_claimed':
      return 'com_ui_xpose_device_claim_not_ready';
    case 'pairing_expired':
      return 'com_ui_xpose_device_claim_expired';
    case 'pairing_not_found':
    case 'pairing_code_invalid':
      return 'com_ui_xpose_device_claim_invalid';
    case 'pairing_rate_limited':
      return 'com_ui_xpose_device_claim_rate_limited';
    default:
      return 'com_ui_xpose_device_claim_error';
  }
}

export default function Devices() {
  const localize = useLocalize();
  const { showToast } = useToastContext();
  const [code, setCode] = useState('');
  const [claimComplete, setClaimComplete] = useState(false);
  const [claimedDeviceId, setClaimedDeviceId] = useState<string | undefined>();
  const claimMutation = useClaimXposeDeviceMutation();
  const normalizedCode = code.trim();
  const canSubmit = normalizedCode.length > 0 && !claimMutation.isLoading;

  const handleClaim = () => {
    if (!canSubmit) {
      return;
    }

    claimMutation.mutate(
      { code: normalizedCode },
      {
        onSuccess: (result) => {
          setClaimComplete(true);
          setClaimedDeviceId(result.deviceId);
          setCode('');
          showToast({
            message: localize('com_ui_xpose_device_claimed'),
            status: 'success',
          });
        },
        onError: (error) => {
          showToast({
            message: localize(errorLabel(error)),
            status: 'error',
          });
        },
      },
    );
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="space-y-1">
        <div className="font-medium">{localize('com_ui_xpose_devices_title')}</div>
        <p className="text-sm text-text-secondary">
          {localize('com_ui_xpose_devices_description')}
        </p>
      </div>

      <div className="flex flex-col gap-1.5">
        <Label htmlFor="xpose-pairing-code">{localize('com_ui_xpose_pairing_code')}</Label>
        <div className="flex flex-col gap-2 sm:flex-row">
          <Input
            id="xpose-pairing-code"
            value={code}
            autoComplete="off"
            autoCapitalize="characters"
            spellCheck={false}
            disabled={claimMutation.isLoading}
            placeholder={localize('com_ui_xpose_pairing_code_placeholder')}
            onChange={(event) => {
              setCode(event.target.value);
              setClaimComplete(false);
              setClaimedDeviceId(undefined);
            }}
            onKeyDown={(event) => {
              if (event.key === 'Enter') {
                event.preventDefault();
                handleClaim();
              }
            }}
          />
          <Button variant="submit" disabled={!canSubmit} onClick={handleClaim}>
            {claimMutation.isLoading ? (
              <span className="flex items-center gap-2">
                <Spinner className="h-4 w-4" />
                {localize('com_ui_xpose_adding_device')}
              </span>
            ) : (
              localize('com_ui_xpose_add_device')
            )}
          </Button>
        </div>
      </div>

      {claimComplete && (
        <div
          role="status"
          className="rounded-lg border border-border-light bg-surface-secondary px-3 py-2 text-sm text-text-secondary"
        >
          <div className="font-medium text-text-primary">
            {localize('com_ui_xpose_device_claimed')}
          </div>
          {claimedDeviceId && (
            <code className="mt-1 block truncate font-mono text-xs text-text-tertiary">
              {claimedDeviceId}
            </code>
          )}
        </div>
      )}
    </div>
  );
}
