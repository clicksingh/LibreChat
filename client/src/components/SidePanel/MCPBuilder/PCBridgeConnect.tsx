import { useState } from 'react';
import { Monitor } from 'lucide-react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { request } from 'librechat-data-provider';
import { Button, OGDialog, OGDialogTemplate } from '@librechat/client';
import { useAuthContext, useLocalize } from '~/hooks';

interface PairingTicket {
  code: string;
  expiresAt: string;
  expiresInSeconds: number;
}

interface PCBridgeStatus {
  connected: boolean;
  deviceName?: string | null;
  serverName?: string;
  toolRevision?: number;
}

/**
 * Authenticated employee PC status and pairing control.
 * The browser never receives the native session secret, Cloudflare credential
 * or MCP bearer. Disconnect is authorized by the signed-in user's own session.
 */
export default function PCBridgeConnect() {
  const localize = useLocalize();
  const { user } = useAuthContext();
  const queryClient = useQueryClient();
  const statusQueryKey = ['cbhr-pc-bridge-status', user?.id] as const;
  const [open, setOpen] = useState(false);
  const [ticket, setTicket] = useState<PairingTicket | null>(null);
  const [busy, setBusy] = useState(false);
  const [disconnecting, setDisconnecting] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const { data: status } = useQuery<PCBridgeStatus>({
    queryKey: statusQueryKey,
    queryFn: async () => (await request.get('/api/mcp/pc-bridge/pair/status')) as PCBridgeStatus,
    enabled: Boolean(user?.id),
    refetchInterval: 3_000,
    refetchIntervalInBackground: false,
    refetchOnWindowFocus: true,
    retry: false,
  });

  async function fetchStatus({ surfaceError = false } = {}) {
    try {
      const next = (await request.get('/api/mcp/pc-bridge/pair/status')) as PCBridgeStatus;
      queryClient.setQueryData(statusQueryKey, next);
      if (next.connected) {
        setTicket(null);
      }
      return next;
    } catch {
      if (surfaceError) {
        setError('Could not check the current CB Bridge connection.');
      }
      return null;
    }
  }

  async function startPairing() {
    setBusy(true);
    setError(null);
    try {
      const current = await fetchStatus();
      if (current?.connected) {
        return;
      }
      const next = (await request.post('/api/mcp/pc-bridge/pair/start', {})) as PairingTicket;
      setTicket(next);
    } catch {
      setTicket(null);
      setError(localize('com_ui_pc_connection_code_error'));
    } finally {
      setBusy(false);
    }
  }

  async function disconnectBridge() {
    setDisconnecting(true);
    setError(null);
    try {
      await request.post('/api/mcp/pc-bridge/pair/disconnect/browser', {});
      queryClient.setQueryData<PCBridgeStatus>(statusQueryKey, { connected: false });
      setTicket(null);
    } catch {
      const current = await fetchStatus();
      if (current?.connected) {
        setError('CB Bridge could not be disconnected. Please try again.');
      }
    } finally {
      setDisconnecting(false);
    }
  }

  async function downloadWindowsBridge() {
    setDownloading(true);
    setError(null);
    try {
      // request.getResponse uses LibreChat's authenticated Axios client.
      // Direct window navigation would omit the bearer token and return 401.
      const response = await request.getResponse<Blob>('/api/mcp/pc-bridge/pair/download/windows', {
        responseType: 'blob',
        headers: { Accept: 'application/octet-stream' },
      });
      const url = window.URL.createObjectURL(response.data);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = 'CB-Bridge-1.2.2-x64.msi';
      document.body.appendChild(anchor);
      try {
        anchor.click();
      } finally {
        anchor.remove();
        window.setTimeout(() => window.URL.revokeObjectURL(url), 60_000);
      }
    } catch {
      setError('CB Bridge download failed. Please refresh the page and try again.');
    } finally {
      setDownloading(false);
    }
  }

  function close() {
    setOpen(false);
    setTicket(null);
    setError(null);
  }

  const connectedName = status?.deviceName?.trim() || 'PC';
  const connected = status?.connected === true;

  return (
    <>
      <Button
        type="button"
        variant="outline"
        size="sm"
        className="shrink-0 gap-1.5"
        onClick={() => {
          setOpen(true);
          setError(null);
          if (!connected) {
            void startPairing();
          }
        }}
        aria-label={connected ? `Connected to ${connectedName}` : localize('com_ui_connect_pc')}
      >
        <Monitor className="size-4" aria-hidden="true" />
        <span>{connected ? `Connected: ${connectedName}` : localize('com_ui_connect_pc')}</span>
      </Button>
      <OGDialog open={open} onOpenChange={(next) => (next ? setOpen(true) : close())}>
        <OGDialogTemplate
          title={
            connected ? `Connected to ${connectedName}` : localize('com_ui_connect_your_computer')
          }
          description={
            connected
              ? 'This Windows PC is available to your CBHR AI conversations.'
              : localize('com_ui_open_pc_bridge_enter_code')
          }
          className="w-11/12 max-w-md"
          main={
            <div className="space-y-4 py-2">
              {connected && (
                <div className="rounded-lg border border-border-medium bg-surface-secondary px-4 py-4">
                  <p className="text-sm font-medium text-text-primary">{connectedName}</p>
                </div>
              )}
              {!connected && busy && (
                <p className="text-sm text-text-secondary">
                  {localize('com_ui_creating_pc_connection_code')}
                </p>
              )}
              {error && (
                <p role="alert" className="text-sm text-text-destructive">
                  {error}
                </p>
              )}
              {!connected && ticket && (
                <>
                  <div
                    className="rounded-lg border border-border-medium bg-surface-secondary px-4 py-5 text-center font-mono text-xl font-semibold tracking-wide"
                    aria-label={localize('com_ui_pc_pairing_code')}
                  >
                    {ticket.code}
                  </div>
                  <p className="text-sm text-text-secondary">
                    {localize('com_ui_pc_pairing_code_validity')}
                  </p>
                  <p className="text-xs text-text-secondary">
                    {localize('com_ui_pc_pairing_security_note')}
                  </p>
                </>
              )}
            </div>
          }
          selection={
            <div className="flex flex-wrap justify-end gap-2">
              {connected ? (
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => void disconnectBridge()}
                  disabled={disconnecting}
                >
                  {disconnecting ? 'Disconnecting…' : 'Disconnect PC'}
                </Button>
              ) : (
                <>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => void downloadWindowsBridge()}
                    disabled={downloading}
                  >
                    {downloading ? 'Downloading CB Bridge…' : 'Download CB Bridge v1.2.2'}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => void startPairing()}
                    disabled={busy}
                  >
                    {localize('com_ui_generate_new_code')}
                  </Button>
                </>
              )}
            </div>
          }
        />
      </OGDialog>
    </>
  );
}
