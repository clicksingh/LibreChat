import { useState } from 'react';
import { Monitor } from 'lucide-react';
import { request } from 'librechat-data-provider';
import { Button, OGDialog, OGDialogTemplate } from '@librechat/client';
import { useLocalize } from '~/hooks';

interface PairingTicket {
  code: string;
  expiresAt: string;
  expiresInSeconds: number;
}

/**
 * One-time employee pairing code. No JWT, Cloudflare credential or MCP bearer
 * ever leaves the browser for the desktop through this component.
 */
export default function PCBridgeConnect() {
  const localize = useLocalize();
  const [open, setOpen] = useState(false);
  const [ticket, setTicket] = useState<PairingTicket | null>(null);
  const [busy, setBusy] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function startPairing() {
    setBusy(true);
    setError(null);
    try {
      const next = (await request.post('/api/mcp/pc-bridge/pair/start', {})) as PairingTicket;
      setTicket(next);
    } catch {
      setTicket(null);
      setError(localize('com_ui_pc_connection_code_error'));
    } finally {
      setBusy(false);
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
      anchor.download = 'CB-Bridge-1.2.1-x64.msi';
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

  return (
    <>
      <Button
        type="button"
        variant="outline"
        size="sm"
        className="shrink-0 gap-1.5"
        onClick={() => {
          setOpen(true);
          void startPairing();
        }}
        aria-label={localize('com_ui_connect_pc')}
      >
        <Monitor className="size-4" aria-hidden="true" />
        <span>{localize('com_ui_connect_pc')}</span>
      </Button>
      <OGDialog open={open} onOpenChange={(next) => (next ? setOpen(true) : close())}>
        <OGDialogTemplate
          title={localize('com_ui_connect_your_computer')}
          description={localize('com_ui_open_pc_bridge_enter_code')}
          className="w-11/12 max-w-md"
          main={
            <div className="space-y-4 py-2">
              {busy && (
                <p className="text-sm text-text-secondary">
                  {localize('com_ui_creating_pc_connection_code')}
                </p>
              )}
              {error && (
                <p role="alert" className="text-sm text-text-destructive">
                  {error}
                </p>
              )}
              {ticket && (
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
              <Button
                type="button"
                variant="outline"
                onClick={() => void downloadWindowsBridge()}
                disabled={downloading}
              >
                {downloading ? 'Downloading CB Bridge…' : 'Download CB Bridge v1.2.1'}
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={() => void startPairing()}
                disabled={busy}
              >
                {localize('com_ui_generate_new_code')}
              </Button>
            </div>
          }
        />
      </OGDialog>
    </>
  );
}
