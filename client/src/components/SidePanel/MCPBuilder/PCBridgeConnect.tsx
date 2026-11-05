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
                onClick={() => {
                  window.location.href = '/api/mcp/pc-bridge/pair/download/windows';
                }}
              >
                Download PC Bridge v1.0.0
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