import { useState } from 'react';
import { Monitor } from 'lucide-react';
import { request } from 'librechat-data-provider';
import { Button, OGDialog, OGDialogTemplate } from '@librechat/client';

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
      setError('Could not create a PC connection code. Please try again.');
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
        aria-label="Connect your PC"
      >
        <Monitor className="size-4" aria-hidden="true" />
        <span>Connect PC</span>
      </Button>
      <OGDialog open={open} onOpenChange={(next) => (next ? setOpen(true) : close())}>
        <OGDialogTemplate
          title="Connect your computer"
          description="Open CBHR PC Bridge on your computer and enter this one-time code."
          className="w-11/12 max-w-md"
          main={
            <div className="space-y-4 py-2">
              {busy && (
                <p className="text-sm text-text-secondary">Creating your connection code...</p>
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
                    aria-label="PC pairing code"
                  >
                    {ticket.code}
                  </div>
                  <p className="text-sm text-text-secondary">
                    Valid for three minutes and usable only once. Keep this window open while you
                    connect.
                  </p>
                  <p className="text-xs text-text-secondary">
                    You never need to provide your password, browser token, or Cloudflare
                    credentials to the desktop helper.
                  </p>
                </>
              )}
            </div>
          }
          selection={
            <Button
              type="button"
              variant="outline"
              onClick={() => void startPairing()}
              disabled={busy}
            >
              Generate new code
            </Button>
          }
        />
      </OGDialog>
    </>
  );
}
