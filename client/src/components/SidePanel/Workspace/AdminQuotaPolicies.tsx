import { useState } from 'react';
import { Button } from '@librechat/client';
import { SystemRoles } from 'librechat-data-provider';
import type { TQuotaPolicyScope } from 'librechat-data-provider';
import { useAuthContext } from '~/hooks';
import {
  useQuotaPoliciesQuery,
  useUpsertQuotaPolicyMutation,
  useDeleteQuotaPolicyMutation,
} from '~/data-provider';
import { formatWorkspaceBytes } from './formatBytes';

const SCOPES: TQuotaPolicyScope[] = ['platformPersonal', 'platformProject', 'group', 'user', 'project'];
const SCOPED_ID_SCOPES = new Set<TQuotaPolicyScope>(['group', 'user', 'project']);

/**
 * 8S3D.1 — narrowest-surface admin quota-policy management (issue #16).
 * Deliberately embedded in the Workspace panel rather than a standalone
 * route/layout: no new page, no new nav entry, reuses the exact role gate
 * already used elsewhere in this client (SystemRoles.ADMIN) — and the
 * server independently re-enforces ACCESS_ADMIN on every request
 * regardless of what this component renders. Lives entirely inside
 * LibreChat's own client; does not touch cbhr-admin at all.
 */
export default function AdminQuotaPolicies() {
  const { user } = useAuthContext();
  const { data: policies, isLoading } = useQuotaPoliciesQuery({
    enabled: user?.role === SystemRoles.ADMIN,
  });
  const upsert = useUpsertQuotaPolicyMutation();
  const del = useDeleteQuotaPolicyMutation();

  const [scope, setScope] = useState<TQuotaPolicyScope>('project');
  const [scopeId, setScopeId] = useState('');
  const [quotaMiB, setQuotaMiB] = useState('');
  const [error, setError] = useState<string | null>(null);

  if (user?.role !== SystemRoles.ADMIN) {
    return null;
  }

  const needsScopeId = SCOPED_ID_SCOPES.has(scope);

  const handleSubmit = () => {
    setError(null);
    const mib = Number(quotaMiB);
    if (!Number.isFinite(mib) || mib <= 0) {
      setError('Quota must be a positive number of MiB.');
      return;
    }
    if (needsScopeId && !scopeId.trim()) {
      setError('This scope requires an id (user id, project workspace id, or group id).');
      return;
    }
    upsert.mutate(
      {
        scope,
        scopeId: needsScopeId ? scopeId.trim() : null,
        quotaBytes: Math.floor(mib * 1024 * 1024),
      },
      {
        onSuccess: () => {
          setScopeId('');
          setQuotaMiB('');
        },
        onError: (err) => setError(err instanceof Error ? err.message : 'Failed to save policy'),
      },
    );
  };

  return (
    <div className="mt-4 border-t border-border-light pt-3">
      <div className="mb-2 text-sm font-medium">Admin: Quota Policies</div>
      <div className="mb-2 text-xs text-text-secondary">
        Sets the resolved quota a workspace converges to on its next sync — the same value a
        matching direct helper limit would otherwise be silently overwritten back to.
      </div>

      {isLoading ? (
        <div className="text-xs text-text-secondary">Loading…</div>
      ) : (
        <table className="mb-3 w-full text-xs">
          <thead>
            <tr className="border-b border-border-light text-left text-text-secondary">
              <th className="py-1 font-medium">Scope</th>
              <th className="py-1 font-medium">Scope ID</th>
              <th className="py-1 text-right font-medium">Quota</th>
              <th className="py-1"></th>
            </tr>
          </thead>
          <tbody>
            {(policies ?? []).map((p) => (
              <tr key={p._id} className="border-b border-border-light/50">
                <td className="py-1">{p.scope}</td>
                <td className="max-w-[120px] truncate py-1" title={p.scopeId ?? ''}>
                  {p.scopeId ?? '—'}
                </td>
                <td className="py-1 text-right">{formatWorkspaceBytes(p.quotaBytes)}</td>
                <td className="py-1 text-right">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => del.mutate({ scope: p.scope, scopeId: p.scopeId })}
                  >
                    Delete
                  </Button>
                </td>
              </tr>
            ))}
            {(policies ?? []).length === 0 && (
              <tr>
                <td colSpan={4} className="py-2 text-center text-text-secondary">
                  No overrides — every workspace uses the platform default.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}

      <div className="flex flex-wrap items-end gap-2">
        <label className="flex flex-col text-xs">
          Scope
          <select
            className="rounded-md border border-border-light bg-surface-primary px-2 py-1"
            value={scope}
            onChange={(e) => setScope(e.target.value as TQuotaPolicyScope)}
          >
            {SCOPES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
        {needsScopeId && (
          <label className="flex flex-col text-xs">
            Scope ID
            <input
              className="rounded-md border border-border-light bg-surface-primary px-2 py-1"
              value={scopeId}
              onChange={(e) => setScopeId(e.target.value)}
              placeholder="user/project/group id"
            />
          </label>
        )}
        <label className="flex flex-col text-xs">
          Quota (MiB)
          <input
            className="w-24 rounded-md border border-border-light bg-surface-primary px-2 py-1"
            value={quotaMiB}
            onChange={(e) => setQuotaMiB(e.target.value)}
            placeholder="1024"
          />
        </label>
        <Button size="sm" onClick={handleSubmit} disabled={upsert.isLoading}>
          {upsert.isLoading ? 'Saving…' : 'Set policy'}
        </Button>
      </div>
      {error && <div className="mt-1 text-xs text-red-500">{error}</div>}
    </div>
  );
}
