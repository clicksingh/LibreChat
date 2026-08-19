import { formatBytes } from '~/utils';
import type { TWorkspaceUsage } from 'librechat-data-provider';

const STATE_COLOR: Record<TWorkspaceUsage['state'], string> = {
  NORMAL: 'bg-green-500',
  WARNING: 'bg-yellow-500',
  CRITICAL: 'bg-orange-500',
  FULL: 'bg-red-600',
};

const STATE_LABEL: Record<TWorkspaceUsage['state'], string> = {
  NORMAL: 'Normal',
  WARNING: 'Warning — approaching your quota',
  CRITICAL: 'Critical — nearly full',
  FULL: 'Full — delete files or request a larger quota',
};

export default function QuotaBar({ usage }: { usage?: TWorkspaceUsage }) {
  if (!usage || usage.quota_bytes == null) {
    return null;
  }
  const pct = Math.min(100, Math.round((usage.used_bytes / usage.quota_bytes) * 100));
  return (
    <div className="mb-2 w-full px-1">
      <div className="mb-1 flex items-center justify-between text-xs text-text-secondary">
        <span>
          {formatBytes(usage.used_bytes)} / {formatBytes(usage.quota_bytes)}
        </span>
        <span>{pct}%</span>
      </div>
      <div className="h-2 w-full overflow-hidden rounded-full bg-surface-secondary">
        <div
          className={`h-full rounded-full transition-all ${STATE_COLOR[usage.state]}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      {usage.state !== 'NORMAL' && (
        <div className="mt-1 text-xs text-text-secondary">{STATE_LABEL[usage.state]}</div>
      )}
    </div>
  );
}
