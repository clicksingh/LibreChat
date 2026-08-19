/**
 * 8S3D.1 — display-formatted byte size WITH unit suffix. The shared
 * `~/utils` `formatBytes` deliberately returns a bare number (no unit
 * string) for callers that render their own suffix separately; this one is
 * for direct display (quota bar, file/trash tables).
 */
export function formatWorkspaceBytes(bytes: number): string {
  if (bytes >= 1024 ** 3) {
    return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
  }
  if (bytes >= 1024 ** 2) {
    return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  }
  if (bytes >= 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${bytes} B`;
}
