/** Only attach the managed web MCP when the user can actually use it. */
export function hasManagedUltraSearch(
  servers: ReadonlyArray<{ serverName: string; effectivePermissions: number }>,
): boolean {
  return servers.some(
    ({ serverName, effectivePermissions }) =>
      serverName === 'ultrasearch' && (effectivePermissions & 1) !== 0,
  );
}

/** The regular managed chat keeps UltraSearch and attaches its connected PC hot. */
export function managedMCPSelection(ultraAvailable: boolean, pcServerName?: string): string[] {
  const result = ultraAvailable ? ['ultrasearch'] : [];
  if (pcServerName && !result.includes(pcServerName)) result.push(pcServerName);
  return result;
}
