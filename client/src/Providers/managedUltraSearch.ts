/** Only attach the managed web MCP when the user can actually use it. */
export function hasManagedUltraSearch(
  servers: ReadonlyArray<{ serverName: string; effectivePermissions: number }>,
): boolean {
  return servers.some(
    ({ serverName, effectivePermissions }) =>
      serverName === 'ultrasearch' && (effectivePermissions & 1) !== 0,
  );
}
