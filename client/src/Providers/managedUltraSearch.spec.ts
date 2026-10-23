import { hasManagedUltraSearch } from './managedUltraSearch';

describe('managed UltraSearch availability', () => {
  it('does not require an absent MCP server', () => {
    expect(hasManagedUltraSearch([])).toBe(false);
    expect(hasManagedUltraSearch([{ serverName: 'other', effectivePermissions: 1 }])).toBe(false);
  });

  it('automatically includes a readable UltraSearch server', () => {
    expect(hasManagedUltraSearch([{ serverName: 'ultrasearch', effectivePermissions: 1 }])).toBe(
      true,
    );
    expect(hasManagedUltraSearch([{ serverName: 'ultrasearch', effectivePermissions: 3 }])).toBe(
      true,
    );
  });

  it('does not attach a server without access', () => {
    expect(hasManagedUltraSearch([{ serverName: 'ultrasearch', effectivePermissions: 0 }])).toBe(
      false,
    );
    expect(hasManagedUltraSearch([{ serverName: 'ultrasearch', effectivePermissions: 2 }])).toBe(
      false,
    );
  });
});
