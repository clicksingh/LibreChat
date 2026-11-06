import { hasManagedUltraSearch, managedMCPSelection } from './managedUltraSearch';

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

describe('hot managed PC Bridge selection', () => {
  it('preserves UltraSearch while attaching the current PC', () => {
    expect(managedMCPSelection(true, 'cbhr_pc_employee')).toEqual([
      'ultrasearch',
      'cbhr_pc_employee',
    ]);
  });
  it('returns to the baseline when the PC disconnects', () => {
    expect(managedMCPSelection(true)).toEqual(['ultrasearch']);
    expect(managedMCPSelection(false)).toEqual([]);
  });
  it('supports a connected PC when UltraSearch is unavailable', () => {
    expect(managedMCPSelection(false, 'cbhr_pc_employee')).toEqual(['cbhr_pc_employee']);
  });
  it('does not duplicate an already selected managed server', () => {
    expect(managedMCPSelection(true, 'ultrasearch')).toEqual(['ultrasearch']);
  });
});
