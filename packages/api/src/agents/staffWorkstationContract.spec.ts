import { buildStaffWorkstationContract } from './staffWorkstationContract';

describe('CBHR AI staff workstation prompt', () => {
  test('managed chat receives requested-output publication contract with authorized tools', () => {
    const prompt = buildStaffWorkstationContract({
      endpoint: 'CBHR AI',
      toolNames: ['bash_tool', 'read_file', 'file_search', 'skill'],
    });
    expect(prompt).toContain('outputs/');
    expect(prompt).toContain('does NOT have /mnt/data');
    expect(prompt).toContain('pwd and ls -la');
    expect(prompt).toContain('.cbhr-publish.json');
    expect(prompt).toContain('multiple distinct requested outputs');
    expect(prompt).toContain('indexed/embedded');
    expect(prompt).toContain('visible, active, authorized skills');
    expect((prompt.match(/CBHR AI STAFF WORKSTATION CONTRACT/g) ?? []).length).toBe(1);
  });

  test('does not inject staff policy into BYOK, other providers, or child runs', () => {
    expect(buildStaffWorkstationContract({ endpoint: 'openAI', toolNames: ['bash_tool'] })).toBe('');
    expect(buildStaffWorkstationContract({ endpoint: 'CBHR AI', toolNames: [] })).toBe('');
    expect(buildStaffWorkstationContract({
      endpoint: 'CBHR AI', toolNames: ['bash_tool'], isSubagent: true,
    })).toBe('');
  });

  test('does not advertise missing capabilities or binaries', () => {
    const prompt = buildStaffWorkstationContract({
      endpoint: 'CBHR AI', toolNames: ['read_file'],
    });
    expect(prompt).not.toContain('.cbhr-publish.json');
    expect(prompt).not.toContain('file_search searches');
    expect(prompt).not.toContain('Discover only visible');
    expect(prompt).not.toContain('LibreOffice is installed');
  });
});
