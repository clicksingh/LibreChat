import { buildStaffWorkstationContract, isCBBridgeToolName } from './staffWorkstationContract';

const BRIDGE_READ = 'read_file_mcp_cbhr-pc-pc-abcdef12-aabbccddee';
const BRIDGE_SCREEN = 'screenshot_mcp_cbhr-pc-pc-abcdef12-aabbccddee';

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
    expect(prompt).toContain('deployment cb-bridge skill');
    expect((prompt.match(/CBHR AI STAFF WORKSTATION CONTRACT/g) ?? []).length).toBe(1);
  });

  test('does not inject staff policy into BYOK, other providers, or child runs', () => {
    expect(buildStaffWorkstationContract({ endpoint: 'openAI', toolNames: ['bash_tool'] })).toBe(
      '',
    );
    expect(buildStaffWorkstationContract({ endpoint: 'CBHR AI', toolNames: [] })).toBe('');
    expect(
      buildStaffWorkstationContract({
        endpoint: 'CBHR AI',
        toolNames: ['bash_tool', BRIDGE_READ],
        isSubagent: true,
      }),
    ).toBe('');
  });

  test('does not advertise missing capabilities or binaries', () => {
    const prompt = buildStaffWorkstationContract({
      endpoint: 'CBHR AI',
      toolNames: ['read_file'],
    });
    expect(prompt).not.toContain('.cbhr-publish.json');
    expect(prompt).not.toContain('file_search searches');
    expect(prompt).not.toContain('Discover only visible');
    expect(prompt).not.toContain('LibreOffice is installed');
    expect(prompt).toContain('No CB Bridge tool is exposed');
    expect(prompt).not.toContain('CB Bridge tools are exposed for this turn');
  });

  test('identifies only well-formed Bridge MCP tool names from actual definitions', () => {
    expect(isCBBridgeToolName(BRIDGE_READ)).toBe(true);
    expect(isCBBridgeToolName(BRIDGE_SCREEN)).toBe(true);
    expect(isCBBridgeToolName('read_file_mcp_cbhr-pc-2')).toBe(true);
    expect(isCBBridgeToolName('read_file')).toBe(false);
    expect(isCBBridgeToolName('bash_tool')).toBe(false);
    expect(isCBBridgeToolName('read_file_mcp_other-server')).toBe(false);
    expect(isCBBridgeToolName('read_file_mcp_cbhr-pc-')).toBe(false);
    expect(isCBBridgeToolName('_mcp_cbhr-pc-2')).toBe(false);
  });

  test('Bridge-only turns receive correct physical-PC policy without claiming sandbox tools', () => {
    const prompt = buildStaffWorkstationContract({
      endpoint: 'CBHR AI',
      toolNames: [BRIDGE_READ, BRIDGE_SCREEN],
    });
    expect(prompt).toContain("employee's physical Windows PC");
    expect(prompt).toContain('AI sandbox is separate');
    expect(prompt).toContain('Files/Projects is durable');
    expect(prompt).toContain('Desktop');
    expect(prompt).toContain('installed apps');
    expect(prompt).toContain('CB Bridge tools are exposed for this turn');
    expect(prompt).toContain('Bridge Read is not Edit');
    expect(prompt).toContain('PowerShell requires its own opt-in');
    expect(prompt).toContain('permission denials');
    expect(prompt).toContain('screenshots describe the real PC only when returned');
    expect(prompt).not.toContain('outputs/');
    expect(prompt).not.toContain(BRIDGE_READ);
    expect(prompt).not.toContain('cbhr-pc-pc-');
  });

  test('ordinary tool names never imply Bridge access and aliases remain forbidden', () => {
    const prompt = buildStaffWorkstationContract({
      endpoint: 'CBHR AI',
      toolNames: ['bash_tool', 'read_file', 'screenshot_mcp_unrelated'],
    });
    expect(prompt).toContain('No CB Bridge tool is exposed');
    expect(prompt).toContain('Never guess aliases such as bash, bash_terminal or powershell');
    expect(prompt).toContain('Do not claim physical-PC access');
    expect(prompt).toContain('Sandbox shell/files do not inspect the physical PC');
  });

  test('tool_search alone can discover PC capabilities without claiming PC access', () => {
    const prompt = buildStaffWorkstationContract({
      endpoint: 'CBHR AI',
      toolNames: ['tool_search'],
    });
    expect(prompt).toContain('tool_search may discover available CB Bridge capabilities');
    expect(prompt).toContain('No CB Bridge tool is exposed');
    expect(prompt).not.toContain('CB Bridge tools are exposed for this turn');
  });
  test('managed prompt size remains bounded in worst common exposed-tool configuration', () => {
    const prompt = buildStaffWorkstationContract({
      endpoint: 'CBHR AI',
      toolNames: [
        'bash_tool',
        'read_file',
        'file_search',
        'skill',
        'tool_search',
        BRIDGE_READ,
        BRIDGE_SCREEN,
      ],
    });
    expect(Buffer.byteLength(prompt, 'utf8')).toBeLessThan(4600);
    expect(prompt.split('\n').length).toBeLessThan(26);
  });
});
