const { getAgentStartupFailureDiagnostic } = require('../agentStartupDiagnostics');

describe('startup diagnostics are useful without logging private exceptions', () => {
  test('reports failure stage and safe app stack location for a local TypeError', () => {
    const err = new TypeError("Cannot read properties of undefined (reading 'status')");
    err.stack = [
      err.toString(),
      '    at bindScope (/app/api/server/controllers/agents/client.js:2698:17)',
      '    at secret (C:\\Users\\Private\\Documents\\account-123456.txt:2:3)',
    ].join('\n');
    const result = getAgentStartupFailureDiagnostic(err, {
      stage: 'file_grants',
      conversationId: 'convo-123',
      runId: 'run-456',
      streamEntered: false,
    });
    expect(result).toMatchObject({
      failureStage: 'file_grants',
      errorName: 'TypeError',
      errorCode: null,
      errorShape: 'null_property_read:status',
      stackSite: 'api/server/controllers/agents/client.js:2698:17',
      conversationId: 'convo-123',
      runId: 'run-456',
      streamEntered: false,
    });
    expect(result.failureFingerprint).toMatch(/^[a-f0-9]{20}$/);
    const logged = JSON.stringify(result);
    expect(logged).not.toContain('Private');
    expect(logged).not.toContain('account-123456');
  });

  test('does not disclose arbitrary model, tool, or file content', () => {
    const secret = 'user@example.com secret-token /uploads/private.csv';
    const err = new Error(`Upstream returned: ${secret}`);
    err.stack = `Error: ${secret}\n    at run (/tmp/${secret}:21:4)`;
    err.code = `unsafe-${secret}`;
    const result = getAgentStartupFailureDiagnostic(err, {
      stage: 'not-a-server-phase',
      conversationId: 'bad id with spaces',
    });
    const logged = JSON.stringify(result);
    expect(result.failureStage).toBe('unknown');
    expect(result.errorShape).toBe('other');
    expect(result.stackSite).toBeNull();
    expect(result.errorCode).toBeNull();
    expect(result.conversationId).toBeNull();
    expect(logged).not.toContain(secret);
    expect(logged).not.toContain('user@example.com');
    expect(logged).not.toContain('/uploads/private.csv');
  });

  test('fingerprint is stable across runs but does not expose the message', () => {
    const err = new Error('confidential account id 987654321');
    const first = getAgentStartupFailureDiagnostic(err, {
      stage: 'run_create',
      runId: 'run-one',
    });
    const second = getAgentStartupFailureDiagnostic(err, {
      stage: 'checkpoint_prune',
      runId: 'run-two',
    });
    expect(first.failureFingerprint).toBe(second.failureFingerprint);
    expect(first.streamEntered).toBe(false);
    expect(second.failureStage).toBe('checkpoint_prune');
    expect(JSON.stringify([first, second])).not.toContain('987654321');
  });
});
