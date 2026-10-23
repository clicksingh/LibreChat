const fs = require('fs');
const path = require('path');

describe('AgentClient durable error boundary', () => {
  it('normalizes unknown sendCompletion failures before persisting ERROR content', () => {
    const source = fs.readFileSync(path.join(__dirname, '..', 'client.js'), 'utf8');
    expect(source).toContain("const { normalizeAgentFailure } = require('./agentFailure');");
    expect(source).toContain('[ContentTypes.ERROR]: videoError ?? normalizeAgentFailure(err)');
    expect(source).not.toContain('An error occurred while processing the request');
  });
});
