const { EModelEndpoint, AgentCapabilities } = require('librechat-data-provider');
const { createConversationMemoryAgent } = require('../memoryProvider');

/**
 * Pins the capability-flag derivation that `AgentClient::useMemory` uses when
 * it calls `initializeAgent` for the memory-extraction agent. The expression
 * is trivial but lives in a controller path that's otherwise hard to unit-
 * test, so a focused regression guard at the pure-logic layer ensures any
 * drift in config-key names (`agents`, `capabilities`) or capability enum
 * values (`execute_code`) surfaces here instead of silently stripping
 * `bash_tool` + `read_file` from memory agents in production.
 *
 * The expression mirrored below is the one in
 * `api/server/controllers/agents/client.js::useMemory`:
 *
 *   new Set(appConfig?.endpoints?.[EModelEndpoint.agents]?.capabilities)
 *     .has(AgentCapabilities.execute_code)
 */
function deriveMemoryCodeEnvAvailable(appConfig) {
  return new Set(appConfig?.endpoints?.[EModelEndpoint.agents]?.capabilities).has(
    AgentCapabilities.execute_code,
  );
}

describe('AgentClient::useMemory — codeEnvAvailable derivation', () => {
  it('returns true when appConfig lists execute_code under the agents endpoint capabilities', () => {
    expect(
      deriveMemoryCodeEnvAvailable({
        endpoints: {
          [EModelEndpoint.agents]: {
            capabilities: [AgentCapabilities.execute_code, AgentCapabilities.file_search],
          },
        },
      }),
    ).toBe(true);
  });

  it('returns false when the agents endpoint omits execute_code', () => {
    expect(
      deriveMemoryCodeEnvAvailable({
        endpoints: {
          [EModelEndpoint.agents]: {
            capabilities: [AgentCapabilities.file_search, AgentCapabilities.web_search],
          },
        },
      }),
    ).toBe(false);
  });

  it('returns false when the capabilities array is absent', () => {
    expect(deriveMemoryCodeEnvAvailable({ endpoints: { [EModelEndpoint.agents]: {} } })).toBe(
      false,
    );
  });

  it('returns false when the agents endpoint config is absent', () => {
    expect(deriveMemoryCodeEnvAvailable({ endpoints: {} })).toBe(false);
  });

  it('returns false when appConfig is null / undefined', () => {
    /* Defensive — `req.config` can be unset in edge-case test harnesses and
       ephemeral-agent flows; the memory path must not throw on access. */
    expect(deriveMemoryCodeEnvAvailable(null)).toBe(false);
    expect(deriveMemoryCodeEnvAvailable(undefined)).toBe(false);
  });

  it('matches the literal string "execute_code" — catches enum rename drift', () => {
    /* Pins the capability enum value so a rename of `AgentCapabilities.execute_code`
       that doesn't propagate to the controllers surfaces here. If this test breaks,
       update the underlying expression in `useMemory` and the helpers in
       `initialize.js` / `openai.js` / `responses.js` to match. */
    expect(AgentCapabilities.execute_code).toBe('execute_code');
    expect(EModelEndpoint.agents).toBe('agents');
  });
});

describe('AgentClient::useMemory — preserve original provider credentials', () => {
  it('restores CBHR AI from the normalized openAI adapter for a managed ephemeral agent', () => {
    const primary = {
      id: 'CBHR AI__zai/glm-5.3-flash___CBHR AI',
      endpoint: 'CBHR AI',
      provider: EModelEndpoint.openAI,
      model: 'zai/glm-5.3-flash',
      model_parameters: { model: 'zai/glm-5.3-flash', temperature: 0.3 },
      tools: ['execute_code', 'file_search'],
      tool_resources: { code: true },
    };
    const memory = createConversationMemoryAgent(primary, 'extract user memories');
    expect(memory.provider).toBe('CBHR AI');
    expect(memory.endpoint).toBe('CBHR AI');
    expect(memory.model).toBe('zai/glm-5.3-flash');
    expect(memory.model_parameters).toEqual(primary.model_parameters);
    expect(memory.model_parameters).not.toBe(primary.model_parameters);
    expect(memory.tools).toEqual([]);
    expect(memory.tool_resources).toBeUndefined();
    expect(memory.instructions).toBe('extract user memories');
    expect(primary.provider).toBe(EModelEndpoint.openAI);
    expect(primary.tools).toEqual(['execute_code', 'file_search']);
  });

  it('preserves the original configured endpoint for a persisted custom agent', () => {
    const primary = {
      id: 'agent_owned',
      endpoint: 'CompanyCustom',
      provider: EModelEndpoint.openAI,
      model: 'tenant-model',
      model_parameters: { model: 'tenant-model' },
    };
    const memory = createConversationMemoryAgent(primary, 'memory');
    expect(memory.provider).toBe('CompanyCustom');
    expect(memory.id).toBe('agent_owned');
  });

  it.each([EModelEndpoint.openAI, EModelEndpoint.anthropic, EModelEndpoint.google])(
    'leaves built-in %s on the same provider',
    (provider) => {
      const memory = createConversationMemoryAgent({
        id: 'agent_builtin',
        endpoint: provider,
        provider,
        model: 'model',
        model_parameters: { model: 'model' },
      });
      expect(memory.provider).toBe(provider);
    },
  );

  it('falls back to provider if source endpoint was not recorded', () => {
    const memory = createConversationMemoryAgent({
      id: 'agent_legacy',
      provider: EModelEndpoint.google,
      model_parameters: { model: 'gemini' },
    });
    expect(memory.provider).toBe(EModelEndpoint.google);
  });

  it('does not accept absent initialized agent input', () => {
    expect(() => createConversationMemoryAgent(null)).toThrow(
      'A primary initialized agent is required',
    );
  });
});
