/**
 * `@librechat/agents` may ship without the skill-flavored tool definitions on
 * older installed versions. Stub them so `registerCodeExecutionTools` (which
 * consumes only the three exports below) can be exercised deterministically.
 * Mirrors the same pattern used in `__tests__/skills.test.ts`.
 */
jest.mock('@librechat/agents', () => ({
  CODE_EXECUTION_TOOLS: new Set(['execute_code', 'bash_tool']),
  ReadFileToolDefinition: {
    name: 'read_file',
    description: 'read skill files using {skillName}/{filePath} and SKILL.md',
    parameters: {
      type: 'object',
      properties: {
        file_path: {
          type: 'string',
          description: 'For skill files: "{skillName}/{path}".',
        },
      },
    },
    responseFormat: 'content',
  },
  BashExecutionToolDefinition: {
    name: 'bash_tool',
    description: 'bash',
    schema: {
      type: 'object',
      properties: {
        command: {
          type: 'string',
          description:
            'The bash command or script to execute. The environment is stateless; variables and state do not persist between executions. Prior /mnt/data files are available and can be modified in place.',
        },
      },
      required: ['command'],
    },
  },
  /**
   * Deterministic stub mirroring the SDK's `buildBashExecutionToolDescription`:
   * carries the same Cloud `/mnt/data` guidance phrases the published package
   * embeds (so the S7 normalization actually has something to rewrite), and
   * appends the LLM-facing reference-syntax marker only when
   * `enableToolOutputReferences` is true.
   */
  buildBashExecutionToolDescription: ({
    enableToolOutputReferences,
  }: {
    enableToolOutputReferences?: boolean;
  } = {}): string =>
    [
      'Runs bash commands and returns stdout/stderr output from a stateless execution environment.',
      '',
      'Usage:',
      '- No network access available.',
      '- Generated files are automatically delivered; **DO NOT** provide download links.',
      '- Persist handoff artifacts in `/mnt/data`.',
      '- Prior /mnt/data files are available and can be modified in place.',
      ...(enableToolOutputReferences === true ? ['{{tool<idx>turn<turn>}}'] : []),
    ].join('\n'),
}));

import { CODE_EXECUTION_TOOLS } from '@librechat/agents';
import type { LCTool, LCToolRegistry } from '@librechat/agents';
import {
  buildToolSet,
  BuildToolSetConfig,
  registerCodeExecutionTools,
  registerFileAuthoringTools,
  registerDocumentVisualQATool,
  FILE_AUTHORING_TOOL_NAMES,
  isFileAuthoringToolDefinition,
  isCodeSessionToolName,
} from './tools';

/** Portable ceiling for OpenAI-compatible tool description validators. */
const TOOL_DESCRIPTION_ADVISORY_MAX_LENGTH = 1024;

function filePathDescription(tool?: LCTool): string {
  const parameters = tool?.parameters as
    | { properties?: { file_path?: { description?: string } } }
    | undefined;
  return parameters?.properties?.file_path?.description ?? '';
}

function maxToolDescriptionLength(definitions: LCTool[]): number {
  return definitions.reduce((max, definition) => {
    const length = definition.description?.length ?? Number.POSITIVE_INFINITY;
    return Math.max(max, length);
  }, 0);
}

describe('buildToolSet', () => {
  describe('event-driven mode (toolDefinitions)', () => {
    it('builds toolSet from toolDefinitions when available', () => {
      const agentConfig: BuildToolSetConfig = {
        toolDefinitions: [
          { name: 'tool_search', description: 'Search for tools' },
          { name: 'list_commits_mcp_github', description: 'List commits' },
          { name: 'calculator', description: 'Calculate' },
        ],
        tools: [],
      };

      const toolSet = buildToolSet(agentConfig);

      expect(toolSet.size).toBe(3);
      expect(toolSet.has('tool_search')).toBe(true);
      expect(toolSet.has('list_commits_mcp_github')).toBe(true);
      expect(toolSet.has('calculator')).toBe(true);
    });

    it('includes tool_search in toolSet for deferred tools workflow', () => {
      const agentConfig: BuildToolSetConfig = {
        toolDefinitions: [
          { name: 'tool_search', description: 'Search for deferred tools' },
          { name: 'deferred_tool_1', description: 'A deferred tool', defer_loading: true },
          { name: 'deferred_tool_2', description: 'Another deferred tool', defer_loading: true },
        ],
      };

      const toolSet = buildToolSet(agentConfig);

      expect(toolSet.has('tool_search')).toBe(true);
      expect(toolSet.has('deferred_tool_1')).toBe(true);
      expect(toolSet.has('deferred_tool_2')).toBe(true);
    });

    it('prefers toolDefinitions over tools when both are present', () => {
      const agentConfig: BuildToolSetConfig = {
        toolDefinitions: [{ name: 'from_definitions' }],
        tools: [{ name: 'from_tools' }],
      };

      const toolSet = buildToolSet(agentConfig);

      expect(toolSet.size).toBe(1);
      expect(toolSet.has('from_definitions')).toBe(true);
      expect(toolSet.has('from_tools')).toBe(false);
    });
  });

  describe('legacy mode (tools)', () => {
    it('falls back to tools when toolDefinitions is empty', () => {
      const agentConfig: BuildToolSetConfig = {
        toolDefinitions: [],
        tools: [{ name: 'web_search' }, { name: 'calculator' }],
      };

      const toolSet = buildToolSet(agentConfig);

      expect(toolSet.size).toBe(2);
      expect(toolSet.has('web_search')).toBe(true);
      expect(toolSet.has('calculator')).toBe(true);
    });

    it('falls back to tools when toolDefinitions is undefined', () => {
      const agentConfig: BuildToolSetConfig = {
        tools: [{ name: 'tool_a' }, { name: 'tool_b' }],
      };

      const toolSet = buildToolSet(agentConfig);

      expect(toolSet.size).toBe(2);
      expect(toolSet.has('tool_a')).toBe(true);
      expect(toolSet.has('tool_b')).toBe(true);
    });
  });

  describe('edge cases', () => {
    it('returns empty set when agentConfig is null', () => {
      const toolSet = buildToolSet(null);
      expect(toolSet.size).toBe(0);
    });

    it('returns empty set when agentConfig is undefined', () => {
      const toolSet = buildToolSet(undefined);
      expect(toolSet.size).toBe(0);
    });

    it('returns empty set when both toolDefinitions and tools are empty', () => {
      const agentConfig: BuildToolSetConfig = {
        toolDefinitions: [],
        tools: [],
      };

      const toolSet = buildToolSet(agentConfig);
      expect(toolSet.size).toBe(0);
    });

    it('filters out null/undefined tool entries', () => {
      const agentConfig: BuildToolSetConfig = {
        tools: [{ name: 'valid_tool' }, null, undefined, { name: 'another_valid' }],
      };

      const toolSet = buildToolSet(agentConfig);

      expect(toolSet.size).toBe(2);
      expect(toolSet.has('valid_tool')).toBe(true);
      expect(toolSet.has('another_valid')).toBe(true);
    });

    it('filters out empty string tool names', () => {
      const agentConfig: BuildToolSetConfig = {
        toolDefinitions: [{ name: 'valid' }, { name: '' }, { name: 'also_valid' }],
      };

      const toolSet = buildToolSet(agentConfig);

      expect(toolSet.size).toBe(2);
      expect(toolSet.has('valid')).toBe(true);
      expect(toolSet.has('also_valid')).toBe(true);
      expect(toolSet.has('')).toBe(false);
    });
  });
});

describe('registerCodeExecutionTools', () => {
  const makeRegistry = (): LCToolRegistry => new Map() as unknown as LCToolRegistry;

  describe('fresh run (no pre-existing defs or registry entries)', () => {
    it('registers read_file + bash_tool when includeBash=true', () => {
      const toolRegistry = makeRegistry();
      const result = registerCodeExecutionTools({
        toolRegistry,
        toolDefinitions: [],
        includeBash: true,
      });

      const names = result.toolDefinitions.map((d) => d.name).sort();
      expect(names).toEqual(['bash_tool', 'read_file']);
      expect(result.registered.sort()).toEqual(['bash_tool', 'read_file']);
      expect(toolRegistry.has('read_file')).toBe(true);
      expect(toolRegistry.has('bash_tool')).toBe(true);
    });

    it('normalizes the published bash_tool /mnt/data guidance to the workspace contract', () => {
      const toolRegistry = makeRegistry();
      const result = registerCodeExecutionTools({
        toolRegistry,
        toolDefinitions: [],
        includeBash: true,
        enableToolOutputReferences: true,
      });

      const bashTool = result.toolDefinitions.find((d) => d.name === 'bash_tool');
      expect(bashTool).toBeDefined();
      const description = String(bashTool?.description);
      expect(description).toContain('sandbox working directory');
      expect(description).toContain('stateless execution environment');
      expect(description).toContain('No network access available.');
      expect(description).toContain('{{tool<idx>turn<turn>}}');
      expect(description).not.toContain('/mnt/data');
      expect(description).not.toContain('/mnt/');

      // 8S3B S9 — the model must verify a deliverable is registered in the
      // run's returned file list before claiming it is ready.
      expect(description).toContain('returned file list');
      expect(description).toContain('verify the file is listed before telling the user it is ready');

      // The published schema's command description embeds the same Cloud
      // guidance — it must be normalized too.
      const command = (bashTool?.parameters as {
        properties?: { command?: { description?: string } };
      })?.properties?.command;
      expect(command?.description).toContain('sandbox working directory');
      expect(command?.description).toContain('returned file list');
      expect(command?.description).not.toContain('/mnt/data');

      // RUN-CODE REGRESSION (incident 2026-08-15): the schema must state the
      // exact wire key. A model contaminated by codeapi's internal {lang, code}
      // HTTP contract emitted {"cmd": ...}, failing required:['command'] with
      // "Received tool input did not match expected schema". The description
      // self-documents the property name so this class of misuse is primed out.
      expect(command?.description).toContain('property name is exactly `command`');
      expect(command?.description).toContain('Do NOT use `cmd`, `code`, or `script`');
      expect(command?.description).toContain('do NOT pass `{lang, code}`');
      expect(command?.description).toContain('The property name is exactly `command` (a string). Do NOT use `cmd`, `code`, or `script`, and do NOT pass `{lang, code}`.');
    });

    it('registers read_file only when includeBash=false', () => {
      const toolRegistry = makeRegistry();
      const result = registerCodeExecutionTools({
        toolRegistry,
        toolDefinitions: [],
        includeBash: false,
      });

      expect(result.toolDefinitions.map((d) => d.name)).toEqual(['read_file']);
      expect(result.registered).toEqual(['read_file']);
      expect(toolRegistry.has('read_file')).toBe(true);
      expect(toolRegistry.has('bash_tool')).toBe(false);
    });

    it('uses a code-only read_file description when skill instructions are disabled', () => {
      const toolRegistry = makeRegistry();
      const result = registerCodeExecutionTools({
        toolRegistry,
        toolDefinitions: [],
        includeBash: true,
        includeSkillFileInstructions: false,
      });

      const readFile = result.toolDefinitions.find((d) => d.name === 'read_file');
      expect(readFile?.description).toContain('code-execution sandbox');
      expect(readFile?.description).toContain('sandbox working directory');
      expect(readFile?.description).not.toContain('/mnt/data');
      expect(readFile?.description).toContain('Do not run ls/find');
      expect(readFile?.description).toContain('/tmp is per-call scratch');
      expect(readFile?.description).toContain('truncated around 256KB');
      expect(readFile?.description).toContain('true filesystem discovery');
      expect(readFile?.description).not.toContain('{skillName}');
      expect(readFile?.description).not.toContain('SKILL.md');
      expect(JSON.stringify(readFile?.parameters)).not.toContain('{skillName}');
    });

    it('upgrades a code-only read_file definition when skills are enabled later in the run', () => {
      const toolRegistry = makeRegistry();
      const codeOnly = registerCodeExecutionTools({
        toolRegistry,
        toolDefinitions: [],
        includeBash: true,
        includeSkillFileInstructions: false,
      });
      const upgraded = registerCodeExecutionTools({
        toolRegistry,
        toolDefinitions: codeOnly.toolDefinitions,
        includeBash: false,
        includeSkillFileInstructions: true,
      });

      const readFile = upgraded.toolDefinitions.find((d) => d.name === 'read_file');
      expect(upgraded.registered).toEqual([]);
      expect(readFile?.description).toContain('{skillName}/{filePath}');
      expect(readFile?.description).toContain('skills/{skillName}/');
      expect(readFile?.description).toContain('SKILL.md');
      expect(toolRegistry.get('read_file')?.description).toBe(readFile?.description);
    });

    it('preserves pre-existing unrelated tool definitions', () => {
      const toolRegistry = makeRegistry();
      const existing: LCTool[] = [
        { name: 'calculator', description: 'calc', parameters: undefined } as LCTool,
      ];
      const result = registerCodeExecutionTools({
        toolRegistry,
        toolDefinitions: existing,
        includeBash: true,
      });

      const names = result.toolDefinitions.map((d) => d.name);
      expect(names).toEqual(['calculator', 'read_file', 'bash_tool']);
    });

    it('keeps code-execution tool descriptions within provider advisory limits', () => {
      const skillAwareWithRefs = registerCodeExecutionTools({
        toolRegistry: makeRegistry(),
        toolDefinitions: [],
        includeBash: true,
        includeSkillFileInstructions: true,
        enableToolOutputReferences: true,
      });
      const codeOnlyWithoutRefs = registerCodeExecutionTools({
        toolRegistry: makeRegistry(),
        toolDefinitions: [],
        includeBash: true,
        includeSkillFileInstructions: false,
        enableToolOutputReferences: false,
      });

      expect(
        maxToolDescriptionLength([
          ...skillAwareWithRefs.toolDefinitions,
          ...codeOnlyWithoutRefs.toolDefinitions,
        ]),
      ).toBeLessThanOrEqual(TOOL_DESCRIPTION_ADVISORY_MAX_LENGTH);
    });
  });

  describe('idempotence (second call in same run)', () => {
    it('is a no-op when both tools already live in the registry', () => {
      const toolRegistry = makeRegistry();
      const first = registerCodeExecutionTools({
        toolRegistry,
        toolDefinitions: [],
        includeBash: true,
      });
      /* Second call simulates skills-path + execute_code-path overlap. */
      const second = registerCodeExecutionTools({
        toolRegistry,
        toolDefinitions: first.toolDefinitions,
        includeBash: true,
      });

      expect(second.registered).toEqual([]);
      expect(second.toolDefinitions).toHaveLength(2);
      const names = second.toolDefinitions.map((d) => d.name).sort();
      expect(names).toEqual(['bash_tool', 'read_file']);
    });

    it('is a no-op when tools already live in toolDefinitions (no registry available)', () => {
      const existing: LCTool[] = [
        { name: 'read_file', description: 'pre', parameters: undefined } as LCTool,
        { name: 'bash_tool', description: 'pre', parameters: undefined } as LCTool,
      ];
      const result = registerCodeExecutionTools({
        toolRegistry: undefined,
        toolDefinitions: existing,
        includeBash: true,
      });

      expect(result.registered).toEqual([]);
      expect(result.toolDefinitions).toEqual(existing);
    });

    it('only adds the missing half when one is already registered', () => {
      const toolRegistry = makeRegistry();
      toolRegistry.set('read_file', {
        name: 'read_file',
        description: 'prev',
        parameters: undefined,
      } as LCTool);
      const result = registerCodeExecutionTools({
        toolRegistry,
        toolDefinitions: [],
        includeBash: true,
      });

      expect(result.registered).toEqual(['bash_tool']);
      const names = result.toolDefinitions.map((d) => d.name);
      expect(names).toEqual(['bash_tool']);
      expect(toolRegistry.has('read_file')).toBe(true);
      expect(toolRegistry.has('bash_tool')).toBe(true);
    });
  });

  describe('no-registry variant', () => {
    it('still returns merged toolDefinitions when toolRegistry is undefined', () => {
      const result = registerCodeExecutionTools({
        toolRegistry: undefined,
        toolDefinitions: [],
        includeBash: true,
      });

      const names = result.toolDefinitions.map((d) => d.name).sort();
      expect(names).toEqual(['bash_tool', 'read_file']);
      expect(result.registered.sort()).toEqual(['bash_tool', 'read_file']);
    });
  });

  describe('enableToolOutputReferences', () => {
    const findBashDef = (defs: LCTool[]): LCTool | undefined =>
      defs.find((d) => d.name === 'bash_tool');

    it('appends the {{tool<idx>turn<turn>}} guide when flag is true', () => {
      const result = registerCodeExecutionTools({
        toolRegistry: makeRegistry(),
        toolDefinitions: [],
        includeBash: true,
        enableToolOutputReferences: true,
      });

      const bash = findBashDef(result.toolDefinitions);
      expect(bash?.description).toContain('{{tool<idx>turn<turn>}}');
    });

    it('omits the {{tool<idx>turn<turn>}} guide when flag is false', () => {
      const result = registerCodeExecutionTools({
        toolRegistry: makeRegistry(),
        toolDefinitions: [],
        includeBash: true,
        enableToolOutputReferences: false,
      });

      const bash = findBashDef(result.toolDefinitions);
      expect(bash?.description).not.toContain('{{tool<idx>turn<turn>}}');
    });

    it('omits the guide by default when flag is unspecified', () => {
      const result = registerCodeExecutionTools({
        toolRegistry: makeRegistry(),
        toolDefinitions: [],
        includeBash: true,
      });

      const bash = findBashDef(result.toolDefinitions);
      expect(bash?.description).not.toContain('{{tool<idx>turn<turn>}}');
    });

    it('returns the same frozen bash_tool reference across calls with the same flag', () => {
      /**
       * The two `bash_tool` variants are cached at module scope so
       * repeated agent inits in the same process don't re-allocate
       * + re-freeze + re-build the description on every call.
       * Asserting reference equality across two fresh registries
       * pins that contract — a regression that switches back to a
       * per-call `Object.freeze` would fail this test.
       */
      const a = registerCodeExecutionTools({
        toolRegistry: makeRegistry(),
        toolDefinitions: [],
        includeBash: true,
        enableToolOutputReferences: true,
      });
      const b = registerCodeExecutionTools({
        toolRegistry: makeRegistry(),
        toolDefinitions: [],
        includeBash: true,
        enableToolOutputReferences: true,
      });

      expect(findBashDef(a.toolDefinitions)).toBe(findBashDef(b.toolDefinitions));
    });

    it('returns distinct frozen references for the two flag variants', () => {
      /**
       * Sanity check on the two-singleton cache: the with-refs and
       * without-refs definitions are distinct objects so toggling
       * the flag in `registerCodeExecutionTools` actually picks up
       * the alternate description, not the same cached reference.
       */
      const withRefs = registerCodeExecutionTools({
        toolRegistry: makeRegistry(),
        toolDefinitions: [],
        includeBash: true,
        enableToolOutputReferences: true,
      });
      const withoutRefs = registerCodeExecutionTools({
        toolRegistry: makeRegistry(),
        toolDefinitions: [],
        includeBash: true,
        enableToolOutputReferences: false,
      });

      const a = findBashDef(withRefs.toolDefinitions);
      const b = findBashDef(withoutRefs.toolDefinitions);
      expect(a).not.toBe(b);
      expect(a?.description).toContain('{{tool<idx>turn<turn>}}');
      expect(b?.description).not.toContain('{{tool<idx>turn<turn>}}');
    });
  });
});

describe('registerFileAuthoringTools', () => {
  const makeRegistry = (): LCToolRegistry => new Map() as unknown as LCToolRegistry;

  it('recognizes host-side file authoring tools as code-session-aware without mutating the shared set', () => {
    expect(isCodeSessionToolName('bash_tool')).toBe(true);
    expect(isCodeSessionToolName('create_file')).toBe(false);
    expect(isCodeSessionToolName('edit_file')).toBe(false);
    expect(isCodeSessionToolName('create_file', FILE_AUTHORING_TOOL_NAMES)).toBe(true);
    expect(isCodeSessionToolName('edit_file', FILE_AUTHORING_TOOL_NAMES)).toBe(true);
    expect(CODE_EXECUTION_TOOLS.has('create_file')).toBe(false);
    expect(CODE_EXECUTION_TOOLS.has('edit_file')).toBe(false);
  });

  it('registers create_file and edit_file with skill-aware descriptions', () => {
    const toolRegistry = makeRegistry();
    const result = registerFileAuthoringTools({
      toolRegistry,
      toolDefinitions: [],
      includeSkillFileInstructions: true,
    });

    const names = result.toolDefinitions.map((d) => d.name).sort();
    expect(names).toEqual(['create_file', 'edit_file']);
    expect(result.registered.sort()).toEqual(['create_file', 'edit_file']);
    expect(toolRegistry.has('create_file')).toBe(true);
    expect(toolRegistry.has('edit_file')).toBe(true);
    expect(result.toolDefinitions[0].responseFormat).toBe('content_and_artifact');
    expect(result.toolDefinitions.map((d) => d.description).join('\n')).toContain('skills/');
    expect(toolRegistry.get('create_file')?.description).toContain('frontmatter name must match');
    expect(toolRegistry.get('create_file')?.description).toContain('trigger-friendly');
    expect(toolRegistry.get('create_file')?.description).toContain('references/template.html');
    expect(toolRegistry.get('create_file')?.description).toContain('templates/{file}');
    expect(toolRegistry.get('edit_file')?.description).toContain('edit_file cannot rename skills');
    expect(toolRegistry.get('edit_file')?.description).toContain('Keep SKILL.md concise');
    expect(toolRegistry.get('edit_file')?.description).toContain('templates/');
    expect(filePathDescription(toolRegistry.get('create_file'))).toContain(
      'frontmatter name must match',
    );
    expect(filePathDescription(toolRegistry.get('edit_file'))).toContain(
      'edit_file cannot rename skills',
    );
  });

  it('registers code-only descriptions for code-exec-only agents', () => {
    const toolRegistry = makeRegistry();
    const result = registerFileAuthoringTools({
      toolRegistry,
      toolDefinitions: [],
      includeSkillFileInstructions: false,
    });

    const createFile = result.toolDefinitions.find((d) => d.name === 'create_file');
    const editFile = result.toolDefinitions.find((d) => d.name === 'edit_file');
    expect(createFile?.description).toContain('code-execution sandbox');
    expect(createFile?.description).toContain('relative to your working directory');
    expect(createFile?.description).not.toContain('/mnt/data');
    expect(createFile?.description).not.toContain('skills/');
    expect(editFile?.description).toContain('code-execution sandbox');
    expect(editFile?.description).toContain('relative to your working directory');
    expect(editFile?.description).not.toContain('/mnt/data');
    expect(editFile?.description).not.toContain('skills/');
    expect(filePathDescription(createFile)).toContain('code-execution sandbox');
    expect(filePathDescription(createFile)).not.toContain('skills/');
    expect(filePathDescription(createFile)).not.toContain('SKILL.md');
    expect(filePathDescription(editFile)).toContain('code-execution sandbox');
    expect(filePathDescription(editFile)).not.toContain('skills/');
    expect(filePathDescription(editFile)).not.toContain('rename skills');
  });

  it('is idempotent across repeated registration calls', () => {
    const toolRegistry = makeRegistry();
    const first = registerFileAuthoringTools({
      toolRegistry,
      toolDefinitions: [],
    });
    const second = registerFileAuthoringTools({
      toolRegistry,
      toolDefinitions: first.toolDefinitions,
    });

    expect(second.registered).toEqual([]);
    expect(second.toolDefinitions).toHaveLength(2);
  });

  it('upgrades code-only definitions to skill-aware definitions', () => {
    const toolRegistry = makeRegistry();
    const codeOnly = registerFileAuthoringTools({
      toolRegistry,
      toolDefinitions: [],
      includeSkillFileInstructions: false,
    });
    const upgraded = registerFileAuthoringTools({
      toolRegistry,
      toolDefinitions: codeOnly.toolDefinitions,
      includeSkillFileInstructions: true,
    });

    expect(upgraded.registered).toEqual([]);
    expect(upgraded.toolDefinitions.find((d) => d.name === 'create_file')?.description).toContain(
      'skills/',
    );
    expect(toolRegistry.get('edit_file')?.description).toContain('skills/');
  });

  it('keeps file-authoring tool descriptions within provider advisory limits', () => {
    const skillAware = registerFileAuthoringTools({
      toolRegistry: makeRegistry(),
      toolDefinitions: [],
      includeSkillFileInstructions: true,
    });
    const codeOnlyRegistry = makeRegistry();
    const codeOnly = registerFileAuthoringTools({
      toolRegistry: codeOnlyRegistry,
      toolDefinitions: [],
      includeSkillFileInstructions: false,
    });
    const upgraded = registerFileAuthoringTools({
      toolRegistry: codeOnlyRegistry,
      toolDefinitions: codeOnly.toolDefinitions,
      includeSkillFileInstructions: true,
    });

    expect(
      maxToolDescriptionLength([
        ...skillAware.toolDefinitions,
        ...codeOnly.toolDefinitions,
        ...upgraded.toolDefinitions,
      ]),
    ).toBeLessThanOrEqual(TOOL_DESCRIPTION_ADVISORY_MAX_LENGTH);
  });

  it('distinguishes host file authoring definitions from user tools with matching names', () => {
    const result = registerFileAuthoringTools({
      toolRegistry: makeRegistry(),
      toolDefinitions: [],
      includeSkillFileInstructions: true,
    });
    const createFile = result.toolDefinitions.find((d) => d.name === 'create_file');

    expect(isFileAuthoringToolDefinition(createFile)).toBe(true);
    expect(
      isFileAuthoringToolDefinition({
        name: 'create_file',
        description: 'A user-defined create_file action',
        parameters: { type: 'object', properties: {} } as LCTool['parameters'],
      }),
    ).toBe(false);
  });
});

describe('registerDocumentVisualQATool', () => {
  const makeRegistry = (): LCToolRegistry => new Map() as unknown as LCToolRegistry;

  it('registers document_visual_qa with the exact self-documenting input schema', () => {
    const toolRegistry = makeRegistry();
    const result = registerDocumentVisualQATool({
      toolRegistry,
      toolDefinitions: [],
    });

    expect(result.registered).toEqual(['document_visual_qa']);
    expect(result.toolDefinitions.map((d) => d.name)).toEqual(['document_visual_qa']);
    expect(toolRegistry.has('document_visual_qa')).toBe(true);

    const def = result.toolDefinitions[0];
    expect(def.name).toBe('document_visual_qa');
    expect(def.responseFormat).toBe('content');

    const properties = (
      def.parameters as { type: 'object'; properties: Record<string, { type?: string }> }
    ).properties;
    expect(Object.keys(properties).sort()).toEqual([
      'file_ids',
      'file_names',
      'focus',
      'maxPages',
      'session_id',
    ]);
    expect((def.parameters as { required?: string[] }).required).toContain('session_id');
    expect(properties.session_id?.type).toBe('string');
    expect((properties.maxPages as { maximum?: number }).maximum).toBe(8);
    expect((properties.maxPages as { default?: number }).default).toBe(4);
  });

  it('documents the checks and verdict schema in the description', () => {
    const result = registerDocumentVisualQATool({
      toolRegistry: makeRegistry(),
      toolDefinitions: [],
    });
    const description = result.toolDefinitions[0].description;
    expect(description).toContain('clipping');
    expect(description).toContain('visual hierarchy');
    expect(description).toContain('legibility');
    expect(description).toContain('"verdict":"PASS"|"ISSUES_FOUND"');
    expect(description).toContain('session_id (required)');
  });

  it('is idempotent across repeated registration calls', () => {
    const toolRegistry = makeRegistry();
    const first = registerDocumentVisualQATool({ toolRegistry, toolDefinitions: [] });
    const second = registerDocumentVisualQATool({
      toolRegistry,
      toolDefinitions: first.toolDefinitions,
    });

    expect(second.registered).toEqual([]);
    expect(second.toolDefinitions).toHaveLength(1);
  });

  it('skips when the tool is already present in the registry', () => {
    const toolRegistry = makeRegistry();
    registerDocumentVisualQATool({ toolRegistry, toolDefinitions: [] });
    const result = registerDocumentVisualQATool({ toolRegistry, toolDefinitions: [] });

    expect(result.registered).toEqual([]);
    expect(result.toolDefinitions).toEqual([]);
  });

  it('keeps the description within provider advisory limits', () => {
    const result = registerDocumentVisualQATool({
      toolRegistry: makeRegistry(),
      toolDefinitions: [],
    });
    expect(
      maxToolDescriptionLength([...result.toolDefinitions]),
    ).toBeLessThanOrEqual(TOOL_DESCRIPTION_ADVISORY_MAX_LENGTH);
  });
});
