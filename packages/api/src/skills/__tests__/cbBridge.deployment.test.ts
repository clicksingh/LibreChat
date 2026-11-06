import path from 'path';
import {
  createDeploymentSkillMethods,
  initializeDeploymentSkills,
  loadDeploymentSkillsFromDirectory,
} from '../deployment';

const projectRoot = path.resolve(__dirname, '../../../../..');
const skillsDirectory = path.join(projectRoot, 'skill');

describe('default read-only CB Bridge deployment skill', () => {
  test('real project startup discovers one centrally deployed, model-invocable skill', async () => {
    const registry = await initializeDeploymentSkills({ projectRoot, env: {} });
    const bridge = registry.list().find((skill) => skill.name === 'cb-bridge');
    expect(bridge).toMatchObject({
      name: 'cb-bridge',
      source: 'deployment',
      deployment: true,
      isPublic: true,
      authorName: 'Deployment',
      alwaysApply: false,
      userInvocable: false,
      disableModelInvocation: false,
      sourceMetadata: { deployment: true, directory: 'skill/cb-bridge' },
    });
    expect(bridge?.description).toContain('physical Windows PC');
    expect(bridge?.fileCount).toBe(0);
    expect(registry.getByName('cb-bridge', registry.ids())?._id.toString()).toBe(
      bridge?._id.toString(),
    );
    const methods = createDeploymentSkillMethods({});
    const resolved = bridge?._id ? await methods.getSkillById(bridge._id) : null;
    expect(resolved).toMatchObject({ source: 'deployment', name: 'cb-bridge' });
  });

  test('deployment skill teaches three domains, permissions, reconnect and concrete intents', async () => {
    const registry = await loadDeploymentSkillsFromDirectory(skillsDirectory, { projectRoot });
    const bridge = registry.list().find((skill) => skill.name === 'cb-bridge');
    expect(bridge).toBeDefined();
    const body = bridge?.body ?? '';
    for (const phrase of [
      'AI sandbox',
      'Files / Project storage',
      'Read',
      'Edit',
      'PowerShell',
      'screenshots',
      'permission',
      'disconnect or reconnect',
      'tool disappears',
      'Check my Desktop',
      'Look at the file on my PC',
      'See my screen',
      'What apps are installed?',
      'Save this to my approved folder',
      'Use my computer',
    ]) {
      expect(body).toContain(phrase);
    }
    expect(body).toContain('Do not send normal staff to configure MCP endpoints');
    expect(body).toContain('CUA is out of scope');
    expect(body).not.toContain('Kimberly');
    expect(body).not.toContain('bearerToken');
  });
});
