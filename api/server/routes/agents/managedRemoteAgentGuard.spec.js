'use strict';
const fs = require('node:fs'),
  path = require('node:path');
describe('remote-agent API route must enforce current company model permissions', () => {
  test.each(['openai.js', 'responses.js'])('%s denies non-admin before handler', (file) => {
    const source = fs.readFileSync(path.join(__dirname, file), 'utf8');
    const auth = source.indexOf('router.use(requireRemoteAgentAuth)');
    const config = source.indexOf('router.use(configMiddleware)');
    const feature = source.indexOf('router.use(checkRemoteAgentsFeature)');
    const guard = source.indexOf('router.use(rejectNonAdminRemoteAgentApi)');
    const post = source.indexOf('router.post(');
    expect(auth).toBeGreaterThan(0);
    expect(config).toBeGreaterThan(auth);
    expect(feature).toBeGreaterThan(config);
    expect(guard).toBeGreaterThan(feature);
    expect(post).toBeGreaterThan(guard);
  });
});
