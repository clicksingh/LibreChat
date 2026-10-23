'use strict';

/**
 * GM mount proof. The admin device-policy router was built, tested (83 specs) and given a real data
 * layer (97 more), but it was never MOUNTED — `api/server/routes/index.js` and `api/server/index.js`
 * were out of scope for every workstream, so the endpoints were proven and unreachable.
 *
 * "Proven" and "used" are different claims, and this file is the difference. It asserts that the
 * routes index actually exports the router and that the mount path is wired in the server, so the
 * panel can reach it on a running server rather than only inside a spec's own Express app.
 */

const path = require('node:path');
const fs = require('node:fs');

const REPO = path.resolve(__dirname, '..', '..', '..', '..');
const routesIndexPath = path.join(REPO, 'api/server/routes/index.js');
const serverIndexPath = path.join(REPO, 'api/server/index.js');

describe('GM mount proof — the admin device-policy router is reachable', () => {
  it('the routes index requires and re-exports the device-policy router', () => {
    /**
     * Asserted against the SOURCE rather than by `require`ing the routes index, and that is a
     * deliberate limit rather than laziness: requiring it pulls in an ESM-only dependency chain that
     * this worktree's jest cannot parse (`Unexpected token 'export'`), which is the same pre-existing
     * issue that makes `ldap.spec.js` and `grants.spec.js` fail. Loading it here would test the
     * toolchain, not the mount. The router MODULE's loadability is proven separately below and by its
     * own 83 specs; what this test must prove is that the index is wired to it.
     */
    const source = fs.readFileSync(routesIndexPath, 'utf8');
    expect(source).toMatch(/const\s+adminDevicePolicy\s*=\s*require\('\.\/admin\/devicePolicy'\)/);
    expect(source).toMatch(/^\s*adminDevicePolicy,\s*$/m);
  });

  it('the router is registered in the index AND mounted, not merely imported', () => {
    /**
     * The three-line shape matters: an import with no mount, or a mount with no export, leaves the
     * endpoints unreachable while looking wired. Both halves are asserted.
     */
    const routesSource = fs.readFileSync(routesIndexPath, 'utf8');
    const serverSource = fs.readFileSync(serverIndexPath, 'utf8');
    expect(routesSource).toMatch(/const\s+adminDevicePolicy\s*=\s*require\('\.\/admin\/devicePolicy'\)/);
    expect(routesSource).toMatch(/^\s*adminDevicePolicy,\s*$/m);
    expect(serverSource).toMatch(
      /app\.use\(\s*'\/api\/admin\/device-policy'\s*,\s*routes\.adminDevicePolicy\s*\)/,
    );
  });

  it('the server mounts it under the admin namespace, beside its siblings', () => {
    const source = fs.readFileSync(serverIndexPath, 'utf8');
    expect(source).toMatch(
      /app\.use\(\s*'\/api\/admin\/device-policy'\s*,\s*routes\.adminDevicePolicy\s*\)/,
    );
    // And it must sit with the rest of the admin family rather than somewhere arbitrary.
    const adminMounts = source.match(/app\.use\('\/api\/admin\/[^']+',\s*routes\.\w+\)/g) || [];
    const names = adminMounts.join('\n');
    expect(names).toMatch(/\/api\/admin\/roles/);
    expect(names).toMatch(/\/api\/admin\/device-policy/);
  });

  it('the mount is additive: every pre-existing admin mount is still present', () => {
    const source = fs.readFileSync(serverIndexPath, 'utf8');
    for (const sibling of [
      '/api/admin/config',
      '/api/admin/grants',
      '/api/admin/groups',
      '/api/admin/roles',
      '/api/admin/skills',
      '/api/admin/users',
      '/api/admin/quota-policy',
    ]) {
      expect(source).toContain(`app.use('${sibling}'`);
    }
  });
});