const { test } = require('node:test');
const assert = require('node:assert/strict');
const { exemptRocketLoader } = require('./post-build.cjs');

test('protects Vite/PWA injected scripts after build, not just source main', () => {
  const source = [
    '<script type="module" crossorigin src="/assets/index-1234.js"></script>',
    '<script src="/registerSW.js"></script>',
    '<script data-cfasync="false">window.initialized = true</script>',
  ].join('\n');
  const protectedHtml = exemptRocketLoader(source);
  assert.match(
    protectedHtml,
    /<script data-cfasync="false" type="module" crossorigin src="\/assets\/index-1234.js"/,
  );
  assert.match(protectedHtml, /<script data-cfasync="false" src="\/registerSW.js"/);
  assert.equal((protectedHtml.match(/data-cfasync="false"/g) || []).length, 3);
  assert.equal(exemptRocketLoader(protectedHtml), protectedHtml);
});

test('preserves script attributes and ignores similar HTML text', () => {
  const html =
    '<script defer nonce="abc" src="/x.js"></script><p>script</p><noscript>off</noscript>';
  assert.equal(
    exemptRocketLoader(html),
    '<script data-cfasync="false" defer nonce="abc" src="/x.js"></script><p>script</p><noscript>off</noscript>',
  );
});
