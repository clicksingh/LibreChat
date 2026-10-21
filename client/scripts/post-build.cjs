const fs = require('fs-extra');
const path = require('path');

/**
 * Rocket Loader rewrites script loading order, including the Vite-PWA
 * registerSW.js script injected AFTER src/index.html transforms.
 * Protect EVERY script tag in final dist/index.html at last build step.
 */
function exemptRocketLoader(html) {
  return html.replace(/<script\b[^>]*>/gi, (tag) =>
    /\bdata-cfasync\s*=/i.test(tag)
      ? tag
      : tag.replace(/^<script\b/i, '<script data-cfasync="false"'),
  );
}

async function postBuild() {
  try {
    await fs.copy('public/assets', 'dist/assets');
    await fs.copy('public/robots.txt', 'dist/robots.txt');
    const target = path.join(process.cwd(), 'dist', 'index.html');
    const original = await fs.readFile(target, 'utf8');
    const protectedHtml = exemptRocketLoader(original);
    if (!/<script\b/i.test(protectedHtml)) {
      throw new Error('dist/index.html contains no scripts; invalid Vite output');
    }
    if (protectedHtml !== original) {
      await fs.writeFile(target, protectedHtml);
    }
    console.log('PWA assets copied; Rocket Loader exemptions applied to all built scripts.');
  } catch (error) {
    console.error('Post-build preparation failed:', error);
    process.exitCode = 1;
  }
}

if (require.main === module) {
  void postBuild();
}

module.exports = { exemptRocketLoader };
