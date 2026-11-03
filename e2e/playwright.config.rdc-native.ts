import { defineConfig } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import baseConfig from './playwright.config.mock';

const generatedConfig = path.resolve(__dirname, '.generated/librechat.e2e.yaml');
let generatedYaml = fs.readFileSync(generatedConfig, 'utf8');
const allowedAddress = "    - '127.0.0.1:8847'";
const allowedOrigin = "    - 'http://127.0.0.1:8847'";

if (!generatedYaml.includes(allowedAddress)) {
  generatedYaml = generatedYaml.replace(
    /^mcpSettings:\r?$/m,
    'mcpSettings:\n  allowedAddresses:\n' + allowedAddress,
  );
}
if (!generatedYaml.includes(allowedOrigin)) {
  generatedYaml = generatedYaml.replace(
    /^ {2}allowedDomains:\r?$/m,
    '  allowedDomains:\n' + allowedOrigin,
  );
}
if (!generatedYaml.includes(allowedAddress) || !generatedYaml.includes(allowedOrigin)) {
  throw new Error('Failed to inject the PC-bridge CI MCP allowlist');
}
fs.writeFileSync(generatedConfig, generatedYaml);

export default defineConfig({
  ...baseConfig,
  testIgnore: [],
  testMatch: ['**/rdc-native-registration.spec.ts'],
  globalSetup: undefined,
  globalTeardown: undefined,
  use: {
    ...baseConfig.use,
    storageState: undefined,
  },
});
