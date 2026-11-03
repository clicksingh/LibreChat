import { defineConfig } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import baseConfig from './playwright.config.mock';

const generatedConfig = path.resolve(__dirname, '.generated/librechat.e2e.yaml');
fs.appendFileSync(generatedConfig, "\nmcpSettings:\n  allowedAddresses:\n    - '127.0.0.1:8847'\n");

export default defineConfig({
  ...baseConfig,
  globalSetup: undefined,
  globalTeardown: undefined,
  use: {
    ...baseConfig.use,
    storageState: undefined,
  },
});
