const esModules = [
  '@langchain/langgraph',
  '@langchain/langgraph-checkpoint',
  '@langchain/langgraph-sdk',
  'uuid',
].join('|');

export default {
  collectCoverageFrom: ['src/**/*.{js,jsx,ts,tsx}', '!<rootDir>/node_modules/'],
  coveragePathIgnorePatterns: ['/node_modules/', '/dist/'],
  testPathIgnorePatterns: [
    '/node_modules/',
    '/dist/',
    '\\.dev\\.ts$',
    '\\.helper\\.ts$',
    '\\.helper\\.d\\.ts$',
    '/__tests__/helpers/',
    '\\.manual\\.spec\\.[jt]sx?$',
  ],
  coverageReporters: ['text', 'cobertura'],
  testResultsProcessor: 'jest-junit',
  transform: {
    '\\.[jt]sx?$': [
      'babel-jest',
      {
        presets: [
          ['@babel/preset-env', { targets: { node: 'current' } }],
          '@babel/preset-typescript',
        ],
      },
    ],
  },
  transformIgnorePatterns: [`/node_modules/(?!(${esModules})/).*/`],
  moduleNameMapper: {
    '^@src/(.*)$': '<rootDir>/src/$1',
    '~/(.*)': '<rootDir>/src/$1',
    /* 8S3C.1 task C — resolve `librechat-data-provider` to this worktree's own
       source rather than the shared host build. The host dist is built from an
       older data-provider and lacks `Tools.document_visual_qa`, which would make
       any added-agent parity test for that tool fail (or, worse, pass silently
       against an undefined enum member). Source and dist are functionally
       equivalent; the source is the authority for the api tests. */
    '^librechat-data-provider$': '<rootDir>/../data-provider/src/index.ts',
  },
  // coverageThreshold: {
  //   global: {
  //     statements: 58,
  //     branches: 49,
  //     functions: 50,
  //     lines: 57,
  //   },
  // },
  setupFiles: ['<rootDir>/jest.setup.cjs'],
  maxWorkers: '50%',
  restoreMocks: true,
  testTimeout: 15000,
};
