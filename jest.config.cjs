module.exports = {
  testEnvironment: 'node',
  roots: ['<rootDir>'],
  testMatch: ['**/__tests__/**/*.js', '**/?(*.)+(spec|test).js'],
  moduleNameMapper: {
    '^~/(.*)$': '<rootDir>/api/$1',
    '^@librechat/data-schemas$': '<rootDir>/packages/data-schemas/dist/index.cjs',
  },
  moduleDirectories: ['node_modules', '<rootDir>'],
  testPathIgnorePatterns: ['/node_modules/', '/dist/', '/.next/'],
  collectCoverageFrom: [
    'api/**/*.js',
    'packages/*/src/**/*.{js,ts}',
    '!**/__tests__/**',
    '!**/node_modules/**',
    '!**/dist/**',
  ],
};
