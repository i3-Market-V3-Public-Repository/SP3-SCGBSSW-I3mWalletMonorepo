const { defaults: tsjPreset } = require('ts-jest/presets')

module.exports = {
  moduleFileExtensions: [
    'ts',
    'tsx',
    'js',
    'jsx'
  ],
  collectCoverage: true,
  collectCoverageFrom: [
    'packages/**/src/**/*.ts',
    '!**/examples/**',
    '!packages/cli/**',
    '!packages/kms-local-react-native/**',
    '!**/types/**',
    '!**/build/**',
    '!**/node_modules/**'
  ],
  coverageReporters: [
    'text',
    'lcov',
    'json'
  ],
  coverageDirectory: './coverage',
  transform: {
    ...tsjPreset.transform
  },
  testMatch: [
    '**/__tests__/**/*.spec.ts'
  ],
  globals: {
    'ts-jest': {
      tsconfig: './tsconfig.json'
    }
  },

  // For main process:
  // runner: '@jest-runner/electron/main',
  testEnvironment: 'node',
  // For renderer process use:
  // runner: '@jest-runner/electron',
  // testEnvironment: '@jest-runner/electron/environment',
  automock: false,
  setupFiles: [
    'dotenv/config'
  ]
}
