/**
 * Application configuration
 */

module.exports = {
  app: {
    name: 'SecureCLI',
    version: '1.0.0',
    description: 'Hybrid SAST Scanner - Vulnerability Detection Engine',
  },

  scanning: {
    maxFileSize: 10 * 1024 * 1024, // 10MB
    batchSize: 100,
    timeout: 30000, // 30 seconds
  },

  detection: {
    enableRegex: true,
    enableAst: true,
    enableTaint: true,
  },

  scoring: {
    baseSeverityWeight: {
      CRITICAL: 10,
      HIGH: 8,
      MEDIUM: 6,
      LOW: 3,
    },
    confidenceThreshold: 0.5,
  },

  reporting: {
    showContext: true,
    contextLines: 2,
    includeEducation: true,
  },

  output: {
    format: 'cli', // cli, json, html, xml
    colors: true,
    verbose: false,
  },
};
