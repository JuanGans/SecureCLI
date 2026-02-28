/**
 * Utility helper functions
 */

/**
 * Get line content from source code
 */
function getLineContent(source, lineNumber) {
  const lines = source.split('\n');
  return lines[lineNumber - 1] || '';
}

/**
 * Extract context lines around finding
 */
function getContextLines(source, lineNumber, context = 2) {
  const lines = source.split('\n');
  const start = Math.max(0, lineNumber - 1 - context);
  const end = Math.min(lines.length, lineNumber + context);
  
  return lines.slice(start, end).map((line, index) => ({
    lineNumber: start + index + 1,
    content: line,
    isTarget: start + index + 1 === lineNumber,
  }));
}

/**
 * Sanitize file path for display
 */
function sanitizePath(filePath) {
  return filePath.replace(/\\/g, '/');
}

/**
 * Generate unique ID
 */
function generateId(prefix = 'finding') {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Parse command line arguments
 */
function parseArgs(argv) {
  const args = {
    target: null,
    verbose: false,
    format: 'cli',
    output: null,
  };

  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    
    if (arg === '--verbose' || arg === '-v') {
      args.verbose = true;
    } else if (arg === '--format') {
      args.format = argv[++i] || 'cli';
    } else if (arg === '--output' || arg === '-o') {
      args.output = argv[++i];
    } else if (!arg.startsWith('-')) {
      args.target = arg;
    }
  }

  return args;
}

module.exports = {
  getLineContent,
  getContextLines,
  sanitizePath,
  generateId,
  parseArgs,
};
