/**
 * Utility helper functions
 */

const path = require('path');

/**
 * Detect programming language from file extension
 */
function detectLanguage(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  
  const languageMap = {
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.php': 'php',
    '.php3': 'php',
    '.php4': 'php',
    '.php5': 'php',
    '.phtml': 'php',
    '.py': 'python',
    '.rb': 'ruby',
    '.java': 'java'
  };
  
  return languageMap[ext] || 'unknown';
}

/**
 * Check if line is in documentation/comment context
 */
function isInDocumentation(code, lineNumber) {
  const lines = code.split('\n');
  const line = lines[lineNumber - 1];
  
  if (!line) return false;
  
  // Check if line is in comment
  const trimmed = line.trim();
  if (trimmed.startsWith('//') || 
      trimmed.startsWith('*') || 
      trimmed.startsWith('/*') ||
      trimmed.includes('<!--')) {
    return true;
  }
  
  // Only flag <pre>/<code> if they're in comments or actual help files
  if (/help\.php/i.test(line)) return true;
  if (trimmed.startsWith('//') && (/<pre>/i.test(line) || /<code>/i.test(line))) return true;
  
  // Check for clear documentation patterns
  const docPatterns = [
    /spoiler/i,
    /example.*code/i,
    /demo.*code/i,
    /how.*exploit/i,
    /documentation/i,
    /this shows/i
  ];
  
  return docPatterns.some(pattern => pattern.test(line));
}

/**
 * Check if code is hardcoded (not user input)
 */
function isHardcoded(code, lineNumber) {
  const lines = code.split('\n');
  const line = lines[lineNumber - 1];
  
  if (!line) return false;

  // Never filter lines containing known danger sinks
  if (/document\.write|\.innerHTML|eval\s*\(|echo\s+|print\s+|mysqli_query|system\s*\(/.test(line)) {
    return false;
  }
  
  // Check for hardcoded patterns
  const hardcodedPatterns = [
    /onclick=["']javascript:[^"']*["']/i,  // onclick with hardcoded js
    /window\.opener/i,  // popup code
    /window\.close/i,
    /self\.close/i,
    /<input[^>]+type=["'](text|submit|button)["'][^>]*>/i,  // Normal form inputs
  ];
  
  return hardcodedPatterns.some(pattern => pattern.test(line));
}

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
  detectLanguage,
  isInDocumentation,
  isHardcoded,
  getLineContent,
  getContextLines,
  sanitizePath,
  generateId,
  parseArgs,
};
