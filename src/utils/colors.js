/**
 * Terminal color utilities for professional reporting
 */

const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  dim: '\x1b[2m',
  
  // Foreground colors
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  
  // Background colors
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgYellow: '\x1b[43m',
  bgBlue: '\x1b[44m',
};

const severity = {
  CRITICAL: `${colors.bright}${colors.red}CRITICAL${colors.reset}`,
  HIGH: `${colors.red}HIGH${colors.reset}`,
  MEDIUM: `${colors.yellow}MEDIUM${colors.reset}`,
  LOW: `${colors.green}LOW${colors.reset}`,
};

const log = {
  error: (msg) => console.log(`${colors.red}[ERROR]${colors.reset} ${msg}`),
  warn: (msg) => console.log(`${colors.yellow}[WARN]${colors.reset} ${msg}`),
  info: (msg) => console.log(`${colors.cyan}[INFO]${colors.reset} ${msg}`),
  success: (msg) => console.log(`${colors.green}[OK]${colors.reset} ${msg}`),
  debug: (msg) => console.log(`${colors.dim}[DEBUG]${colors.reset} ${msg}`),
};

module.exports = {
  colors,
  severity,
  log,
};
