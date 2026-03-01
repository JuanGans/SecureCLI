/**
 * Enhanced PHP Source-Sink Mapping
 * STAGE 2: Static Taint Analysis Configuration
 * 
 * Defines what is a source, what is a sink, and the vulnerability types
 * This is used by the taint analyzer to validate data flows
 */

/**
 * DATA SOURCES - Where tainted data enters the application
 */
const PHP_DATA_SOURCES = {
  // User input sources
  $_GET: {
    name: 'URL Query Parameters',
    category: 'USER_INPUT',
    severity: 'HIGH',
    description: 'Data from HTTP GET parameters'
  },
  $_POST: {
    name: 'HTTP POST Body',
    category: 'USER_INPUT',
    severity: 'HIGH',
    description: 'Data from HTTP POST parameters'
  },
  $_REQUEST: {
    name: 'HTTP Request Data',
    category: 'USER_INPUT',
    severity: 'HIGH',
    description: 'Data from GET, POST, or COOKIE'
  },
  $_COOKIE: {
    name: 'HTTP Cookies',
    category: 'USER_CONTROLLED',
    severity: 'MEDIUM',
    description: 'Data from HTTP cookies'
  },
  $_FILES: {
    name: 'File Upload Data',
    category: 'USER_INPUT',
    severity: 'CRITICAL',
    description: 'Uploaded file metadata'
  },
  $_SESSION: {
    name: 'Session Data',
    category: 'APPLICATION_STATE',
    severity: 'MEDIUM',
    description: 'Session variables (may be user-controlled)'
  },
  $_SERVER: {
    name: 'Server Variables',
    category: 'ENVIRONMENT',
    severity: 'MEDIUM',
    description: 'HTTP headers, server info (some are user-controlled: USER_AGENT, REFERER, etc.)'
  },
  $_ENV: {
    name: 'Environment Variables',
    category: 'ENVIRONMENT',
    severity: 'LOW',
    description: 'System environment variables'
  },

  // User-controlled server variables (subset of $_SERVER)
  'USER_AGENT': {
    name: 'User Agent Header',
    category: 'USER_INPUT',
    severity: 'HIGH',
    parent: '$_SERVER'
  },
  'HTTP_REFERER': {
    name: 'HTTP Referer Header',
    category: 'USER_INPUT',
    severity: 'HIGH',
    parent: '$_SERVER'
  },
  'HTTP_ACCEPT_LANGUAGE': {
    name: 'Accept Language Header',
    category: 'USER_INPUT',
    severity: 'MEDIUM',
    parent: '$_SERVER'
  },
  'QUERY_STRING': {
    name: 'Raw Query String',
    category: 'USER_INPUT',
    severity: 'HIGH',
    parent: '$_SERVER'
  },

  // Function inputs (may return user-controlled data)
  'input()': {
    name: 'Laravel Input Helper',
    category: 'FRAMEWORK',
    severity: 'HIGH',
    description: 'Laravel input() function'
  }
};

/**
 * DATA SINKS - Where tainted data could cause vulnerabilities
 */
const PHP_DATA_SINKS = {
  // XSS SINKS - Output to browser
  'echo': {
    name: 'Echo Output',
    vulnerabilityType: 'XSS',
    severity: 'HIGH',
    description: 'Direct output to browser',
    requiresSanitization: ['htmlspecialchars', 'htmlentities', 'strip_tags']
  },
  'print': {
    name: 'Print Output',
    vulnerabilityType: 'XSS',
    severity: 'HIGH',
    description: 'Direct output to browser',
    requiresSanitization: ['htmlspecialchars', 'htmlentities', 'strip_tags']
  },
  'printf': {
    name: 'Formatted Print',
    vulnerabilityType: 'XSS',
    severity: 'HIGH',
    description: 'Formatted output to browser',
    requiresSanitization: ['htmlspecialchars', 'htmlentities', 'strip_tags']
  },
  'sprintf': {
    name: 'String Formatting',
    vulnerabilityType: 'XSS',
    severity: 'MEDIUM',
    description: 'String formatting (might be output later)',
    requiresSanitization: ['htmlspecialchars', 'htmlentities', 'strip_tags']
  },
  'file_put_contents': {
    name: 'File Write',
    vulnerabilityType: 'FILE_INJECTION',
    severity: 'HIGH',
    description: 'Write to file'
  },
  'header': {
    name: 'HTTP Header Output',
    vulnerabilityType: 'HEADER_INJECTION',
    severity: 'HIGH',
    description: 'Set HTTP headers'
  },
  'setcookie': {
    name: 'Cookie Setting',
    vulnerabilityType: 'COOKIE_INJECTION',
    severity: 'MEDIUM',
    description: 'Set HTTP cookies'
  },
  'curl_setopt': {
    name: 'CURL Configuration',
    vulnerabilityType: 'SSRF',
    severity: 'HIGH',
    description: 'Set CURL options (URL parameter)'
  },

  // SQL SINKS - Database execution
  'mysqli_query': {
    name: 'MySQLi Query',
    vulnerabilityType: 'SQL_INJECTION',
    severity: 'CRITICAL',
    description: 'Execute query with MySQLi',
    requiresSanitization: ['prepared_statements', 'parameterized_query']
  },
  'mysql_query': {
    name: 'MySQL Query (Deprecated)',
    vulnerabilityType: 'SQL_INJECTION',
    severity: 'CRITICAL',
    description: 'Execute query with deprecated mysql extension',
    requiresSanitization: ['prepared_statements']
  },
  'query': {
    name: 'Database Query',
    vulnerabilityType: 'SQL_INJECTION',
    severity: 'CRITICAL',
    description: 'Generic query execution',
    requiresSanitization: ['prepared_statements', 'parameterized_query']
  },
  'prepare': {
    name: 'Prepared Statement',
    vulnerabilityType: 'SQL_INJECTION',
    severity: 'LOW',
    description: 'Prepared statement preparation (safe if parameters used)',
    isParameterized: true
  },
  'execute': {
    name: 'Execute Query',
    vulnerabilityType: 'SQL_INJECTION',
    severity: 'CRITICAL',
    description: 'Execute prepared or unprepared query'
  },
  'select': {
    name: 'SELECT Query',
    vulnerabilityType: 'SQL_INJECTION',
    severity: 'CRITICAL',
    description: 'Execute SELECT query'
  },
  'insert': {
    name: 'INSERT Query',
    vulnerabilityType: 'SQL_INJECTION',
    severity: 'CRITICAL',
    description: 'Execute INSERT query'
  },
  'update': {
    name: 'UPDATE Query',
    vulnerabilityType: 'SQL_INJECTION',
    severity: 'CRITICAL',
    description: 'Execute UPDATE query'
  },
  'delete': {
    name: 'DELETE Query',
    vulnerabilityType: 'SQL_INJECTION',
    severity: 'CRITICAL',
    description: 'Execute DELETE query'
  },

  // CODE EXECUTION SINKS
  'eval': {
    name: 'PHP eval()',
    vulnerabilityType: 'CODE_INJECTION',
    severity: 'CRITICAL',
    description: 'Execute arbitrary PHP code'
  },
  'assert': {
    name: 'PHP assert()',
    vulnerabilityType: 'CODE_INJECTION',
    severity: 'CRITICAL',
    description: 'PHP assert function'
  },
  'system': {
    name: 'System Command Execution',
    vulnerabilityType: 'COMMAND_INJECTION',
    severity: 'CRITICAL',
    description: 'Execute system commands'
  },
  'exec': {
    name: 'exec() Command',
    vulnerabilityType: 'COMMAND_INJECTION',
    severity: 'CRITICAL',
    description: 'Execute system command'
  },
  'passthru': {
    name: 'passthru() Command',
    vulnerabilityType: 'COMMAND_INJECTION',
    severity: 'CRITICAL',
    description: 'Execute external program'
  },
  'shell_exec': {
    name: 'shell_exec() Command',
    vulnerabilityType: 'COMMAND_INJECTION',
    severity: 'CRITICAL',
    description: 'Execute shell command'
  },
  'proc_open': {
    name: 'proc_open() Process',
    vulnerabilityType: 'COMMAND_INJECTION',
    severity: 'CRITICAL',
    description: 'Execute process'
  },
  'include': {
    name: 'Include File',
    vulnerabilityType: 'FILE_INCLUSION',
    severity: 'CRITICAL',
    description: 'Include PHP file'
  },
  'require': {
    name: 'Require File',
    vulnerabilityType: 'FILE_INCLUSION',
    severity: 'CRITICAL',
    description: 'Require PHP file'
  },
  'include_once': {
    name: 'Include File Once',
    vulnerabilityType: 'FILE_INCLUSION',
    severity: 'CRITICAL',
    description: 'Include PHP file once'
  },
  'require_once': {
    name: 'Require File Once',
    vulnerabilityType: 'FILE_INCLUSION',
    severity: 'CRITICAL',
    description: 'Require PHP file once'
  }
};

/**
 * SANITIZATION FUNCTIONS - Functions that clean tainted data
 */
const SANITIZATION_FUNCTIONS = {
  'htmlspecialchars': {
    appliesTo: ['XSS'],
    effectiveness: 0.95,
    description: 'Converts special characters to HTML entities'
  },
  'htmlentities': {
    appliesTo: ['XSS'],
    effectiveness: 0.95,
    description: 'Converts all applicable characters to HTML entities'
  },
  'strip_tags': {
    appliesTo: ['XSS'],
    effectiveness: 0.85,
    description: 'Strip HTML and PHP tags (not foolproof)'
  },
  'urlencode': {
    appliesTo: ['XSS', 'URL_PARAMETER'],
    effectiveness: 0.90,
    description: 'Encode for URL'
  },
  'substr': {
    appliesTo: [],  // Not sufficient alone
    effectiveness: 0.00,
    description: 'String slicing (not sufficient)'
  },
  'strlen': {
    appliesTo: [],  // Not sanitization
    effectiveness: 0.00,
    description: 'Get string length (not sanitization)'
  },

  // Parameterized queries
  'prepared_statements': {
    appliesTo: ['SQL_INJECTION'],
    effectiveness: 1.0,
    description: 'Use prepared statements with parameters'
  },
  'parameterized_query': {
    appliesTo: ['SQL_INJECTION'],
    effectiveness: 1.0,
    description: 'Use parameterized queries'
  },

  // Database escaping (less secure)
  'mysqli_real_escape_string': {
    appliesTo: ['SQL_INJECTION'],
    effectiveness: 0.70,
    description: 'MySQLi escaping (not recommended)'
  },
  'mysql_real_escape_string': {
    appliesTo: ['SQL_INJECTION'],
    effectiveness: 0.70,
    description: 'MySQL escaping (deprecated)'
  }
};

/**
 * VULNERABILITY PATTERNS - How sources flow to sinks
 */
const VULNERABILITY_PATTERNS = [
  {
    name: 'Direct Output XSS',
    source: ['$_GET', '$_POST', '$_REQUEST'],
    sink: ['echo', 'print', 'printf'],
    type: 'XSS_DIRECT',
    severity: 'HIGH'
  },
  {
    name: 'Variable Assignment XSS',
    source: ['$_GET', '$_POST', '$_REQUEST'],
    sink: ['echo', 'print', 'printf'],
    type: 'XSS_VARIABLE',
    severity: 'HIGH',
    chain: true
  },
  {
    name: 'String Concatenation XSS',
    source: ['$_GET', '$_POST', '$_REQUEST'],
    sink: ['echo', 'print', 'printf'],
    type: 'XSS_CONCAT',
    severity: 'HIGH',
    requiresOperator: ['.', 'concatenation']
  },
  {
    name: 'Direct SQL Injection',
    source: ['$_GET', '$_POST', '$_REQUEST'],
    sink: ['mysqli_query', 'mysql_query', 'query'],
    type: 'SQLI_DIRECT',
    severity: 'CRITICAL'
  },
  {
    name: 'SQL Injection via Variable',
    source: ['$_GET', '$_POST', '$_REQUEST'],
    sink: ['mysqli_query', 'mysql_query', 'query'],
    type: 'SQLI_VARIABLE',
    severity: 'CRITICAL',
    chain: true
  },
  {
    name: 'Command Injection',
    source: ['$_GET', '$_POST', '$_REQUEST'],
    sink: ['system', 'exec', 'passthru', 'shell_exec'],
    type: 'CMD_INJECTION',
    severity: 'CRITICAL'
  }
];

module.exports = {
  PHP_DATA_SOURCES,
  PHP_DATA_SINKS,
  SANITIZATION_FUNCTIONS,
  VULNERABILITY_PATTERNS
};
