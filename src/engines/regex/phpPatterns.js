/**
 * PHP-Specific Vulnerability Patterns
 * Focuses on real PHP vulnerabilities (not documentation)
 */

const PHP_SQL_PATTERNS = [
  // Pattern 1: Direct variable in query (most common PHP SQLi)
  {
    type: 'SQLI_DIRECT_VAR',
    name: 'Direct Variable in SQL Query',
    severity: 'CRITICAL',
    confidence: 0.85,
    description: 'Variable directly embedded in SQL query without escaping',
    regex: /(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$\w+)\s*\.\s*["']/,
    example: '$query = "SELECT * FROM users WHERE id=" . $_GET["id"];'
  },
  
  // Pattern 2: String concatenation with $_GET, $_POST, etc.
  {
    type: 'SQLI_CONCAT',
    name: 'SQL Query with Superglobal Concatenation',
    severity: 'CRITICAL',
    confidence: 0.90,
    description: 'User input from $_GET/$_POST concatenated into SQL query',
    regex: /(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*["'].*\..*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)/i,
    example: '"SELECT * FROM users WHERE name=\'" . $_POST["name"] . "\'"'
  },
  
  // Pattern 3: mysqli_query with variable
  {
    type: 'SQLI_MYSQLI_QUERY',
    name: 'mysqli_query with Unsanitized Input',
    severity: 'CRITICAL',
    confidence: 0.88,
    description: 'mysqli_query() called with concatenated user input',
    regex: /mysqli_query\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$\w+)/,
    example: 'mysqli_query($conn, "SELECT * FROM users WHERE id=" . $_GET["id"])'
  },
  
  // Pattern 4: mysql_query (deprecated but still used)
  {
    type: 'SQLI_MYSQL_QUERY',
    name: 'mysql_query with Unsanitized Input (Deprecated)',
    severity: 'CRITICAL',
    confidence: 0.85,
    description: 'Deprecated mysql_query() with user input',
    regex: /mysql_query\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$\w+)/,
    example: 'mysql_query("SELECT * FROM users WHERE id=" . $_GET["id"])'
  },
  
  // Pattern 5: PDO query without prepare
  {
    type: 'SQLI_PDO_QUERY',
    name: 'PDO query() without Prepared Statement',
    severity: 'HIGH',
    confidence: 0.82,
    description: 'PDO query() method with concatenated user input',
    regex: /->query\s*\(\s*["'].*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$\w+)/,
    example: '$pdo->query("SELECT * FROM users WHERE id=" . $_GET["id"])'
  },
  
  // Pattern 6: Variable interpolation in SQL string
  {
    type: 'SQLI_VAR_INTERPOLATION',
    name: 'SQL Variable Interpolation',
    severity: 'CRITICAL',
    confidence: 0.85,
    description: 'Variable interpolated directly in SQL query string',
    regex: /(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).+["'].*\$\w+.*["']/i,
    example: '$query = "SELECT * FROM users WHERE user_id = \'$id\'";'
  }
];

const PHP_XSS_PATTERNS = [
  // Pattern 1: echo with $_GET/$_POST (most common PHP XSS)
  {
    type: 'XSS_ECHO',
    name: 'Echo Unsanitized User Input',
    severity: 'HIGH',
    confidence: 0.85,
    description: 'User input echoed without htmlspecialchars()',
    regex: /echo\s+(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)(?!.*htmlspecialchars|.*htmlentities)/,
    example: 'echo $_GET["name"];'
  },
  
  // Pattern 2: print with user input
  {
    type: 'XSS_PRINT',
    name: 'Print Unsanitized User Input',
    severity: 'HIGH',
    confidence: 0.83,
    description: 'User input printed without sanitization',
    regex: /print\s+(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)(?!.*htmlspecialchars|.*htmlentities)/,
    example: 'print $_POST["comment"];'
  },
  
  // Pattern 3: Variable directly in HTML context
  {
    type: 'XSS_HTML_VAR',
    name: 'Variable in HTML Without Escaping',
    severity: 'HIGH',
    confidence: 0.80,
    description: 'PHP variable embedded in HTML without escaping',
    regex: /<[^>]*\{?\s*\$(\w+|\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)\s*\}?[^>]*>/,
    example: '<div><?php echo $_GET["content"]; ?></div>'
  },
  
  // Pattern 4: Short echo tag with user input
  {
    type: 'XSS_SHORT_ECHO',
    name: 'Short Echo Tag with User Input',
    severity: 'HIGH',
    confidence: 0.82,
    description: 'Short echo tag (<?=) with unsanitized input',
    regex: /<\?=\s*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$\w+)(?!.*htmlspecialchars|.*htmlentities)/,
    example: '<?= $_GET["name"] ?>'
  },
  
  // Pattern 5: Echo variable in string context
  {
    type: 'XSS_ECHO_VAR',
    name: 'Echo Variable Without Sanitization',
    severity: 'MEDIUM',
    confidence: 0.70,
    description: 'Variable echoed in string without clear sanitization',
    regex: /echo\s+["'].*\{\s*\$\w+\s*\}.*["'](?!.*htmlspecialchars|.*htmlentities)/,
    example: 'echo "<div>Name: {$name}</div>";'
  },
  
  // Pattern 6: String concatenation with superglobals (IMPROVED)
  // Only match when concatenation operator (.) is used - indicates actual string building
  {
    type: 'XSS_CONCAT',
    name: 'String Concatenation with User Input',
    severity: 'HIGH',
    confidence: 0.75,  // Lowered - needs sink validation
    description: 'User input concatenated into HTML string (needs confirmation it\'s output)',
    regex: /['"]\s*\.\s*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)(?!.*htmlspecialchars|.*htmlentities|.*urlencode)/i,
    example: '$html .= \'<pre>Hello \' . $_GET[\'name\'] . \'</pre>\';',
    note: 'This is a source detection only. Vulnerability confirmed only if output via echo/print.'
  }
];

module.exports = {
  PHP_SQL_PATTERNS,
  PHP_XSS_PATTERNS
};
