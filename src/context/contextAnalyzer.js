/**
 * PHASE 2: Context Analyzer Module
 * Purpose: Analyze taint results + AST to determine fix strategy
 * Separates detection from remediation logic
 */

class ContextAnalyzer {
  constructor(astEngine) {
    this.astEngine = astEngine;
  }

  /**
   * Analyze taint finding and determine appropriate fix strategy
   * @param {Object} taintFinding - Finding from taint analyzer
   * @returns {Object} Fix strategy with context
   */
  analyze(taintFinding) {
    const { apiContext, vulnerabilityType, sinkFunction, sourceVar, connectionVar } = taintFinding;

    // Determine fix strategy based on API and vulnerability type
    const fixStrategy = this.determineFixStrategy(apiContext, vulnerabilityType);

    // Extract additional context from AST
    const context = this.extractContext(taintFinding);

    return {
      // Original finding
      ...taintFinding,
      
      // Fix strategy
      fixStrategy: fixStrategy,
      
      // Extended context
      context: {
        variableName: sourceVar,
        connectionName: connectionVar || this.inferConnectionName(sinkFunction),
        tableName: context.tableName,
        sanitizerNeeded: this.determineSanitizer(vulnerabilityType, apiContext),
        inputType: this.inferInputType(sourceVar),
      },
      
      // Confidence level for fix recommendation
      fixConfidence: this.calculateFixConfidence(apiContext, context),
    };
  }

  /**
   * Determine appropriate fix strategy based on context
   */
  determineFixStrategy(apiContext, vulnerabilityType) {
    if (vulnerabilityType === 'SQLI') {
      return this.determineSQLIFixStrategy(apiContext);
    }
    
    if (vulnerabilityType === 'XSS') {
      return this.determineXSSFixStrategy(apiContext);
    }

    return 'generic_sanitization';
  }

  /**
   * Determine SQL Injection fix strategy
   */
  determineSQLIFixStrategy(apiContext) {
    if (!apiContext || !apiContext.api) {
      return 'generic_prepared_statement';
    }

    const strategyMap = {
      'mysqli': 'mysqli_prepared',
      'PDO': 'pdo_prepared',
      'generic_sql': 'orm_parameterized',
    };

    return strategyMap[apiContext.api] || 'generic_prepared_statement';
  }

  /**
   * Determine XSS fix strategy
   */
  determineXSSFixStrategy(apiContext) {
    if (!apiContext || !apiContext.type) {
      return 'generic_escape';
    }

    const strategyMap = {
      'innerHTML': 'textContent_replacement',
      'write': 'safe_encoding',
      'textContent': 'already_safe', // textContent is already safe, but check context
    };

    return strategyMap[apiContext.type] || 'generic_escape';
  }

  /**
   * Extract additional context from AST
   */
  extractContext(finding) {
    const context = {
      tableName: null,
      queryPattern: null,
    };

    // Try to extract table name from AST
    if (finding.astNode && finding.astNode.arguments.length > 0) {
      const firstArg = finding.astNode.arguments[0];
      
      if (firstArg.type === 'Literal' && typeof firstArg.value === 'string') {
        context.tableName = this.extractTableFromQuery(firstArg.value);
        context.queryPattern = this.identifyQueryPattern(firstArg.value);
      }
    }

    return context;
  }

  /**
   * Extract table name from SQL query
   */
  extractTableFromQuery(query) {
    if (!query) return null;

    // Match: SELECT ... FROM tableName
    const fromMatch = query.match(/FROM\s+`?(\w+)`?/i);
    if (fromMatch) return fromMatch[1];

    // Match: INSERT INTO tableName
    const intoMatch = query.match(/INTO\s+`?(\w+)`?/i);
    if (intoMatch) return intoMatch[1];

    // Match: UPDATE tableName
    const updateMatch = query.match(/UPDATE\s+`?(\w+)`?/i);
    if (updateMatch) return updateMatch[1];

    return null;
  }

  /**
   * Identify SQL query pattern (SELECT, INSERT, UPDATE, DELETE)
   */
  identifyQueryPattern(query) {
    if (!query) return 'UNKNOWN';

    const patterns = {
      SELECT: /^\s*SELECT/i,
      INSERT: /^\s*INSERT/i,
      UPDATE: /^\s*UPDATE/i,
      DELETE: /^\s*DELETE/i,
    };

    for (const [pattern, regex] of Object.entries(patterns)) {
      if (regex.test(query)) return pattern;
    }

    return 'UNKNOWN';
  }

  /**
   * Determine appropriate sanitizer function
   */
  determineSanitizer(vulnerabilityType, apiContext) {
    if (vulnerabilityType === 'SQLI') {
      return null; // Prepared statements don't need additional sanitizers
    }

    if (vulnerabilityType === 'XSS') {
      if (apiContext?.api === 'DOM') {
        return 'htmlspecialchars'; // For PHP
      }
      return 'escape'; // For JavaScript
    }

    return 'validate_input';
  }

  /**
   * Infer input type from variable name
   */
  inferInputType(varName) {
    if (!varName) return 'string';

    const patterns = {
      integer: /id|count|age|year|number/i,
      email: /email|mail/i,
      string: /name|title|description|text/i,
    };

    for (const [type, regex] of Object.entries(patterns)) {
      if (regex.test(varName)) return type;
    }

    return 'string';
  }

  /**
   * Infer connection variable name from sink function
   */
  inferConnectionName(sinkFunction) {
    // Common patterns: conn, db, connection, database, pdo, mysqli
    const commonNames = ['conn', 'db', 'connection', 'pdo', 'mysqli'];
    
    // If sink contains dot notation, extract object name
    if (sinkFunction && sinkFunction.includes('.')) {
      return sinkFunction.split('.')[0];
    }

    // Return default
    return 'conn';
  }

  /**
   * Calculate confidence level for fix recommendation
   */
  calculateFixConfidence(apiContext, context) {
    let confidence = 0.5; // Base confidence

    // Higher confidence if API is clearly detected
    if (apiContext && apiContext.api !== 'unknown') {
      confidence += 0.2;
    }

    // Higher confidence if we have table name
    if (context.tableName) {
      confidence += 0.15;
    }

    // Higher confidence if query pattern is identified
    if (context.queryPattern && context.queryPattern !== 'UNKNOWN') {
      confidence += 0.15;
    }

    return Math.min(confidence, 1.0);
  }
}

module.exports = ContextAnalyzer;
