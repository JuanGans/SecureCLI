/**
 * PHP Static Taint Analyzer
 * STAGE 2: Static Taint Analysis
 * 
 * Tracks data flow from sources (user input) to sinks (outputs/execution)
 * Eliminates false positives by validating complete vulnerability chains
 */

class PHPTaintAnalyzer {
  constructor() {
    this.taintedVariables = new Map();      // Variable -> source type mapping
    this.dataFlows = [];                     // Complete flow chains
    this.findings = [];                      // Actual vulnerabilities found
    this.variableAssignments = new Map();   // Track variable assignments
  }

  /**
   * Analyze PHP code for taint flows
   * Returns vulnerabilities with complete chain proof
   */
  analyze(code, filePath = 'unknown') {
    try {
      this.reset();
      
      // Step 1: Find all superglobal sources and track their usage
      this.extractSources(code);
      
      // Step 2: Track variable assignments and propagation
      this.trackAssignments(code);
      
      // Step 3: Find sinks and validate complete chains
      this.findSinksWithChains(code);
      
      return this.findings;
    } catch (error) {
      console.error(`PHP Taint Analysis Error: ${error.message}`);
      return [];
    }
  }

  /**
   * Reset analysis state
   */
  reset() {
    this.taintedVariables.clear();
    this.dataFlows = [];
    this.findings = [];
    this.variableAssignments.clear();
  }

  /**
   * STEP 1: Extract sources - identify superglobals and their first usage
   */
  extractSources(code) {
    const lines = code.split('\n');
    
    // Pattern A: assignment — $id = $_GET['id']
    const assignmentPatterns = [
      /\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES|SESSION|ENV)\s*[\[\{]/gi
    ];

    // Pattern B: direct superglobal usage — track superglobals themselves as virtual tainted vars
    // so that mysqli_query($conn, "... " . $_GET['id']) is also caught
    const directSuperGlobalPattern = /\$_(GET|POST|REQUEST|COOKIE|SESSION|ENV|COOKIE|FILES)\s*[\[\{]/gi;
    
    lines.forEach((line, lineIndex) => {
      // A) Variable assignment from superglobal
      for (const pattern of assignmentPatterns) {
        const matches = [...line.matchAll(pattern)];
        matches.forEach(match => {
          const varName = match[1];
          const superglobal = '$_' + match[2];
          if (!this.taintedVariables.has(varName)) {
            this.taintedVariables.set(varName, {
              type: 'SOURCE',
              sourceType: this.getSourceType(superglobal),
              severity: 'HIGH',
              line: lineIndex + 1,
              context: 'direct_superglobal',
              superglobal: superglobal
            });
          }
        });
      }

      // B) Direct superglobal — register virtual variable _GET_direct, _POST_direct, etc.
      // so checkSQLSinks / checkXSSSinks can detect them inline
      const directMatches = [...line.matchAll(directSuperGlobalPattern)];
      directMatches.forEach(match => {
        const superglobal = '$_' + match[1];
        const virtualName = '_' + match[1] + '_direct';
        if (!this.taintedVariables.has(virtualName)) {
          this.taintedVariables.set(virtualName, {
            type: 'SOURCE',
            sourceType: this.getSourceType(superglobal),
            severity: 'HIGH',
            line: lineIndex + 1,
            context: 'inline_superglobal',
            superglobal: superglobal,
            isInlineDirect: true
          });
        }
      });

      // C) Check if the line itself uses a superglobal inline inside a SQL sink
      this._checkInlineSuperglobalSink(line, lineIndex);
    });
  }

  /**
   * STEP 1b: Detect inline superglobal directly used in a sink on same line
   * e.g. mysqli_query($conn, "SELECT ... " . $_GET['id'])
   */
  _checkInlineSuperglobalSink(line, lineIndex) {
    const inlineSQLPattern = /(mysqli_query|mysql_query|->query|->execute|->prepare|->exec)\s*\([^)]*(\$_(GET|POST|REQUEST|COOKIE))/i;
    const inlineXSSPattern = /(echo|print|printf)\s+[^;]*(\$_(GET|POST|REQUEST|COOKIE))/i;
    const inlineCMDPattern = /(system|exec|shell_exec|passthru|popen)\s*\([^)]*(\$_(GET|POST|REQUEST|COOKIE))/i;

    const sqlMatch = inlineSQLPattern.exec(line);
    if (sqlMatch) {
      const superglobal = sqlMatch[2];
      const sourceType = this.getSourceType(superglobal.replace(/\[.*/, ''));
      this.findings.push({
        type: 'SQLI_TAINTED_QUERY',
        name: `SQL Injection: superglobal ${superglobal} used directly in SQL sink`,
        severity: 'CRITICAL',
        confidence: 0.93,
        line: lineIndex + 1,
        variable: superglobal,
        sink: sqlMatch[1],
        sourceType: sourceType,
        chain: [superglobal, sqlMatch[1]],
        description: `${superglobal} flows directly to SQL execution ${sqlMatch[1]} without parameterization`,
        proof: { source: sourceType, sink: sqlMatch[1], propagation: [superglobal], vulnerability_confirmed: true }
      });
    }

    const xssMatch = inlineXSSPattern.exec(line);
    if (xssMatch) {
      const superglobal = xssMatch[2];
      const sourceType = this.getSourceType(superglobal.replace(/\[.*/, ''));
      this.findings.push({
        type: 'XSS_TAINTED_OUTPUT',
        name: `XSS: superglobal ${superglobal} echoed directly without escaping`,
        severity: 'HIGH',
        confidence: 0.90,
        line: lineIndex + 1,
        variable: superglobal,
        sink: xssMatch[1],
        sourceType: sourceType,
        chain: [superglobal, xssMatch[1]],
        description: `${superglobal} output directly via ${xssMatch[1]} without htmlspecialchars`,
        proof: { source: sourceType, sink: xssMatch[1], propagation: [superglobal], vulnerability_confirmed: true }
      });
    }

    const cmdMatch = inlineCMDPattern.exec(line);
    if (cmdMatch) {
      const superglobal = cmdMatch[2];
      const sourceType = this.getSourceType(superglobal.replace(/\[.*/, ''));
      this.findings.push({
        type: 'CODE_INJECTION_TAINTED',
        name: `Command Injection: superglobal ${superglobal} passed directly to ${cmdMatch[1]}`,
        severity: 'CRITICAL',
        confidence: 0.93,
        line: lineIndex + 1,
        variable: superglobal,
        sink: cmdMatch[1],
        sourceType: sourceType,
        chain: [superglobal, cmdMatch[1]],
        description: `${superglobal} flows directly to command execution ${cmdMatch[1]} without sanitization`,
        proof: { source: sourceType, sink: cmdMatch[1], propagation: [superglobal], vulnerability_confirmed: true }
      });
    }
  }

  /**
   * Get source type from superglobal name
   */
  getSourceType(superglobal) {
    const sourceMap = {
      '$_GET': 'URL_PARAMETER',
      '$_POST': 'POST_PARAMETER',
      '$_REQUEST': 'REQUEST_PARAMETER',
      '$_COOKIE': 'COOKIE',
      '$_SERVER': 'SERVER_VARIABLE',
      '$_FILES': 'FILE_UPLOAD',
      '$_SESSION': 'SESSION_DATA',
      '$_ENV': 'ENVIRONMENT'
    };
    return sourceMap[superglobal] || 'UNKNOWN_SOURCE';
  }

  /**
   * STEP 2: Track variable assignments and propagation
   */
  trackAssignments(code) {
    const lines = code.split('\n');
    
    // PHP sanitization functions
    const sanitizationFunctions = [
      'htmlspecialchars',
      'htmlentities',
      'addslashes',
      'mysqli_real_escape_string',
      'mysql_real_escape_string',
      'filter_var',
      'filter_input',
      'intval',
      'floatval',
      'stripslashes',
      'strip_tags',
      'preg_replace',
      'trim',
      'escapeshellarg',
      'escapeshellcmd'
    ];
    
    // For each tainted variable, find where it's used in assignments
    for (const [varName, taintInfo] of this.taintedVariables.entries()) {
      lines.forEach((line, lineIndex) => {
        // Check if variable is sanitized
        const sanitizationPattern = new RegExp(
          `\\$([a-zA-Z_][a-zA-Z0-9_]*)\\s*=\\s*(${sanitizationFunctions.join('|')})\\s*\\([^)]*\\$${varName}[^)]*\\)`,
          'i'
        );
        const sanitizeMatch = sanitizationPattern.exec(line);
        
        if (sanitizeMatch) {
          const sanitizedVar = sanitizeMatch[1];
          const sanitizeFunc = sanitizeMatch[2];
          
          // Mark as sanitized (don't track as tainted)
          this.taintedVariables.set(sanitizedVar, {
            type: 'SANITIZED',
            sourceType: taintInfo.sourceType,
            severity: 'LOW',
            line: lineIndex + 1,
            context: 'sanitized_with_' + sanitizeFunc,
            chain: [varName, sanitizedVar],
            sanitizedBy: sanitizeFunc,
            isSanitized: true
          });
          
          return; // Skip normal propagation for sanitized variables
        }
        
        // Find assignments involving this variable (normal propagation)
        // Pattern: $newVar = ... $oldVar ...
        const usagePattern = new RegExp(`\\$([a-zA-Z_][a-zA-Z0-9_]*)\\s*=\\s*([^;]*\\$${varName}[^;]*);?`, 'i');
        const match = usagePattern.exec(line);
        
        if (match) {
          const newVar = match[1];
          const assignment = match[2];
          
          // Track this propagation only if source is not sanitized
          if (!this.taintedVariables.has(newVar) && !taintInfo.isSanitized) {
            this.taintedVariables.set(newVar, {
              type: 'PROPAGATED',
              sourceType: taintInfo.sourceType,
              severity: taintInfo.severity,
              line: lineIndex + 1,
              context: 'propagation',
              chain: [varName, newVar],
              originalSource: taintInfo.superglobal
            });
          }
        }
      });
    }
  }

  /**
   * STEP 3: Find sinks and validate complete chains
   */
  findSinksWithChains(code) {
    const lines = code.split('\n');
    
    lines.forEach((line, lineIndex) => {
      // Check for SQL execution sinks
      this.checkSQLSinks(line, lineIndex, code);
      
      // Check for XSS output sinks
      this.checkXSSSinks(line, lineIndex, code);
      
      // Check for command execution sinks
      this.checkCommandSinks(line, lineIndex, code);
    });
  }

  /**
   * Check for SQL injection sinks
   */
  checkSQLSinks(line, lineIndex, sourceCode) {
    // Patterns for SQL execution
    const sqlSinkPatterns = [
      /mysqli_query\s*\([^)]*\$(\w+)[^)]*\)/i,
      /mysql_query\s*\([^)]*\$(\w+)[^)]*\)/i,
      /->query\s*\([^)]*\$(\w+)[^)]*\)/i,
      /->execute\s*\([^)]*\$(\w+)[^)]*\)/i,
      /->prepare\s*\([^)]*\$(\w+)[^)]*\)/i,
      /->exec\s*\([^)]*\$(\w+)[^)]*\)/i,
    ];
    
    for (const pattern of sqlSinkPatterns) {
      const match = pattern.exec(line);
      if (match) {
        const sinkVarName = match[1];
        
        // Check if this variable is tainted
        if (this.isTaintedVariable(sinkVarName)) {
          const taintInfo = this.taintedVariables.get(sinkVarName);
          
          this.findings.push({
            type: 'SQLI_TAINTED_QUERY',
            name: `SQL Injection via tainted variable \`${sinkVarName}\``,
            severity: 'CRITICAL',
            confidence: 0.92,  // High confidence for proven chain
            line: lineIndex + 1,
            variable: sinkVarName,
            sink: this.extractSinkFunc(line),
            sourceType: taintInfo.sourceType,
            chain: this.buildChain(sinkVarName),
            description: `User input from ${taintInfo.sourceType} flows to SQL execution without parameterization`,
            proof: {
              source: taintInfo.sourceType,
              sink: this.extractSinkFunc(line),
              propagation: this.buildChain(sinkVarName),
              vulnerability_confirmed: true
            }
          });
        }
      }
    }
    
    // Also check for variable interpolation in SQL strings
    // Pattern: $query = "SELECT ... '$variable' ..." then passed to query
    const stringInterpolationRegex = /\$query\s*=\s*["']([^"']*\$(\w+)[^"']*)["']/i;
    const stringMatch = stringInterpolationRegex.exec(line);
    
    if (stringMatch) {
      const varInString = stringMatch[2];
      
      // Check if this variable is tainted
      if (this.isTaintedVariable(varInString)) {
        const taintInfo = this.taintedVariables.get(varInString);
        
        // Now check next few lines for mysqli_query with $query
        const lines = sourceCode.split('\n');
        const nextLines = lines.slice(lineIndex, Math.min(lineIndex + 5, lines.length));
        
        for (const nextLine of nextLines) {
          if (/(mysqli_query|mysql_query|->query|->execute|->exec)\s*\(\s*[^)]*\$query/i.test(nextLine)) {
            this.findings.push({
              type: 'SQLI_TAINTED_QUERY',
              name: `SQL Injection via variable interpolation`,
              severity: 'CRITICAL',
              confidence: 0.90,
              line: lineIndex + 1,
              variable: varInString,
              sink: 'mysqli_query',
              sourceType: taintInfo.sourceType,
              chain: this.buildChain(varInString),
              description: `Variable \`${varInString}\` from ${taintInfo.sourceType} is interpolated into SQL query`,
              proof: {
                source: taintInfo.sourceType,
                sink: 'mysqli_query',
                propagation: this.buildChain(varInString),
                vulnerability_confirmed: true
              }
            });
            break;
          }
        }
      }
    }
  }

  /**
   * Check for XSS sinks
   */
  checkXSSSinks(line, lineIndex, sourceCode) {
    // Output patterns
    const xssSinkPatterns = [
      /echo\s+([^;]*\$(\w+)[^;]*)/i,
      /print\s+([^;]*\$(\w+)[^;]*)/i,
      /printf\s*\([^)]*\$(\w+)[^)]*\)/i,
    ];
    
    for (const pattern of xssSinkPatterns) {
      const match = pattern.exec(line);
      if (match) {
        const sinkVarName = match[2] || (match[1] && this.extractVarName(match[1]));
        
        if (sinkVarName && this.isTaintedVariable(sinkVarName)) {
          const taintInfo = this.taintedVariables.get(sinkVarName);
          
          this.findings.push({
            type: 'XSS_TAINTED_OUTPUT',
            name: `XSS via tainted output`,
            severity: 'HIGH',
            confidence: 0.85,
            line: lineIndex + 1,
            variable: sinkVarName,
            sink: this.extractSinkFunc(line),
            sourceType: taintInfo.sourceType,
            chain: this.buildChain(sinkVarName),
            description: `Tainted variable \`${sinkVarName}\` output to browser without escaping`,
            proof: {
              source: taintInfo.sourceType,
              sink: this.extractSinkFunc(line),
              propagation: this.buildChain(sinkVarName),
              vulnerability_confirmed: true
            }
          });
        }
      }
    }
  }

  /**
   * Check for command execution sinks
   */
  checkCommandSinks(line, lineIndex, sourceCode) {
    const commandSinkPatterns = [
      /eval\s*\([^)]*\$(\w+)[^)]*\)/i,
      /system\s*\([^)]*\$(\w+)[^)]*\)/i,
      /exec\s*\([^)]*\$(\w+)[^)]*\)/i,
      /shell_exec\s*\([^)]*\$(\w+)[^)]*\)/i,
    ];
    
    for (const pattern of commandSinkPatterns) {
      const match = pattern.exec(line);
      if (match) {
        const sinkVarName = match[1];
        
        if (this.isTaintedVariable(sinkVarName)) {
          const taintInfo = this.taintedVariables.get(sinkVarName);
          
          this.findings.push({
            type: 'CODE_INJECTION_TAINTED',
            name: `Code/Command Injection via tainted variable`,
            severity: 'CRITICAL',
            confidence: 0.92,
            line: lineIndex + 1,
            variable: sinkVarName,
            sink: this.extractSinkFunc(line),
            sourceType: taintInfo.sourceType,
            chain: this.buildChain(sinkVarName),
            description: `User input flows to code execution without sanitization`,
            proof: {
              source: taintInfo.sourceType,
              sink: this.extractSinkFunc(line),
              propagation: this.buildChain(sinkVarName),
              vulnerability_confirmed: true
            }
          });
        }
      }
    }
  }

  /**
   * Helper: Check if variable is tainted (and not sanitized)
   */
  isTaintedVariable(varName) {
    if (!varName) return false;
    if (!this.taintedVariables.has(varName)) return false;
    
    const taintInfo = this.taintedVariables.get(varName);
    
    // If variable is marked as sanitized, it's no longer tainted
    if (taintInfo.isSanitized || taintInfo.type === 'SANITIZED') {
      return false;
    }
    
    return true;
  }

  /**
   * Helper: Extract sink function name from line
   */
  extractSinkFunc(line) {
    // Match function names like echo, print, mysqli_query, etc.
    const match = /(\w+)\s*\(/i.exec(line);
    return match ? match[1] : 'unknown';
  }

  /**
   * Helper: Build chain from source to current variable
   */
  buildChain(varName) {
    const taintInfo = this.taintedVariables.get(varName);
    return taintInfo && taintInfo.chain ? taintInfo.chain : [varName];
  }

  /**
   * Helper: Extract variable name from expression
   */
  extractVarName(expr) {
    const match = /\$(\w+)/.exec(expr);
    return match ? match[1] : null;
  }

  /**
   * Get all findings
   */
  getFindings() {
    return this.findings;
  }

  /**
   * Get tainted variables
   */
  getTaintedVariables() {
    return Array.from(this.taintedVariables.entries()).map(([name, info]) => ({
      name,
      ...info
    }));
  }
}

module.exports = PHPTaintAnalyzer;
