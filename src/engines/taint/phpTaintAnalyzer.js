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
      
      // Step 2.5: Re-check sanitization sufficiency for context
      this.validateSanitizationSufficiency(code);
      
      // Step 3: Find sinks and validate complete chains
      this.findSinksWithChains(code);
      
      // Step 4: Deduplicate findings (prevent same sink reported twice)
      this.deduplicateFindings();
      
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

    // Pattern A2: function-wrapped superglobal assignment — $name = str_replace('x', '', $_GET['name'])
    // Uses .* instead of [^)]* to handle regex patterns that contain ) inside string arguments
    const wrappedAssignmentPattern = /\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\w+\s*\(.*\$_(GET|POST|REQUEST|COOKIE|SESSION|ENV)\s*\[/gi;

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

      // A2) Function-wrapped superglobal: $name = str_replace('', '', $_GET['name'])
      // Track as tainted — BUT check if wrapping function is a proper sanitizer
      const wrappedMatches = [...line.matchAll(wrappedAssignmentPattern)];
      wrappedMatches.forEach(match => {
        const varName = match[1];
        const superglobal = '$_' + match[2];
        if (!this.taintedVariables.has(varName)) {
          // Extract the wrapping function name
          const funcMatch = /=\s*(\w+)\s*\(/.exec(line);
          const wrapperFunc = funcMatch ? funcMatch[1] : '';
          
          // Proper XSS sanitization functions — mark as SANITIZED
          const properSanitizers = ['htmlspecialchars', 'htmlentities', 'intval', 'floatval', 'filter_var', 'filter_input'];
          if (properSanitizers.includes(wrapperFunc)) {
            this.taintedVariables.set(varName, {
              type: 'SANITIZED',
              sourceType: this.getSourceType(superglobal),
              severity: 'LOW',
              line: lineIndex + 1,
              context: 'sanitized_with_' + wrapperFunc,
              chain: [superglobal, varName],
              sanitizedBy: wrapperFunc,
              isSanitized: true
            });
          } else {
            this.taintedVariables.set(varName, {
              type: 'SOURCE',
              sourceType: this.getSourceType(superglobal),
              severity: 'HIGH',
              line: lineIndex + 1,
              context: 'wrapped_superglobal',
              superglobal: superglobal
            });
          }
        }
      });

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
    const inlineXSSConcatPattern = /\$\w+\s*\.=\s*[^;]*(\$_(GET|POST|REQUEST|COOKIE|SESSION))\s*\[/i;
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

    // Detect $html .= '...' . $_GET['name'] . '...' (concat with superglobal in .= context)
    const xssConcatMatch = inlineXSSConcatPattern.exec(line);
    if (xssConcatMatch && !xssMatch) {
      const superglobal = xssConcatMatch[1];
      const sourceType = this.getSourceType(superglobal.replace(/\[.*/, ''));
      // Ensure no htmlspecialchars on the same line 
      if (!/htmlspecialchars|htmlentities/.test(line)) {
        this.findings.push({
          type: 'XSS_TAINTED_OUTPUT',
          name: `XSS: superglobal ${superglobal} concatenated into HTML output without escaping`,
          severity: 'HIGH',
          confidence: 0.90,
          line: lineIndex + 1,
          variable: superglobal,
          sink: '.= (HTML concatenation)',
          sourceType: sourceType,
          chain: [superglobal, '.='],
          description: `${superglobal} concatenated into HTML string without htmlspecialchars`,
          proof: { source: sourceType, sink: '.=', propagation: [superglobal], vulnerability_confirmed: true }
        });
      }
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
        // Check if variable is sanitized (direct pattern)
        const sanitizationPattern = new RegExp(
          `\\$([a-zA-Z_][a-zA-Z0-9_]*)\\s*=\\s*(${sanitizationFunctions.join('|')})\\s*\\([^)]*\\$${varName}[^)]*\\)`,
          'i'
        );
        const sanitizeMatch = sanitizationPattern.exec(line);
        
        // Also check ternary pattern: $var = ((cond) ? sanitizeFunc(..., $var) : fallback)
        // Common in DVWA: $msg = ((isset($GLOBALS[...])) ? mysqli_real_escape_string($GLOBALS[...], $msg) : ...)
        let ternarySanitizeMatch = null;
        if (!sanitizeMatch) {
          const ternaryPattern = new RegExp(
            `\\$([a-zA-Z_][a-zA-Z0-9_]*)\\s*=\\s*\\(?\\(?[^;]*(${sanitizationFunctions.join('|')})\\s*\\([^)]*\\$${varName}`,
            'i'
          );
          ternarySanitizeMatch = ternaryPattern.exec(line);
        }

        const effectiveMatch = sanitizeMatch || ternarySanitizeMatch;
        
        if (effectiveMatch) {
          const sanitizedVar = effectiveMatch[1];
          const sanitizeFunc = effectiveMatch[2];
          
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
        
        // Check for str_replace targeting specific tags — this is NOT real sanitization
        // str_replace('<script>', '', $var) is bypassable via <Script>, <img onerror=...>
        const strReplacePattern = new RegExp(
          `\\$([a-zA-Z_][a-zA-Z0-9_]*)\\s*=\\s*str_replace\\s*\\(\\s*['"]['"]?\\s*<\\s*script\\s*>['"]\\s*,\\s*['"]\\s*['"]\\s*,\\s*[^)]*\\$${varName}`,
          'i'
        );
        const strReplaceMatch = strReplacePattern.exec(line);
        if (strReplaceMatch) {
          const assignedVar = strReplaceMatch[1];
          // Mark as insufficiently sanitized — str_replace is bypassable
          this.taintedVariables.set(assignedVar, {
            type: 'INSUFFICIENTLY_SANITIZED',
            sourceType: taintInfo.sourceType,
            severity: 'HIGH',
            line: lineIndex + 1,
            context: 'bypassable_str_replace',
            chain: [varName, assignedVar],
            isSanitized: false,
            insufficientReason: 'str_replace only removes exact <script> tag — bypassable via case variation or event handlers',
          });
          return;
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
          
          // Skip if there's proper output encoding on this line
          if (/htmlspecialchars|htmlentities/.test(line)) continue;
          
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

    // .= with string interpolation containing tainted variable: $html .= "...{$name}..."
    const concatInterpolation = /\.\=\s*["'].*\{\$(\w+)\}/i;
    const concatMatch = concatInterpolation.exec(line);
    if (concatMatch) {
      const varName = concatMatch[1];
      if (this.isTaintedVariable(varName)) {
        const taintInfo = this.taintedVariables.get(varName);
        if (!/htmlspecialchars|htmlentities/.test(line)) {
          this.findings.push({
            type: 'XSS_TAINTED_OUTPUT',
            name: `XSS via tainted variable in HTML string interpolation`,
            severity: 'HIGH',
            confidence: 0.88,
            line: lineIndex + 1,
            variable: varName,
            sink: '.= (string interpolation)',
            sourceType: taintInfo.sourceType,
            chain: this.buildChain(varName),
            description: `Tainted variable \`${varName}\` interpolated into HTML output without encoding`,
            proof: {
              source: taintInfo.sourceType,
              sink: '.=',
              propagation: this.buildChain(varName),
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
   * Step 2.5: Validate that sanitization is sufficient for the context
   * e.g., mysqli_real_escape_string is NOT enough for unquoted numeric context
   * e.g., str_replace('<script>') / preg_replace for script tags only is bypassable XSS
   */
  validateSanitizationSufficiency(code) {
    const lines = code.split('\n');

    for (const [varName, taintInfo] of this.taintedVariables.entries()) {
      if (taintInfo.type !== 'SANITIZED') continue;

      const sanitizeFunc = taintInfo.sanitizedBy;

      // Check 1: mysqli_real_escape_string in unquoted SQL numeric context
      if (sanitizeFunc === 'mysqli_real_escape_string' || sanitizeFunc === 'mysql_real_escape_string') {
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          const numericContextPattern = new RegExp(
            `(WHERE|AND|OR|SET)\\s+\\w+\\s*=\\s*\\$${varName}(?!['"])`, 'i'
          );
          if (numericContextPattern.test(line)) {
            this.taintedVariables.set(varName, {
              ...taintInfo,
              type: 'INSUFFICIENTLY_SANITIZED',
              isSanitized: false,
              severity: 'HIGH',
              insufficientReason: `${sanitizeFunc} does not protect unquoted numeric context`,
            });
            break;
          }
        }
      }

      // Check 2: str_replace / preg_replace targeting only <script> tags — bypassable XSS
      if (sanitizeFunc === 'preg_replace' || sanitizeFunc === 'strip_tags') {
        // Check the original sanitization line for what's being replaced
        const sanitizeLine = lines[taintInfo.line - 1] || '';
        const onlyTargetsScript = /preg_replace\s*\(\s*['"].*script/i.test(sanitizeLine);
        
        if (onlyTargetsScript) {
          // preg_replace that only targets <script> is insufficient — <img onerror=...> bypasses it
          this.taintedVariables.set(varName, {
            ...taintInfo,
            type: 'INSUFFICIENTLY_SANITIZED',
            isSanitized: false,
            severity: 'HIGH',
            insufficientReason: `${sanitizeFunc} only removes script tags, bypassable via event handlers (e.g. <img onerror=...>)`,
          });
        }
      }

      // Check 3: stripslashes / trim — these are NOT XSS sanitization
      if (sanitizeFunc === 'stripslashes' || sanitizeFunc === 'trim') {
        // Check if the variable is later used in HTML output context without further encoding
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          const outputPattern = new RegExp(`(echo|print|\\.=)\\s*[^;]*\\$${varName}`, 'i');
          if (outputPattern.test(line) && !/htmlspecialchars|htmlentities/.test(line)) {
            this.taintedVariables.set(varName, {
              ...taintInfo,
              type: 'INSUFFICIENTLY_SANITIZED',
              isSanitized: false,
              severity: 'HIGH',
              insufficientReason: `${sanitizeFunc} does not prevent XSS — output requires htmlspecialchars`,
            });
            break;
          }
        }
      }
    }
  }

  /**
   * Step 4: Deduplicate findings
   * Removes duplicate findings for the same vulnerability (same sink call)
   */
  deduplicateFindings() {
    const unique = [];

    for (const finding of this.findings) {
      const duplicateIdx = unique.findIndex(existing =>
        this._isSameFinding(existing, finding)
      );

      if (duplicateIdx === -1) {
        unique.push(finding);
      } else if (finding.confidence > unique[duplicateIdx].confidence) {
        // Keep higher confidence, merge
        unique[duplicateIdx] = { ...finding, engines: this._mergeEngines(unique[duplicateIdx], finding) };
      }
    }

    this.findings = unique;
  }

  /**
   * Check if two findings refer to the same vulnerability
   */
  _isSameFinding(a, b) {
    // Same type category
    const categoryA = (a.type || '').split('_')[0];
    const categoryB = (b.type || '').split('_')[0];
    if (categoryA !== categoryB) return false;

    // Same line and same type
    if (a.line === b.line && a.type === b.type) return true;

    // Same sink on nearby lines
    if (a.sink && b.sink && a.sink === b.sink) {
      if (Math.abs((a.line || 0) - (b.line || 0)) <= 5) return true;
    }

    // Same proof sink
    if (a.proof && b.proof && a.proof.sink === b.proof.sink) {
      if (Math.abs((a.line || 0) - (b.line || 0)) <= 5) return true;
    }

    return false;
  }

  /**
   * Merge engine arrays from two findings
   */
  _mergeEngines(a, b) {
    const engines = new Set([
      ...(a.engines || [a.engine || 'TAINT_ANALYSIS']),
      ...(b.engines || [b.engine || 'TAINT_ANALYSIS'])
    ]);
    return Array.from(engines).filter(Boolean);
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
