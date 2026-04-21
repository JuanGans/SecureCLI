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
    this.rootCauseVulnerabilities = new Map(); // Track root cause findings
    this.codePatternHash = new Map();       // Hash of code patterns to detect duplicates
  }

  /**
   * Analyze PHP code for taint flows
   * Returns vulnerabilities with complete chain proof
   * ENHANCED: Root cause detection (query construction, output statement)
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

      // Step 2.8: Detect root causes NOW — after taint map is fully built
      // This allows root cause detection to use actual taint data, not just heuristics
      this.detectRootCauseSQLInjection(code);
      this.detectRootCauseXSS(code);
      
      // Step 3: Find sinks and validate complete chains
      this.findSinksWithChains(code);
      
      // Step 4: Deduplicate findings (prevent same sink reported twice)
      // ENHANCED: Now also deduplicates by code pattern similarity
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
    this.rootCauseVulnerabilities.clear();
    this.codePatternHash.clear();
  }

  /**
   * ENHANCED: Detect root cause SQL Injection
   * Focus on query CONSTRUCTION with unsanitized input
   * Pattern: $query = "... WHERE ... = '$variable' ..."
   * This is the ROOT CAUSE, not the execution point
   * NOW USES TAINT MAP for accurate detection
   */
  detectRootCauseSQLInjection(code) {
    const lines = code.split('\n');
    
    // Pattern: $query = "... $variable ..." where variable is user input
    const queryConstructionPatterns = [
      // Double quotes with interpolation: $query = "SELECT ... WHERE id = '$id'"
      /\$([a-zA-Z_]\w*)\s*=\s*"([^"]*\$([a-zA-Z_]\w*)[^"]*)"/gi,
      // Concatenation with variable: $query = 'SELECT' . $var . 'WHERE'
      // More flexible: allow multiple dots and strings around variable
      /\$([a-zA-Z_]\w*)\s*=\s*["'].*?["']\s*\.\s*\$([a-zA-Z_]\w*)\s*\./gi,
      // Concatenation ending with variable: $query = 'SELECT' . $var
      /\$([a-zA-Z_]\w*)\s*=\s*["'][^"']*["']\s*\.\s*\$([a-zA-Z_]\w*)(?!\s*\.)/gi,
      // Append operations: $query .= "text with $var" (double-quoted allows single quotes inside)
      /\$([a-zA-Z_]\w*)\s*\.=\s*"([^"]*\$([a-zA-Z_]\w*)[^"]*)"/gi,
      // Append operations: $query .= 'text with $var' (single-quoted)
      /\$([a-zA-Z_]\w*)\s*\.=\s*'([^']*\$([a-zA-Z_]\w*)[^']*)'/gi,
      // Direct variable append: $query .= $var
      /\$([a-zA-Z_]\w*)\s*\.=\s*\$([a-zA-Z_]\w*)/gi,
    ];

    lines.forEach((line, lineIndex) => {
      // Check for query construction patterns
      for (const pattern of queryConstructionPatterns) {
        pattern.lastIndex = 0; // BUG FIX #1: Reset lastIndex setiap baris untuk avoid state bleeding
        let match;
        while ((match = pattern.exec(line)) !== null) {
          const queryVarName = match[1]; // e.g., 'query'
          // Extract user variable: for patterns with interpolation it's match[3], for concat it's match[2]
          let userVariable = match[3] || match[2];
          const queryContent = match[2] || '';

          // Skip if no user variable extracted
          if (!userVariable) continue;

          // BUG FIX #2: Capture ALL $variables dalam query string, bukan hanya yang pertama
          // Contoh: INSERT INTO t VALUES ('$message','$name') — cek keduanya!
          const allVarsInQuery = [...(queryContent || '').matchAll(/\$([a-zA-Z_]\w*)/g)].map(m => m[1]);
          if (allVarsInQuery.length > 1) {
            // Multiple variables: check each one to find the FIRST vulnerable one
            let foundVulnerable = false;
            for (const varToCheck of allVarsInQuery) {
              if (this.isTaintedVariable(varToCheck) && !foundVulnerable) {
                userVariable = varToCheck;
                foundVulnerable = true;
                break;
              }
            }
            // If no tainted found via map, use the first one (heuristic fallback)
            if (!foundVulnerable && allVarsInQuery.length > 0) {
              userVariable = allVarsInQuery[0];
            }
          }

          // Check if this is actually a query (contains SQL keywords)
          const fullLine = line;
          if (!/(WHERE|INSERT|UPDATE|DELETE|SELECT|FROM|SET\s|VALUES)/i.test(fullLine) &&
              !/(WHERE|INSERT|UPDATE|DELETE|SELECT|FROM|SET\s|VALUES)/i.test(queryContent)) {
            continue;
          }

          // PRIMARY CHECK: use taint map (accurate — set by extractSources/trackAssignments)
          // FALLBACK: heuristic name-based check
          const isTaintedVar = userVariable && this.isTaintedVariable(userVariable);
          const isDirectSuperglobal = /\$_(GET|POST|REQUEST|COOKIE|SESSION|ENV|FILES)/.test(line);
          const isHeuristicInput = !isTaintedVar && this._isLikelyUserInput(userVariable);
          
          // CRITICAL FIX: Check if variable is SQL-escaped but not parameterized
          // e.g., mysqli_real_escape_string() is NOT equivalent to prepared statements
          // So even if isTaintedVar is false, we need to check if it's using SQL escape functions
          const isSQLEscapedButNotParameterized = !isTaintedVar && userVariable && 
            this.taintedVariables.has(userVariable) && 
            this.taintedVariables.get(userVariable).sanitizedBy &&
            ['mysqli_real_escape_string', 'mysql_real_escape_string'].includes(
              this.taintedVariables.get(userVariable).sanitizedBy
            );
          
          const isUserInput = isTaintedVar || isDirectSuperglobal || isHeuristicInput || isSQLEscapedButNotParameterized;

          if (isUserInput && !this._hasParameterization(queryContent || line)) {
            // Generate hash from normalized line (more accurate than just queryContent)
            const patternHash = this._generatePatternHash(line);
            
            // Check for duplicates
            if (this.rootCauseVulnerabilities.has(patternHash)) {
              continue;
            }

            this.rootCauseVulnerabilities.set(patternHash, true);
            this.codePatternHash.set(patternHash, {
              pattern: line.trim().substring(0, 60),
              lines: [lineIndex + 1]
            });

            // Get actual source type from taint map if available
            const taintInfo = userVariable && this.taintedVariables.get(userVariable);
            const actualSourceType = taintInfo ? taintInfo.sourceType : 'USER_INPUT';
            
            // Determine confidence and description based on detection method
            let confidence, detectionMethod, description, sanitizationNote;
            if (isTaintedVar) {
              confidence = 0.97;
              detectionMethod = 'taint_map';
              description = `Query variable \`${queryVarName}\` constructed with unsanitized user input \`${userVariable}\` via string interpolation. No parameterization detected.`;
              sanitizationNote = null;
            } else if (isDirectSuperglobal) {
              confidence = 0.95;
              detectionMethod = 'direct_superglobal';
              description = `Query variable \`${queryVarName}\` contains superglobal directly in string interpolation. No parameterization detected.`;
              sanitizationNote = null;
            } else if (isSQLEscapedButNotParameterized) {
              confidence = 0.88; // Lower confidence - escaped but not parameterized
              detectionMethod = 'sql_escaped_not_parameterized';
              const sanitizeFunc = taintInfo.sanitizedBy;
              description = `Query variable \`${queryVarName}\` uses ${sanitizeFunc}() which provides SQL escaping but NOT equivalent to prepared statements. String interpolation with escaped user input can still be vulnerable in edge cases (e.g., numeric contexts, multi-byte character attacks).`;
              sanitizationNote = `Sanitized with ${sanitizeFunc}() - insufficient for SQL context`;
            } else {
              confidence = 0.80;
              detectionMethod = 'heuristic';
              description = `Query variable \`${queryVarName}\` constructed with heuristically-detected user input \`${userVariable}\` via string interpolation. No parameterization detected.`;
              sanitizationNote = null;
            }

            this.findings.push({
              type: 'SQLI_ROOT_CAUSE',
              name: `SQL Injection Root Cause: Unsanitized query construction`,
              severity: 'CRITICAL',
              confidence,
              line: lineIndex + 1,
              variable: queryVarName,
              sink: 'Query construction via string interpolation/concatenation',
              sourceType: actualSourceType,
              vulnerableVariable: userVariable,
              description,
              sanitizationNote,
              recommendation: 'Use prepared statements with ? placeholders or named parameters',
              patternHash: patternHash,
              codeSnippet: line.trim(),
              isRootCause: true,
              detectionMethod,
              proof: {
                source: actualSourceType,
                sink: 'Query construction',
                propagation: [userVariable, queryVarName],
                vulnerability_confirmed: isTaintedVar || isDirectSuperglobal || isSQLEscapedButNotParameterized
              }
            });
          }
        }
      }
    });
  }

  /**
   * ENHANCED: Detect root cause XSS
   * Focus on OUTPUT operations without encoding
   * Pattern: echo, print, .= with unsanitized variable in HTML context
   * This is the ROOT CAUSE (unescaped output)
   * NOW USES TAINT MAP for accurate detection
   */
  detectRootCauseXSS(code) {
    const lines = code.split('\n');
    
    // Patterns for direct output without encoding
    const outputPatterns = [
      // echo/print with string containing $var: echo "<p>$name</p>"
      /(?:echo|print)\s+["'][^"']*\$([a-zA-Z_]\w*)[^"']*["']/gi,
      // echo/print with {$var}: echo "<p>{$name}</p>"
      /(?:echo|print)\s+["'][^"']*\{\$([a-zA-Z_]\w*)\}[^"']*["']/gi,
      // .= concatenation: $html .= "<tag>$var</tag>" or "<tag>{$var}</tag>"
      /\$([a-zA-Z_]\w*)\s*\.=\s*["'][^"']*\$([a-zA-Z_]\w*)[^"']*["']/gi,
      // .= with {$var} interpolation: $html .= "<pre>ID: {$var}"
      /\$([a-zA-Z_]\w*)\s*\.=\s*["'][^"']*\{\$([a-zA-Z_]\w*)\}[^"']*["']/gi,
      // .= concatenation with dot operator: $html .= '<p>' . $_GET['name'] . '</p>'
      /\$([a-zA-Z_]\w*)\s*\.=\s*['"][^'"]*['"]\s*\.\s*\$_([A-Z_]+)/gi,
      // .= concatenation with dot and variable: $var .= '<p>' . $data . '</p>'
      /\$([a-zA-Z_]\w*)\s*\.=\s*['"][^'"]*['"]\s*\.\s*\$([a-zA-Z_]\w*)/gi,
    ];

    lines.forEach((line, lineIndex) => {
      // Skip lines with proper encoding
      if (/htmlspecialchars|htmlentities|htmlescape|escape|sanitize/i.test(line)) {
        return;
      }

      for (const pattern of outputPatterns) {
        pattern.lastIndex = 0; // BUG FIX #1: Reset lastIndex setiap baris untuk avoid state bleeding
        let match;
        while ((match = pattern.exec(line)) !== null) {
          // Determine which group contains the variable
          let outputVar;
          let outputStatement;
          let sourceType;
          
          const isEchoLine = /^\s*(?:echo|print)\s/i.test(line);
          if (isEchoLine) {
            // echo/print: match[1] = variable name (without $)
            outputVar = match[1];
            outputStatement = line.match(/(?:echo|print)/i)?.[0] || 'echo';
          } else if (match[2] && ['GET', 'POST', 'REQUEST', 'COOKIE', 'SESSION', 'ENV', 'FILES', 'SERVER'].includes(match[2])) {
            // .= concatenation with superglobal: match[2] = GET/POST/etc
            outputVar = '_' + match[2] + '_direct';  // Virtual variable for direct superglobal
            sourceType = this.getSourceType('$_' + match[2]);
            outputStatement = '.= (concat with $_' + match[2] + ')';
          } else if (match[2]) {
            // .= concatenation: match[1] = output var, match[2] = tainted var
            outputVar = match[2];
            outputStatement = '.=';
          } else if (match[1]) {
            outputVar = match[1];
            outputStatement = '.=';
          } else {
            continue;
          }
          
          // Cleanup: remove $ prefix if accidentally included
          if (outputVar && outputVar.startsWith('$')) {
            outputVar = outputVar.substring(1);
          }

          // PRIMARY CHECK: use taint map — is this variable actually tainted?
          // FALLBACK: heuristic name-based check
          const isTaintedVar = this.isTaintedVariable(outputVar);
          const isDirectSuperglobal = /\$_(GET|POST|REQUEST|COOKIE|SESSION|ENV|FILES)/.test(line);
          const isHeuristicInput = !isTaintedVar && this._isLikelyUserInput(outputVar);
          const isUserInput = isTaintedVar || isDirectSuperglobal || isHeuristicInput;
          
          if (isUserInput) {
            // Hash from full normalized line — catches duplicates across MySQL/SQLite blocks
            const patternHash = this._generatePatternHash(line);
            const hashKey = 'XSS_' + patternHash;

            // Avoid duplicates
            if (this.rootCauseVulnerabilities.has(hashKey)) {
              continue;
            }

            this.rootCauseVulnerabilities.set(hashKey, true);
            this.codePatternHash.set(hashKey, {
              pattern: line.trim().substring(0, 60),
              lines: [lineIndex + 1]
            });

            // Get actual source type from taint map if available
            const taintInfo = this.taintedVariables.get(outputVar);
            const actualSourceType = sourceType || (taintInfo ? taintInfo.sourceType : 'USER_INPUT');
            const confidence = isTaintedVar ? 0.95 : isDirectSuperglobal ? 0.92 : 0.75;

            this.findings.push({
              type: 'XSS_ROOT_CAUSE',
              name: `XSS Root Cause: Unescaped output in HTML context`,
              severity: 'HIGH',
              confidence,
              line: lineIndex + 1,
              variable: outputVar,
              sink: outputStatement,
              sourceType: actualSourceType,
              description: `Variable \`${outputVar}\` output directly to HTML via ${outputStatement} without htmlspecialchars() or equivalent encoding.`,
              recommendation: 'Wrap user input with htmlspecialchars($' + outputVar + ', ENT_QUOTES, "UTF-8")',
              patternHash: hashKey,
              codeSnippet: line.trim(),
              isRootCause: true,
              detectionMethod: isTaintedVar ? 'taint_map' : isDirectSuperglobal ? 'direct_superglobal' : 'heuristic',
              proof: {
                source: actualSourceType,
                sink: 'HTML output',
                propagation: [outputVar],
                vulnerability_confirmed: isTaintedVar || isDirectSuperglobal
              }
            });
          }
        }
      }
    });
  }

  /**
   * Helper: Generate hash of code pattern to detect duplicates
   * Uses simplified pattern, ignoring variable names
   */
  _generatePatternHash(codeSnippet) {
    // Normalize: remove specific variable names, keep structure
    const normalized = codeSnippet
      .replace(/\$[a-zA-Z_]\w*/g, '$VAR')          // Replace all variables with $VAR
      .replace(/['"][^'"]*['"]/g, '"STR"')          // Replace all strings with "STR"
      .replace(/\d+/g, 'NUM')                        // Replace numbers with NUM
      .toLowerCase()
      .trim();
    
    // Simple hash
    let hash = 0;
    for (let i = 0; i < normalized.length; i++) {
      const char = normalized.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return 'pattern_' + Math.abs(hash);
  }

  /**
   * Helper: Check if variable is likely user input
   */
  _isLikelyUserInput(varName) {
    if (!varName) return false;
    
    // ONLY skip heuristic if variable is explicitly marked as SANITIZED
    // If it's in taint map but NOT sanitized, let the heuristic provide fallback confidence
    if (this.taintedVariables && this.taintedVariables.has(varName)) {
      const taintInfo = this.taintedVariables.get(varName);
      // Return false (skip heuristic) ONLY if sanitized — we already have proof from taint map
      if (taintInfo.isSanitized || taintInfo.type === 'SANITIZED') {
        return false; // It's been properly sanitized, not user input
      }
      // If it's in map but NOT sanitized, continue to heuristic check
      // This gives heuristic a chance to provide additional detection signal
    }
    
    // Variables that commonly hold user input in PHP apps
    // Expanded from DVWA-only to general PHP app patterns
    const userInputPatterns = [
      // Identity / common input fields
      'id', 'uid', 'userid', 'user_id',
      'name', 'username', 'uname', 'login',
      'email', 'mail',
      'password', 'passwd', 'pass', 'pwd',
      // Search / query
      'query', 'search', 'q', 'keyword', 'term', 'filter',
      'sql', 'stmt',
      // Generic input
      'input', 'data', 'val', 'value', 'param', 'arg',
      'content', 'body', 'text', 'msg', 'message',
      // Names
      'first', 'last', 'fname', 'lname', 'fullname',
      'title', 'subject', 'comment',
      // System / command
      'cmd', 'command', 'exec', 'path', 'file', 'filename',
      'url', 'uri', 'redirect', 'target', 'dest',
      // Misc
      'key', 'token', 'code', 'hash', 'ref',
      'order', 'sort', 'page', 'limit', 'offset',
    ];

    const lowerName = varName.toLowerCase();
    return userInputPatterns.some(pattern => lowerName.includes(pattern));
  }

  /**
   * Helper: Check if query uses parameterization
   */
  _hasParameterization(queryContent) {
    // Check for parameterized query patterns
    const paramPatterns = [
      /\?/,                    // ? placeholder
      /:\w+/,                  // :name placeholder
      /\$\d+/,                 // $1, $2 placeholder
      /prepared|parameterized|prepare|bind/i  // Prepared statement keywords
    ];

    return paramPatterns.some(pattern => pattern.test(queryContent));
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
    
    // PHP sanitization functions - separated by context
    // Proper SQL sanitizers: prevent SQL injection
    const sqlSanitizers = [
      'mysqli_real_escape_string',
      'mysql_real_escape_string',
      'intval',
      'floatval',
      'filter_var',
      'filter_input'
    ];
    
    // Proper XSS sanitizers: prevent HTML/JavaScript injection
    const xssSanitizers = [
      'htmlspecialchars',
      'htmlentities',
      'strip_tags',
      'filter_var',
      'filter_input'
    ];
    
    // Command sanitizers
    const commandSanitizers = [
      'escapeshellarg',
      'escapeshellcmd',
      'intval'
    ];
    
    // NOT proper sanitizers (just formatting):
    // - trim, stripslashes, strip_tags, preg_replace, addslashes (alone)
    const allSanitizers = [...new Set([...sqlSanitizers, ...xssSanitizers, ...commandSanitizers])];
    
    // For each tainted variable, find where it's used in assignments
    for (const [varName, taintInfo] of this.taintedVariables.entries()) {
      lines.forEach((line, lineIndex) => {
        // Check if variable is sanitized (direct pattern)
        const sanitizationPattern = new RegExp(
          `\\$([a-zA-Z_][a-zA-Z0-9_]*)\\s*=\\s*(${allSanitizers.join('|')})\\s*\\([^)]*\\$${varName}[^)]*\\)`,
          'i'
        );
        const sanitizeMatch = sanitizationPattern.exec(line);
        
        // Also check ternary pattern: $var = ((cond) ? sanitizeFunc(..., $var) : fallback)
        // Common in DVWA: $msg = ((isset($GLOBALS[...])) ? mysqli_real_escape_string($GLOBALS[...], $msg) : ...)
        let ternarySanitizeMatch = null;
        if (!sanitizeMatch) {
          const ternaryPattern = new RegExp(
            `\\$([a-zA-Z_][a-zA-Z0-9_]*)\\s*=\\s*\\(?\\(?[^;]*(${allSanitizers.join('|')})\\s*\\([^)]*\\$${varName}`,
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

    // BUG FIX #3: DB Fetch Propagation — $row = mysqli_fetch_assoc($result) inherits taint from $result
    // This fixes detection of XSS in display code using $row['column']
    lines.forEach((line, lineIndex) => {
      const dbFetchPat = /\$(\w+)\s*=\s*(mysqli_fetch_assoc|mysqli_fetch_array|fetch_assoc|fetchArray)\s*\(\s*\$(\w+)/i;
      const dbm = dbFetchPat.exec(line);
      if (dbm && this.isTaintedVariable(dbm[3])) {
        const rowVar = dbm[1];
        const resultVar = dbm[3];
        const resultTaint = this.taintedVariables.get(resultVar);
        
        if (!this.taintedVariables.has(rowVar)) {
          this.taintedVariables.set(rowVar, {
            type: 'DB_PROPAGATED',
            sourceType: resultTaint.sourceType,
            severity: 'HIGH',
            line: lineIndex + 1,
            context: 'db_fetch_row',
            chain: [...(resultTaint.chain || [resultVar]), rowVar],
            isDbRow: true,
            originalSource: resultTaint.superglobal
          });
        }
      }
    });
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
   * ENHANCED: Also uses pattern hash to detect code duplicates in different blocks
   */
  deduplicateFindings() {
    const unique = [];
    const patternsSeen = new Map(); // Track patterns to eliminate duplicates

    for (const finding of this.findings) {
      // Check by pattern hash first (detects duplicates like XSS in MySQL and SQLite blocks)
      if (finding.patternHash) {
        if (patternsSeen.has(finding.patternHash)) {
          // Duplicate pattern found - skip or merge with higher confidence
          const existingIdx = patternsSeen.get(finding.patternHash);
          if (finding.confidence > unique[existingIdx].confidence) {
            unique[existingIdx] = { 
              ...finding, 
              engines: this._mergeEngines(unique[existingIdx], finding),
              duplicateCount: (unique[existingIdx].duplicateCount || 1) + 1,
              allLines: [...(unique[existingIdx].allLines || []), finding.line]
            };
          }
          continue;
        }
        patternsSeen.set(finding.patternHash, unique.length);
      }

      // Then check by traditional logic for non-pattern findings
      const duplicateIdx = unique.findIndex(existing =>
        this._isSameFinding(existing, finding)
      );

      if (duplicateIdx === -1) {
        unique.push(finding);
      } else if (finding.confidence > unique[duplicateIdx].confidence) {
        // Keep higher confidence, merge
        unique[duplicateIdx] = { 
          ...finding, 
          engines: this._mergeEngines(unique[duplicateIdx], finding),
          duplicateCount: (unique[duplicateIdx].duplicateCount || 1) + 1,
          allLines: [...(unique[duplicateIdx].allLines || []), finding.line]
        };
      }
    }

    this.findings = unique;
  }

  /**
   * Check if two findings refer to the same vulnerability
   * ENHANCED: Now prioritizes root cause findings and considers pattern similarity
   */
  _isSameFinding(a, b) {
    // Different vulnerability types - definitely not the same
    const categoryA = (a.type || '').split('_')[0];
    const categoryB = (b.type || '').split('_')[0];
    if (categoryA !== categoryB) return false;

    // If both are root cause findings with same pattern hash, they're the same
    if (a.isRootCause && b.isRootCause && a.patternHash && a.patternHash === b.patternHash) {
      return true;
    }

    // Same line and same type
    if (a.line === b.line && a.type === b.type) return true;

    // Same vulnerable variable in same vulnerability type
    if (a.variable && b.variable && a.variable === b.variable) {
      if (a.type === b.type) {
        return true;
      }
    }

    // Same sink on nearby lines - only merge if root cause detection
    if (a.sink && b.sink && a.sink === b.sink) {
      if (Math.abs((a.line || 0) - (b.line || 0)) <= 5) {
        // For execution points, don't merge - keep both
        // For root causes, merge
        return a.isRootCause && b.isRootCause;
      }
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
