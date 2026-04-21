/**
 * Multi-Engine Vulnerability Detector
 * Coordinates findings from:
 * 1. Regex Engine (pattern matching)
 * 2. Taint Analysis Engine (data flow)
 * 3. AST Engine (structural analysis)
 * 
 * Implements a voting/confidence system to reduce false positives
 */

class MultiEngineDetector {
  constructor() {
    this.regexFindings = [];
    this.taintFindings = [];
    this.astFindings = [];
    this.consolidatedFindings = [];
  }

  /**
   * Detect vulnerabilities using multiple engines
   * Returns consolidated findings with increased confidence when engines agree
   */
  async detect(filePath, code, language = 'php') {
    this.consolidatedFindings = [];
    
    // Only apply taint analysis for PHP
    if (language === 'php') {
      return this.detectPHP(filePath, code);
    } else {
      return this.detectJavaScript(filePath, code);
    }
  }

  /**
   * PHP Detection - Multi-engine approach
   */
  detectPHP(filePath, code) {
    // Engine 1: Regex patterns (fast, but false positives)
    const regexEngine = require('./regex/regexEngine');
    const regex = new regexEngine();
    this.regexFindings = regex.scan(code, 'php');

    // Engine 2: Static Taint Analysis (accurate, but slower)
    const PHPTaintAnalyzer = require('./taint/phpTaintAnalyzer');
    const taintAnalyzer = new PHPTaintAnalyzer();
    this.taintFindings = taintAnalyzer.analyze(code, filePath);

    // BUG FIX #4: DOM XSS Detection - analyze inline JavaScript in PHP files
    // This catches DOM-based XSS that pure PHP taint analysis cannot detect
    const inlineJSFindings = this._detectDOMBasedXSSInPHP(code, filePath);
    this.taintFindings = this.taintFindings.concat(inlineJSFindings);

    // Consolidate and validate findings
    return this.consolidateFindings(filePath);
  }

  /**
   * BUG FIX #4: Detect DOM-based XSS in inline JavaScript within PHP files
   * JavaScript DOM operations like document.write, innerHTML cannot be tracked by PHP taint analysis
   * This method extracts inline JS and analyzes it separately
   */
  _detectDOMBasedXSSInPHP(code, filePath) {
    const findings = [];
    
    // Extract inline JavaScript blocks from PHP
    // Pattern: <script>...JS code...</script>
    const scriptBlockRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
    const TaintAnalyzer = require('./taint/TaintAnalyzer');
    const jsAnalyzer = new TaintAnalyzer();
    
    let match;
    let blockNumber = 0;
    while ((match = scriptBlockRegex.exec(code)) !== null) {
      const jsCode = match[1];
      blockNumber++;
      
      // Skip if this block appears to be external (src attribute)
      if (match[0].includes('src=')) continue;
      
      // Analyze this JS block for taint flow
      try {
        const jsFindings = jsAnalyzer.analyze(jsCode);
        
        // Convert JS findings to PHP context and add to results
        for (const jsF of jsFindings) {
          findings.push({
            ...jsF,
            type: 'XSS_DOM_BASED',
            name: 'DOM-based XSS in inline JavaScript',
            context: `Inline <script> block #${blockNumber}`,
            sourceLanguage: 'JavaScript',
            severity: 'HIGH',
            isRootCause: true, // DOM XSS is inherently a root cause
            detectionMethod: 'javascript_ast',
            description: `DOM operation (${jsF.description || 'document.write/innerHTML'}) uses tainted JavaScript variable without sanitization`
          });
        }
      } catch (error) {
        // Silent fail for JS parsing errors - don't break PHP analysis
        continue;
      }
    }
    
    // Also check for PHP echo with JS in string containing variables
    // Pattern: echo "<script>...var = <?php echo $var ?> ...</script>"
    const phpEchoJSPattern = /echo\s+["']<script>[^<]*\$\w+[^<]*<\/script>["']/gi;
    const phpEchoMatches = [...code.matchAll(phpEchoJSPattern)];
    
    for (const phpMatch of phpEchoMatches) {
      const line = phpMatch[0];
      const varMatch = /\$([a-zA-Z_]\w*)/.exec(line);
      
      if (varMatch) {
        findings.push({
          type: 'XSS_DOM_BASED',
          name: 'Potential DOM XSS via PHP-generated JavaScript',
          severity: 'HIGH',
          confidence: 0.85,
          variable: varMatch[1],
          sink: 'echo (into JavaScript context)',
          sourceType: 'USER_INPUT',
          isRootCause: true,
          detectionMethod: 'php_to_js_transition',
          description: `PHP variable \`${varMatch[1]}\` echoed into JavaScript context without escaping. May be vulnerable to DOM XSS if used in unsafe JS operations.`,
          recommendation: 'Use json_encode() or javascript-specific escaping before output to JS context'
        });
      }
    }
    
    return findings;
  }

  /**
   * JavaScript Detection - Current approach
   */
  detectJavaScript(filePath, code) {
    // For JavaScript, continue with existing approach
    const astEngine = require('./ast/astEngine');
    const ast = new astEngine();
    return ast.scanFile(filePath, code);
  }

  /**
   * Consolidate findings from multiple engines
   * Algorithm:
   * 1. Start with ROOT CAUSE findings (highest priority)
   * 2. Add taint analysis findings (high confidence, proven chains)
   * 3. Match regex findings with taint findings (boost confidence if both agree)
   * 4. Flag regex-only findings with lower confidence (unconfirmed sources)
   * 5. Remove obvious false positives
   * 6. Deduplicate similar execution points when root cause exists
   */
  consolidateFindings(filePath) {
    const consolidated = [];
    const processedRegexIds = new Set();

    // PHASE 0: Prioritize ROOT CAUSE findings (e.g., query construction, unescaped output)
    const rootCauseFindings = this.taintFindings.filter(f => f.isRootCause);
    const executionPointFindings = this.taintFindings.filter(f => !f.isRootCause);

    // Add root cause findings first
    for (const rootCauseFinding of rootCauseFindings) {
      consolidated.push({
        ...rootCauseFinding,
        engine: 'TAINT_ANALYSIS',
        engines: ['TAINT_ANALYSIS'],
        confidence: rootCauseFinding.confidence || 0.95,
        isConfirmedVulnerability: true,
        reason: 'Root cause detected: ' + (rootCauseFinding.vulnerability_type || 'vulnerability construction')
      });
    }

    // PHASE 1: Add execution point findings only if no matching root cause exists
    for (const executionFinding of executionPointFindings) {
      // Check if there's a matching root cause for this execution point
      const hasMatchingRootCause = rootCauseFindings.some(rcf =>
        this._isRelatedToRootCause(executionFinding, rcf)
      );

      if (!hasMatchingRootCause) {
        consolidated.push({
          ...executionFinding,
          engine: 'TAINT_ANALYSIS',
          engines: ['TAINT_ANALYSIS'],
          confidence: executionFinding.confidence || 0.95,
          isConfirmedVulnerability: true,
          reason: 'Proven data flow from source to sink'
        });
      }
    }

    // PHASE 2: Match regex findings with taint findings
    for (const regexFinding of this.regexFindings) {
      const matchingTaint = this.taintFindings.find(tf => 
        this.findingsMatch(regexFinding, tf)
      );

      if (matchingTaint) {
        // Boost confidence - both engines agree
        const existing = consolidated.find(f => this.findingsMatch(f, regexFinding));
        if (existing) {
          existing.confidence = Math.min(0.98, (existing.confidence + 0.10));
          existing.engines.push('REGEX');
          existing.reason = 'Confirmed by both Taint Analysis and Regex Engine';
        }
        processedRegexIds.add(regexFinding.id || regexFinding.line);
      }
    }

    // PHASE 3: Add remaining regex findings with confidence reduction
    for (const regexFinding of this.regexFindings) {
      const findingId = regexFinding.id || regexFinding.line;
      
      if (!processedRegexIds.has(findingId)) {
        // Check if this is a probable false positive
        if (this.isProbableFalsePositive(regexFinding)) {
          continue; // Skip obvious false positives
        }

        // Add as unconfirmed finding with lower confidence
        consolidated.push({
          ...regexFinding,
          engine: 'REGEX',
          engines: ['REGEX'],
          confidence: this.calculateAdjustedConfidence(regexFinding),
          isConfirmedVulnerability: false,
          reason: 'Source detected by regex (not confirmed as sink)',
          note: 'Manual review recommended - may be false positive'
        });
      }
    }

    // PHASE 4: Sort by priority (root cause > execution point), then severity and line number
    consolidated.sort((a, b) => {
      // Root cause findings come first
      if (a.isRootCause && !b.isRootCause) return -1;
      if (!a.isRootCause && b.isRootCause) return 1;

      // Then sort by severity
      const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
      const aScore = (severityOrder[a.severity] || 4) * 10000 + (a.line || 0);
      const bScore = (severityOrder[b.severity] || 4) * 10000 + (b.line || 0);
      return aScore - bScore;
    });

    this.consolidatedFindings = consolidated;
    return consolidated;
  }

  /**
   * Check if execution point finding is related to a root cause finding
   * (e.g., same vulnerable variable)
   */
  _isRelatedToRootCause(executionFinding, rootCauseFinding) {
    // Same vulnerability type
    if ((executionFinding.type || '').split('_')[0] !== (rootCauseFinding.type || '').split('_')[0]) {
      return false;
    }

    // Same variable
    if (executionFinding.variable === rootCauseFinding.variable) {
      return true;
    }

    // Vulnerable variable mentioned in root cause
    if (rootCauseFinding.vulnerableVariable && executionFinding.variable === rootCauseFinding.vulnerableVariable) {
      return true;
    }

    // Same variable name in chain
    const execChain = executionFinding.chain || [];
    const rootChain = rootCauseFinding.chain || [];
    const commonVars = execChain.filter(v => rootChain.includes(v));
    return commonVars.length > 0;
  }

  /**
   * Check if two findings refer to the same vulnerability
   */
  findingsMatch(finding1, finding2) {
    // Match by line number
    if (finding1.line === finding2.line) {
      return true;
    }

    // Match by variable name
    if (finding1.variable && finding2.variable && finding1.variable === finding2.variable) {
      return true;
    }

    // Match by sink function
    if (finding1.sink && finding2.sink && finding1.sink === finding2.sink) {
      if (finding1.line && finding2.line && Math.abs(finding1.line - finding2.line) <= 2) {
        return true;
      }
    }

    return false;
  }

  /**
   * Detect probable false positives
   * These are regex findings that almost certainly aren't vulnerabilities
   */
  isProbableFalsePositive(regexFinding) {
    const falsePositivePatterns = [
      // Conditional statements (isset, empty, etc.) - not output
      {
        check: (f) => f.type === 'XSS_CONCAT' && f.description?.includes('isset'),
        reason: 'Conditional check, not output'
      },
      // Simple variable assignment - not output
      {
        check: (f) => f.type === 'XSS_CONCAT' && f.description?.includes('assignment'),
        reason: 'Variable assignment, not output'
      },
      // Variable declaration in function signature
      {
        check: (f) => f.type === 'XSS_CONCAT' && f.line < 5,
        reason: 'Likely parameter declaration'
      }
    ];

    for (const pattern of falsePositivePatterns) {
      if (pattern.check(regexFinding)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Calculate adjusted confidence for regex-only findings
   * Reduce confidence if not confirmed by taint analysis
   */
  calculateAdjustedConfidence(regexFinding) {
    let adjustedConfidence = regexFinding.confidence || 0.75;

    // Reduce confidence for findings that need sink validation
    if (regexFinding.type === 'XSS_CONCAT') {
      // XSS_CONCAT is a source detection, not sink confirmation
      adjustedConfidence = Math.max(0.40, adjustedConfidence - 0.30);
    }

    // Reduce confidence for patterns without high specificity
    if (regexFinding.confidence < 0.80) {
      adjustedConfidence = Math.max(0.35, adjustedConfidence - 0.20);
    }

    return adjustedConfidence;
  }

  /**
   * Generate detection report
   */
  getReport() {
    const report = {
      totalFindings: this.consolidatedFindings.length,
      confirmedVulnerabilities: this.consolidatedFindings.filter(f => f.isConfirmedVulnerability).length,
      unconfirmedFindings: this.consolidatedFindings.filter(f => !f.isConfirmedVulnerability).length,
      byEngine: {
        taintAnalysis: this.consolidatedFindings.filter(f => f.engines?.includes('TAINT_ANALYSIS')).length,
        regex: this.consolidatedFindings.filter(f => f.engines?.includes('REGEX')).length,
        both: this.consolidatedFindings.filter(f => f.engines?.length > 1).length
      },
      bySeverity: {
        CRITICAL: this.consolidatedFindings.filter(f => f.severity === 'CRITICAL').length,
        HIGH: this.consolidatedFindings.filter(f => f.severity === 'HIGH').length,
        MEDIUM: this.consolidatedFindings.filter(f => f.severity === 'MEDIUM').length,
        LOW: this.consolidatedFindings.filter(f => f.severity === 'LOW').length
      },
      findings: this.consolidatedFindings
    };

    return report;
  }

  /**
   * Get findings with filtering options
   */
  getFindings(options = {}) {
    let findings = this.consolidatedFindings;

    // Filter by engine
    if (options.engine) {
      findings = findings.filter(f => f.engines?.includes(options.engine));
    }

    // Filter by severity
    if (options.severity) {
      findings = findings.filter(f => f.severity === options.severity);
    }

    // Filter by vulnerability type
    if (options.type) {
      findings = findings.filter(f => f.type === options.type);
    }

    // Filter by confidence threshold
    if (options.minConfidence !== undefined) {
      findings = findings.filter(f => (f.confidence || 0) >= options.minConfidence);
    }

    // Include/exclude unconfirmed findings
    if (options.confirmed === true) {
      findings = findings.filter(f => f.isConfirmedVulnerability === true);
    } else if (options.confirmed === false) {
      findings = findings.filter(f => f.isConfirmedVulnerability === false);
    }

    return findings;
  }

  /**
   * Get quality metrics
   */
  getQualityMetrics() {
    const total = this.consolidatedFindings.length;
    
    if (total === 0) {
      return {
        precision: 1.0,
        engineAgreement: 'N/A',
        falsePositiveRate: 0,
        message: 'No findings detected'
      };
    }

    const confirmed = this.consolidatedFindings.filter(f => f.isConfirmedVulnerability).length;
    const avgConfidence = this.consolidatedFindings.reduce((sum, f) => sum + (f.confidence || 0), 0) / total;
    const multiEngine = this.consolidatedFindings.filter(f => (f.engines || []).length > 1).length;

    return {
      totalFindings: total,
      confirmedVulnerabilities: confirmed,
      precision: confirmed / total,
      falsePositiveRate: (total - confirmed) / total,
      avgConfidence: avgConfidence,
      engineAgreement: `${multiEngine}/${total} findings confirmed by multiple engines`,
      improvement: 'Taint analysis reduces false positives compared to regex-only approach'
    };
  }
}

module.exports = MultiEngineDetector;
