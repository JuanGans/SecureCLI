/**
 * Core Scanner - Orchestrates all detection engines
 * ENHANCED: Multi-language support with PHP compatibility
 */

const fs = require('fs');
const path = require('path');
const RegexEngine = require('../engines/regex/regexEngine');
const TaintAnalyzer = require('../engines/taint/taintAnalyzer');
const ASTEngine = require('../engines/ast/astEngine');
const ContextAnalyzer = require('../context/contextAnalyzer');
const RiskScorer = require('../scoring/riskScorer');
const Logger = require('../utils/logger');
const { detectLanguage, isInDocumentation, isHardcoded } = require('../utils/helpers');
const CommentStripper = require('../utils/commentStripper');

// ENHANCED: Dynamic modules for adaptive remediation
const DynamicPatternAnalyzer = require('../engines/patterns/dynamicPatternAnalyzer');
const ContextExtractor = require('./contextExtractor');
const AdaptiveFixGenerator = require('../remediation/adaptiveFixGenerator');
const RuleBasedRecommendationEngine = require('../remediation/ruleBasedRecommendationEngine');

// NEW: Multi-engine detection for improved accuracy
const MultiEngineDetector = require('../engines/multiEngineDetector');
const PHPTaintAnalyzer = require('../engines/taint/phpTaintAnalyzer');
const PHPTokenizer = require('../engines/ast/phpTokenizer');
const SQLiConsolidator = require('../engines/sqli/consolidate');

// XSS Detection Engines
const ReflectedXSSDetector = require('../engines/xss/reflected');
const StoredXSSDetector = require('../engines/xss/stored');
const DOMBasedXSSDetector = require('../engines/xss/dom-based');
const EventXSSDetector = require('../engines/xss/event');
const XSSConsolidator = require('../engines/xss/consolidate');

class Scanner {
  constructor(options = {}) {
    this.options = options;
    this.regexEngine = new RegexEngine();
    this.taintAnalyzer = new TaintAnalyzer();
    this.phpTaintAnalyzer = new PHPTaintAnalyzer();  // NEW: PHP-specific taint analyzer
    this.phpTokenizer = new PHPTokenizer();
    this.astEngine = new ASTEngine();
    this.contextAnalyzer = new ContextAnalyzer(this.astEngine);
    this.scorer = new RiskScorer();
    this.logger = new Logger(options.verbose);
    this.multiEngineDetector = new MultiEngineDetector();  // NEW: Multi-engine coordinator
    
    // XSS Detection Engines
    this.reflectedXSSDetector = new ReflectedXSSDetector();
    this.storedXSSDetector = new StoredXSSDetector();
    this.domBasedXSSDetector = new DOMBasedXSSDetector();
    this.eventXSSDetector = new EventXSSDetector();
    
    // ENHANCED: Initialize dynamic modules
    this.patternAnalyzer = new DynamicPatternAnalyzer();
    this.contextExtractor = new ContextExtractor();
    this.fixGenerator = new AdaptiveFixGenerator();
    this.ruleRecommendationEngine = new RuleBasedRecommendationEngine({
      contextAnalyzer: this.contextAnalyzer,
      contextExtractor: this.contextExtractor,
      fixGenerator: this.fixGenerator,
    });
  }

  /**
   * Scan a single file
   * ENHANCED: Multi-engine support for PHP with taint analysis
   * - PHP: Regex + Lexical (Tokenizer/AST) + Taint Analysis
   * - JavaScript/TypeScript: AST + Taint Analysis
   * 
   * OPTIMIZATION: For DVWA-like structures with wrapper files, skip wrapper and scan actual vulnerable files in /source/ subdirectory directly
   */
  scanFile(filePath) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const findings = [];
      const language = detectLanguage(filePath);

      // Parse AST only for JavaScript/TypeScript files
      if (language === 'javascript' || language === 'typescript') {
        try {
          this.astEngine.reset();
          this.astEngine.parse(content);
        } catch (astError) {
          this.logger.warn(`AST parsing skipped for ${filePath}: ${astError.message}`);
        }
      } else if (language === 'php') {
        // PHP files use multi-engine detection (Regex + Taint Analysis + Lexical/AST)
        this.logger.info(`PHP file detected: ${filePath} (using multi-engine detection)`);
        
        // OPTIMIZATION: For wrapper files with /source/ subdirectory, scan source files directly
        // This avoids false positives from wrapper orchestration logic
        const fileName = path.basename(filePath).toLowerCase();
        const isWrapperFile = fileName === 'index.php';
        const parentDir = path.dirname(filePath);
        const sourceDir = path.join(parentDir, 'source');
        const hasSourceDir = fs.existsSync(sourceDir);
        
        if (isWrapperFile && hasSourceDir) {
          this.logger.debug(`[WRAPPER DETECTION] Found /source/ subdirectory - will skip wrapper and scan actual vulnerable files`);
          this.logger.debug(`[WRAPPER DETECTION] Source directory: ${sourceDir}`);
          
          try {
            const sourceFiles = fs.readdirSync(sourceDir)
              .filter(f => f.endsWith('.php'))
              .map(f => path.join(sourceDir, f))
              .sort(); // Scan in consistent order
            
            if (sourceFiles.length === 0) {
              this.logger.debug(`[WRAPPER DETECTION] No PHP files in /source/ - fallback to wrapper`);
              return this.detectPHPWithMultiEngine(filePath, content);
            }
            
            this.logger.debug(`[WRAPPER DETECTION] Found ${sourceFiles.length} source files to scan`);
            
            // Scan each source file separately to maintain clean detection context
            // All 3 engines (regex, lexical/AST, taint) will run on each source file
            let phpFindings = [];
            for (const sourceFile of sourceFiles) {
              this.logger.debug(`[ENGINE: Regex+Lexical+Taint] Scanning: ${path.basename(sourceFile)}`);
              const sourceContent = fs.readFileSync(sourceFile, 'utf-8');
              const sourceFileFindings = this.detectPHPWithMultiEngine(sourceFile, sourceContent);
              this.logger.debug(`[ENGINE: Regex+Lexical+Taint] Found ${sourceFileFindings.length} findings in ${path.basename(sourceFile)}`);
              
              // Ensure all findings have correct file path for source file
              sourceFileFindings.forEach(f => {
                f.file = sourceFile;
              });
              
              phpFindings = phpFindings.concat(sourceFileFindings);
            }
            
            return phpFindings;
          } catch (err) {
            this.logger.warn(`Failed to scan source files: ${err.message}`);
            // Fallback to scanning wrapper if source scanning fails
            return this.detectPHPWithMultiEngine(filePath, content);
          }
        }
        
        // Normal PHP file (not a wrapper) - scan directly
        // All 3 engines (regex, lexical/AST, taint) will run
        return this.detectPHPWithMultiEngine(filePath, content);
      }

      // LAYER 1: DETECTION
      const regexFindings = this.detectWithRegex(content, language);
      
      // Taint analysis only for JavaScript — uses AST parsed above via taintAnalyzer
      let taintFindings = [];
      if (language === 'javascript' || language === 'typescript') {
        taintFindings = this.detectWithTaint(content);

        // AST-enhanced: cross-validate taint findings with ASTEngine's call graph
        // to add structural evidence (which variable/function calls are involved)
        taintFindings = this._enrichTaintWithAST(taintFindings);
      }

      findings.push(...regexFindings);
      findings.push(...taintFindings);

      // LAYER 2: FILTER FALSE POSITIVES
      const filteredFindings = findings.filter(finding => {
        // Skip if in documentation
        if (isInDocumentation(content, finding.line)) {
          this.logger.debug(`Skipping documentation at line ${finding.line}`);
          return false;
        }
        
        // Skip if hardcoded (not user input)
        if (isHardcoded(content, finding.line)) {
          this.logger.debug(`Skipping hardcoded content at line ${finding.line}`);
          return false;
        }
        
        return true;
      });

      // LAYER 3: CONTEXT ANALYSIS & REMEDIATION
      const enhancedFindings = filteredFindings.map(finding => {
        // Apply rule-based contextual remediation to SQLI/XSS findings.
        // Works for taint, taint+ast, and regex findings by normalizing vulnerability type.
        if (this.shouldApplyContextualRemediation(finding)) {
          return this.enhanceFindingWithContext(finding, content);
        }
        return finding;
      });

      // LAYER 4: SCORING
      const scoredFindings = enhancedFindings.map(finding => {
        const scored = this.scoreFinding(finding);
        return this.addCWEMapping(scored);
      });

      return scoredFindings;
    } catch (error) {
      this.logger.error(`Failed to scan ${filePath}: ${error.message}`);
      return [];
    }
  }

  /**
   * Detect PHP vulnerabilities using multi-engine approach
   * Combines Regex + Static Taint Analysis with voting mechanism
   * 
   * Returns:
   * - High confidence findings where both engines agree
   * - Medium confidence findings from proven taint flows
   * - Lower confidence regex-only findings (when taint can't confirm)
   */
  detectPHPWithMultiEngine(filePath, content) {
    try {
      // Step 0: Strip comments to avoid false positives
      const cleanedContent = CommentStripper.strip(content, 'php');

      // Step 0.5: Structural analysis (AST/token-based stage for PHP)
      this.logger.debug(`Running PHP structural analysis on ${filePath}`);
      const structuralAnalysis = this.analyzePHPStructure(cleanedContent);
      
      // Step 1: Run taint analysis (high confidence, proven chains)
      this.logger.debug(`Running PHP taint analysis on ${filePath}`);
      const taintFindings = this.phpTaintAnalyzer.analyze(cleanedContent, filePath);
      
      // Step 2: Run regex patterns  
      this.logger.debug(`Running regex detection on ${filePath}`);
      const regexFindings = this.detectWithRegex(cleanedContent, 'php');

      // Step 2.5: Run dedicated XSS engines
      this.logger.debug(`Running XSS engines on ${filePath}`);
      const xssFindings = this.detectWithXSSEngines(cleanedContent, filePath);

      // Step 3: Consolidate findings using multi-engine logic
      this.logger.debug(`Consolidating findings from ${taintFindings.length} taint, ${regexFindings.length} regex, and ${xssFindings.length} XSS detections`);
      const consolidatedFindings = this.consolidateDetections(
        filePath, 
        cleanedContent, 
        taintFindings, 
        [...regexFindings, ...xssFindings],
        structuralAnalysis
      );

      // LAYER 2: FILTER FALSE POSITIVES
      const filteredFindings = consolidatedFindings.filter(finding => {
        if (isInDocumentation(cleanedContent, finding.line)) {
          this.logger.debug(`Skipping documentation at line ${finding.line}`);
          return false;
        }
        if (isHardcoded(cleanedContent, finding.line)) {
          this.logger.debug(`Skipping hardcoded content at line ${finding.line}`);
          return false;
        }
        return true;
      });

      // LAYER 4: SCORING & CWE MAPPING
      const scoredFindings = filteredFindings.map(finding => {
        const scored = this.scoreFinding(finding);
        return this.addCWEMapping(scored);
      });

      return scoredFindings;
    } catch (error) {
      this.logger.error(`PHP multi-engine detection failed: ${error.message}`);
      // Fallback to regex only
      return this.detectWithRegex(content, 'php');
    }
  }

  /**
   * Consolidate detection results from multiple engines
   * Algorithm:
   * 1. Start with taint findings (proven data flows)
   * 2. Cross-validate with regex findings
   * 3. Adjust confidence based on engine agreement
   * 4. Remove low-confidence findings that lack proof
   */
  consolidateDetections(filePath, content, taintFindings, regexFindings, structuralAnalysis = null) {
    const consolidated = [];
    const processedRegexFindings = new Set();

    // PHASE 1: Add all taint findings with high confidence
    for (const taintFinding of taintFindings) {
      const structuralEvidence = this.getStructuralEvidence(taintFinding, structuralAnalysis, content);
      const engines = ['TAINT_ANALYSIS'];

      if (structuralEvidence.confirmed) {
        engines.push('AST_STRUCTURAL');
      }

      consolidated.push({
        ...taintFinding,
        engine: structuralEvidence.confirmed ? 'taint+regex+ast' : 'taint+regex',
        engines,
        confidence: Math.min(0.99, (taintFinding.confidence || 0.95) + (structuralEvidence.confidenceBoost || 0)),
        isProvenVulnerability: true,
        reason: structuralEvidence.confirmed
          ? 'Confirmed by taint analysis with structural validation (AST/token stage)'
          : 'Confirmed by taint analysis - proven data flow from source to sink',
        structuralEvidence: structuralEvidence.summary,
        file: filePath
      });
    }

    // PHASE 2: Cross-validate regex findings with taint findings
    for (let i = 0; i < regexFindings.length; i++) {
      const regexFinding = regexFindings[i];
      const findingKey = `${regexFinding.line}-${regexFinding.type}`;
      
      // Check if this regex finding matches a taint finding
      const matchingTaint = taintFindings.find(tf => 
        this.findingsCorrelate(regexFinding, tf, content)
      );

      if (matchingTaint) {
        // Both engines detected it - boost confidence
        const existingConsolidated = consolidated.find(cf => 
          cf.line === regexFinding.line && 
          (cf.type === regexFinding.type || cf.severity === regexFinding.severity)
        );

        if (existingConsolidated) {
          existingConsolidated.confidence = Math.min(0.99, existingConsolidated.confidence + 0.05);
          existingConsolidated.engines.push('REGEX');
          existingConsolidated.reason = 'Confirmed by both Taint Analysis and Regex Engine';
        }
        
        processedRegexFindings.add(findingKey);
      } else {
        // Only regex detected - include with lower confidence
        // But filter out obvious false positives
        if (!this.isLikelyFalsePositive(regexFinding, content)) {
          // Drop XSS reflected/event findings that require taint confirmation but got none
          // (stored XSS storage findings are kept even without taint confirmation)
          if (regexFinding.requiresTaintConfirmation &&
              (regexFinding.type === 'XSS_REFLECTED' || regexFinding.type === 'XSS_EVENT_HANDLER')) {
            this.logger.debug(`Filtered: ${regexFinding.type} at line ${regexFinding.line} - requires taint confirmation`);
            continue;
          }

          const structuralEvidence = this.getStructuralEvidence(regexFinding, structuralAnalysis, content);
          const engines = ['REGEX'];

          if (structuralEvidence.confirmed) {
            engines.push('AST_STRUCTURAL');
          }

          consolidated.push({
            ...regexFinding,
            engine: structuralEvidence.confirmed ? 'regex+ast' : 'regex',
            engines,
            confidence: Math.min(0.95, this.adjustConfidenceForRegexOnly(regexFinding) + (structuralEvidence.confidenceBoost || 0)),
            isProvenVulnerability: false,
            reason: structuralEvidence.confirmed
              ? 'Pattern detected with structural support (needs taint confirmation)'
              : 'Source detected (needs manual verification - not confirmed as sink)',
            file: filePath,
            structuralEvidence: structuralEvidence.summary,
            note: 'Detected by pattern matching only - may require manual verification'
          });
        } else {
          this.logger.debug(`Filtered out likely false positive at line ${regexFinding.line}: ${regexFinding.type}`);
        }
      }
    }

    // Sort by severity and line
    consolidated.sort((a, b) => {
      const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
      const aSeverity = severityOrder[a.severity] || 4;
      const bSeverity = severityOrder[b.severity] || 4;
      return aSeverity !== bSeverity ? aSeverity - bSeverity : (a.line || 0) - (b.line || 0);
    });

    // Final deduplication pass using SQLi and XSS consolidators
    let deduplicated = SQLiConsolidator.consolidate(consolidated);
    deduplicated = XSSConsolidator.consolidate(deduplicated);

    this.logger.info(`Consolidated: ${deduplicated.length} findings (${deduplicated.filter(f => f.isProvenVulnerability).length} proven, ${deduplicated.filter(f => !f.isProvenVulnerability).length} unconfirmed)`);

    return deduplicated;
  }

  /**
   * Check if findings from different engines correlate
   */
  findingsCorrelate(regexFinding, taintFinding, content) {
    // Same line
    if (regexFinding.line === taintFinding.line) {
      return true;
    }

    // Same variable
    if (regexFinding.variable && taintFinding.variable && 
        regexFinding.variable === taintFinding.variable) {
      return true;
    }

    // Same type category on nearby lines
    const regexCategory = (regexFinding.type || '').split('_')[0];
    const taintCategory = (taintFinding.type || '').split('_')[0];
    if (regexCategory === taintCategory && Math.abs((regexFinding.line || 0) - (taintFinding.line || 0)) <= 5) {
      return true;
    }

    // Cross-type matches: SQLI regex types vs SQLI taint types
    const sqliRegexTypes = ['SQLI_DIRECT_VAR', 'SQLI_CONCAT', 'SQLI_MYSQLI_QUERY', 'SQLI_MYSQL_QUERY', 'SQLI_PDO_QUERY', 'SQLI_VAR_INTERPOLATION'];
    const sqliTaintTypes = ['SQLI_TAINTED_QUERY'];
    if (sqliRegexTypes.includes(regexFinding.type) && sqliTaintTypes.includes(taintFinding.type)) {
      if (Math.abs((regexFinding.line || 0) - (taintFinding.line || 0)) <= 5) return true;
    }

    // Cross-type matches: XSS regex types vs XSS taint types
    const xssRegexTypes = ['XSS_ECHO', 'XSS_PRINT', 'XSS_CONCAT', 'XSS_HTML_VAR', 'XSS_SHORT_ECHO', 'XSS_ECHO_VAR'];
    const xssEngineTypes = ['XSS_REFLECTED', 'XSS_STORED', 'XSS_STORED_INPUT', 'XSS_STORED_OUTPUT', 'XSS_DOM_BASED', 'XSS_EVENT_HANDLER'];
    const xssTaintTypes = ['XSS_TAINTED_OUTPUT'];
    const allXssTypes = [...xssRegexTypes, ...xssEngineTypes];
    if (allXssTypes.includes(regexFinding.type) && xssTaintTypes.includes(taintFinding.type)) {
      if (Math.abs((regexFinding.line || 0) - (taintFinding.line || 0)) <= 3) return true;
    }

    return false;
  }

  /**
   * Distinguish between SQLi and XSS context based on code analysis
   * Returns which vulnerability type is more likely
   */
  getVulnerabilityContext(content, lineNumber) {
    const lines = content.split('\n');
    const contextStart = Math.max(0, lineNumber - 5);
    const contextEnd = Math.min(lines.length, lineNumber + 5);
    const context = lines.slice(contextStart, contextEnd).join('\n');
    
    // SQL Keywords and patterns that indicate SQLi context
    const sqlKeywords = /(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN|UNION|ORDER\s+BY|GROUP\s+BY|HAVING|CREATE|DROP|ALTER|EXEC|EXECUTE|QUERY|PREPARED|mysqli|mysql_query|pdo|prepared.*statement)/i;
    const sqlOperators = /(\$_GET|\$_POST|\$_REQUEST).*["']\s*\.\s*["'](SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)/i;
    const sqlInjectionPatterns = /(UNION\s+SELECT|OR\s+1\s*=\s*1|".*or.*")/i;
    
    // XSS Keywords and patterns that indicate XSS context
    const xssKeywords = /(echo|print|innerHTML|innerText|document\.write|appendChild|insertBefore|addEventListener|onclick|onerror|onload|<script|<img|<iframe|<embed|htmlspecialchars|htmlentities|escape)/i;
    const htmlTags = /<(?:script|iframe|embed|object|img|svg|style|link|form|input)\b[^>]*>/i;
    const eventHandlers = /on(error|load|click|mouseover|focus|submit|change)\s*=/i;
    
    // Count indicators
    let sqlScore = 0;
    let xssScore = 0;
    
    // Check for SQL keywords
    if (sqlKeywords.test(context)) sqlScore += 3;
    if (sqlOperators.test(context)) sqlScore += 5;
    if (sqlInjectionPatterns.test(context)) sqlScore += 4;
    
    // Check for XSS keywords
    if (xssKeywords.test(context)) xssScore += 3;
    if (htmlTags.test(context)) xssScore += 4;
    if (eventHandlers.test(context)) xssScore += 3;
    
    // Check current line specifically
    const currentLine = lines[lineNumber - 1] || '';
    if (/SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|mysqli_query|mysql_query|pdo.*query/i.test(currentLine)) {
      sqlScore += 2;
    }
    if (/echo|print|innerHTML|innerText|document\.write|addEventListener/i.test(currentLine)) {
      xssScore += 2;
    }
    if (/<[a-z]/i.test(currentLine) && !/<[\s!]/i.test(currentLine)) {
      xssScore += 1;
    }
    
    return {
      sqlScore,
      xssScore,
      isSQLi: sqlScore > xssScore,
      isXSS: xssScore > sqlScore,
      isMixed: sqlScore === xssScore && sqlScore > 0,
      moreContext: { context, currentLine }
    };
  }

  /**
   * Identify likely false positives to filter out
   * ENHANCED: Better distinction between SQLi and XSS
   */
  isLikelyFalsePositive(regexFinding, content) {
    // Get the code line context
    const lines = content.split('\n');
    const codeLine = lines[regexFinding.line - 1] || '';

    // Filter 1: XSS_CONCAT in conditional statements (isset, empty, etc.)
    if (regexFinding.type === 'XSS_CONCAT' && /^\s*(if|while|switch)\s*\(/.test(codeLine)) {
      return true;
    }

    // Filter 2: Simple assignment without output
    if (regexFinding.type === 'XSS_CONCAT' && /^\s*\$\w+\s*=\s*\$_(GET|POST|REQUEST|COOKIE)/.test(codeLine)) {
      return true;
    }

    // Filter 3: Variable declarations in function/array context
    if (regexFinding.type === 'XSS_CONCAT' && /\[\s*['"]?\w+['"]?\s*\]\s*=\s*\$_(GET|POST|REQUEST)/.test(codeLine)) {
      return true;
    }

    // Filter 4: XSS_DOM false positive - likely SQL comparison operators
    // Pattern: `<` or `>` followed by SQL context (numbers, column names, keywords)
    if (regexFinding.type === 'XSS_DOM' && /[<>]\s*(?:\d+|'[^']*'|"[^"]*"|SELECT|FROM|WHERE|AND|OR|IN)\b/i.test(codeLine)) {
      // This looks like SQL comparison, not XSS
      // Check if XSS is actually more likely
      const vulnContext = this.getVulnerabilityContext(content, regexFinding.line);
      if (vulnContext.isSQLi) {
        this.logger.debug(`Filtering XSS_DOM at line ${regexFinding.line} - SQL context detected`);
        return true;
      }
    }

    // Filter 5: XSS_DOM false positive - HTML comment or documentation
    if (regexFinding.type === 'XSS_DOM' && /\/\/|\/\*|<!--/.test(codeLine)) {
      return true;
    }

    return false;
  }

  /**
   * Adjust confidence for regex-only findings
   * Reduce confidence since they lack taint proof
   */
  adjustConfidenceForRegexOnly(regexFinding) {
    let adjusted = regexFinding.confidence || 0.75;

    // XSS_CONCAT is just source detection, not sink confirmation
    if (regexFinding.type === 'XSS_CONCAT') {
      adjusted = Math.max(0.30, adjusted - 0.35);
    }

    // Lower confidence for medium-confidence patterns
    if (adjusted < 0.80) {
      adjusted = Math.max(0.20, adjusted - 0.25);
    }

    return adjusted;
  }

  /**
   * PHP structural analysis stage (token/AST-like validation)
   */
  analyzePHPStructure(content) {
    try {
      const tokens = this.phpTokenizer.tokenize(content);
      const lines = content.split('\n');

      const sqlSinkLines = new Set();
      const xssSinkLines = new Set();
      const commandSinkLines = new Set();

      tokens.forEach(token => {
        if (token.type !== 'FUNCTION') return;

        const fn = (token.value || '').toLowerCase();
        if (['mysqli_query', 'mysql_query', 'query', 'execute', 'prepare', 'exec'].includes(fn)) {
          sqlSinkLines.add(token.line);
        }
        if (['echo', 'print', 'printf', 'sprintf'].includes(fn)) {
          xssSinkLines.add(token.line);
        }
        if (['eval', 'assert', 'system', 'shell_exec', 'passthru', 'exec'].includes(fn)) {
          commandSinkLines.add(token.line);
        }
      });

      const bracketBalance = {
        paren: (content.match(/\(/g) || []).length - (content.match(/\)/g) || []).length,
        square: (content.match(/\[/g) || []).length - (content.match(/\]/g) || []).length,
        curly: (content.match(/\{/g) || []).length - (content.match(/\}/g) || []).length,
      };

      const structureHealthy = bracketBalance.paren === 0 && bracketBalance.square === 0 && bracketBalance.curly === 0;

      return {
        available: true,
        tokenCount: tokens.length,
        structureHealthy,
        sqlSinkLines,
        xssSinkLines,
        commandSinkLines,
        summary: {
          tokenCount: tokens.length,
          structureHealthy,
          sqlSinks: sqlSinkLines.size,
          xssSinks: xssSinkLines.size,
          commandSinks: commandSinkLines.size,
          totalLines: lines.length,
        }
      };
    } catch (error) {
      this.logger.debug(`PHP structural analysis failed: ${error.message}`);
      return { available: false, structureHealthy: false, summary: { error: error.message } };
    }
  }

  /**
   * Attach structural evidence and confidence boost for matching sink lines
   */
  getStructuralEvidence(finding, structuralAnalysis, content) {
    if (!structuralAnalysis || !structuralAnalysis.available) {
      return { confirmed: false, confidenceBoost: 0, summary: null };
    }

    const line = finding.line || 0;
    const type = (finding.type || '').toUpperCase();

    let confirmed = false;
    let sinkKind = null;

    if (type.includes('SQLI') && structuralAnalysis.sqlSinkLines.has(line)) {
      confirmed = true;
      sinkKind = 'sql';
    } else if (type.includes('XSS') && structuralAnalysis.xssSinkLines.has(line)) {
      confirmed = true;
      sinkKind = 'xss';
    } else if ((type.includes('CODE_INJECTION') || type.includes('COMMAND')) && structuralAnalysis.commandSinkLines.has(line)) {
      confirmed = true;
      sinkKind = 'command';
    }

    const confidenceBoost = confirmed && structuralAnalysis.structureHealthy ? 0.02 : 0;

    return {
      confirmed,
      confidenceBoost,
      summary: {
        confirmed,
        sinkKind,
        structureHealthy: structuralAnalysis.structureHealthy,
      }
    };
  }

  /**
   * Determine whether finding is eligible for contextual remediation.
   */
  shouldApplyContextualRemediation(finding) {
    const vulnType = (finding.vulnerabilityType || '').toUpperCase();
    const type = (finding.type || '').toUpperCase();

    return vulnType === 'SQLI' || vulnType === 'XSS' ||
      type.includes('SQLI') || type.includes('XSS');
  }

  /**
   * Enhance finding with full rule-based contextual recommendation.
   */
  enhanceFindingWithContext(finding, sourceCode = '') {
    try {
      const contextAwareFix = this.ruleRecommendationEngine.recommend(finding, sourceCode);

      if (!contextAwareFix) {
        return finding;
      }

      return {
        ...finding,
        contextAwareFix,
        adaptiveFix: contextAwareFix,
        remediationMode: 'rule-based-contextual',
      };
    } catch (error) {
      return finding;
    }
  }

  /**
   * Find matching pattern information for a finding
   * ENHANCED: Correlates detection with dynamic pattern analysis results
   */
  findMatchingPattern(finding, patternAnalysis) {
    if (!patternAnalysis || patternAnalysis.patterns.length === 0) {
      return null;
    }

    // Find pattern that matches this finding's line
    const matchingPattern = patternAnalysis.patterns.find(p => 
      p.line === finding.line || 
      (p.startLine <= finding.line && finding.line <= p.endLine)
    );

    return matchingPattern || null;
  }

  /**
   * Detect vulnerabilities using regex patterns
   * ENHANCED: Language-aware detection
   */
  detectWithRegex(content, language = 'javascript') {
    const findings = [];
    const lines = content.split('\n');

    lines.forEach((line, index) => {
      const matches = this.regexEngine.scan(line, language);
      matches.forEach(match => {
        findings.push({
          engine: 'regex',
          type: match.type,
          name: match.name,
          severity: match.severity,
          confidence: match.confidence,
          description: match.description,
          line: index + 1,
          code: line,
          language: language
        });
      });
    });

    return findings;
  }

  /**
   * Detect XSS using dedicated XSS engines
   * Runs all 4 XSS type detectors and consolidates results
   */
  detectWithXSSEngines(content, filePath) {
    const allXSSFindings = [];

    try {
      // Run all 4 XSS engines
      const reflected = this.reflectedXSSDetector.detect(content, filePath);
      const stored = this.storedXSSDetector.detect(content, filePath);
      const domBased = this.domBasedXSSDetector.detect(content, filePath);
      const event = this.eventXSSDetector.detect(content, filePath);

      allXSSFindings.push(...reflected, ...stored, ...domBased, ...event);

      // Consolidate XSS findings (remove duplicates across engines)
      const consolidated = XSSConsolidator.consolidate(allXSSFindings);

      this.logger.debug(`XSS engines: ${reflected.length} reflected, ${stored.length} stored, ${domBased.length} DOM, ${event.length} event → ${consolidated.length} unique`);

      return consolidated;
    } catch (error) {
      this.logger.debug(`XSS engine detection error: ${error.message}`);
      return allXSSFindings;
    }
  }

  /**
   * Detect vulnerabilities using taint analysis
   * ENHANCED: Use vulnerability type from taint analyzer
   */
  detectWithTaint(content) {
    const taintFindings = this.taintAnalyzer.analyze(content);

    return taintFindings.map(finding => {
      const vulnType = finding.vulnerabilityType || 'UNKNOWN';
      const baseType = vulnType === 'SQLI' ? 'SQLI_GENERIC' : 
                      vulnType === 'XSS' ? 'XSS_GENERIC' : 'GENERIC';
      const baseName = vulnType === 'SQLI' ? 'Generic SQL Injection' :
                      vulnType === 'XSS' ? 'Generic XSS' : 'Generic Vulnerability';

      return {
        engine: 'taint',
        type: baseType,
        name: baseName,
        severity: 'HIGH',
        confidence: 0.85,
        line: finding.line,
        code: finding.code,
        flow: finding.flow,
        // Pass through enhanced context from taint analyzer
        apiContext: finding.apiContext,
        vulnerabilityType: finding.vulnerabilityType,
        sinkFunction: finding.sinkFunction,
        sourceVar: finding.sourceVar,
        connectionVar: finding.connectionVar,
        astNode: finding.astNode,
        sanitized: finding.sanitized,
      };
    });
  }

  /**
   * Enrich JavaScript taint findings with data from ASTEngine's parsed call graph.
   * ASTEngine has already walked the AST and stored variables/callExpressions.
   * This method adds ast_confirmed flag and connection variable when ASTEngine
   * independently agrees a sink function was called at the same line.
   */
  _enrichTaintWithAST(taintFindings) {
    return taintFindings.map(finding => {
      // Look up the sink call in ASTEngine's call expression list
      const matchingCall = this.astEngine.callExpressions.find(call =>
        call.line === finding.line &&
        call.callee &&
        finding.sinkFunction &&
        call.callee.includes(finding.sinkFunction)
      );

      if (matchingCall) {
        // ASTEngine independently confirmed this call exists at this line
        const connectionVar = this.astEngine.extractDBConnection(matchingCall) || finding.connectionVar;
        return {
          ...finding,
          engine: 'taint+ast',
          confidence: Math.min(0.98, (finding.confidence || 0.85) + 0.07),
          ast_confirmed: true,
          connectionVar,
          reason: 'Confirmed by taint analysis + AST call graph',
        };
      }

      return finding;
    });
  }

  /**
   * Score a single finding
   * ENHANCED: Incorporates adaptive fix confidence and context-based risk reduction
   */
  scoreFinding(finding) {
    // Use finding's confidence if already set, otherwise calculate from engine
    let baseConfidence = finding.confidence !== undefined 
      ? finding.confidence 
      : this.scorer.calculateConfidence(finding.engine || 'regex');
    
    // ENHANCED: Boost confidence if adaptive fix is available
    if (finding.adaptiveFix && finding.adaptiveFix.confidence) {
      baseConfidence = Math.max(baseConfidence, finding.adaptiveFix.confidence);
    }

    const riskScore = this.scorer.calculateRiskScore(finding.severity, baseConfidence);
    const exploitability = this.scorer.calculateExploitability(finding.severity, baseConfidence);

    // ENHANCED: Include remediation metadata
    const riskReduction = finding.adaptiveFix?.riskReduction || 0;

    return {
      ...finding,
      riskScore,
      confidence: baseConfidence,
      exploitability,
      effectiveRisk: Math.max(0, riskScore - riskReduction),
      // Preserve file path if already set (e.g., for DVWA source files scanned from wrapper)
      file: finding.file || finding.file, // Keep existing file path
    };
  }

  /**
   * Add CWE (Common Weakness Enumeration) mapping to findings
   * Maps vulnerability types to international weakness IDs
   */
  addCWEMapping(finding) {
    const cweMap = {
      // SQL Injection
      'SQLI_TAINTED_QUERY': { cwe: 'CWE-89', name: 'SQL Injection' },
      'SQLI_VAR_INTERPOLATION': { cwe: 'CWE-89', name: 'SQL Injection' },
      'SQLI_MYSQLI_QUERY': { cwe: 'CWE-89', name: 'SQL Injection' },
      'SQLI_MYSQL_QUERY': { cwe: 'CWE-89', name: 'SQL Injection' },
      'SQLI_RAW_QUERY': { cwe: 'CWE-89', name: 'SQL Injection' },
      
      // Cross-Site Scripting (XSS)
      'XSS_TAINTED_OUTPUT': { cwe: 'CWE-79', name: 'Cross-site Scripting' },
      'XSS_DOM_MANIPULATION': { cwe: 'CWE-79', name: 'Cross-site Scripting' },
      'XSS_DOM_ASSIGNMENT': { cwe: 'CWE-79', name: 'Cross-site Scripting' },
      'XSS_INNERHTML': { cwe: 'CWE-79', name: 'Cross-site Scripting' },
      'XSS_SCRIPT_INJECTION': { cwe: 'CWE-79', name: 'Cross-site Scripting' },
      'XSS_REFLECTED': { cwe: 'CWE-79', name: 'Cross-site Scripting (Reflected)' },
      'XSS_STORED': { cwe: 'CWE-79', name: 'Cross-site Scripting (Stored)' },
      'XSS_STORED_INPUT': { cwe: 'CWE-79', name: 'Cross-site Scripting (Stored - Input)' },
      'XSS_STORED_OUTPUT': { cwe: 'CWE-79', name: 'Cross-site Scripting (Stored - Output)' },
      'XSS_DOM_BASED': { cwe: 'CWE-79', name: 'Cross-site Scripting (DOM-Based)' },
      'XSS_EVENT_HANDLER': { cwe: 'CWE-79', name: 'Cross-site Scripting (Event Handler)' },
      
      // Code Injection
      'CODE_INJECTION_TAINTED': { cwe: 'CWE-94', name: 'Code Injection' },
      'CODE_INJECTION_EVAL': { cwe: 'CWE-95', name: 'Eval Injection' },
      
      // Command Injection
      'COMMAND_INJECTION': { cwe: 'CWE-78', name: 'OS Command Injection' },
      
      // Path Traversal
      'PATH_TRAVERSAL': { cwe: 'CWE-22', name: 'Path Traversal' },
      
      // Insecure Deserialization
      'INSECURE_DESERIALIZATION': { cwe: 'CWE-502', name: 'Deserialization of Untrusted Data' },
      
      // Authentication & Session
      'WEAK_AUTH': { cwe: 'CWE-287', name: 'Improper Authentication' },
      'SESSION_FIXATION': { cwe: 'CWE-384', name: 'Session Fixation' },
      
      // Cryptography
      'WEAK_CRYPTO': { cwe: 'CWE-327', name: 'Use of Broken Cryptographic Algorithm' },
      'HARDCODED_SECRET': { cwe: 'CWE-798', name: 'Hardcoded Credentials' },
      
      // Default fallback
      'UNKNOWN': { cwe: 'CWE-1035', name: 'Unclassified Vulnerability' }
    };

    const mapping = cweMap[finding.type] || cweMap['UNKNOWN'];
    
    return {
      ...finding,
      cwe: mapping.cwe,
      cweName: mapping.name,
      cweUrl: `https://cwe.mitre.org/data/definitions/${mapping.cwe.split('-')[1]}.html`
    };
  }

  /**
   * Resolve a PHP include path to an absolute filesystem path
   * Handles relative paths, constants, and common patterns from DVWA
   * @param {string} includePath - The path as written in the include statement
   * @param {string} baseDir - Directory of the file doing the including
   * @param {string} originalFilePath - Original file path for context
   * @returns {string|null} Resolved absolute path, or null if can't resolve
   */
  resolveIncludePath(includePath, baseDir, originalFilePath) {
    // Simple relative path
    const resolvedPath = path.join(baseDir, includePath);
    if (fs.existsSync(resolvedPath)) {
      return path.normalize(resolvedPath);
    }

    // Try up 2 directories (common for DVWA structure)
    const upPath = path.join(baseDir, '..', '..', includePath);
    if (fs.existsSync(upPath)) {
      return path.normalize(upPath);
    }

    // Absolute path
    if (fs.existsSync(includePath)) {
      return path.normalize(includePath);
    }

    return null;
  }
}

module.exports = Scanner;
