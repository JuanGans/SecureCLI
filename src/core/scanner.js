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
const TemplateEngine = require('../remediation/templateEngine');
const RiskScorer = require('../scoring/riskScorer');
const Logger = require('../utils/logger');
const { detectLanguage, isInDocumentation, isHardcoded } = require('../utils/helpers');
const CommentStripper = require('../utils/commentStripper');

// ENHANCED: Dynamic modules for adaptive remediation
const DynamicPatternAnalyzer = require('../engines/patterns/dynamicPatternAnalyzer');
const ContextExtractor = require('./contextExtractor');
const AdaptiveFixGenerator = require('../remediation/adaptiveFixGenerator');

// NEW: Multi-engine detection for improved accuracy
const MultiEngineDetector = require('../engines/multiEngineDetector');
const PHPTaintAnalyzer = require('../engines/taint/phpTaintAnalyzer');
const PHPTokenizer = require('../engines/ast/phpTokenizer');

class Scanner {
  constructor(options = {}) {
    this.options = options;
    this.regexEngine = new RegexEngine();
    this.taintAnalyzer = new TaintAnalyzer();
    this.phpTaintAnalyzer = new PHPTaintAnalyzer();  // NEW: PHP-specific taint analyzer
    this.phpTokenizer = new PHPTokenizer();
    this.astEngine = new ASTEngine();
    this.contextAnalyzer = new ContextAnalyzer(this.astEngine);
    this.templateEngine = new TemplateEngine();
    this.scorer = new RiskScorer();
    this.logger = new Logger(options.verbose);
    this.multiEngineDetector = new MultiEngineDetector();  // NEW: Multi-engine coordinator
    
    // ENHANCED: Initialize dynamic modules
    this.patternAnalyzer = new DynamicPatternAnalyzer();
    this.contextExtractor = new ContextExtractor();
    this.fixGenerator = new AdaptiveFixGenerator();
  }

  /**
   * Scan a single file
   * ENHANCED: Multi-engine support for PHP with taint analysis
   * - PHP: Regex + Static Taint Analysis + Multi-engine voting
   * - JavaScript/TypeScript: AST + Taint Analysis
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
        // NEW: PHP files use multi-engine detection (Regex + Taint Analysis)
        this.logger.info(`PHP file detected: ${filePath} (using multi-engine detection)`);
        return this.detectPHPWithMultiEngine(filePath, content);
      }

      // LAYER 1: DETECTION
      const regexFindings = this.detectWithRegex(content, language);
      
      // Taint analysis only for JavaScript
      let taintFindings = [];
      if (language === 'javascript' || language === 'typescript') {
        taintFindings = this.detectWithTaint(content);
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
        // Apply context analysis to taint findings
        if (finding.engine === 'taint' && finding.apiContext) {
          return this.enhanceFindingWithContext(finding);
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

      // Step 3: Consolidate findings using multi-engine logic
      this.logger.debug(`Consolidating findings from ${taintFindings.length} taint and ${regexFindings.length} regex detections`);
      const consolidatedFindings = this.consolidateDetections(
        filePath, 
        cleanedContent, 
        taintFindings, 
        regexFindings,
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

    this.logger.info(`Consolidated: ${consolidated.length} findings (${consolidated.filter(f => f.isProvenVulnerability).length} proven, ${consolidated.filter(f => !f.isProvenVulnerability).length} unconfirmed)`);

    return consolidated;
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

    // Nearby lines and related types
    if (Math.abs((regexFinding.line || 0) - (taintFinding.line || 0)) <= 3) {
      if ((regexFinding.type === 'XSS_CONCAT' && taintFinding.type === 'XSS_TAINTED_OUTPUT') ||
          (regexFinding.type === 'SQLI_VAR_INTERPOLATION' && taintFinding.type === 'SQLI_TAINTED_QUERY')) {
        return true;
      }
    }

    return false;
  }

  /**
   * Identify likely false positives to filter out
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
   * Enhance finding with context analysis and remediation template
   * PHASE 2 & 3 Integration (Legacy method for backward compatibility)
   */
  enhanceFindingWithContext(finding) {
    try {
      // Analyze context to determine fix strategy
      const analyzedFinding = this.contextAnalyzer.analyze(finding);

      // Generate context-aware fix using template engine
      const contextAwareFix = this.templateEngine.render(analyzedFinding);

      return {
        ...analyzedFinding,
        contextAwareFix: contextAwareFix,
      };
    } catch (error) {
      // If context analysis fails, return original finding
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
      file: undefined, // Will be set by scanner orchestrator
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
      'XSS_REFLECTED': { cwe: 'CWE-79', name: 'Cross-site Scripting' },
      'XSS_STORED': { cwe: 'CWE-79', name: 'Cross-site Scripting' },
      
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
}

module.exports = Scanner;
