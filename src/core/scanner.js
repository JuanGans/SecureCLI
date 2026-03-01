/**
 * Core Scanner - Orchestrates all detection engines
 * ENHANCED: Integrated with Dynamic Adaptive Remediation System
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

// ENHANCED: Dynamic modules for adaptive remediation
const DynamicPatternAnalyzer = require('../engines/patterns/dynamicPatternAnalyzer');
const ContextExtractor = require('./contextExtractor');
const AdaptiveFixGenerator = require('../remediation/adaptiveFixGenerator');

class Scanner {
  constructor(options = {}) {
    this.options = options;
    this.regexEngine = new RegexEngine();
    this.taintAnalyzer = new TaintAnalyzer();
    this.astEngine = new ASTEngine();
    this.contextAnalyzer = new ContextAnalyzer(this.astEngine);
    this.templateEngine = new TemplateEngine();
    this.scorer = new RiskScorer();
    this.logger = new Logger(options.verbose);
    
    // ENHANCED: Initialize dynamic modules
    this.patternAnalyzer = new DynamicPatternAnalyzer();
    this.contextExtractor = new ContextExtractor();
    this.fixGenerator = new AdaptiveFixGenerator();
  }

  /**
   * Scan a single file
   * Using original static template system for stability
   */
  scanFile(filePath) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const findings = [];

      // Parse AST first (for context analysis)
      this.astEngine.reset();
      this.astEngine.parse(content);

      // LAYER 1: DETECTION
      const regexFindings = this.detectWithRegex(content);
      const taintFindings = this.detectWithTaint(content);

      findings.push(...regexFindings);
      findings.push(...taintFindings);

      // LAYER 2: CONTEXT ANALYSIS & REMEDIATION (using original stable system)
      const enhancedFindings = findings.map(finding => {
        // Apply context analysis to taint findings
        if (finding.engine === 'taint' && finding.apiContext) {
          return this.enhanceFindingWithContext(finding);
        }
        return finding;
      });

      // LAYER 3: SCORING
      const scoredFindings = enhancedFindings.map(finding => this.scoreFinding(finding));

      return scoredFindings;
    } catch (error) {
      this.logger.error(`Failed to scan ${filePath}: ${error.message}`);
      return [];
    }
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
   */
  detectWithRegex(content) {
    const findings = [];
    const lines = content.split('\n');

    lines.forEach((line, index) => {
      const matches = this.regexEngine.scan(line);
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
    let baseConfidence = this.scorer.calculateConfidence(finding.engine);
    
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
}

module.exports = Scanner;
