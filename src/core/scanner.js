/**
 * Core Scanner - Orchestrates all detection engines
 */

const fs = require('fs');
const path = require('path');
const RegexEngine = require('../engines/regex/regexEngine');
const TaintAnalyzer = require('../engines/taint/taintAnalyzer');
const RiskScorer = require('../scoring/riskScorer');
const Logger = require('../utils/logger');

class Scanner {
  constructor(options = {}) {
    this.options = options;
    this.regexEngine = new RegexEngine();
    this.taintAnalyzer = new TaintAnalyzer();
    this.scorer = new RiskScorer();
    this.logger = new Logger(options.verbose);
  }

  /**
   * Scan a single file
   */
  scanFile(filePath) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const findings = [];

      // LAYER 1: DETECTION
      const regexFindings = this.detectWithRegex(content);
      const taintFindings = this.detectWithTaint(content);

      findings.push(...regexFindings);
      findings.push(...taintFindings);

      // LAYER 3: SCORING
      const scoredFindings = findings.map(finding => this.scoresFinding(finding));

      return scoredFindings;
    } catch (error) {
      this.logger.error(`Failed to scan ${filePath}: ${error.message}`);
      return [];
    }
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
   */
  detectWithTaint(content) {
    const taintFindings = this.taintAnalyzer.analyze(content);

    return taintFindings.map(finding => ({
      engine: 'taint',
      type: finding.sink.includes('query') ? 'SQLI_GENERIC' : 'XSS_GENERIC',
      name: finding.sink.includes('query') ? 'Generic SQL Injection' : 'Generic XSS',
      severity: 'HIGH',
      confidence: 0.85,
      line: finding.line,
      code: finding.code,
      flow: finding.flow,
    }));
  }

  /**
   * Score a single finding
   */
  scoresFinding(finding) {
    const riskScore = this.scorer.calculateRiskScore(finding.severity, finding.confidence);
    const confidence = this.scorer.calculateConfidence(finding.engine);
    const exploitability = this.scorer.calculateExploitability(finding.severity, confidence);

    return {
      ...finding,
      riskScore,
      confidence,
      exploitability,
      file: undefined, // Will be set by scanner orchestrator
    };
  }
}

module.exports = Scanner;
