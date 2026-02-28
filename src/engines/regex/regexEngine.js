/**
 * LAYER 1: DETECTION - Regex Engine
 */

const { SQL_PATTERNS } = require('./sqlPatterns');
const { XSS_PATTERNS } = require('./xssPatterns');

class RegexEngine {
  constructor() {
    this.patterns = {
      sql: SQL_PATTERNS,
      xss: XSS_PATTERNS,
    };
  }

  /**
   * Scan code line against all patterns
   */
  scan(code, type = 'all') {
    const findings = [];

    if (type === 'sql' || type === 'all') {
      findings.push(...this.scanPatterns(code, this.patterns.sql));
    }

    if (type === 'xss' || type === 'all') {
      findings.push(...this.scanPatterns(code, this.patterns.xss));
    }

    return findings;
  }

  /**
   * Internal: scan code against pattern set
   */
  scanPatterns(code, patterns) {
    const findings = [];

    patterns.forEach(pattern => {
      if (pattern.regex.test(code)) {
        findings.push({
          engine: 'regex',
          type: pattern.type,
          name: pattern.name,
          severity: pattern.severity,
          confidence: pattern.confidence,
          description: pattern.description,
          matchedPattern: pattern.regex.toString(),
        });
      }
    });

    return findings;
  }

  /**
   * Get pattern by type
   */
  getPattern(type) {
    const allPatterns = [...this.patterns.sql, ...this.patterns.xss];
    return allPatterns.find(p => p.type === type);
  }

  /**
   * Add custom pattern
   */
  addPattern(category, pattern) {
    if (category === 'sql' || category === 'sqli') {
      this.patterns.sql.push(pattern);
    } else if (category === 'xss') {
      this.patterns.xss.push(pattern);
    }
  }
}

module.exports = RegexEngine;
