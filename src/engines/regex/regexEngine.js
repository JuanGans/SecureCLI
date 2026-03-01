/**
 * LAYER 1: DETECTION - Regex Engine
 * ENHANCED: Multi-language support
 */

const { SQL_PATTERNS } = require('./sqlPatterns');
const { XSS_PATTERNS } = require('./xssPatterns');
const { PHP_SQL_PATTERNS, PHP_XSS_PATTERNS } = require('./phpPatterns');

class RegexEngine {
  constructor() {
    this.patterns = {
      javascript: {
        sql: SQL_PATTERNS,
        xss: XSS_PATTERNS,
      },
      php: {
        sql: PHP_SQL_PATTERNS,
        xss: PHP_XSS_PATTERNS,
      }
    };
  }

  /**
   * Scan code line against all patterns
   * ENHANCED: Language-aware detection
   */
  scan(code, language = 'javascript') {
    const findings = [];

    // Use language-specific patterns, fallback to JavaScript patterns
    const langPatterns = this.patterns[language] || this.patterns.javascript;

    // Scan both SQL and XSS patterns
    findings.push(...this.scanPatterns(code, langPatterns.sql, language));
    findings.push(...this.scanPatterns(code, langPatterns.xss, language));

    return findings;
  }

  /**
   * Internal: scan code against pattern set
   * ENHANCED: Context-aware matching
   */
  scanPatterns(code, patterns, language = 'javascript') {
    const findings = [];

    patterns.forEach(pattern => {
      // Language-specific filtering
      if (language === 'php') {
        // For PHP, be more selective to reduce false positives
        // Skip patterns that match hardcoded HTML structures
        if (pattern.type === 'XSS_HTML_TAGS' && /<input[^>]+type=["'](text|submit|button)["']/.test(code)) {
          return; // Skip normal form inputs
        }
      }
      
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
   * Get pattern by type (searches all languages)
   */
  getPattern(type) {
    for (const lang in this.patterns) {
      const allPatterns = [...this.patterns[lang].sql, ...this.patterns[lang].xss];
      const found = allPatterns.find(p => p.type === type);
      if (found) return found;
    }
    return null;
  }

  /**
   * Add custom pattern
   */
  addPattern(category, pattern, language = 'javascript') {
    if (!this.patterns[language]) {
      this.patterns[language] = { sql: [], xss: [] };
    }
    
    if (category === 'sql' || category === 'sqli') {
      this.patterns[language].sql.push(pattern);
    } else if (category === 'xss') {
      this.patterns[language].xss.push(pattern);
    }
  }
}

module.exports = RegexEngine;
