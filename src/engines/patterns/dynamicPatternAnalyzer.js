/**
 * ENHANCED: Dynamic Pattern Analyzer
 * Purpose: Recognize various real-life bug patterns and variations
 * Supports multiple coding styles and contexts
 */

class DynamicPatternAnalyzer {
  constructor() {
    this.patterns = {
      sqli: [
        // Pattern 1: String concatenation
        {
          name: 'string_concatenation',
          regex: /["'`].*\+\s*\w+\s*\+.*["'`]/,
          description: 'String concatenation in SQL query',
          examples: [
            '"SELECT * FROM users WHERE id = " + userId',
            '`SELECT * FROM ${tableName} WHERE...`',
            '"INSERT INTO users VALUES'
          ]
        },
        // Pattern 2: Template literals
        {
          name: 'template_literal',
          regex: /`.*\$\{.*\}.*`/,
          description: 'Template literal with interpolation in SQL',
          examples: [
            '`SELECT * FROM users WHERE id = ${id}`',
            '`INSERT INTO ${table}...`'
          ]
        },
        // Pattern 3: Direct query concatenation in function call
        {
          name: 'direct_query_concat',
          regex: /\.(query|execute|prepare)\s*\(\s*["'`].*\+/,
          description: 'Direct concatenation in prepared function',
          examples: [
            'db.query("SELECT * FROM users WHERE id=" + id)',
            'conn.execute("INSERT..." + values)'
          ]
        },
        // Pattern 4: Variable in query with operators
        {
          name: 'variable_with_operators',
          regex: /WHERE\s+\w+\s*(=|>|<|!=|>=|<=)\s*["']?\$?\w+["']?/i,
          description: 'Variable used directly in WHERE clause',
          examples: [
            'WHERE id = (concatenated variable)',
            'WHERE status = "(concatenated variable)"'
          ]
        },
        // Pattern 5: Array/Object field access in query
        {
          name: 'object_field_access',
          regex: /query.*\[.*\]|query.*\..*\s*\+|\.query.*req\./,
          description: 'Object field directly in query',
          examples: [
            'db.query("... WHERE id = " + req.query.id)',
            'connection.execute("... WHERE user = " + params[key])'
          ]
        }
      ],
      xss: [
        // Pattern 1: innerHTML assignment
        {
          name: 'innerHTML_assignment',
          regex: /\.innerHTML\s*=\s*[\w$"'`]+/,
          description: 'Direct innerHTML assignment with user input',
          examples: [
            'element.innerHTML = userInput',
            'document.getElementById("content").innerHTML = data'
          ]
        },
        // Pattern 2: document.write
        {
          name: 'document_write',
          regex: /document\.write\s*\(.*[\w$"`]+\s*\)/,
          description: 'document.write with user-controlled content',
          examples: [
            'document.write(userName)',
            'document.write("<h1>" + title + "</h1>")'
          ]
        },
        // Pattern 3: eval-like functions
        {
          name: 'eval_functions',
          regex: /(eval|setTimeout|setInterval)\s*\(\s*[\w$"'`]+/,
          description: 'Dynamic code execution functions',
          examples: [
            'eval(userCode)',
            'setTimeout(timerFunc, delay)'
          ]
        },
        // Pattern 4: Template literal in HTML context
        {
          name: 'template_html_context',
          regex: /`\s*<.*\$\{.*\}.*>/,
          description: 'Template literal with HTML and user data',
          examples: [
            '`<div>${userName}</div>`',
            '`<img src=${imageUrl}>`'
          ]
        },
        // Pattern 5: Attribute injection
        {
          name: 'attribute_injection',
          regex: /\s+\w+\s*=\s*["']\s*\$\{|["']\+\w+\+["']/,
          description: 'User input in HTML attributes',
          examples: [
            '<input value="${userInput}">',
            '<div class="(concatenated variable)"></div>'
          ]
        }
      ]
    };
  }

  /**
   * Analyze code for all pattern variations
   */
  analyzePatterns(code, vulnerabilityType = 'all') {
    const findings = [];

    const types = vulnerabilityType === 'all' 
      ? Object.keys(this.patterns)
      : [vulnerabilityType];

    types.forEach(type => {
      const patterns = this.patterns[type];
      const lines = code.split('\n');

      lines.forEach((line, lineIndex) => {
        patterns.forEach(pattern => {
          if (pattern.regex.test(line)) {
            findings.push({
              type: type.toUpperCase(),
              pattern: pattern.name,
              patternDescription: pattern.description,
              line: lineIndex + 1,
              code: line.trim(),
              variations: this.identifyVariation(line, pattern),
              severity: this.calculateSeverity(type, pattern.name)
            });
          }
        });
      });
    });

    return findings;
  }

  /**
   * Identify specific variation of the pattern
   */
  identifyVariation(code, pattern) {
    const variations = {
      sqli: {
        string_concatenation: this.detectConcatenationStyle(code),
        template_literal: this.detectTemplateStyle(code),
        variable_with_operators: this.extractOperator(code),
      },
      xss: {
        innerHTML_assignment: this.detectInnerHTMLVariation(code),
        template_html_context: this.detectHTMLTemplateVariation(code),
        attribute_injection: this.detectAttributeType(code),
      }
    };

    return variations[pattern.name] || {};
  }

  /**
   * Detect concatenation style
   */
  detectConcatenationStyle(code) {
    if (code.includes('+')) {
      return {
        style: 'plus_operator',
        example: code
      };
    }
    if (code.includes('${')) {
      return {
        style: 'template_literal',
        example: code
      };
    }
    if (code.includes('concat(')) {
      return {
        style: 'concat_function',
        example: code
      };
    }
    return { style: 'unknown' };
  }

  /**
   * Detect template literal style
   */
  detectTemplateStyle(code) {
    const backtickMatch = code.match(/`([^`]*\$\{[^}]*\}[^`]*)`/);
    if (backtickMatch) {
      return {
        style: 'backtick_template',
        template: backtickMatch[0],
        hasHTML: backtickMatch[1].includes('<')
      };
    }
    return { style: 'unknown' };
  }

  /**
   * Extract operator from WHERE clause
   */
  extractOperator(code) {
    const operatorMatch = code.match(/WHERE\s+(\w+)\s+(=|>|<|!=|>=|<=|LIKE|IN|BETWEEN)\s+(.+)/i);
    if (operatorMatch) {
      return {
        column: operatorMatch[1],
        operator: operatorMatch[2],
        value: operatorMatch[3].trim()
      };
    }
    return null;
  }

  /**
   * Calculate severity based on vulnerability type and pattern
   */
  calculateSeverity(type, pattern) {
    const severityMap = {
      sqli: {
        string_concatenation: 'CRITICAL',
        template_literal: 'CRITICAL',
        direct_query_concat: 'CRITICAL',
        variable_with_operators: 'HIGH',
        object_field_access: 'HIGH'
      },
      xss: {
        innerHTML_assignment: 'HIGH',
        document_write: 'HIGH',
        eval_functions: 'CRITICAL',
        template_html_context: 'HIGH',
        attribute_injection: 'MEDIUM'
      }
    };

    return severityMap[type]?.[pattern] || 'MEDIUM';
  }

  /**
   * Detect innerHTML variation
   */
  detectInnerHTMLVariation(code) {
    const elementMatch = code.match(/document\.getElementById\(['"]([^'"]+)['"]\)|(\w+)\./);
    return {
      element: elementMatch?.[1] || elementMatch?.[2] || 'unknown',
      source: this.extractDataSource(code)
    };
  }

  /**
   * Detect HTML template variation
   */
  detectHTMLTemplateVariation(code) {
    const tags = code.match(/<\w+/g) || [];
    return {
      tags: tags.slice(0, 3),
      hasInterpolation: code.includes('${')
    };
  }

  /**
   * Detect attribute type (class, id, src, data-*, etc)
   */
  detectAttributeType(code) {
    const attrMatch = code.match(/(\w+-*\w+)\s*=/);
    return {
      attribute: attrMatch?.[1] || 'unknown',
      riskLevel: this.getAttributeRiskLevel(attrMatch?.[1])
    };
  }

  /**
   * Get risk level for specific HTML attribute
   */
  getAttributeRiskLevel(attribute) {
    const highRisk = ['src', 'href', 'onclick', 'onload', 'onerror', 'action'];
    const mediumRisk = ['class', 'style', 'data'];
    const lowRisk = ['title', 'alt', 'placeholder'];

    if (highRisk.includes(attribute)) return 'HIGH';
    if (mediumRisk.includes(attribute)) return 'MEDIUM';
    if (lowRisk.includes(attribute)) return 'LOW';
    return 'MEDIUM';
  }

  /**
   * Extract data source from code
   */
  extractDataSource(code) {
    if (code.includes('req.')) {
      const paramMatch = code.match(/req\.(query|body|params|headers|cookies)\.(\w+)/);
      return paramMatch ? `req.${paramMatch[1]}.${paramMatch[2]}` : 'req.*';
    }
    if (code.includes('location.')) {
      return 'location.' + (code.match(/location\.(\w+)/)?.[1] || '*');
    }
    if (code.includes('document.')) {
      return 'document.' + (code.match(/document\.(\w+)/)?.[1] || '*');
    }
    const varMatch = code.match(/=\s*(\w+)/);
    return varMatch?.[1] || 'unknown_source';
  }
}

module.exports = DynamicPatternAnalyzer;
