/**
 * PHASE 3: Dynamic Template Engine
 * Purpose: Render fix recommendations using templates with placeholder replacement
 * Provides context-aware, deterministic remediation suggestions
 */

const templates = require('./templates.json');

class TemplateEngine {
  constructor() {
    this.templates = templates;
  }

  /**
   * Render fix recommendation based on context
   * @param {Object} analyzedFinding - Finding with context from ContextAnalyzer
   * @returns {Object} Rendered fix recommendation
   */
  render(analyzedFinding) {
    const { fixStrategy, context, vulnerabilityType } = analyzedFinding;

    // Get appropriate template
    const template = this.getTemplate(vulnerabilityType, fixStrategy);

    if (!template) {
      return this.getGenericFix(vulnerabilityType);
    }

    // Prepare placeholder values from context
    const placeholderValues = this.preparePlaceholders(context, analyzedFinding);

    // Render template
    const renderedCode = this.replacePlaceholders(template.template, placeholderValues);
    const renderedExample = this.replacePlaceholders(template.example, placeholderValues);

    return {
      name: template.name,
      description: template.description,
      code: renderedCode,
      example: renderedExample,
      placeholders: placeholderValues,
      confidence: analyzedFinding.fixConfidence || 0.7,
    };
  }

  /**
   * Get template from JSON based on vulnerability type and fix strategy
   */
  getTemplate(vulnerabilityType, fixStrategy) {
    const vulnKey = vulnerabilityType.toLowerCase();
    
    if (this.templates[vulnKey] && this.templates[vulnKey][fixStrategy]) {
      return this.templates[vulnKey][fixStrategy];
    }

    return null;
  }

  /**
   * Prepare placeholder values from context
   */
  preparePlaceholders(context, finding) {
    const placeholders = {
      var: context.variableName || 'userInput',
      conn: context.connectionName || 'conn',
      table: context.tableName || 'users',
      column: 'id', // Default, could be enhanced
      type: this.mapInputTypeToParamType(context.inputType),
      pdoType: this.mapInputTypeToPDO(context.inputType),
      param: this.extractParamName(context.variableName),
      element: 'element',
      Var: this.capitalize(context.variableName || 'userInput'),
    };

    return placeholders;
  }

  /**
   * Replace all placeholders in template string
   * Supports {{placeholder}} syntax
   */
  replacePlaceholders(templateString, values) {
    if (!templateString) return '';

    let result = templateString;

    // Replace all {{placeholder}} with actual values
    for (const [key, value] of Object.entries(values)) {
      const regex = new RegExp(`{{${key}}}`, 'g');
      result = result.replace(regex, value);
    }

    return result;
  }

  /**
   * Map input type to mysqli bind_param type
   */
  mapInputTypeToParamType(inputType) {
    const typeMap = {
      integer: 'i',
      string: 's',
      email: 's',
      double: 'd',
      float: 'd',
    };

    return typeMap[inputType] || 's';
  }

  /**
   * Map input type to PDO parameter type
   */
  mapInputTypeToPDO(inputType) {
    const typeMap = {
      integer: 'INT',
      string: 'STR',
      email: 'STR',
      boolean: 'BOOL',
    };

    return typeMap[inputType] || 'STR';
  }

  /**
   * Extract parameter name from variable name
   * Example: $userId -> id, userEmail -> email
   */
  extractParamName(varName) {
    if (!varName) return 'value';

    // Remove $ prefix if PHP
    let cleaned = varName.replace(/^\$/, '');

    // Convert camelCase/PascalCase to lowercase
    // userId -> id, userEmail -> email
    const match = cleaned.match(/[A-Z][a-z]+$/);
    if (match) {
      return match[0].toLowerCase();
    }

    return cleaned.toLowerCase();
  }

  /**
   * Capitalize first letter
   */
  capitalize(str) {
    if (!str) return '';
    return str.charAt(0).toUpperCase() + str.slice(1);
  }

  /**
   * Get generic fix for unknown patterns
   */
  getGenericFix(vulnerabilityType) {
    const genericFixes = {
      SQLI: {
        name: 'Generic SQL Injection Prevention',
        description: 'Gunakan prepared statements atau parameterized queries.',
        code: '// Gunakan prepared statement sesuai database API Anda\n$stmt = $conn->prepare("SELECT * FROM table WHERE column = ?");\n$stmt->execute([$userInput]);',
        example: 'Lihat dokumentasi database API Anda untuk implementasi prepared statement.',
        confidence: 0.5,
      },
      XSS: {
        name: 'Generic XSS Prevention',
        description: 'Encode/escape semua user input sebelum output.',
        code: '// PHP: htmlspecialchars\necho htmlspecialchars($userInput, ENT_QUOTES, \'UTF-8\');\n\n// JavaScript: textContent\nelement.textContent = userInput;',
        example: 'Gunakan encoding function sesuai bahasa pemrograman Anda.',
        confidence: 0.5,
      },
    };

    return genericFixes[vulnerabilityType] || {
      name: 'Security Best Practice',
      description: 'Validasi dan sanitasi semua user input.',
      code: '// Validasi input\n// Gunakan whitelist validation\n// Escape output',
      example: 'Terapkan defense-in-depth security.',
      confidence: 0.3,
    };
  }

  /**
   * Render multiple findings
   */
  renderBatch(analyzedFindings) {
    return analyzedFindings.map(finding => this.render(finding));
  }
}

module.exports = TemplateEngine;
