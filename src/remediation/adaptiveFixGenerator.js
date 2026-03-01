/**
 * ENHANCED: Adaptive Fix Generator
 * Purpose: Generate context-aware fixes based on actual code structure
 * Adapts to real-life variations in code patterns
 */

class AdaptiveFixGenerator {
  constructor() {
    this.fixStrategies = {
      sqli: {
        mysql_procedural: this.generateMysqlFix,
        mysql_oo: this.generatePreparedFix,
        pdo: this.generatePDOFix,
        generic_orm: this.generateORMFix,
        node_generic: this.generateNodeFix
      },
      xss: {
        innerHTML: this.generateInnerHTMLFix,
        dom_write: this.generateDOMWriteFix,
        template_literal: this.generateTemplateFix,
        attribute: this.generateAttributeFix,
        server_response: this.generateServerFix
      }
    };
  }

  /**
   * Generate adaptive fix based on full context
   */
  generateFix(vulnerabilityType, extractedContext, originalCode) {
    const strategy = this.selectStrategy(vulnerabilityType, extractedContext);
    
    if (!strategy) {
      return this.generateGenericFix(vulnerabilityType, extractedContext);
    }

    const fix = strategy.call(this, extractedContext, originalCode);

    return {
      ...fix,
      context: extractedContext,
      riskReduction: this.calculateRiskReduction(fix, extractedContext)
    };
  }

  /**
   * Select best strategy based on detected framework and pattern
   */
  selectStrategy(vulnerabilityType, context) {
    const framework = context.framework?.detected?.[0] || 'generic';
    const strategies = this.fixStrategies[vulnerabilityType];

    if (!strategies) return null;

    if (vulnerabilityType === 'SQLI') {
      if (framework === 'pdo') return strategies.pdo;
      if (framework === 'mysql') return strategies.mysql_oo;
      if (context.codeStructure?.hasConditionals) {
        return strategies.generic_orm;
      }
      return strategies.node_generic;
    }

    if (vulnerabilityType === 'XSS') {
      const sink = context.outputSink?.primarySink;
      if (sink?.method === 'innerHTML') return strategies.innerHTML;
      if (sink?.method === 'send') return strategies.server_response;
      if (context.dataFlow?.transformations?.includes('template_literal')) {
        return strategies.template_literal;
      }
      return strategies.dom_write;
    }

    return null;
  }

  /**
   * Generate MySQL procedural fix
   */
  generateMysqlFix(context, originalCode) {
    const variable = context.variableInfo?.[0]?.name || 'input';
    const paramType = this.inferParamType(context.variableInfo?.[0]);

    return {
      strategy: 'mysql_prepared',
      name: 'MySQL Prepared Statement',
      description: 'Use mysqli prepared statements to prevent SQL injection',
      
      code: '$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");\n' +
            '$stmt->bind_param("' + paramType + '", $' + variable + ');\n' +
            '$stmt->execute();\n' +
            '$result = $stmt->get_result();',

      explanation: 'Prepared statements separate SQL structure from data, preventing injection attacks. ' +
                  'The bind_param() method with type parameter "' + paramType + '" ensures type safety.',

      steps: [
        'Use $conn->prepare() with ? placeholders',
        'Add $stmt->bind_param("' + paramType + '", $' + variable + ') for each parameter',
        'Call $stmt->execute() to run the query safely'
      ],

      confidence: 0.92,
      applicability: 'HIGH'
    };
  }

  /**
   * Generate prepared statement fix (generic)
   */
  generatePreparedFix(context, originalCode) {
    const variable = context.inputSource?.sources?.[0] || 'userInput';
    const sink = context.outputSink?.primarySink?.method || 'query';

    return {
      strategy: 'prepared_statement',
      name: 'Prepared Statement Fix',
      description: 'Use prepared statement with ' + sink + '() method to prevent injection',

      code: '// Instead of: query("SELECT * FROM users WHERE id = " + id);\n' +
            '// Use this:\n' +
            '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");\n' +
            '$stmt->execute([' + variable + ']);',

      explanation: 'Prepared statements use parameterized queries where data and SQL ' +
                  'structure are completely separated. This is the safest approach.',

      steps: [
        'Use prepare() method with ? placeholders',
        'Pass data separately in execute() method',
        'Never concatenate user data into query strings'
      ],

      confidence: 0.94,
      applicability: 'HIGH'
    };
  }

  /**
   * Generate PDO-specific fix
   */
  generatePDOFix(context, originalCode) {
    const variable = context.variableInfo?.[0]?.name || 'input';
    
    return {
      strategy: 'pdo_named_parameters',
      name: 'PDO Named Parameters',
      description: 'Use PDO prepared statements with named parameters',

      code: '$stmt = $pdo->prepare("SELECT * FROM users WHERE email = :email");\n' +
            '$stmt->bindParam(\':email\', $' + variable + ', PDO::PARAM_STR);\n' +
            '$stmt->execute();',

      alternativeCode: '// Or using execute with array:\n' +
                      '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");\n' +
                      '$stmt->execute([\':id\' => $' + variable + ']);',

      explanation: 'PDO provides both positional (?) and named (:name) parameters. ' +
                  'Named parameters are more readable and less error-prone.',

      steps: [
        'Replace SQL value with :parameterName',
        'Use bindParam() or pass array to execute()',
        'Data is automatically escaped and type-safe'
      ],

      confidence: 0.95,
      applicability: 'HIGH'
    };
  }

  /**
   * Generate ORM-style fix
   */
  /**
   * Generate ORM-style fix
   */
  generateORMFix(context, originalCode) {
    const variable = context.variableInfo?.[0]?.name || 'userId';
    const framework = context.framework?.detected?.[0] || 'generic';

    const ormExamples = {
      sequelize: 'User.findAll({ where: { id: ' + variable + ' } });',
      mongoose: 'User.find({ _id: ' + variable + ' });',
      typeorm: 'const user = await User.findOne(' + variable + ');',
      generic: 'db.query("SELECT * FROM users WHERE id = ?", [' + variable + ']);'
    };

    const exampleCode = ormExamples[framework] || ormExamples.generic;
    const frameworkName = framework.charAt(0).toUpperCase() + framework.slice(1);

    return {
      strategy: 'orm_parameterized',
      name: frameworkName + ' ORM Query',
      description: 'Use ' + framework + ' ORM\'s built-in query methods for safety',

      code: exampleCode,

      explanation: 'ORMs (Object-Relational Mappers) handle parameterization automatically. ' +
                  'They provide type safety and prevent SQL injection by design.',

      recommendation: 'This is the recommended approach for ' + framework + ' applications. ' +
                     'The ORM handles all query construction safely.',

      confidence: 0.93,
      applicability: 'HIGH'
    };
  }

  /**
   * Generate Node.js generic fix
   */
  generateNodeFix(context, originalCode) {
    const variable = context.inputSource?.sources?.[0] || 'req.query.id';
    const extractedVar = this.extractVariableName(variable);

    return {
      strategy: 'node_parameterized',
      name: 'Node.js Parameterized Query',
      description: 'Use parameterized queries with placeholders',

      code: `const query = "SELECT * FROM users WHERE id = ?";
db.query(query, [${extractedVar}], (err, results) => {
  if (err) throw err;
  res.json(results);
});`,

      explanation: `Node.js database drivers support parameterized queries.
The ? placeholder is replaced with properly escaped values.`,

      steps: [
        'Use ? placeholders in query string',
        'Pass values in array as second parameter',
        'Driver handles escaping and type safety'
      ],

      confidence: 0.90,
      applicability: 'HIGH'
    };
  }

  /**
   * Generate XSS fix for innerHTML
   */
  generateInnerHTMLFix(context, originalCode) {
    const variable = context.dataFlow?.variable || 'userInput';
    const element = context.outputSink?.primarySink?.element || 'element';

    return {
      strategy: 'textContent_replacement',
      name: 'Replace innerHTML with textContent',
      description: 'Use textContent instead of innerHTML to prevent XSS',

      badCode: element + '.innerHTML = "' + variable + '";',
      goodCode: element + '.textContent = ' + variable + ';',

      explanation: 'textContent treats all input as plain text and never interprets HTML. ' +
                  'This is the safest way to set element content from user data.',

      steps: [
        'Replace .innerHTML = with .textContent =',
        'No HTML encoding needed - textContent handles it',
        'Works for any element that should display text'
      ],

      whyTextContent: [
        'No HTML parsing - pure text insertion',
        'No risk of script execution',
        'Simpler and more performant'
      ],

      confidence: 0.98,
      applicability: 'HIGH'
    };
  }

  /**
   * Generate XSS fix for document.write
   */
  generateDOMWriteFix(context, originalCode) {
    const variable = context.dataFlow?.variable || 'userInput';
    const varCapitalized = variable?.charAt(0).toUpperCase() + (variable?.slice(1) || '');

    return {
      strategy: 'html_encoding',
      name: 'HTML Encode Output',
      description: 'Encode user input before writing to document',

      helper: 'function encodeHTML(text) {\n' +
              '  const map = {\n' +
              '    \'&\': \'&amp;\',\n' +
              '    \'<\': \'&lt;\',\n' +
              '    \'>\': \'&gt;\',\n' +
              '    \'"\': \'&quot;\',\n' +
              '    "\'": \'&#039;\'\n' +
              '  };\n' +
              '  return String(text).replace(/[&<>"\']/g, m => map[m]);\n' +
              '}',

      goodCode: 'const encoded' + varCapitalized + ' = encodeHTML(' + variable + ');\n' +
                'document.write("<h1>" + encoded' + varCapitalized + ' + "</h1>");',

      explanation: 'Encoding HTML ensures that special characters are treated as text, ' +
                  'not as HTML/JavaScript code.',

      steps: [
        'Create encoding function for HTML entities',
        'Encode user input before using it in HTML context',
        'Special characters become safe HTML entities'
      ],

      confidence: 0.90,
      applicability: 'MEDIUM'
    };
  }

  /**
   * Generate fix for template literals
   */
  generateTemplateFix(context, originalCode) {
    const variable = context.variableInfo?.[0]?.name || 'data';

    return {
      strategy: 'template_escape',
      name: 'Escape Template Literals',
      description: 'Properly escape data in template literals',

      badCode: 'const html = `<div>${userInput}</div>`;\n' +
               'element.innerHTML = html;',

      goodCode: 'const html = `<div>${encodeHTML(userInput)}</div>`;\n' +
                'element.textContent = html;  // Or use a safe method to set HTML',

      alternativeApproach: '// Better: Use textContent for plain text\n' +
                          'element.textContent = userInput;\n\n' +
                          '// Or use a library like DOMPurify for safe HTML',

      explanation: 'Template literals do NOT automatically escape HTML. ' +
                  'You must manually encode or use safe DOM methods.',

      steps: [
        'Identify all variables in template literals used in HTML context',
        'Apply HTML encoding function to each variable',
        'Or better: use textContent instead of innerHTML'
      ],

      confidence: 0.88,
      applicability: 'HIGH'
    };
  }

  /**
   * Generate fix for HTML attributes
   */
  generateAttributeFix(context, originalCode) {
    const attribute = context.outputSink?.primarySink?.event || 'href';
    const variable = context.variableInfo?.[0]?.name || 'url';

    return {
      strategy: 'attribute_encoding',
      name: 'Encode HTML Attributes',
      description: 'Safely set HTML attributes to prevent event handler injection',

      badCode: '<a href="' + variable + '">Link</a>',

      goodCode: '<a href="' + 'escapeAttr(' + variable + ')' + '">Link</a>',

      helper: 'function escapeAttr(value) {\n' +
              '  return encodeURI(String(value))\n' +
              '    .replace(/"/g, \'&quot;\')\n' +
              '    .replace(/\'/g, \'&#39;\');\n' +
              '}',

      dangerousAttributes: ['href', 'src', 'onclick', 'onload', 'onerror', 'action'],
      
      explanation: 'HTML attributes can contain event handlers if not properly encoded. ' +
                  'Use attribute encoding to prevent this.',

      steps: [
        'Identify attributes receiving user data',
        'Apply attribute encoding function',
        'Test with malicious payloads like: javascript: or " onerror="'
      ],

      confidence: 0.85,
      applicability: 'HIGH'
    };
  }

  /**
   * Generate fix for server-side output
   */
  generateServerFix(context, originalCode) {
    const variable = context.dataFlow?.variable || 'userData';
    const responseMethod = context.outputSink?.primarySink?.method || 'send';

    return {
      strategy: 'express_encoding',
      name: 'Encode Express Response',
      description: 'Safely encode data in Express responses',

      badCode: `res.send("<h1>" + userInput + "</h1>");`,

      goodCode: `const html = escapeHtml(userInput);
res.send("<h1>" + html + "</h1>");`,

      betterApproach: `// Use a template engine with auto-escaping
res.render('template', { title: userInput });  // Most template engines auto-escape`,

      helper: `function escapeHtml(unsafe) {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}`,

      explanation: `Server-side rendered HTML must escape all user data.
Use template engines with auto-escaping for safer defaults.`,

      confidence: 0.92,
      applicability: 'HIGH'
    };
  }

  /**
   * Generate generic fix
   */
  generateGenericFix(vulnerabilityType, context) {
    return {
      strategy: 'generic_sanitization',
      name: 'Generic Sanitization',
      description: 'Apply general security best practices',

      keyRecommendations: [
        'Validate input: check type, length, format',
        'Use parameterized queries for databases',
        'Encode output appropriate to context',
        'Implement Content Security Policy (CSP)',
        'Use established security libraries'
      ],

      explanation: `Without specific framework context, follow defense-in-depth principles.
Combine validation, parameterization, and encoding.`,

      confidence: 0.60,
      applicability: 'MEDIUM'
    };
  }

  /**
   * Infer parameter type from variable info
   */
  inferParamType(varInfo) {
    if (!varInfo) return 's'; // Default to string

    if (varInfo.type === 'number') return 'i';
    if (varInfo.type === 'double') return 'd';
    if (varInfo.type === 'blob') return 'b';

    return 's'; // Default to string
  }

  /**
   * Extract variable name from source expression
   */
  extractVariableName(source) {
    const match = source.match(/\.(\w+)$/);
    return match ? match[1] : source;
  }

  /**
   * Escape HTML for attribute
   */
  escapeAttr(value) {
    return String(value)
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  /**
   * Calculate risk reduction percentage
   */
  calculateRiskReduction(fix, context) {
    let reduction = 0.7; // Base: 70% risk reduction

    // Increase reduction for high-confidence fixes
    if (fix.confidence > 0.9) reduction += 0.15;

    // Account for existing validation
    if (context.codeStructure?.hasValidation) reduction -= 0.05;

    return Math.min(reduction, 0.99);
  }
}

module.exports = AdaptiveFixGenerator;
