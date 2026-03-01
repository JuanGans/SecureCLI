/**
 * ENHANCED: Context Extractor for Real-Life Code
 * Purpose: Extract detailed context from actual code structure
 * Handles multiple frameworks, patterns, and coding styles
 */

const acorn = require('acorn');
const walk = require('acorn-walk');

class ContextExtractor {
  constructor() {
    this.frameworks = {
      express: {
        requestPatterns: ['req.query', 'req.body', 'req.params', 'req.headers'],
        responsePatterns: ['res.send', 'res.json', 'res.render'],
        dbPatterns: ['db.query', 'connection.query', 'pool.query']
      },
      mysql: {
        connectionPatterns: ['mysql.createConnection', 'mysql.createPool'],
        queryPatterns: ['connection.query', 'pool.query', 'mysql_query', 'mysqli_query']
      },
      pdo: {
        connectionPatterns: ['new PDO', '$pdo ='],
        queryPatterns: ['$pdo->query', '$pdo->exec', '$pdo->prepare']
      },
      sequelize: {
        queryPatterns: ['Model.findAll', 'Model.find', 'sequelize.query'],
        optionPatterns: ['where:', 'attributes:']
      }
    };

    this.codePatterns = {
      functionScope: null,
      variables: new Map(),
      assignments: [],
      functionCalls: [],
      dataFlow: []
    };
  }

  /**
   * Extract comprehensive context from vulnerable code
   */
  extractContext(code, lineNumber, vulnerabilityType) {
    try {
      const ast = acorn.parse(code, {
        ecmaVersion: 'latest',
        sourceType: 'script',
        locations: true
      });

      const context = {
        framework: this.detectFramework(code),
        codeStructure: this.analyzeCodeStructure(ast, code, lineNumber),
        dataFlow: this.analyzeDataFlow(ast, code, lineNumber),
        variableInfo: this.extractVariableInfo(ast, code, lineNumber),
        functionContext: this.extractFunctionContext(ast, code, lineNumber),
        inputSource: this.identifyInputSource(code, lineNumber),
        outputSink: this.identifyOutputSink(code, lineNumber),
        dataTransformation: this.analyzeTransformation(code, lineNumber),
      };

      return context;
    } catch (error) {
      console.error(`Context extraction error: ${error.message}`);
      return null;
    }
  }

  /**
   * Detect framework being used
   */
  detectFramework(code) {
    const detectedFrameworks = [];

    if (code.includes('require("express")') || code.includes("require('express')")) {
      detectedFrameworks.push('express');
    }
    if (code.includes('require("mysql")') || code.includes("require('mysql')")) {
      detectedFrameworks.push('mysql');
    }
    if (code.includes('PDO') || code.includes('pdo->')) {
      detectedFrameworks.push('pdo');
    }
    if (code.includes('Sequelize') || code.includes('sequelize.')) {
      detectedFrameworks.push('sequelize');
    }
    if (code.includes('mongoose')) {
      detectedFrameworks.push('mongoose');
    }

    return {
      detected: detectedFrameworks.length > 0 ? detectedFrameworks : ['generic'],
      counts: detectedFrameworks.reduce((acc, f) => {
        acc[f] = (acc[f] || 0) + 1;
        return acc;
      }, {})
    };
  }

  /**
   * Analyze code structure (loops, conditionals, etc)
   */
  analyzeCodeStructure(ast, code, lineNumber) {
    const structure = {
      hasErrorHandling: false,
      hasValidation: false,
      hasLoops: false,
      hasConditionals: false,
      nestingLevel: 0,
      complexity: 0
    };

    walk.simple(ast, {
      TryStatement: () => {
        structure.hasErrorHandling = true;
      },
      IfStatement: () => {
        structure.hasConditionals = true;
      },
      WhileStatement: () => {
        structure.hasLoops = true;
      },
      ForStatement: () => {
        structure.hasLoops = true;
      }
    });

    // Check for validation patterns
    const lines = code.split('\n');
    const vulnLine = lines[lineNumber - 1] || '';
    structure.hasValidation = this.detectValidationPatterns(vulnLine);
    
    return structure;
  }

  /**
   * Detect validation patterns
   */
  detectValidationPatterns(code) {
    const validationKeywords = [
      'validate', 'check', 'sanitize', 'escape', 'filter',
      'isValid', 'isNull', 'isEmpty', 'match', 'test'
    ];

    return validationKeywords.some(keyword => 
      code.toLowerCase().includes(keyword)
    );
  }

  /**
   * Analyze data flow from source to sink
   */
  analyzeDataFlow(ast, code, lineNumber) {
    const dataFlow = {
      sources: [],
      transformations: [],
      sink: null,
      directFlow: false
    };

    const lines = code.split('\n');
    const context = lines.slice(Math.max(0, lineNumber - 5), lineNumber + 5);

    // Look for Request sources
    if (code.includes('req.')) {
      const match = code.match(/req\.(query|body|params|headers|cookies)\.(\w+)/);
      if (match) {
        dataFlow.sources.push({
          type: 'request_parameter',
          source: `req.${match[1]}.${match[2]}`,
          parameter: match[2],
          sourceType: match[1]
        });
      }
    }

    // Look for location sources
    if (code.includes('location.')) {
      const match = code.match(/location\.(\w+)/);
      dataFlow.sources.push({
        type: 'location',
        source: `location.${match?.[1] || 'unknown'}`
      });
    }

    // Look for database sinks
    if (code.includes('.query(') || code.includes('mysqli_query')) {
      dataFlow.directFlow = !code.match(/prepare|parameterized|bound/i);
    }

    return dataFlow;
  }

  /**
   * Extract variable information
   */
  extractVariableInfo(ast, code, lineNumber) {
    const variables = new Map();
    const lines = code.split('\n');
    const context = lines.slice(Math.max(0, lineNumber - 10), lineNumber);

    walk.simple(ast, {
      VariableDeclarator: (node) => {
        if (node.id?.name) {
          variables.set(node.id.name, {
            name: node.id.name,
            type: this.inferType(node.init),
            initializedAt: node.loc?.start.line,
            isFromRequest: code.includes(`${node.id.name}`) && 
                          (code.includes('req.') || code.includes('location.'))
          });
        }
      }
    });

    return Array.from(variables.values());
  }

  /**
   * Infer variable type from initialization
   */
  inferType(initNode) {
    if (!initNode) return 'unknown';
    
    if (initNode.type === 'Literal') {
      if (typeof initNode.value === 'string') return 'string';
      if (typeof initNode.value === 'number') return 'number';
      return 'literal';
    }
    
    if (initNode.type === 'MemberExpression') {
      return 'object_property';
    }
    
    if (initNode.type === 'CallExpression') {
      return 'function_result';
    }

    return initNode.type?.toLowerCase() || 'unknown';
  }

  /**
   * Extract function context
   */
  extractFunctionContext(ast, code, lineNumber) {
    let functionName = null;
    let functionType = null;
    let parameters = [];

    walk.simple(ast, {
      FunctionDeclaration: (node) => {
        if (node.loc?.start.line <= lineNumber && 
            node.loc?.end.line >= lineNumber) {
          functionName = node.id?.name;
          functionType = 'declaration';
          parameters = node.params.map(p => p.name || 'unknown');
        }
      },
      ArrowFunctionExpression: (node) => {
        if (node.loc?.start.line <= lineNumber && 
            node.loc?.end.line >= lineNumber) {
          functionName = 'arrow_function';
          functionType = 'arrow';
          parameters = node.params.map(p => p.name || 'unknown');
        }
      }
    });

    return {
      name: functionName,
      type: functionType,
      parameters: parameters,
      isProbablyHandler: this.isProbablyEventHandler(functionName)
    };
  }

  /**
   * Detect if function is likely an event handler
   */
  isProbablyEventHandler(functionName) {
    if (!functionName) return false;
    
    const handlerPatterns = ['handle', 'on', 'callback', 'listen', 'get', 'post', 'put', 'delete'];
    return handlerPatterns.some(pattern => 
      functionName.toLowerCase().includes(pattern)
    );
  }

  /**
   * Identify input source (req, location, etc)
   */
  identifyInputSource(code, lineNumber) {
    const sources = [];

    if (code.includes('req.query')) sources.push('query_string');
    if (code.includes('req.body')) sources.push('request_body');
    if (code.includes('req.params')) sources.push('url_parameters');
    if (code.includes('req.headers')) sources.push('http_headers');
    if (code.includes('req.cookies')) sources.push('cookies');
    if (code.includes('location.')) sources.push('url_location');
    if (code.includes('document.')) sources.push('dom');
    if (code.includes('localStorage') || code.includes('sessionStorage')) {
      sources.push('web_storage');
    }

    return {
      sources: sources.length > 0 ? sources : ['unknown'],
      isUserControlled: sources.length > 0,
      trustLevel: this.calculateTrustLevel(sources)
    };
  }

  /**
   * Calculate trust level of input source
   */
  calculateTrustLevel(sources) {
    // Higher number = higher trust
    if (sources.includes('query_string') || sources.includes('url_parameters')) {
      return 0.3; // Low trust - directly from user
    }
    if (sources.includes('request_body')) {
      return 0.3; // Low trust
    }
    if (sources.includes('http_headers')) {
      return 0.4; // Medium - can be spoofed
    }
    if (sources.includes('cookies')) {
      return 0.5; // Medium - depends on cookie security
    }
    return 0.9; // High trust - internal source
  }

  /**
   * Identify output sink
   */
  identifyOutputSink(code, lineNumber) {
    const sinks = new Map();

    // SQL sinks
    if (code.includes('query(') || code.includes('execute(')) {
      sinks.set('sql_query', {
        type: 'sql',
        method: code.match(/(\w+)\(.*query|execute/)?.[1] || 'unknown',
        isSafeMethod: code.includes('prepare') || code.includes('bind')
      });
    }

    // DOM sinks
    if (code.includes('innerHTML')) {
      sinks.set('dom_innerHTML', {
        type: 'dom',
        method: 'innerHTML',
        isSafeMethod: false
      });
    }

    if (code.includes('textContent')) {
      sinks.set('dom_textContent', {
        type: 'dom',
        method: 'textContent',
        isSafeMethod: true
      });
    }

    // HTTP response sinks
    if (code.includes('res.send') || code.includes('res.write')) {
      sinks.set('http_response', {
        type: 'http',
        method: code.match(/(send|write|render|json)/)?.[1] || 'unknown',
        isSafeMethod: false
      });
    }

    return {
      sinks: Array.from(sinks.entries()).map(([key, val]) => val),
      primarySink: sinks.values().next().value || null,
      count: sinks.size
    };
  }

  /**
   * Analyze transformations on data
   */
  analyzeTransformation(code, lineNumber) {
    const transformations = [];

    if (code.includes('.trim()')) transformations.push('trim');
    if (code.includes('.toLowerCase()')) transformations.push('lowercase');
    if (code.includes('.toUpperCase()')) transformations.push('uppercase');
    if (code.includes('parseInt') || code.includes('parseFloat')) {
      transformations.push('type_conversion');
    }
    if (code.includes('.filter(') || code.includes('.slice(')) {
      transformations.push('filtering');
    }
    if (code.includes('.split(') || code.includes('.join(')) {
      transformations.push('string_manipulation');
    }
    if (code.includes('.encode') || code.includes('escape')) {
      transformations.push('encoding');
    }

    return {
      applied: transformations,
      hasProtectiveTransformation: transformations.includes('encoding') ||
                                  transformations.includes('type_conversion'),
      count: transformations.length
    };
  }

  /**
   * Merge all context information
   */
  generateContextReport(code, lineNumber, vulnerabilityType) {
    const fullContext = this.extractContext(code, lineNumber, vulnerabilityType);

    return {
      ...fullContext,
      riskAssessment: {
        isDirectFlow: fullContext?.dataFlow?.directFlow,
        hasProtection: fullContext?.codeStructure?.hasValidation || 
                      fullContext?.dataTransformation?.hasProtectiveTransformation,
        trustScore: fullContext?.inputSource?.trustLevel,
        overallRisk: this.calculateOverallRisk(fullContext)
      }
    };
  }

  /**
   * Calculate overall risk score
   */
  calculateOverallRisk(context) {
    let risk = 0.5; // Base risk

    // Increase risk for direct flow
    if (context?.dataFlow?.directFlow) risk += 0.3;

    // Decrease risk for validation/transformation
    if (context?.codeStructure?.hasValidation) risk -= 0.1;
    if (context?.dataTransformation?.hasProtectiveTransformation) risk -= 0.1;

    // Adjust by trust level
    if (context?.inputSource?.trustLevel) {
      risk *= (1 - context.inputSource.trustLevel);
    }

    return Math.min(Math.max(risk, 0.1), 0.95);
  }
}

module.exports = ContextExtractor;
