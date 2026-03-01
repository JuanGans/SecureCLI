/**
 * PHASE 1: AST Engine - Dedicated AST Parser & Analyzer
 * Purpose: Parse code, extract structure, detect patterns
 */

const acorn = require('acorn');
const walk = require('acorn-walk');

class ASTEngine {
  constructor() {
    this.variables = new Map();      // Variable declarations
    this.functions = new Map();       // Function definitions
    this.callExpressions = [];        // All function calls
    this.assignments = [];            // All assignments
  }

  /**
   * Parse code into AST and extract structure
   */
  parse(code, language = 'javascript') {
    try {
      if (language === 'javascript') {
        return this.parseJavaScript(code);
      }
      // Future: Add PHP parser support
      return null;
    } catch (error) {
      console.error(`AST Parse Error: ${error.message}`);
      return null;
    }
  }

  /**
   * Parse JavaScript code
   */
  parseJavaScript(code) {
    const ast = acorn.parse(code, {
      ecmaVersion: 'latest',
      sourceType: 'script',
      locations: true,
    });

    this.extractStructure(ast);

    return ast;
  }

  /**
   * Extract code structure from AST
   */
  extractStructure(ast) {
    walk.simple(ast, {
      VariableDeclarator: (node) => {
        if (node.id && node.id.name) {
          this.variables.set(node.id.name, {
            name: node.id.name,
            init: node.init,
            type: node.init?.type || 'unknown',
            line: node.loc?.start.line,
          });
        }
      },

      FunctionDeclaration: (node) => {
        if (node.id && node.id.name) {
          this.functions.set(node.id.name, {
            name: node.id.name,
            params: node.params,
            body: node.body,
            line: node.loc?.start.line,
          });
        }
      },

      CallExpression: (node) => {
        this.callExpressions.push({
          callee: this.getFullName(node.callee),
          arguments: node.arguments,
          node: node,
          line: node.loc?.start.line,
        });
      },

      AssignmentExpression: (node) => {
        this.assignments.push({
          left: this.getFullName(node.left),
          right: node.right,
          operator: node.operator,
          line: node.loc?.start.line,
        });
      },
    });
  }

  /**
   * Get full qualified name from node
   */
  getFullName(node) {
    if (!node) return null;

    if (node.type === 'Identifier') {
      return node.name;
    }

    if (node.type === 'MemberExpression') {
      const obj = this.getFullName(node.object);
      const prop = node.computed ? '[computed]' : this.getFullName(node.property);
      return obj && prop ? `${obj}.${prop}` : null;
    }

    return null;
  }

  /**
   * Find variable declaration by name
   */
  getVariable(name) {
    return this.variables.get(name);
  }

  /**
   * Find function calls by callee name
   */
  findCallsByName(calleeName) {
    return this.callExpressions.filter(call => 
      call.callee && call.callee.includes(calleeName)
    );
  }

  /**
   * Extract connection variable from database calls
   * Example: conn.query() -> returns 'conn'
   */
  extractDBConnection(callExpression) {
    if (!callExpression.callee) return null;

    // For patterns like: conn.query, db.execute, pool.query
    if (callExpression.callee.includes('.')) {
      const parts = callExpression.callee.split('.');
      return parts[0];
    }

    return null;
  }

  /**
   * Extract table name from SQL query string (basic heuristic)
   */
  extractTableName(queryNode) {
    if (!queryNode || queryNode.type !== 'Literal') return null;

    const query = queryNode.value;
    if (typeof query !== 'string') return null;

    // Match: SELECT ... FROM tableName, INSERT INTO tableName, etc.
    const fromMatch = query.match(/FROM\s+(\w+)/i);
    if (fromMatch) return fromMatch[1];

    const intoMatch = query.match(/INTO\s+(\w+)/i);
    if (intoMatch) return intoMatch[1];

    return null;
  }

  /**
   * Clear stored data for next analysis
   */
  reset() {
    this.variables.clear();
    this.functions.clear();
    this.callExpressions = [];
    this.assignments = [];
  }
}

module.exports = ASTEngine;
