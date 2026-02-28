/**
 * LAYER 1: DETECTION - Taint Analysis Engine
 */

const acorn = require('acorn');
const walk = require('acorn-walk');
const { isSource, isSink } = require('./sourceSinkMap');

class TaintAnalyzer {
  constructor() {
    this.tainted = new Set();
    this.variableValues = new Map();
    this.findings = [];
  }

  /**
   * Parse and analyze JavaScript code for taint flow
   */
  analyze(code) {
    try {
      const ast = acorn.parse(code, {
        ecmaVersion: 'latest',
        sourceType: 'script',
        locations: true,
      });

      this.tainted = new Set();
      this.variableValues = new Map();
      this.findings = [];

      this.walkAST(ast, code);

      return this.findings;
    } catch (error) {
      return [];
    }
  }

  /**
   * Walk through AST nodes
   */
  walkAST(ast, code) {
    walk.simple(ast, {
      VariableDeclarator: (node) => this.handleVariableDeclarator(node),
      AssignmentExpression: (node) => this.handleAssignmentExpression(node),
      CallExpression: (node) => this.handleCallExpression(node, code),
    });
  }

  /**
   * Handle variable declarations
   */
  handleVariableDeclarator(node) {
    if (!node.init) return;

    const varName = node.id.name;
    const initName = this.getFullName(node.init);

    // Check if initialized from source
    if (initName && isSource(initName)) {
      this.tainted.add(varName);
    }

    // Track literal values
    if (node.init.type === 'Literal') {
      this.variableValues.set(varName, node.init.value);
    }

    // Track concatenation/binary expressions
    if (node.init.type === 'BinaryExpression') {
      if (this.containsTainted(node.init)) {
        this.tainted.add(varName);
      }
    }
  }

  /**
   * Handle assignment expressions
   */
  handleAssignmentExpression(node) {
    if (!node.left || !node.right) return;

    const assignee = this.getFullName(node.left);

    if (this.containsTainted(node.right)) {
      if (assignee) {
        this.tainted.add(assignee);
      }
    }
  }

  /**
   * Handle function calls (sinks)
   */
  handleCallExpression(node, code) {
    if (!node.callee || !node.arguments.length) return;

    const calleeName = this.getFullName(node.callee);

    if (calleeName && isSink(calleeName)) {
      node.arguments.forEach(arg => {
        if (this.containsTainted(arg)) {
          const argName = this.getFullName(arg);
          const rawCode = code.slice(arg.start, arg.end);

          this.findings.push({
            engine: 'taint',
            sink: calleeName,
            source: argName,
            line: node.loc.start.line,
            flow: `${argName} → ${calleeName}`,
            code: rawCode,
          });
        }
      });
    }
  }

  /**
   * Get full qualified name of node
   */
  getFullName(node) {
    if (!node) return null;

    if (node.type === 'Identifier') {
      return node.name;
    }

    if (node.type === 'MemberExpression') {
      const obj = this.getFullName(node.object);
      const prop = this.getFullName(node.property);
      return obj && prop ? `${obj}.${prop}` : null;
    }

    return null;
  }

  /**
   * Check if node contains tainted variables
   */
  containsTainted(node) {
    if (!node) return false;

    if (node.type === 'Identifier') {
      return this.tainted.has(node.name);
    }

    if (node.type === 'BinaryExpression' || node.type === 'LogicalExpression') {
      return this.containsTainted(node.left) || this.containsTainted(node.right);
    }

    if (node.type === 'CallExpression') {
      return node.arguments.some(arg => this.containsTainted(arg));
    }

    if (node.type === 'MemberExpression') {
      return this.containsTainted(node.object) || this.containsTainted(node.property);
    }

    return false;
  }
}

module.exports = TaintAnalyzer;
