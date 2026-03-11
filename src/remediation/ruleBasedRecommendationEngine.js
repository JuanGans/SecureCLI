/**
 * Rule-Based Contextual Recommendation Engine
 * Purpose: Generate remediation from explicit rules + code context (not template lookup).
 */

class RuleBasedRecommendationEngine {
  constructor({ contextAnalyzer, contextExtractor, fixGenerator }) {
    this.contextAnalyzer = contextAnalyzer;
    this.contextExtractor = contextExtractor;
    this.fixGenerator = fixGenerator;
    this.rules = this._buildRules();
  }

  recommend(finding, sourceCode = '') {
    const vulnerabilityType = this._normalizeVulnerabilityType(finding);
    if (!vulnerabilityType) return null;

    const analyzedFinding = this.contextAnalyzer.analyze({
      ...finding,
      vulnerabilityType,
    });

    const extractedContext = this._extractRichContext(sourceCode, finding.line, vulnerabilityType);
    const mergedContext = this._mergeContexts(analyzedFinding?.context, extractedContext);

    const selectedRule = this._selectRule({
      finding,
      analyzedFinding,
      extractedContext,
      vulnerabilityType,
    });

    const fix = selectedRule
      ? selectedRule.action({ finding, analyzedFinding, extractedContext, mergedContext, vulnerabilityType })
      : this.fixGenerator.generateGenericFix(vulnerabilityType, mergedContext || {});

    if (!fix) return null;

    const riskReduction = this.fixGenerator.calculateRiskReduction(fix, mergedContext || {});
    const confidence = Math.max(fix.confidence || 0.6, analyzedFinding?.fixConfidence || 0.6);

    return {
      ...fix,
      confidence,
      riskReduction,
      recommendationMode: 'rule-based-contextual',
      ruleId: selectedRule ? selectedRule.id : 'fallback.generic',
      ruleName: selectedRule ? selectedRule.name : 'Generic Fallback Rule',
      context: mergedContext,
    };
  }

  _buildRules() {
    return [
      {
        id: 'sqli.php.mysqli',
        name: 'SQLI via mysqli API',
        priority: 100,
        applies: ({ finding, analyzedFinding }) => {
          if ((analyzedFinding?.vulnerabilityType || '').toUpperCase() !== 'SQLI') return false;
          const api = analyzedFinding?.apiContext?.api || '';
          const sink = finding?.sinkFunction || '';
          const code = finding?.code || '';
          return api === 'mysqli' || /mysqli_/i.test(sink) || /mysqli_/i.test(code);
        },
        action: ({ mergedContext, finding }) => this.fixGenerator.generateMysqlFix(mergedContext || {}, finding?.code || ''),
      },
      {
        id: 'sqli.php.pdo',
        name: 'SQLI via PDO API',
        priority: 95,
        applies: ({ finding, analyzedFinding }) => {
          if ((analyzedFinding?.vulnerabilityType || '').toUpperCase() !== 'SQLI') return false;
          const api = analyzedFinding?.apiContext?.api || '';
          const sink = finding?.sinkFunction || '';
          const code = finding?.code || '';
          return api === 'PDO' || /pdo|->prepare|->query|->exec/i.test(sink) || /\$pdo|new\s+PDO/i.test(code);
        },
        action: ({ mergedContext, finding }) => this.fixGenerator.generatePDOFix(mergedContext || {}, finding?.code || ''),
      },
      {
        id: 'sqli.orm.parameterized',
        name: 'SQLI in ORM/Query Builder usage',
        priority: 90,
        applies: ({ analyzedFinding, extractedContext }) => {
          if ((analyzedFinding?.vulnerabilityType || '').toUpperCase() !== 'SQLI') return false;
          const frameworks = extractedContext?.framework?.detected || [];
          return frameworks.some(f => ['sequelize', 'mongoose', 'typeorm'].includes(f));
        },
        action: ({ mergedContext, finding }) => this.fixGenerator.generateORMFix(mergedContext || {}, finding?.code || ''),
      },
      {
        id: 'sqli.node.parameterized',
        name: 'SQLI in Node.js query sink',
        priority: 85,
        applies: ({ finding, analyzedFinding, extractedContext }) => {
          if ((analyzedFinding?.vulnerabilityType || '').toUpperCase() !== 'SQLI') return false;
          const sink = finding?.sinkFunction || '';
          const frameworks = extractedContext?.framework?.detected || [];
          return /query|execute|db\.|pool\./i.test(sink) || frameworks.includes('express') || frameworks.includes('mysql');
        },
        action: ({ mergedContext, finding }) => this.fixGenerator.generateNodeFix(mergedContext || {}, finding?.code || ''),
      },
      {
        id: 'xss.dom.innerhtml',
        name: 'XSS via innerHTML sink',
        priority: 100,
        applies: ({ finding, analyzedFinding }) => {
          if ((analyzedFinding?.vulnerabilityType || '').toUpperCase() !== 'XSS') return false;
          const sink = finding?.sinkFunction || '';
          const type = analyzedFinding?.apiContext?.type || '';
          const code = finding?.code || '';
          return /innerHTML/i.test(sink) || type === 'innerHTML' || /innerHTML\s*=/.test(code);
        },
        action: ({ mergedContext, finding }) => this.fixGenerator.generateInnerHTMLFix(mergedContext || {}, finding?.code || ''),
      },
      {
        id: 'xss.dom.write',
        name: 'XSS via document.write sink',
        priority: 95,
        applies: ({ finding, analyzedFinding }) => {
          if ((analyzedFinding?.vulnerabilityType || '').toUpperCase() !== 'XSS') return false;
          const sink = finding?.sinkFunction || '';
          const type = analyzedFinding?.apiContext?.type || '';
          const code = finding?.code || '';
          return /document\.write|\.write\(/i.test(sink) || type === 'write' || /document\.write\(/i.test(code);
        },
        action: ({ mergedContext, finding }) => this.fixGenerator.generateDOMWriteFix(mergedContext || {}, finding?.code || ''),
      },
      {
        id: 'xss.server.response',
        name: 'XSS via server response sink',
        priority: 90,
        applies: ({ finding, analyzedFinding }) => {
          if ((analyzedFinding?.vulnerabilityType || '').toUpperCase() !== 'XSS') return false;
          const sink = finding?.sinkFunction || '';
          const code = finding?.code || '';
          return /res\.send|send\(/i.test(sink) || /res\.send\(/i.test(code);
        },
        action: ({ mergedContext, finding }) => this.fixGenerator.generateServerFix(mergedContext || {}, finding?.code || ''),
      },
      {
        id: 'xss.template.literal',
        name: 'XSS in template literal output',
        priority: 88,
        applies: ({ finding, analyzedFinding, extractedContext }) => {
          if ((analyzedFinding?.vulnerabilityType || '').toUpperCase() !== 'XSS') return false;
          const code = finding?.code || '';
          const transformations = extractedContext?.dataFlow?.transformations || [];
          return /`.*\$\{.*\}.*`/.test(code) || transformations.includes('template_literal');
        },
        action: ({ mergedContext, finding }) => this.fixGenerator.generateTemplateFix(mergedContext || {}, finding?.code || ''),
      },
      {
        id: 'sqli.fallback.prepared',
        name: 'Generic SQLI fallback rule',
        priority: 10,
        applies: ({ analyzedFinding }) => (analyzedFinding?.vulnerabilityType || '').toUpperCase() === 'SQLI',
        action: ({ mergedContext, finding }) => this.fixGenerator.generatePreparedFix(mergedContext || {}, finding?.code || ''),
      },
      {
        id: 'xss.fallback.escape',
        name: 'Generic XSS fallback rule',
        priority: 10,
        applies: ({ analyzedFinding }) => (analyzedFinding?.vulnerabilityType || '').toUpperCase() === 'XSS',
        action: ({ mergedContext, finding }) => this.fixGenerator.generateDOMWriteFix(mergedContext || {}, finding?.code || ''),
      },
    ];
  }

  _selectRule(context) {
    const candidates = this.rules
      .filter(rule => {
        try {
          return rule.applies(context);
        } catch (e) {
          return false;
        }
      })
      .sort((a, b) => b.priority - a.priority);

    return candidates[0] || null;
  }

  _extractRichContext(sourceCode, lineNumber, vulnerabilityType) {
    if (!sourceCode || !lineNumber) return null;
    try {
      return this.contextExtractor.extractContext(sourceCode, lineNumber, vulnerabilityType);
    } catch (error) {
      return null;
    }
  }

  _mergeContexts(baseContext, richContext) {
    return {
      ...(baseContext || {}),
      ...(richContext || {}),
      variableInfo: richContext?.variableInfo || [],
      dataFlow: richContext?.dataFlow || {},
      outputSink: richContext?.outputSink || {},
      framework: richContext?.framework || { detected: ['generic'] },
      codeStructure: richContext?.codeStructure || {},
      inputSource: richContext?.inputSource || {},
    };
  }

  _normalizeVulnerabilityType(finding) {
    if (finding?.vulnerabilityType) {
      return String(finding.vulnerabilityType).toUpperCase();
    }

    const type = String(finding?.type || '').toUpperCase();
    if (type.includes('SQLI') || type.includes('SQL')) return 'SQLI';
    if (type.includes('XSS')) return 'XSS';
    return null;
  }
}

module.exports = RuleBasedRecommendationEngine;