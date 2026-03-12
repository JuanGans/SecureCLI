/**
 * DOM-Based XSS Detection Engine
 * Detects DOM-based XSS where user input flows through client-side JavaScript
 * 
 * Attack vector: document.write(location.hash), innerHTML = url_param
 * Context: JavaScript within PHP files, standalone JS
 */

class DOMBasedXSSDetector {
  constructor() {
    // DOM sources (client-side user input)
    this.sourcePatterns = [
      /location\.(hash|search|href|pathname)/i,
      /document\.(URL|referrer|cookie|domain)/i,
      /window\.(name|location)/i,
      /document\.location/i,
      /decodeURI(Component)?\s*\(/i,
      /URLSearchParams/i,
    ];

    // DOM sinks (client-side output/execution)
    this.sinkPatterns = [
      {
        name: 'document.write',
        regex: /document\.write(ln)?\s*\(/i,
        severity: 'CRITICAL',
        confidence: 0.92,
      },
      {
        name: 'innerHTML Assignment',
        regex: /\.innerHTML\s*=\s*[^;]+/i,
        severity: 'HIGH',
        confidence: 0.90,
      },
      {
        name: 'outerHTML Assignment',
        regex: /\.outerHTML\s*=\s*[^;]+/i,
        severity: 'HIGH',
        confidence: 0.90,
      },
      {
        name: 'insertAdjacentHTML',
        regex: /\.insertAdjacentHTML\s*\(/i,
        severity: 'HIGH',
        confidence: 0.88,
      },
      {
        name: 'eval with input',
        regex: /eval\s*\([^)]*[\w$]/i,
        severity: 'CRITICAL',
        confidence: 0.95,
      },
      {
        name: 'setTimeout/setInterval string',
        regex: /(setTimeout|setInterval)\s*\(\s*['"]/i,
        severity: 'HIGH',
        confidence: 0.85,
      },
      {
        name: 'jQuery html()',
        regex: /\.html\s*\([^)]+[\w$]/i,
        severity: 'HIGH',
        confidence: 0.85,
      },
    ];

    // PHP-specific: user input rendered into <script> blocks
    this.phpDOMPatterns = [
      {
        name: 'PHP var in script tag',
        regex: /<script[^>]*>[^<]*\$_(GET|POST|REQUEST|COOKIE)/i,
        confidence: 0.92,
        description: 'PHP superglobal rendered inside <script> block',
      },
      {
        name: 'PHP echo in JS assignment',
        regex: /var\s+\w+\s*=\s*['"][^'"]*<\?(?:php|=)\s*(?:echo\s+)?\$_(GET|POST|REQUEST)/i,
        confidence: 0.90,
        description: 'PHP superglobal assigned to JavaScript variable',
      },
      {
        name: 'PHP echo in script context',
        regex: /<script[^>]*>[^<]*<\?(?:php)?\s+(?:echo|print)\s+\$_(GET|POST|REQUEST)/i,
        confidence: 0.92,
        description: 'PHP echoes superglobal inside script element',
      },
    ];
  }

  /**
   * Detect DOM-based XSS patterns
   */
  detect(code, filePath = '') {
    const findings = [];
    const isPhp = filePath.endsWith('.php');

    // Check for DOM source → sink flows in JavaScript
    findings.push(...this._detectJSDOMFlows(code, filePath));

    // PHP-specific: user input in <script> context
    if (isPhp) {
      findings.push(...this._detectPHPDOMPatterns(code, filePath));
    }

    return findings;
  }

  /**
   * Detect JavaScript DOM source → sink flows
   */
  _detectJSDOMFlows(code, filePath) {
    const findings = [];
    const lines = code.split('\n');
    let inScriptBlock = false;

    // Phase 1: Collect tainted JS variables assigned from DOM sources
    const taintedJSVars = new Set();
    lines.forEach((line, index) => {
      if (/<script/i.test(line)) inScriptBlock = true;
      if (/<\/script/i.test(line)) inScriptBlock = false;
      if (!inScriptBlock && filePath.endsWith('.php')) return;

      // Detect: var x = document.location.href... or var x = location.search...
      const assignMatch = /(?:var|let|const)\s+(\w+)\s*=\s*(.+)/i.exec(line);
      if (assignMatch) {
        const varName = assignMatch[1];
        const rhs = assignMatch[2];
        if (this.sourcePatterns.some(src => src.test(rhs))) {
          taintedJSVars.add(varName);
        }
      }
    });

    // Phase 2: Check sinks (same-line source OR tainted variable usage)
    inScriptBlock = false;
    lines.forEach((line, index) => {
      if (/<script/i.test(line)) inScriptBlock = true;
      if (/<\/script/i.test(line)) inScriptBlock = false;

      // Only check in script context or .js files
      if (!inScriptBlock && filePath.endsWith('.php')) return;

      for (const sink of this.sinkPatterns) {
        if (sink.regex.test(line)) {
          const hasDirectSource = this.sourcePatterns.some(src => src.test(line));
          const hasTaintedVar = [...taintedJSVars].some(v => {
            const varPattern = new RegExp(`\\b${v}\\b`);
            return varPattern.test(line);
          });
          const hasVariableConcat = /[\+]\s*\w/.test(line) && !/^\s*(\/\/|\/\*|\*)/.test(line);

          if (hasDirectSource || hasTaintedVar || hasVariableConcat) {
            const confidence = hasDirectSource
              ? sink.confidence
              : hasTaintedVar
                ? Math.max(0.70, sink.confidence - 0.05)
                : Math.max(0.60, sink.confidence - 0.15);

            findings.push({
              type: 'XSS_DOM_BASED',
              subtype: 'DOM',
              name: `DOM-Based XSS: ${sink.name}`,
              severity: sink.severity,
              confidence: confidence,
              line: index + 1,
              code: line.trim(),
              description: `User-controlled input flows to DOM sink: ${sink.name}`,
              file: filePath,
              engine: 'xss-dom',
              hasDirectSource: hasDirectSource,
              hasTaintedVariable: hasTaintedVar,
              remediation: {
                fix: this._getRemediationForSink(sink.name),
                description: 'Sanitize input before inserting into DOM',
              }
            });
            break;
          }
        }
      }
    });

    return findings;
  }

  /**
   * Detect PHP-rendered values in <script> context
   */
  _detectPHPDOMPatterns(code, filePath) {
    const findings = [];
    const lines = code.split('\n');
    let inScript = false;

    lines.forEach((line, index) => {
      if (/<script/i.test(line)) inScript = true;

      if (inScript) {
        for (const pattern of this.phpDOMPatterns) {
          if (pattern.regex.test(line)) {
            if (/htmlspecialchars|htmlentities|json_encode|addslashes/.test(line)) {
              continue;
            }

            findings.push({
              type: 'XSS_DOM_BASED',
              subtype: 'DOM',
              name: `DOM-Based XSS: ${pattern.name}`,
              severity: 'HIGH',
              confidence: pattern.confidence,
              line: index + 1,
              code: line.trim(),
              description: pattern.description,
              file: filePath,
              engine: 'xss-dom',
              remediation: {
                fix: 'json_encode($value, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT)',
                description: 'Use json_encode for safe JavaScript context insertion',
              }
            });
            break;
          }
        }
      }

      if (/<\/script/i.test(line)) inScript = false;
    });

    return findings;
  }

  _getRemediationForSink(sinkName) {
    const remediations = {
      'document.write': 'Use textContent or createElement instead of document.write',
      'innerHTML Assignment': 'Use textContent instead of innerHTML, or sanitize with DOMPurify',
      'outerHTML Assignment': 'Use createElement/textContent instead of outerHTML',
      'insertAdjacentHTML': 'Use insertAdjacentText or sanitize HTML with DOMPurify',
      'eval with input': 'Never use eval() with user input. Use JSON.parse() for data.',
      'setTimeout/setInterval string': 'Pass function reference instead of string',
      'jQuery html()': 'Use jQuery .text() instead of .html() for user content',
    };
    return remediations[sinkName] || 'Sanitize user input before DOM insertion';
  }
}

module.exports = DOMBasedXSSDetector;
