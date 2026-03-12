/**
 * Event Handler XSS Detection Engine
 * Detects XSS via HTML event handler attributes and attribute injection
 * 
 * Attack vector: onerror=alert(1), onclick=steal(), " onfocus="alert(1)
 * PHP context: User input in HTML attributes without encoding
 */

class EventXSSDetector {
  constructor() {
    this.eventHandlers = [
      'onerror', 'onload', 'onclick', 'onmouseover', 'onmouseout',
      'onfocus', 'onblur', 'onchange', 'onsubmit', 'onreset',
      'onkeydown', 'onkeyup', 'onkeypress', 'ondblclick',
      'onmousedown', 'onmouseup', 'onmousemove', 'onselect',
      'oninput', 'oncontextmenu', 'ondrag', 'ondrop',
      'onscroll', 'onresize', 'onunload', 'onbeforeunload',
      'ontouchstart', 'ontouchmove', 'ontouchend',
      'onanimationend', 'ontransitionend',
    ];

    this.patterns = [
      // Pattern 1: PHP superglobal in HTML attribute
      {
        name: 'Superglobal in HTML Attribute',
        regex: /<[^>]+(value|href|src|action|data|style|class|id|title|alt|placeholder)\s*=\s*["'][^"']*\$_(GET|POST|REQUEST|COOKIE)/i,
        negativeRegex: /htmlspecialchars|htmlentities|urlencode/i,
        confidence: 0.92,
        description: 'Superglobal placed in HTML attribute without encoding',
      },
      // Pattern 2: PHP echo creating element with user input
      {
        name: 'Echo HTML with Superglobal',
        regex: /(echo|print)\s+["']<[^>]*\$_(GET|POST|REQUEST|COOKIE)/i,
        negativeRegex: /htmlspecialchars|htmlentities|urlencode/i,
        confidence: 0.90,
        description: 'Echo creates HTML with unencoded superglobal',
      },
      // Pattern 3: Event handler with PHP output
      {
        name: 'Event Handler with PHP',
        regex: new RegExp(`<[^>]+(${this.eventHandlers.slice(0, 15).join('|')})\\s*=\\s*["'][^"']*\\$_(GET|POST|REQUEST)`, 'i'),
        confidence: 0.95,
        description: 'User input placed directly in HTML event handler',
      },
      // Pattern 4: Unquoted attribute with superglobal
      {
        name: 'Unquoted Attribute with Superglobal',
        regex: /<[^>]+\w+=\$_(GET|POST|REQUEST|COOKIE)/i,
        confidence: 0.95,
        description: 'Superglobal in unquoted HTML attribute - critical XSS',
      },
      // Pattern 5: href with potential javascript: protocol
      {
        name: 'href with User Input',
        regex: /<a[^>]+href\s*=\s*["']\s*\$_(GET|POST|REQUEST)/i,
        negativeRegex: /urlencode|filter_var.*FILTER_VALIDATE_URL/i,
        confidence: 0.93,
        description: 'User input in href attribute - javascript: protocol possible',
      },
      // Pattern 6: src attribute with user input
      {
        name: 'src with User Input',
        regex: /<(img|iframe|script|embed|object|video|audio|source)[^>]+src\s*=\s*["'][^"']*\$_(GET|POST|REQUEST)/i,
        negativeRegex: /filter_var.*FILTER_VALIDATE_URL|htmlspecialchars/i,
        confidence: 0.93,
        description: 'User input in src attribute - may load arbitrary resources',
      },
      // Pattern 7: style attribute injection
      {
        name: 'Style Attribute Injection',
        regex: /style\s*=\s*["'][^"']*\$_(GET|POST|REQUEST)/i,
        confidence: 0.85,
        description: 'User input in style attribute - CSS injection possible',
      },
      // Pattern 8: Echo/print building event handler dynamically
      {
        name: 'Dynamic Event Handler Creation',
        regex: new RegExp(`(echo|print)\\s+[^;]*(${this.eventHandlers.slice(0, 10).join('|')})\\s*=\\s*[^;]*\\$_(GET|POST|REQUEST)`, 'i'),
        negativeRegex: /htmlspecialchars|htmlentities/i,
        confidence: 0.95,
        description: 'Event handler dynamically created with unencoded user input',
      },
    ];
  }

  /**
   * Detect event handler and attribute XSS patterns
   */
  detect(code, filePath = '') {
    const findings = [];
    const lines = code.split('\n');

    lines.forEach((line, index) => {
      for (const pattern of this.patterns) {
        if (pattern.regex.test(line)) {
          if (pattern.negativeRegex && pattern.negativeRegex.test(line)) {
            continue;
          }

          findings.push({
            type: 'XSS_EVENT_HANDLER',
            subtype: 'EVENT',
            name: `Event/Attribute XSS: ${pattern.name}`,
            severity: 'HIGH',
            confidence: pattern.confidence,
            line: index + 1,
            code: line.trim(),
            description: pattern.description,
            file: filePath,
            engine: 'xss-event',
            requiresTaintConfirmation: pattern.requiresTaintConfirmation || false,
            remediation: {
              fix: 'htmlspecialchars($input, ENT_QUOTES, \'UTF-8\')',
              description: 'Encode attribute values with htmlspecialchars() using ENT_QUOTES',
            }
          });
          break; // One finding per line
        }
      }
    });

    return findings;
  }
}

module.exports = EventXSSDetector;
