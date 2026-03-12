/**
 * Reflected XSS Detection Engine
 * Detects reflected XSS where user input is directly echoed in response
 * 
 * Attack vector: <script>alert(1)</script>, javascript:alert(1)
 * PHP context: echo $_GET['name'], print $_POST['data']
 */

class ReflectedXSSDetector {
  constructor() {
    this.patterns = [
      // Pattern 1: Direct echo of superglobal
      {
        name: 'Direct Echo Superglobal',
        regex: /echo\s+[^;]*\$_(GET|POST|REQUEST|COOKIE)\s*\[/i,
        negativeRegex: /htmlspecialchars|htmlentities|strip_tags|urlencode|intval|filter_var/i,
        confidence: 0.95,
        description: 'User input from superglobal echoed directly without encoding',
      },
      // Pattern 2: Print of superglobal
      {
        name: 'Direct Print Superglobal',
        regex: /print\s+[^;]*\$_(GET|POST|REQUEST|COOKIE)\s*\[/i,
        negativeRegex: /htmlspecialchars|htmlentities|strip_tags|urlencode/i,
        confidence: 0.93,
        description: 'User input printed directly without encoding',
      },
      // Pattern 3: Short echo tag <?= $_GET[...]
      {
        name: 'Short Echo Tag Superglobal',
        regex: /<\?=\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/i,
        negativeRegex: /htmlspecialchars|htmlentities/i,
        confidence: 0.93,
        description: 'Short echo tag outputs superglobal without encoding',
      },
      // Pattern 4: echo with concatenation of superglobal
      {
        name: 'Echo Concat Superglobal',
        regex: /echo\s+.*\.\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/i,
        negativeRegex: /htmlspecialchars|htmlentities|urlencode/i,
        confidence: 0.93,
        description: 'Superglobal concatenated in echo statement without encoding',
      },
      // Pattern 5: String concatenation with superglobal used in output context
      {
        name: 'String Concat Output',
        regex: /['"].*['"]\s*\.\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/i,
        negativeRegex: /htmlspecialchars|htmlentities|urlencode/i,
        confidence: 0.80,
        description: 'Superglobal concatenated into string (check if output context)',
        requiresOutputContext: true,
      },
      // Pattern 6: Echo string interpolation
      {
        name: 'Echo String Interpolation',
        regex: /echo\s+["'].*\{\$_(GET|POST|REQUEST|COOKIE)\[/i,
        negativeRegex: /htmlspecialchars|htmlentities/i,
        confidence: 0.92,
        description: 'Superglobal interpolated in echo string without encoding',
      },
      // Pattern 7: printf with superglobal
      {
        name: 'Printf Superglobal',
        regex: /printf?\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)/i,
        negativeRegex: /htmlspecialchars|htmlentities/i,
        confidence: 0.90,
        description: 'Superglobal used in printf without encoding',
      },
      // Pattern 8: .= concatenation with superglobal (DVWA pattern: $html .= '...' . $_GET['name'] . '...')
      {
        name: 'Concat Assignment Superglobal',
        regex: /\.\=\s*[^;]*\$_(GET|POST|REQUEST|COOKIE)\s*\[/i,
        negativeRegex: /htmlspecialchars|htmlentities|strip_tags|urlencode/i,
        confidence: 0.92,
        description: 'Superglobal concatenated into output buffer without encoding',
      },
      // Pattern 9: String interpolation in .= (DVWA pattern: $html .= "...{$name}...")
      {
        name: 'Interpolation in Concat Assignment',
        regex: /\.\=\s*["'][^"']*\{\$\w+\}[^"']*["']/i,
        negativeRegex: /htmlspecialchars|htmlentities|strip_tags/i,
        confidence: 0.60,
        requiresTaintConfirmation: true,
        description: 'Variable interpolated in .= string (needs taint check)',
      },
      // Pattern 10: Echo tainted variable (needs taint confirmation)
      {
        name: 'Echo Tainted Variable',
        regex: /echo\s+["'][^"']*\{\$\w+\}[^"']*["']/i,
        negativeRegex: /htmlspecialchars|htmlentities|strip_tags/i,
        confidence: 0.60,
        requiresTaintConfirmation: true,
        description: 'Variable interpolated in echo (needs taint check)',
      },
    ];
  }

  /**
   * Detect reflected XSS in PHP code
   */
  detect(code, filePath = '') {
    const findings = [];
    const lines = code.split('\n');

    lines.forEach((line, index) => {
      for (const pattern of this.patterns) {
        if (pattern.regex.test(line)) {
          // Check for sanitization on same line
          if (pattern.negativeRegex && pattern.negativeRegex.test(line)) {
            continue;
          }

          // For output context patterns, check if line is actually output
          if (pattern.requiresOutputContext) {
            if (!/echo|print|printf|<\?=/.test(line) && !this._isInOutputContext(lines, index)) {
              continue;
            }
          }

          // For taint-confirmation patterns, check if the interpolated variable
          // has been sanitized with htmlspecialchars/htmlentities somewhere in the file
          if (pattern.requiresTaintConfirmation) {
            const varMatch = /\{\$(\w+)\}/.exec(line);
            if (varMatch) {
              const varName = varMatch[1];
              const isSanitized = lines.some(l =>
                new RegExp(`\\$${varName}\\s*=\\s*(htmlspecialchars|htmlentities|intval|floatval|filter_var)\\s*\\(`, 'i').test(l)
              );
              if (isSanitized) continue;
            }
          }

          findings.push({
            type: 'XSS_REFLECTED',
            subtype: 'REFLECTED',
            name: `Reflected XSS: ${pattern.name}`,
            severity: 'HIGH',
            confidence: pattern.confidence,
            line: index + 1,
            code: line.trim(),
            description: pattern.description,
            file: filePath,
            engine: 'xss-reflected',
            requiresTaintConfirmation: pattern.requiresTaintConfirmation || false,
            remediation: {
              fix: 'htmlspecialchars($input, ENT_QUOTES, \'UTF-8\')',
              description: 'Encode output with htmlspecialchars() before rendering',
            }
          });
          break; // One finding per line to avoid duplicates
        }
      }
    });

    return findings;
  }

  /**
   * Check if a line is within an output context (nearby echo/print)
   */
  _isInOutputContext(lines, lineIndex) {
    const start = Math.max(0, lineIndex - 3);
    const end = Math.min(lines.length, lineIndex + 3);
    for (let i = start; i < end; i++) {
      if (/echo|print|printf|<\?=|\.=\s*['"]</.test(lines[i])) {
        return true;
      }
    }
    return false;
  }
}

module.exports = ReflectedXSSDetector;
