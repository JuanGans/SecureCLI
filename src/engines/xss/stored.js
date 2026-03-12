/**
 * Stored XSS Detection Engine
 * Detects stored XSS where user input is saved to database then output
 * 
 * Attack vector: POST data → INSERT into DB → SELECT + echo to all users
 * PHP context: $_POST → INSERT INTO → SELECT → echo without encoding
 */

class StoredXSSDetector {
  constructor() {
    // Patterns for data storage (input side)
    this.storagePatterns = [
      {
        name: 'INSERT with Superglobal',
        regex: /INSERT\s+INTO\s+.*\$_(GET|POST|REQUEST)/i,
        confidence: 0.85,
      },
      {
        name: 'INSERT with Variable',
        regex: /INSERT\s+INTO\s+\w+.*VALUES\s*\([^)]*\$\w+/i,
        confidence: 0.75,
        requiresTaintConfirmation: true,
      },
      {
        name: 'Database Execute INSERT',
        regex: /(mysql_query|mysqli_query|->query|->execute)\s*\([^)]*INSERT[^)]*\$\w+/i,
        confidence: 0.80,
      },
      {
        name: 'Database Execute with $query containing INSERT',
        regex: /(mysql_query|mysqli_query|->query|->execute)\s*\([^)]*\$query/i,
        confidence: 0.70,
        requiresInsertContext: true,
      },
    ];

    // Patterns for data output without encoding (output side)
    this.outputPatterns = [
      {
        name: 'Echo Database Row Field',
        regex: /echo\s+[^;]*\$row\s*\[/i,
        negativeRegex: /htmlspecialchars|htmlentities/i,
        confidence: 0.82,
      },
      {
        name: 'Echo Fetch Result Variable',
        regex: /echo\s+[^;]*\$(result|data|record|item|entry|comment|name|message|content)\s*[\[;]/i,
        negativeRegex: /htmlspecialchars|htmlentities/i,
        confidence: 0.75,
      },
      {
        name: 'Interpolated DB Variable in Echo',
        regex: /echo\s+["'][^"']*\{\$\w+\}[^"']*["']/i,
        negativeRegex: /htmlspecialchars|htmlentities/i,
        confidence: 0.72,
      },
      {
        name: 'Concat DB Variable in Echo',
        regex: /echo\s+.*\.\s*\$(row|result|data|record)\s*\[/i,
        negativeRegex: /htmlspecialchars|htmlentities/i,
        confidence: 0.78,
      },
    ];

    // Context: fetch loop (indicates DB retrieval)
    this.fetchPatterns = [
      /while\s*\(\s*\$\w+\s*=\s*(mysqli_fetch|mysql_fetch|->fetch)/i,
      /foreach\s*\(\s*\$\w+\s+as\s+\$row/i,
      /\$\w+\s*=\s*(mysqli_fetch_assoc|mysqli_fetch_array|->fetch)/i,
    ];
  }

  /**
   * Detect stored XSS patterns in PHP code
   */
  detect(code, filePath = '') {
    const findings = [];
    const lines = code.split('\n');

    // Phase 1: Find storage points (INSERT with user data)
    const storagePoints = this._findStoragePoints(lines, filePath);

    // Phase 2: Find output points (echo from DB results without encoding)
    const outputPoints = this._findOutputPoints(lines, code, filePath);

    // Phase 3: Has database fetch context?
    const hasFetchContext = this.fetchPatterns.some(p => p.test(code));

    // Phase 4: Correlate findings
    if (storagePoints.length > 0 && outputPoints.length > 0) {
      // Both storage and output - high confidence stored XSS
      outputPoints.forEach(point => {
        findings.push({
          ...point,
          type: 'XSS_STORED',
          confidence: Math.min(0.95, point.confidence + 0.10),
          storedXSSConfirmed: true,
          relatedStoragePoints: storagePoints.map(s => s.line),
        });
      });
    } else if (outputPoints.length > 0 && hasFetchContext) {
      // Output from DB without encoding - medium confidence
      outputPoints.forEach(point => {
        findings.push({
          ...point,
          type: 'XSS_STORED_OUTPUT',
          note: 'Database output without encoding - check if stored data is sanitized',
        });
      });
    } else if (storagePoints.length > 0) {
      // Only storage side visible
      storagePoints.forEach(point => {
        findings.push({
          ...point,
          note: 'User data stored without XSS sanitization - check output points',
        });
      });
    }

    return findings;
  }

  _findStoragePoints(lines, filePath) {
    const points = [];
    const fullCode = lines.join('\n');
    const hasInsertQuery = /INSERT\s+INTO/i.test(fullCode);

    lines.forEach((line, index) => {
      for (const pattern of this.storagePatterns) {
        if (pattern.regex.test(line)) {
          // For patterns that require INSERT context, check if code has INSERT statement
          if (pattern.requiresInsertContext && !hasInsertQuery) {
            continue;
          }

          // Check if the INSERT destination data has NO htmlspecialchars
          // Only flag if there's no proper XSS encoding before storage
          const hasXSSEncoding = this._hasXSSEncodingBeforeLine(lines, index);

          points.push({
            type: 'XSS_STORED_INPUT',
            subtype: 'STORED',
            name: `Stored XSS (Input): ${pattern.name}`,
            severity: 'HIGH',
            confidence: hasXSSEncoding ? pattern.confidence * 0.5 : pattern.confidence,
            line: index + 1,
            code: line.trim(),
            description: hasXSSEncoding
              ? 'User input stored after partial encoding — verify all fields are encoded'
              : 'User input stored in database without XSS sanitization',
            file: filePath,
            engine: 'xss-stored',
            requiresTaintConfirmation: pattern.requiresTaintConfirmation || false,
          });
          break;
        }
      }
    });

    return points;
  }

  /**
   * Check if there's htmlspecialchars encoding before the given line index
   */
  _hasXSSEncodingBeforeLine(lines, targetIndex) {
    for (let i = 0; i < targetIndex; i++) {
      if (/htmlspecialchars|htmlentities/.test(lines[i])) {
        return true;
      }
    }
    return false;
  }

  _findOutputPoints(lines, code, filePath) {
    const points = [];

    lines.forEach((line, index) => {
      for (const pattern of this.outputPatterns) {
        if (pattern.regex.test(line)) {
          if (pattern.negativeRegex && pattern.negativeRegex.test(line)) {
            continue;
          }

          points.push({
            type: 'XSS_STORED_OUTPUT',
            subtype: 'STORED',
            name: `Stored XSS (Output): ${pattern.name}`,
            severity: 'HIGH',
            confidence: pattern.confidence,
            line: index + 1,
            code: line.trim(),
            description: 'Database result output without htmlspecialchars encoding',
            file: filePath,
            engine: 'xss-stored',
            remediation: {
              fix: 'htmlspecialchars($row[\'column\'], ENT_QUOTES, \'UTF-8\')',
              description: 'Encode database output before rendering in HTML',
            }
          });
          break;
        }
      }
    });

    return points;
  }
}

module.exports = StoredXSSDetector;
