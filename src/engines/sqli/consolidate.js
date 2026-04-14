/**
 * SQLi Finding Consolidator
 * Deduplicates and merges SQL injection findings from multiple engines
 * Prevents duplicate vulnerability reports for the same sink
 * ENHANCED: Filters out XSS misclassifications
 */

class SQLiConsolidator {
  /**
   * Consolidate SQLi findings - removes duplicates, keeps highest confidence
   * ENHANCED: Separate XSS from SQLi findings
   * @param {Array} findings - All findings from different engines
   * @returns {Array} Deduplicated findings
   */
  static consolidate(findings) {
    const sqliFindings = findings.filter(f => {
      const type = (f.type || '').toUpperCase();
      // Only include actual SQLi types
      return type.includes('SQLI');
    });
    const nonSqli = findings.filter(f => {
      const type = (f.type || '').toUpperCase();
      return !type.includes('SQLI');
    });

    const deduplicated = SQLiConsolidator.deduplicate(sqliFindings);
    return [...deduplicated, ...nonSqli];
  }

  /**
   * Remove duplicate SQLi findings
   * Two findings are duplicates if they reference the same sink call
   */
  static deduplicate(findings) {
    const unique = [];

    for (const finding of findings) {
      const duplicateIdx = unique.findIndex(existing =>
        SQLiConsolidator.isSameFinding(existing, finding)
      );

      if (duplicateIdx === -1) {
        unique.push(finding);
      } else if (finding.confidence > unique[duplicateIdx].confidence) {
        // Higher confidence → replace but merge engine info
        unique[duplicateIdx] = SQLiConsolidator.mergeFinding(unique[duplicateIdx], finding);
      } else {
        // Lower confidence → just merge engine info into existing
        unique[duplicateIdx] = SQLiConsolidator.mergeFinding(finding, unique[duplicateIdx]);
      }
    }

    return unique;
  }

  /**
   * Check if two findings reference the same vulnerability
   */
  static isSameFinding(a, b) {
    // Ensure both are SQLi
    if (!((a.type || '').includes('SQLI') && (b.type || '').includes('SQLI'))) {
      return false;
    }

    // Same line and same type
    if (a.line === b.line && a.type === b.type) return true;

    // Same sink function and nearby lines (within 5 lines)
    if (a.sink && b.sink && a.sink === b.sink) {
      if (Math.abs((a.line || 0) - (b.line || 0)) <= 5) return true;
    }

    // Same variable chain leading to same sink
    if (a.variable && b.variable && a.sink && b.sink && a.sink === b.sink) {
      const chainA = a.chain || [a.variable];
      const chainB = b.chain || [b.variable];
      if (chainA.some(v => chainB.includes(v))) return true;
    }

    // Same type category on nearby lines with same proof sink
    if (a.proof && b.proof && a.proof.sink === b.proof.sink) {
      if (Math.abs((a.line || 0) - (b.line || 0)) <= 5) return true;
    }

    return false;
  }

  /**
   * Merge two findings - keep the primary, combine engine info
   */
  static mergeFinding(secondary, primary) {
    const engines = new Set([
      ...(primary.engines || [primary.engine]),
      ...(secondary.engines || [secondary.engine])
    ]);

    return {
      ...primary,
      engines: Array.from(engines).filter(Boolean),
      engine: Array.from(engines).filter(Boolean).join('+'),
      confidence: Math.max(primary.confidence || 0, secondary.confidence || 0),
    };
  }

  /**
   * Classify SQLi subtype based on query context
   */
  static classifySubtype(finding, code) {
    if (!code) return finding;

    const queryContext = SQLiConsolidator.extractQueryContext(code, finding.line);

    let subtype = 'CLASSIC';

    if (/UNION\s+SELECT/i.test(queryContext)) {
      subtype = 'UNION';
    } else if (/SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY|pg_sleep/i.test(queryContext)) {
      subtype = 'TIME_BASED';
    } else if (/\bOR\s+1\s*=\s*1\b|\bOR\s+TRUE\b|\bAND\s+1\s*=\s*1\b/i.test(queryContext)) {
      subtype = 'BOOLEAN';
    } else if (/;\s*(DROP|DELETE|UPDATE|INSERT|CREATE|ALTER)\b/i.test(queryContext)) {
      subtype = 'STACKED';
    } else if (/(extractvalue|updatexml|json_extract)\s*\(/i.test(queryContext)) {
      subtype = 'ERROR_BASED';
    } else if (/INSERT\s+INTO/i.test(queryContext)) {
      subtype = 'INSERT';
    } else if (/UPDATE\s+.*SET/i.test(queryContext)) {
      subtype = 'UPDATE';
    }

    return {
      ...finding,
      sqliSubtype: subtype
    };
  }

  /**
   * Extract SQL query context around a finding line
   */
  static extractQueryContext(code, line) {
    const lines = code.split('\n');
    const start = Math.max(0, (line || 1) - 3);
    const end = Math.min(lines.length, (line || 1) + 2);
    return lines.slice(start, end).join('\n');
  }

  /**
   * Check if sanitization is sufficient for the SQL context
   * e.g., mysqli_real_escape_string is NOT enough for unquoted numeric context
   */
  static isInsufficientSanitization(sanitizeFunc, queryContext) {
    // mysqli_real_escape_string only protects string context (quoted)
    // If the variable is used in numeric context without quotes, it's still vulnerable
    if (sanitizeFunc === 'mysqli_real_escape_string' || sanitizeFunc === 'mysql_real_escape_string') {
      // Check if variable is in unquoted numeric context
      // Pattern: WHERE id = $var (no quotes around $var)
      if (/WHERE\s+\w+\s*=\s*\$\w+/i.test(queryContext) && !/WHERE\s+\w+\s*=\s*['"]/.test(queryContext)) {
        return true; // Insufficient - numeric context without quotes
      }
    }
    return false;
  }
}

module.exports = SQLiConsolidator;
