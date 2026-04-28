/**
 * XSS Finding Consolidator
 * Deduplicates and merges XSS findings from multiple engines
 * (Reflected, Stored, DOM-Based, Event Handler + Taint Analysis)
 * ENHANCED: Filters out SQLi misclassifications
 */

class XSSConsolidator {
  /**
   * Consolidate XSS findings - removes duplicates, keeps highest confidence
   * ENHANCED: Only consolidate actual XSS findings
   * @param {Array} findings - All findings from different XSS engines
   * @returns {Array} Deduplicated findings
   */
  static consolidate(findings) {
    const xssFindings = findings.filter(f => {
      const type = (f.type || '').toUpperCase();
      // Only include actual XSS types, NOT SQLi types
      return type.includes('XSS') && !type.includes('SQLI');
    });
    const nonXss = findings.filter(f => {
      const type = (f.type || '').toUpperCase();
      return !type.includes('XSS') || type.includes('SQLI');
    });

    const deduplicated = XSSConsolidator.deduplicate(xssFindings);
    return [...nonXss, ...deduplicated];
  }

  /**
   * Remove duplicate XSS findings from different engines
   */
  static deduplicate(findings) {
    const unique = [];

    for (const finding of findings) {
      const duplicateIdx = unique.findIndex(existing =>
        XSSConsolidator.isSameFinding(existing, finding)
      );

      if (duplicateIdx === -1) {
        unique.push(finding);
      } else if (finding.confidence > unique[duplicateIdx].confidence) {
        unique[duplicateIdx] = XSSConsolidator.mergeFinding(unique[duplicateIdx], finding);
      } else {
        unique[duplicateIdx] = XSSConsolidator.mergeFinding(finding, unique[duplicateIdx]);
      }
    }

    return unique;
  }

  /**
   * Check if two XSS findings are the same vulnerability
   */
  static isSameFinding(a, b) {
    // Ensure both are XSS and not SQLi
    if (!((a.type || '').includes('XSS') && (b.type || '').includes('XSS'))) {
      return false;
    }
    if ((a.type || '').includes('SQLI') || (b.type || '').includes('SQLI')) {
      return false;
    }


    // STRICT: Same file + same line - definitely same finding
    if (a.file === b.file && a.line === b.line) {
      console.log(`[XSS-DEDUP] Duplicate found at ${a.file}:${a.line}`);
      return true;
    }
    // Same variable and nearby lines
    if (a.variable && b.variable && a.variable === b.variable) {
      if (Math.abs((a.line || 0) - (b.line || 0)) <= 3) return true;
    }

    // Same sink on same line
    if (a.sink && b.sink && a.sink === b.sink && a.line === b.line) return true;

    return false;
  }

  /**
   * Merge two findings - keep primary, combine engine info
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
   * Classify XSS subtype based on context
   */
  static classifySubtype(finding) {
    const type = (finding.type || '').toUpperCase();

    if (type.includes('REFLECTED') || type === 'XSS_ECHO' || type === 'XSS_PRINT') {
      return 'REFLECTED';
    }
    if (type.includes('STORED')) {
      return 'STORED';
    }
    if (type.includes('DOM')) {
      return 'DOM';
    }
    if (type.includes('EVENT')) {
      return 'EVENT_HANDLER';
    }
    if (type === 'XSS_TAINTED_OUTPUT') {
      // Taint analysis - classify based on context
      if (finding.sourceType === 'URL_PARAMETER') return 'REFLECTED';
      if (finding.sourceType === 'POST_PARAMETER') return 'REFLECTED';
      return 'REFLECTED'; // Default for taint-detected XSS
    }

    return 'GENERIC';
  }
}

module.exports = XSSConsolidator;
