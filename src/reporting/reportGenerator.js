/**
 * LAYER 5: PRESENTATION - Report Generator
 */

const { severity: severityColors } = require('../utils/colors');
const { getLineContent, getContextLines, sanitizePath } = require('../utils/helpers');
const { getOWASPMapping } = require('../owasp/owaspMapper');
const templates = require('./educationalTemplates.json');

class ReportGenerator {
  constructor(verbose = false) {
    this.verbose = verbose;
  }

  getEducationTemplate(findingType) {
    if (templates.education[findingType]) {
      return templates.education[findingType];
    }

    if (findingType.startsWith('SQLI_')) {
      return templates.education.SQLI_GENERIC;
    }

    if (findingType.startsWith('XSS_')) {
      return templates.education.XSS_GENERIC;
    }

    return null;
  }

  formatRecommendations(education) {
    if (education?.recommendations?.length) {
      return education.recommendations.map(item => `   - ${item}`).join('\n') + '\n';
    }

    return [
      '   - Gunakan query terparameter (prepared statements)',
      '   - Validasi input dari pengguna sesuai kebutuhan bisnis',
      '   - Lakukan encoding output saat menampilkan data ke browser',
    ].join('\n') + '\n';
  }

  formatFixSnippet(education) {
    if (!education?.fixSnippet) {
      return '';
    }

    return `🛠️  Snippet Perbaikan:\n\n\`\`\`javascript\n${education.fixSnippet}\n\`\`\`\n\n`;
  }

  /**
   * Generate CLI report for findings
   */
  generateCLIReport(findings, sourceCode, filePath) {
    let report = '';

    findings.forEach((finding, index) => {
      report += this.generateFindingReport(finding, sourceCode, filePath, index + 1);
    });

    return report;
  }

  /**
   * Generate individual finding report
   */
  generateFindingReport(finding, sourceCode, filePath, index) {
    const owasp = getOWASPMapping(finding.type);
    const education = this.getEducationTemplate(finding.type);

    let report = '\n' + '='.repeat(60) + '\n';
    report += `🔴 VULNERABILITY #${index}\n`;
    report += '='.repeat(60) + '\n\n';

    // Header info
    report += `📁 File: ${sanitizePath(filePath)}\n`;
    report += `📍 Line: ${finding.line}\n`;
    report += `🏷️  Type: ${finding.type} (${finding.name || 'Unknown'})\n`;
    report += `🎯 Engine: ${finding.engine}\n\n`;

    // Severity badges
    report += `📊 Risk Assessment:\n`;
    report += `   Severity: ${severityColors[finding.severity] || finding.severity}\n`;
    report += `   Risk Score: ${finding.riskScore}/10\n`;
    report += `   Confidence: ${(finding.confidence * 100).toFixed(0)}%\n`;
    report += `   Exploitability: ${finding.exploitability}/10\n\n`;

    // OWASP Classification
    report += `🏛️  OWASP Classification:\n`;
    report += `   Category: ${owasp.category}\n`;
    report += `   CWE: ${owasp.cwe}\n\n`;

    // Code context
    if (sourceCode) {
      const contextLines = getContextLines(sourceCode, finding.line, 2);
      report += `📝 Code Context:\n`;
      contextLines.forEach(line => {
        const marker = line.isTarget ? '>>> ' : '    ';
        report += `${marker}${String(line.lineNumber).padStart(4)}: ${line.content}\n`;
      });
      report += '\n';
    }

    // Penjelasan
    if (education) {
      report += `📘 Penjelasan:\n`;
      report += `   ${education.explanation}\n\n`;

      if (this.verbose) {
        report += `📚 Detail Tambahan:\n`;
        report += `   ${education.title}\n`;
        report += `   Dampak: ${education.impact}\n\n`;
      }
    } else {
      report += `📘 Penjelasan:\n`;
      report += `   Pola kode ini terdeteksi berisiko dan berpotensi membuka celah keamanan jika input pengguna tidak diproses dengan aman.\n\n`;
    }

    // Recommendations
    report += `💡 Rekomendasi:\n`;
    report += this.formatRecommendations(education) + '\n';

    // Context-aware fix (if available from template engine)
    if (finding.contextAwareFix) {
      report += this.formatContextAwareFix(finding.contextAwareFix);
    } else {
      report += this.formatFixSnippet(education);
    }

    return report;
  }

  /**
   * Format context-aware fix snippet (PHASE 3 & 4 integration)
   */
  formatContextAwareFix(fix) {
    if (!fix) return '';

    let output = `🔧 Context-Aware Fix (${fix.name}):\n\n`;
    output += `   ${fix.description}\n\n`;
    output += `   Confidence: ${(fix.confidence * 100).toFixed(0)}%\n\n`;
    output += `🛠️  Recommended Code:\n\n\`\`\`\n${fix.code}\n\`\`\`\n\n`;
    
    if (fix.example && fix.example !== fix.code) {
      output += `📖 Example:\n\n\`\`\`\n${fix.example}\n\`\`\`\n\n`;
    }

    return output;
  }

  /**
   * Generate JSON report (PHASE 4: Structured Output)
   */
  generateJSONReport(findings) {
    return JSON.stringify(
      findings.map(finding => this.generateStructuredFinding(finding)),
      null,
      2
    );
  }

  /**
   * Generate structured finding with complete information
   * PHASE 4: Complete structured JSON output
   */
  generateStructuredFinding(finding) {
    const owasp = getOWASPMapping(finding.type);
    const education = this.getEducationTemplate(finding.type);

    return {
      // Core vulnerability info
      vulnerability: finding.name || finding.type,
      type: finding.type,
      severity: finding.severity,
      confidence: finding.confidence || 0.8,
      
      // Location info
      file: finding.file,
      line: finding.line,
      
      // Detection info
      engine: finding.engine,
      flow: finding.flow,
      
      // Risk assessment
      riskScore: finding.riskScore,
      exploitability: finding.exploitability,
      
      // Code context
      originalCode: finding.code || '',
      codeContext: finding.codeContext || null,
      
      // Classification
      owasp: {
        category: owasp.category,
        cwe: owasp.cwe,
        rank: owasp.rank || null,
      },
      
      // Educational content
      explanation: education?.explanation || 'Vulnerability detected',
      impact: education?.impact || 'Security risk',
      
      // Remediation (from template engine if available)
      remediation: finding.remediation || {
        description: education?.explanation || 'Follow security best practices',
        recommendations: education?.recommendations || [],
        fixSnippet: education?.fixSnippet || null,
      },
      
      // Context-aware fix (if available from context analyzer + template engine)
      contextAwareFix: finding.contextAwareFix || null,
      
      // Metadata
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Generate summary statistics
   */
  generateSummary(findings) {
    const stats = {
      totalFindings: findings.length,
      bySeverity: {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
      },
      byType: {},
      byEngine: {
        regex: 0,
        taint: 0,
        ast: 0,
      },
    };

    findings.forEach(finding => {
      stats.bySeverity[finding.severity]++;
      stats.byType[finding.type] = (stats.byType[finding.type] || 0) + 1;
      stats.byEngine[finding.engine]++;
    });

    return stats;
  }
}

module.exports = ReportGenerator;
