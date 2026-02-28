/**
 * Main Orchestrator - Coordinates all layers
 * Layer: 1 (Detection) → 2 (Classification) → 3 (Scoring) → 4 (Reporting) → 5 (Presentation)
 */

const fs = require('fs');
const path = require('path');
const Scanner = require('./scanner');
const FileLoader = require('./fileLoader');
const ReportGenerator = require('../reporting/reportGenerator');
const Logger = require('../utils/logger');

class Orchestrator {
  constructor(options = {}) {
    this.options = options;
    this.scanner = new Scanner(options);
    this.reporter = new ReportGenerator(options.verbose);
    this.logger = new Logger(options.verbose);
    this.allFindings = [];
  }

  /**
   * Main entry point - executes all 5 layers
   */
  async orchestrate(target, outputPath = null) {
    this.logger.info(`Starting SecureCLI scan on ${target}`);

    try {
      // Load files
      const files = FileLoader.loadFiles(target);
      this.logger.success(`Found ${files.length} files to scan`);

      // Scan all files (LAYER 1: DETECTION)
      files.forEach(file => {
        const sourceCode = fs.readFileSync(file, 'utf-8');
        const fileFindings = this.scanner.scanFile(file);

        fileFindings.forEach(finding => {
          finding.file = file;
          this.allFindings.push(finding);
        });
      });

      // Generate reports (LAYER 4 & 5: REPORTING & PRESENTATION)
      const reports = this.generateReports(outputPath);

      this.logger.success(`Scan completed: ${this.allFindings.length} vulnerabilities found`);

      return {
        findings: this.allFindings,
        reports,
        summary: this.reporter.generateSummary(this.allFindings),
      };
    } catch (error) {
      this.logger.error(`Orchestration failed: ${error.message}`);
      throw error;
    }
  }

  /**
   * Generate reports in various formats
   */
  generateReports(outputPath) {
    const reports = {};

    // CLI Report
    let cliReport = '\n' + '═'.repeat(70) + '\n';
    cliReport += '         🔐  SECURECLI - VULNERABILITY SCAN REPORT  🔐\n';
    cliReport += '═'.repeat(70) + '\n\n';

    this.allFindings.forEach((finding, index) => {
      const sourceCode = fs.readFileSync(finding.file, 'utf-8');
      cliReport += this.reporter.generateFindingReport(
        finding,
        sourceCode,
        finding.file,
        index + 1
      );
    });

    cliReport += this.generateSummarySection();
    reports.cli = cliReport;

    // JSON Report
    reports.json = this.reporter.generateJSONReport(this.allFindings);

    // Save if output path provided
    if (outputPath) {
      fs.writeFileSync(path.join(outputPath, 'report.json'), reports.json);
      fs.writeFileSync(path.join(outputPath, 'report.txt'), cliReport);
      this.logger.success(`Reports saved to ${outputPath}`);
    }

    return reports;
  }

  /**
   * Generate summary section with statistics
   */
  generateSummarySection() {
    const summary = this.reporter.generateSummary(this.allFindings);

    let section = '\n' + '═'.repeat(70) + '\n';
    section += '📊 SCAN SUMMARY\n';
    section += '═'.repeat(70) + '\n\n';

    section += `Total Vulnerabilities Found: ${summary.totalFindings}\n\n`;

    section += `By Severity:\n`;
    Object.entries(summary.bySeverity).forEach(([level, count]) => {
      if (count > 0) {
        section += `  🔴 ${level.padEnd(10)}: ${count}\n`;
      }
    });

    section += `\nBy Detection Engine:\n`;
    Object.entries(summary.byEngine).forEach(([engine, count]) => {
      if (count > 0) {
        section += `  🔧 ${engine.toUpperCase().padEnd(10)}: ${count}\n`;
      }
    });

    section += `\nTop Vulnerability Types:\n`;
    Object.entries(summary.byType)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .forEach(([type, count]) => {
        section += `  • ${type}: ${count}\n`;
      });

    section += '\n' + '═'.repeat(70) + '\n';

    return section;
  }
}

module.exports = Orchestrator;
