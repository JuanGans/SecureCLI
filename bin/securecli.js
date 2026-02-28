#!/usr/bin/env node

/**
 * SecureCLI - Hybrid SAST Vulnerability Scanner
 * Professional Enterprise-Grade Static Application Security Testing
 * 
 * Execution Flow:
 * Layer 1 → Detection (Regex, Taint, AST)
 * Layer 2 → Classification (SQLi, XSS categorization)
 * Layer 3 → Scoring (Risk, Confidence, Exploitability)
 * Layer 4 → Reporting (Generation, Formatting)
 * Layer 5 → Presentation (CLI, JSON, HTML output)
 */

const path = require('path');
const Orchestrator = require('../src/core/orchestrator');
const { parseArgs } = require('../src/utils/helpers');
const { log } = require('../src/utils/colors');
const config = require('../src/config/config');

/**
 * Display help information
 */
function displayHelp() {
  console.log(`
  ╔════════════════════════════════════════════════════════════╗
  ║          🔐 SecureCLI - Vulnerability Scanner 🔐           ║
  ║         Hybrid SAST Engine for JavaScript/PHP             ║
  ╚════════════════════════════════════════════════════════════╝

  Usage: securecli [options] <target>

  Arguments:
    <target>              File or directory to scan

  Options:
    -v, --verbose         Enable verbose output with full explanations
    -o, --output <path>   Save reports to specified directory
    --format <fmt>        Output format: cli, json (default: cli)
    -h, --help            Display this help message
    --version             Display version information

  Examples:
    securecli /path/to/app
    securecli app.js --verbose -o ./reports
    securecli /path/to/code --format json

  Layers of Analysis:
    Layer 1: Detection    → Regex, Taint Analysis, AST Parsing
    Layer 2: Classification → SQLi, XSS Type Detection
    Layer 3: Scoring     → Risk & Confidence Calculation
    Layer 4: Reporting   → Report Generation
    Layer 5: Presentation → Output Formatting (CLI/JSON/HTML)
  `);
}

/**
 * Display version
 */
function displayVersion() {
  console.log(`\n${config.app.name} v${config.app.version}`);
  console.log(`${config.app.description}\n`);
}

/**
 * Main execution
 */
async function main() {
  const args = parseArgs(process.argv);

  // Handle help
  if (process.argv.includes('-h') || process.argv.includes('--help')) {
    displayHelp();
    process.exit(0);
  }

  // Handle version
  if (process.argv.includes('--version')) {
    displayVersion();
    process.exit(0);
  }

  // Validate target
  if (!args.target) {
    log.error('❌ Error: No target specified');
    console.log('\nUsage: securecli [options] <target>\n');
    displayHelp();
    process.exit(1);
  }

  try {
    const orchestrator = new Orchestrator({
      verbose: args.verbose,
      format: args.format,
    });

    console.log(`\n  🔍 Starting scan on: ${args.target}\n`);

    const result = await orchestrator.orchestrate(args.target, args.output);

    // Display CLI report
    if (args.format === 'cli' || !args.format) {
      console.log(result.reports.cli);
    } else if (args.format === 'json') {
      console.log(result.reports.json);
    }

    // Exit with appropriate code
    process.exit(result.findings.length > 0 ? 1 : 0);
  } catch (error) {
    log.error(`Fatal error: ${error.message}`);
    if (args.verbose) {
      console.error(error.stack);
    }
    process.exit(2);
  }
}

// Run main
main();
