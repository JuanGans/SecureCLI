/**
 * DVWA Detection Test Suite
 * Tests against real DVWA installation at C:\xampp\htdocs\DVWA\vulnerabilities\
 * 
 * Expected results:
 * - SQLi low/medium/high: TRUE POSITIVE (should detect SQLi)
 * - SQLi impossible: TRUE NEGATIVE (0 SQLi findings)
 * - XSS Reflected low/medium/high: TRUE POSITIVE (should detect XSS)
 * - XSS Reflected impossible: TRUE NEGATIVE (0 XSS findings)
 * - XSS Stored low: TRUE POSITIVE (stored XSS risk)
 * - XSS Stored medium/high: TRUE POSITIVE (bypassable sanitization on $name)
 * - XSS DOM index.php: TRUE POSITIVE (document.write with location.href)
 * 
 * Run: node tests/test-dvwa.js
 */

const path = require('path');
const Scanner = require('../src/core/scanner');

const DVWA_BASE = 'C:\\xampp\\htdocs\\DVWA\\vulnerabilities';

const scanner = new Scanner({ verbose: false });

// Test definitions
const tests = [
  // === SQLi Tests ===
  {
    name: 'SQLi Low',
    file: path.join(DVWA_BASE, 'sqli', 'source', 'low.php'),
    expectVuln: true,
    vulnType: 'SQLI',
    description: '$_REQUEST[id] directly in SQL query without sanitization',
  },
  {
    name: 'SQLi Medium',
    file: path.join(DVWA_BASE, 'sqli', 'source', 'medium.php'),
    expectVuln: true,
    vulnType: 'SQLI',
    description: 'mysqli_real_escape_string but unquoted numeric context — still vulnerable',
  },
  {
    name: 'SQLi High',
    file: path.join(DVWA_BASE, 'sqli', 'source', 'high.php'),
    expectVuln: true,
    vulnType: 'SQLI',
    description: '$_SESSION[id] in SQL query — tainted via session manipulation',
  },
  {
    name: 'SQLi Impossible',
    file: path.join(DVWA_BASE, 'sqli', 'source', 'impossible.php'),
    expectVuln: false,
    vulnType: 'SQLI',
    description: 'PDO prepared statement with bindParam — properly secured',
  },

  // === XSS Reflected Tests ===
  {
    name: 'XSS Reflected Low',
    file: path.join(DVWA_BASE, 'xss_r', 'source', 'low.php'),
    expectVuln: true,
    vulnType: 'XSS',
    description: '$_GET[name] directly concatenated in output without encoding',
  },
  {
    name: 'XSS Reflected Medium',
    file: path.join(DVWA_BASE, 'xss_r', 'source', 'medium.php'),
    expectVuln: true,
    vulnType: 'XSS',
    description: 'str_replace(<script>) is bypassable — <ScRiPt> or <img onerror=...>',
  },
  {
    name: 'XSS Reflected High',
    file: path.join(DVWA_BASE, 'xss_r', 'source', 'high.php'),
    expectVuln: true,
    vulnType: 'XSS',
    description: 'preg_replace for script tags only — bypassable via event handlers',
  },
  {
    name: 'XSS Reflected Impossible',
    file: path.join(DVWA_BASE, 'xss_r', 'source', 'impossible.php'),
    expectVuln: false,
    vulnType: 'XSS',
    description: 'htmlspecialchars() — properly encoded output',
  },

  // === XSS Stored Tests ===
  {
    name: 'XSS Stored Low',
    file: path.join(DVWA_BASE, 'xss_s', 'source', 'low.php'),
    expectVuln: true,
    vulnType: 'XSS',
    description: 'INSERT without htmlspecialchars — stored XSS risk',
  },
  {
    name: 'XSS Stored Medium',
    file: path.join(DVWA_BASE, 'xss_s', 'source', 'medium.php'),
    expectVuln: true,
    vulnType: 'XSS',
    description: '$name only has str_replace(<script>) — bypassable stored XSS',
  },
  {
    name: 'XSS Stored High',
    file: path.join(DVWA_BASE, 'xss_s', 'source', 'high.php'),
    expectVuln: true,
    vulnType: 'XSS',
    description: '$name only has preg_replace for script — bypassable stored XSS',
  },

  // === XSS DOM Test ===
  {
    name: 'XSS DOM index.php',
    file: path.join(DVWA_BASE, 'xss_d', 'index.php'),
    expectVuln: true,
    vulnType: 'XSS',
    description: 'document.write with location.href — DOM-based XSS',
  },
];

// Run tests
console.log('='.repeat(80));
console.log('  SecureCLI — DVWA Detection Test Suite');
console.log('  Target: C:\\xampp\\htdocs\\DVWA\\vulnerabilities\\');
console.log('='.repeat(80));
console.log('');

let passed = 0;
let failed = 0;
const failures = [];
let tp = 0, fp = 0, fn = 0, tn = 0;

for (const test of tests) {
  try {
    const findings = scanner.scanFile(test.file);

    // Filter findings by vulnerability type
    const relevantFindings = findings.filter(f => {
      const type = (f.type || '').toUpperCase();
      if (test.vulnType === 'SQLI') {
        return type.includes('SQLI');
      }
      if (test.vulnType === 'XSS') {
        return type.includes('XSS');
      }
      return false;
    });

    const hasVuln = relevantFindings.length > 0;
    const testPassed = hasVuln === test.expectVuln;

    // Confusion matrix
    if (test.expectVuln && hasVuln) tp++;
    else if (test.expectVuln && !hasVuln) fn++;
    else if (!test.expectVuln && hasVuln) fp++;
    else tn++;

    if (testPassed) {
      passed++;
      console.log(`  [PASS] ${test.name}`);
      if (hasVuln) {
        const topFinding = relevantFindings.sort((a, b) => (b.confidence || 0) - (a.confidence || 0))[0];
        console.log(`         -> ${topFinding.type} | confidence: ${(topFinding.confidence * 100).toFixed(0)}% | line: ${topFinding.line}`);
        if (relevantFindings.length > 1) {
          console.log(`         -> (${relevantFindings.length} total findings)`);
        }
      } else {
        console.log(`         -> No ${test.vulnType} findings (correct: true negative)`);
      }
    } else {
      failed++;
      const reason = test.expectVuln
        ? `Expected ${test.vulnType} but found 0 (FALSE NEGATIVE)`
        : `Expected 0 ${test.vulnType} but found ${relevantFindings.length} (FALSE POSITIVE)`;
      console.log(`  [FAIL] ${test.name}`);
      console.log(`         -> ${reason}`);
      console.log(`         -> ${test.description}`);

      if (!test.expectVuln && relevantFindings.length > 0) {
        relevantFindings.forEach(f => {
          console.log(`         -> FP: ${f.type} @ line ${f.line} (${((f.confidence || 0) * 100).toFixed(0)}%)`);
        });
      }

      failures.push({ test: test.name, reason });
    }
  } catch (err) {
    failed++;
    console.log(`  [ERR]  ${test.name}`);
    console.log(`         -> ${err.message}`);
    failures.push({ test: test.name, reason: err.message });
    if (test.expectVuln) fn++;
    else tn++;
  }
}

// Summary
console.log('');
console.log('='.repeat(80));
const total = passed + failed;
const passRate = ((passed / total) * 100).toFixed(1);
console.log(`  Results: ${passed}/${total} passed (${passRate}%)`);

if (failures.length > 0) {
  console.log('');
  console.log('  Failures:');
  failures.forEach(f => {
    console.log(`    - ${f.test}: ${f.reason}`);
  });
}

const precision = tp / (tp + fp) || 0;
const recall = tp / (tp + fn) || 0;
const f1 = (2 * precision * recall) / (precision + recall) || 0;

console.log('');
console.log('  Detection Metrics:');
console.log(`    True Positives:  ${tp}`);
console.log(`    False Positives: ${fp}`);
console.log(`    True Negatives:  ${tn}`);
console.log(`    False Negatives: ${fn}`);
console.log(`    Precision: ${(precision * 100).toFixed(1)}%`);
console.log(`    Recall:    ${(recall * 100).toFixed(1)}%`);
console.log(`    F1-Score:  ${(f1 * 100).toFixed(1)}%`);
console.log('='.repeat(80));

process.exit(failed > 0 ? 1 : 0);
