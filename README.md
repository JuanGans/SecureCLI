# 🔐 SecureCLI - Hybrid SAST Vulnerability Scanner

Professional enterprise-grade Static Application Security Testing (SAST) engine for detecting SQL Injection and Cross-Site Scripting (XSS) vulnerabilities in JavaScript and PHP applications.

## ✨ Features

- **5-Layer Architecture**: Professional layered detection approach
  - Layer 1: Detection (Regex, Taint Analysis, AST)
  - Layer 2: Classification (SQLi types, XSS types)
  - Layer 3: Scoring (Risk, Confidence, Exploitability)
  - Layer 4: Reporting (Multi-format generation)
  - Layer 5: Presentation (CLI, JSON, HTML output)

- **Multiple Detection Engines**
  - ✅ **Regex Engine**: Pattern-based detection with 20+ signatures
  - ✅ **Taint Analysis**: Data flow tracking from sources to sinks
  - ✅ **AST Analysis**: Abstract Syntax Tree analysis (extensible)

- **SQL Injection Detection**
  - UNION-based attacks
  - Time-based blind injection
  - Boolean-based injection
  - Error-based injection
  - Stacked queries

- **XSS Detection**
  - Reflected XSS
  - Stored XSS
  - DOM-based XSS
  - Event handler injection
  - JavaScript protocol URLs

- **Advanced Scoring**
  - Severity-based risk calculation
  - Confidence metrics
  - Exploitability assessment
  - OWASP Top 10 mapping

- **Educational Reporting**
  - Detailed vulnerability explanations
  - Code examples (vulnerable & secure)
  - Remediation guidance
  - References and best practices

## 📦 Installation

```bash
# Clone repository
git clone https://github.com/security-team/securecli.git
cd securecli

# Install dependencies
npm install

# Make CLI executable (Unix/Mac)
chmod +x bin/securecli.js

# Install globally
npm install -g .
```

## 🚀 Quick Start

```bash
# Scan a single file
securecli app.js

# Scan entire directory
securecli /path/to/project

# Verbose mode with full explanations
securecli app.js --verbose

# Output to JSON
securecli app.js --format json

# Save reports to directory
securecli app.js -o ./security-reports
```

## 📋 Usage

```
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
```

## 🏗️ Project Structure

```
securecli/
│
├── bin/
│   └── securecli.js              # CLI entry point
│
├── src/
│   ├── core/
│   │   ├── orchestrator.js        # 5-layer coordinator
│   │   ├── scanner.js             # Detection orchestrator
│   │   └── fileLoader.js          # File system utilities
│   │
│   ├── engines/
│   │   ├── regex/
│   │   │   ├── sqlPatterns.js     # SQL injection patterns
│   │   │   ├── xssPatterns.js     # XSS patterns
│   │   │   └── regexEngine.js     # Pattern matching engine
│   │   └── taint/
│   │       ├── sourceSinkMap.js   # Source/sink definitions
│   │       └── taintAnalyzer.js   # Data flow tracking
│   │
│   ├── vulnerabilities/
│   │   ├── sqli/                  # SQL injection classifiers
│   │   └── xss/                   # XSS classifiers
│   │
│   ├── scoring/
│   │   └── riskScorer.js          # Risk calculation
│   │
│   ├── reporting/
│   │   ├── reportGenerator.js     # Report generation
│   │   └── educationalTemplates.json # Learning materials
│   │
│   ├── owasp/
│   │   └── owaspMapper.js         # OWASP Top 10 mapping
│   │
│   ├── utils/
│   │   ├── colors.js              # Terminal colors
│   │   ├── logger.js              # Logging system
│   │   └── helpers.js             # Utility functions
│   │
│   └── config/
│       └── config.js               # Configuration
│
├── examples/
│   ├── vulnerable-sqli.js
│   └── vulnerable-xss.js
│
├── package.json
├── README.md
└── LICENSE
```

## 🔍 Detection Examples

### SQL Injection Detection

```javascript
// ❌ VULNERABLE
const query = "SELECT * FROM users WHERE id = " + userId;
db.query(query);

// ✅ SECURE
const query = "SELECT * FROM users WHERE id = ?";
db.query(query, [userId]);
```

### XSS Detection

```javascript
// ❌ VULNERABLE
res.send("<h1>Hello " + userName + "</h1>");

// ✅ SECURE
const escapeHtml = require('escape-html');
res.send(`<h1>Hello ${escapeHtml(userName)}</h1>`);
```

## 📊 Output Examples

### CLI Output
```
☐ VULNERABILITY #1
   File: app.js
   Line: 12
   Type: SQLI_UNION
   Severity: CRITICAL
   Risk Score: 9/10
   Confidence: 95%
```

### JSON Output
```json
[
  {
    "type": "SQLI_UNION",
    "severity": "CRITICAL",
    "line": 12,
    "file": "app.js",
    "riskScore": 9
  }
]
```

## 🧪 Testing

```bash
# Run all tests
npm test

# Run specific test suite
npm run test:regex
npm run test:taint
npm run test:scoring

# Scan examples
npm run scan:examples
```

## 🎯 Vulnerability Types

### SQL Injection (SQLi)
- **SQLI_UNION**: UNION SELECT attacks
- **SQLI_TIME**: Time-based blind injections
- **SQLI_BOOLEAN**: Boolean-based logic manipulation
- **SQLI_ERROR**: Error-based information extraction
- **SQLI_STACKED**: Multiple statement execution

### Cross-Site Scripting (XSS)
- **XSS_REFLECTED**: Script in HTTP response
- **XSS_STORED**: Persistent script in database
- **XSS_DOM**: DOM element manipulation
- **XSS_EVENT_HANDLER**: Event handler injection
- **XSS_PROTOCOL**: JavaScript protocol URLs

## 📈 Risk Scoring

Risk Score = (Base Severity Weight × Confidence) × Detection Boost

| Severity | Weight | Example |
|----------|--------|---------|
| CRITICAL | 10     | UNION SELECT, Time-based SQLi |
| HIGH     | 8      | Error-based SQLi, Reflected XSS |
| MEDIUM   | 6      | Boolean-based SQLi, DOM XSS |
| LOW      | 3      | Information disclosure |

## 🔐 OWASP Mapping

All detected vulnerabilities are mapped to OWASP Top 10 2021:
- **A03:2021 – Injection**: SQL Injection, Command Injection
- Includes CWE references for comprehensive tracking

## 📚 Educational Resources

Every finding includes:
- Detailed vulnerability explanation
- Code examples (vulnerable & secure)
- Impact assessment
- Remediation steps
- References to OWASP & security best practices

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional detection patterns
- PHP support expansion
- Performance optimization
- Additional output formats (HTML, XML)
- Machine learning-based classification

## 📄 License

MIT License - See LICENSE file for details

## ⚠️ Disclaimer

This tool is designed for security research and authorized testing only. Users are responsible for ensuring they have proper authorization before scanning any applications. Unauthorized security testing is illegal.

## 📞 Support

- Documentation: See README.md and inline code comments
- Issues: Report on GitHub
- Security: Report security issues privately

---

**SecureCLI** - Making application security accessible through professional SAST analysis.
  