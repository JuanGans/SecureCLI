# SecureCLI - Architecture Overview

## 5-Layer Professional Architecture

```
┌─────────────────────────────────────────────────────┐
│ LAYER 5: PRESENTATION                               │
│ Output Formatting (CLI, JSON, HTML, XML)            │
│ ✓ Color-coded terminal output                       │
│ ✓ Structured JSON export                            │
│ ✓ Statistics and summary                            │
└─────────────────────────────────────────────────────┘
                           ↑
┌─────────────────────────────────────────────────────┐
│ LAYER 4: REPORTING                                  │
│ Report Generation & Documentation                   │
│ ✓ Finding reports with context                      │
│ ✓ Educational templates                             │
│ ✓ Remediation guidance                              │
│ ✓ OWASP mapping                                     │
└─────────────────────────────────────────────────────┘
                           ↑
┌─────────────────────────────────────────────────────┐
│ LAYER 3: SCORING                                    │
│ Risk Assessment & Confidence Calculation            │
│ ✓ Severity-based risk scoring (1-10)                │
│ ✓ Confidence metrics                                │
│ ✓ Exploitability assessment                         │
│ ✓ Impact level determination                        │
└─────────────────────────────────────────────────────┘
                           ↑
┌─────────────────────────────────────────────────────┐
│ LAYER 2: CLASSIFICATION                             │
│ Vulnerability Type Identification                   │
│ ✓ SQL Injection variants (5 types)                  │
│ ✓ XSS variants (3-5 types)                          │
│ ✓ Source/Sink classification                        │
│ ✓ Attack vector categorization                      │
└─────────────────────────────────────────────────────┘
                           ↑
┌─────────────────────────────────────────────────────┐
│ LAYER 1: DETECTION                                  │
│ Vulnerability Identification                        │
│ ┌──────────────────────────────────────────────┐   │
│ │ Regex Engine          │ Pattern Matching      │   │
│ │ • 20+ signatures      │ • Fast scanning       │   │
│ │ • SQL patterns        │ • Low false positives │   │
│ │ • XSS patterns        │                       │   │
│ └──────────────────────────────────────────────┘   │
│ ┌──────────────────────────────────────────────┐   │
│ │ Taint Analyzer        │ Data Flow Analysis    │   │
│ │ • Source tracking     │ • Intermediate nodes  │   │
│ │ • Sink detection      │ • Flow visualization  │   │
│ │ • Propagation rules   │ • Deep inspection     │   │
│ └──────────────────────────────────────────────┘   │
│ ┌──────────────────────────────────────────────┐   │
│ │ AST Parser            │ Semantic Analysis     │   │
│ │ • JavaScript parsing  │ • Code structure      │   │
│ │ • PHP support (ext)   │ • Context awareness   │   │
│ │ • Control flow        │                       │   │
│ └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
                           ↑
┌─────────────────────────────────────────────────────┐
│ SOURCE CODE                                         │
│ JavaScript, PHP, etc.                               │
└─────────────────────────────────────────────────────┘
```

## Data Flow Through Layers

```
Source Code File
      ↓
[LAYER 1] Detection Engines
      ├─→ Regex Engine: Pattern matches
      ├─→ Taint Analyzer: Flow findings
      └─→ AST Parser: Structural analysis
      ↓
Raw Findings {type, severity, confidence, line, engine}
      ↓
[LAYER 2] Classification
      ├─→ SQLi Classifier (Boolean, Union, Time, Error, Stacked)
      ├─→ XSS Classifier (Reflected, Stored, DOM)
      └─→ Categories findings by attack vector
      ↓
Classified Findings {type, category, cwe, attack_vector}
      ↓
[LAYER 3] Scoring
      ├─→ Risk Score Calculation (1-10)
      ├─→ Confidence Adjustment
      └─→ Exploitability Assessment
      ↓
Scored Findings {riskScore, confidence, exploitability, impact}
      ↓
[LAYER 4] Reporting
      ├─→ Gather OWASP Information
      ├─→ Generate Remediation Advice
      ├─→ Prepare Educational Content
      └─→ Format Finding Reports
      ↓
Report Data {findings, recommendations, education, owasp}
      ↓
[LAYER 5] Presentation
      ├─→ CLI Output (with colors)
      ├─→ JSON Export
      ├─→ HTML Report (future)
      └─→ Statistics Summary
      ↓
Final Output to User
```

## Key Components & Responsibilities

### Core Components
- **Orchestrator**: Coordinates all 5 layers, manages workflow
- **Scanner**: Runs detection engines on source code
- **FileLoader**: Handles file system traversal and access

### Detection Engines (Layer 1)
- **RegexEngine**: Fast pattern-based scanning
- **TaintAnalyzer**: Data flow tracking with AST
- **ASTParser**: Abstract syntax tree analysis (extensible)

### Classification (Layer 2)
- **SQL Injection Classifiers**
  - SQLiUnion: UNION-based attacks
  - SQLiTime: Time-based blind
  - SQLiBoolean: Boolean-based logic
  - SQLiError: Error-based extraction
  - SQLiStacked: Multiple statements

- **XSS Classifiers**
  - XSSReflected: Direct response injection
  - XSSStored: Database persistence
  - XSSDoM: DOM manipulation

### Scoring System (Layer 3)
- **RiskScorer**
  - Base severity weights (CRITICAL: 10, HIGH: 8, MEDIUM: 6, LOW: 3)
  - Confidence calculation with boosters
  - Exploitability assessment
  - Impact level determination

### Reporting (Layer 4)
- **ReportGenerator**: Formats findings with context
- **EducationalTemplates**: Learning materials for each vulnerability type
- **OWASPMapper**: Links vulnerabilities to OWASP categories and CWEs

### Presentation (Layer 5)
- **CLI Output**: Color-coded terminal display
- **JSON Export**: Machine-readable format
- **Summary Statistics**: Aggregated metrics
- **Educational Info**: Detailed explanations and fixes

## Configuration System

- **config.js**: Centralized configuration
  - App metadata
  - Scanning parameters
  - Detection settings
  - Scoring weights
  - Reporting options
  - Output formats

## Utility Systems

- **Logger**: Structured logging with levels
- **Colors**: Terminal color management
- **Helpers**: Common utility functions
  - Line content extraction
  - Context line retrieval
  - Path sanitization
  - Argument parsing

## Extension Points

Easy to extend for new:
- Vulnerability types (add classifiers)
- Detection patterns (add to regex engines)
- Scoring rules (modify risk scorer)
- Output formats (add presenters)
- Languages (add AST parsers)

---

This architecture ensures:
✅ Separation of concerns
✅ Testability of each layer
✅ Scalability and extensibility
✅ Professional-grade quality
✅ Educational value
