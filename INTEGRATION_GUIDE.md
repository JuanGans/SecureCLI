# Integration Guide: Context-Aware Remediation System

## Quick Start

### 1. Basic Usage (No Changes Required)
The new context-aware remediation system is **automatically integrated** into the scanner:

```javascript
const Scanner = require('./src/core/scanner');
const scanner = new Scanner({ verbose: true });
const findings = scanner.scanFile('app.js');
```

The scanner automatically:
- Detects with Regex, AST, and Taint engines
- Analyzes context with ContextAnalyzer
- Generates fixes with TemplateEngine
- Reports with structured JSON

---

## 2. Using Context-Aware Findings in Code

### Getting the Context-Aware Fix

```javascript
const findings = scanner.scanFile('vulnerable.js');

findings.forEach(finding => {
  if (finding.contextAwareFix) {
    console.log(`Fix Strategy: ${finding.contextAwareFix.name}`);
    console.log(`Confidence: ${finding.contextAwareFix.confidence}`);
    console.log(`Code:\n${finding.contextAwareFix.code}`);
  }
});
```

### Example Output
```
Fix Strategy: MySQL Prepared Statement (mysqli)
Confidence: 0.85
Code:
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();
$result = $stmt->get_result();
```

---

## 3. Template Customization

### Adding a New Fix Strategy

**File:** `src/remediation/templates.json`

```json
{
  "sqli": {
    "my_custom_strategy": {
      "name": "My Custom Fix",
      "description": "Description of the fix",
      "template": "Code template with {{placeholders}}",
      "placeholders": {
        "conn": "Connection variable",
        "var": "User input variable"
      },
      "example": "Actual example code"
    }
  }
}
```

### Updating Context Analyzer Strategy

**File:** `src/context/contextAnalyzer.js`

```javascript
determineSQLIFixStrategy(apiContext) {
  const strategyMap = {
    'my-api': 'my_custom_strategy',
    'mysqli': 'mysqli_prepared',
    // ... existing mappings
  };
  
  return strategyMap[apiContext.api] || 'generic_prepared_statement';
}
```

---

## 4. Extending API Detection

### Adding New Database API

**File:** `src/engines/taint/taintAnalyzer.js` - `detectAPIContext()` method:

```javascript
detectAPIContext(node, sinkName) {
  // ... existing code ...
  
  if (sinkName.includes('mongodb') || sinkName.includes('mongo')) {
    return { api: 'mongodb', type: 'noSQL' };
  }
  
  // ... rest of code ...
}
```

### Adding New Sink Detection

**File:** `src/engines/taint/sourceSinkMap.js`:

```javascript
const SINK_DEFINITIONS = {
  sql: [
    'mongodb.find',    // Add MongoDB
    'elasticsearch',   // Add Elasticsearch
    // ... existing sinks ...
  ],
};
```

---

## 5. Customizing Report Output

### Generate Custom JSON Report

```javascript
const reportGenerator = new ReportGenerator();

const customReport = findings.map(finding => ({
  type: finding.type,
  severity: finding.severity,
  line: finding.line,
  
  // Include context-aware fix only if high confidence
  fix: finding.contextAwareFix && finding.contextAwareFix.confidence > 0.8
    ? finding.contextAwareFix
    : null,
  
  // Add custom fields
  reviewedAt: new Date(),
  assignedTo: 'security-team',
}));

fs.writeFileSync('custom_report.json', 
  JSON.stringify(customReport, null, 2));
```

---

## 6. Filtering by Context

### Get Only High-Confidence Fixes

```javascript
const confidenceFindings = findings.filter(f => 
  f.contextAwareFix && 
  f.contextAwareFix.confidence >= 0.8
);
```

### Get Only Specific API Findings

```javascript
// Get only mysqli SQL injections
const mysqliFinding = findings.filter(f =>
  f.apiContext?.api === 'mysqli' &&
  f.vulnerabilityType === 'SQLI'
);

// Get only jQuery vulnerabilities (future)
const xssFindings = findings.filter(f =>
  f.vulnerabilityType === 'XSS'
);
```

---

## 7. Advanced: Custom Context Analyzer

### Extend Context Analyzer with Custom Logic

```javascript
const ContextAnalyzer = require('./src/context/contextAnalyzer');

class CustomContextAnalyzer extends ContextAnalyzer {
  analyze(taintFinding) {
    const analyzed = super.analyze(taintFinding);
    
    // Add custom context
    if (analyzed.context.tableName === 'users') {
      analyzed.riskLevel = 'CRITICAL'; // User table = more critical
    }
    
    return analyzed;
  }
}

// Use in scanner
const customAnalyzer = new CustomContextAnalyzer(astEngine);
```

---

## 8. Testing Context-Aware Fixes

### Unit Test Example

```javascript
const assert = require('assert');
const TemplateEngine = require('./src/remediation/templateEngine');

it('should render mysqli prepared statement fix', () => {
  const engine = new TemplateEngine();
  
  const finding = {
    fixStrategy: 'mysqli_prepared',
    vulnerabilityType: 'SQLI',
    context: {
      variableName: 'userId',
      connectionName: 'conn',
      tableName: 'users',
      inputType: 'integer',
    },
  };
  
  const fix = engine.render(finding);
  
  assert(fix.code.includes('$conn->prepare'));
  assert(fix.code.includes('bind_param'));
  assert(fix.confidence > 0.7);
});
```

---

## 9. API Reference

### Scanner Class

```javascript
const Scanner = require('./src/core/scanner');

// Constructor
const scanner = new Scanner({
  verbose: true,      // Enable verbose logging
});

// Scan single file
const findings = scanner.scanFile('app.js');

// Properties
scanner.taintAnalyzer   // Access taint analyzer
scanner.contextAnalyzer // Access context analyzer
scanner.templateEngine  // Access template engine
```

### ContextAnalyzer Class

```javascript
const ContextAnalyzer = require('./src/context/contextAnalyzer');

const analyzer = new ContextAnalyzer(astEngine);

// Analyze single finding
const analyzed = analyzer.analyze(taintFinding);

// analyze() returns:
{
  fixStrategy: string,        // 'mysqli_prepared', 'pdo_prepared', etc.
  context: {
    variableName: string,     // User input variable name
    connectionName: string,   // DB connection variable
    tableName: string,        // Extracted table name
    sanitizerNeeded: boolean,
    inputType: string,        // 'integer', 'string', 'email'
  },
  fixConfidence: number,      // 0.0-1.0
}
```

### TemplateEngine Class

```javascript
const TemplateEngine = require('./src/remediation/templateEngine');

const engine = new TemplateEngine();

// Render single finding
const fix = engine.render(analyzedFinding);

// render() returns:
{
  name: string,           // 'MySQL Prepared Statement (mysqli)'
  description: string,    // Detailed description
  code: string,          // Rendered code template
  example: string,       // Full working example
  placeholders: object,  // {conn: 'conn', var: 'userId', ...}
  confidence: number,    // 0.0-1.0
}

// Render batch
const fixes = engine.renderBatch(analyzedFindings);
```

---

## 10. Common Patterns

### Pattern 1: Get All SQL Fixes
```javascript
const sqlFixes = findings
  .filter(f => f.vulnerabilityType === 'SQLI')
  .map(f => f.contextAwareFix)
  .filter(f => f && f.confidence > 0.7);
```

### Pattern 2: Export Fixes as Code Files
```javascript
const fs = require('fs');

findings
  .filter(f => f.contextAwareFix)
  .forEach((finding, idx) => {
    const filename = `fix_${idx}_${finding.type}.js`;
    fs.writeFileSync(filename, finding.contextAwareFix.code);
  });
```

### Pattern 3: Generate Fix Checklist
```javascript
const checklist = findings
  .filter(f => f.contextAwareFix)
  .map(f => `
    [ ] Line ${f.line}: ${f.name}
        Fix Strategy: ${f.contextAwareFix.name}
        Confidence: ${(f.contextAwareFix.confidence * 100).toFixed(0)}%
  `)
  .join('\n');
```

### Pattern 4: Compare Fixes by Severity
```javascript
const fixsByGroup = {};

findings.forEach(f => {
  const key = `${f.severity}_${f.type}`;
  if (!fixsByGroup[key]) fixsByGroup[key] = [];
  fixsByGroup[key].push(f.contextAwareFix);
});

// Now grouped by severity and type
```

---

## 11. Troubleshooting

### Issue: Context-Aware Fix Not Generated
**Probable Cause:** Finding is from regex, not taint engine

**Solution:** Regex findings don't have `apiContext` - only taint findings do
```javascript
if (finding.engine === 'taint' && finding.apiContext) {
  // Has context-aware fix
}
```

### Issue: Wrong Fix Strategy Selected
**Probable Cause:** API detection incorrect

**Solution:** Check `apiContext` detection in taintAnalyzer:
```javascript
console.log(finding.apiContext); // Should show detected API
```

### Issue: Placeholder Not Replaced
**Probable Cause:** Variable extraction failed

**Solution:** Check variable name extraction:
```javascript
console.log(finding.sourceVar);        // User input variable
console.log(finding.connectionVar);    // DB connection
```

---

## 12. Performance Considerations

### Scanning Large Files
```javascript
// For large codebases, consider filtering first:
const findings = scanner.scanFile(filePath)
  .filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
```

### Batch Processing
```javascript
// Process files in parallel
const files = getFilesList();
const allFindings = await Promise.all(
  files.map(f => Promise.resolve(scanner.scanFile(f)))
);
```

---

## 13. Next Steps

1. **Customize Templates** - Add your organization's fix patterns
2. **Integrate with CI/CD** - Automate security scanning
3. **Build Web UI** - Interactive fix viewer (PHASE 5)
4. **Add More APIs** - Support additional frameworks

---

## Support & Contributing

For issues or feature requests related to context-aware remediation:
1. Check template definitions in `templates.json`
2. Verify API detection in `taintAnalyzer.js`
3. Test with existing examples in `examples/`

---

**Last Updated:** February 28, 2026  
**Stable Version:** 1.0.0
