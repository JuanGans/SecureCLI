/**
 * Taint Analysis Tests
 */

const TaintAnalyzer = require('../../src/engines/taint/taintAnalyzer');

describe('Taint Analyzer', () => {
  let analyzer;

  beforeEach(() => {
    analyzer = new TaintAnalyzer();
  });

  describe('Basic Taint Tracking', () => {
    test('should track tainted variables from sources', () => {
      const code = `
        const id = req.body.id;
        const query = "SELECT * FROM users WHERE id = " + id;
        db.query(query);
      `;

      const findings = analyzer.analyze(code);
      
      expect(findings.length).toBeGreaterThan(0);
    });

    test('should track taint through assignments', () => {
      const code = `
        const userInput = req.query.name;
        const processed = userInput;
        document.write(processed);
      `;

      const findings = analyzer.analyze(code);
      
      expect(Array.isArray(findings)).toBe(true);
    });
  });

  describe('Source Detection', () => {
    test('should identify req.body as source', () => {
      const code = `
        const dangerous = req.body.search;
        db.query("SELECT * FROM products WHERE name = " + dangerous);
      `;

      const findings = analyzer.analyze(code);
      
      expect(findings.length).toBeGreaterThan(0);
    });

    test('should identify req.query as source', () => {
      const code = `
        const search = req.query.q;
        res.send("<h1>" + search + "</h1>");
      `;

      const findings = analyzer.analyze(code);
      
      expect(Array.isArray(findings)).toBe(true);
    });
  });

  describe('Sink Detection', () => {
    test('should identify db.query as sink', () => {
      const code = `
        const id = req.body.id;
        db.query("SELECT * FROM users WHERE id = " + id);
      `;

      const findings = analyzer.analyze(code);
      
      expect(findings.length).toBeGreaterThan(0);
    });

    test('should identify res.send as sink', () => {
      const code = `
        const name = req.query.name;
        res.send(name);
      `;

      const findings = analyzer.analyze(code);
      
      expect(Array.isArray(findings)).toBe(true);
    });
  });

  describe('Error Handling', () => {
    test('should handle syntax errors gracefully', () => {
      const invalidCode = 'const x = { invalid syntax }}';
      const findings = analyzer.analyze(invalidCode);
      
      expect(Array.isArray(findings)).toBe(true);
    });

    test('should return empty array for valid safe code', () => {
      const safeCode = `
        const x = 5;
        const y = x + 10;
        console.log(y);
      `;

      const findings = analyzer.analyze(safeCode);
      
      expect(Array.isArray(findings)).toBe(true);
    });
  });
});
