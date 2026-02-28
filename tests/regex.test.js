/**
 * Regex Engine Tests
 */

const RegexEngine = require('../../src/engines/regex/regexEngine');

describe('Regex Engine', () => {
  let engine;

  beforeEach(() => {
    engine = new RegexEngine();
  });

  describe('SQL Injection Detection', () => {
    test('should detect UNION-based SQL injection', () => {
      const code = "const query = 'SELECT * FROM users UNION SELECT password FROM admin'";
      const findings = engine.scan(code, 'sql');
      
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].type).toBe('SQLI_UNION');
    });

    test('should detect time-based SQL injection', () => {
      const code = "const query = 'SELECT * FROM users WHERE id = 1 AND SLEEP(5)'";
      const findings = engine.scan(code, 'sql');
      
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].type).toBe('SQLI_TIME');
    });

    test('should detect boolean-based SQL injection', () => {
      const code = "const condition = 'WHERE id = 1 OR 1=1'";
      const findings = engine.scan(code, 'sql');
      
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].type).toBe('SQLI_BOOLEAN');
    });
  });

  describe('XSS Detection', () => {
    test('should detect script tag injection', () => {
      const code = "res.send('<script>alert(1)</script>')";
      const findings = engine.scan(code, 'xss');
      
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].type).toBe('XSS_SCRIPT_TAG');
    });

    test('should detect event handler injection', () => {
      const code = "const html = '<img onerror=\"alert(1)\" />'";
      const findings = engine.scan(code, 'xss');
      
      expect(findings.length).toBeGreaterThan(0);
    });
  });

  describe('Pattern Management', () => {
    test('should retrieve pattern by type', () => {
      const pattern = engine.getPattern('SQLI_UNION');
      
      expect(pattern).toBeDefined();
      expect(pattern.type).toBe('SQLI_UNION');
    });

    test('should add custom pattern', () => {
      const customPattern = {
        type: 'CUSTOM_TEST',
        name: 'Custom Pattern',
        regex: /testpattern/i,
        severity: 'HIGH',
        confidence: 0.8,
      };

      engine.addPattern('sql', customPattern);
      const retrieved = engine.getPattern('CUSTOM_TEST');
      
      expect(retrieved).toBeDefined();
      expect(retrieved.type).toBe('CUSTOM_TEST');
    });
  });
});
