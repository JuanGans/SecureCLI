/**
 * Risk Scoring Tests
 */

const RiskScorer = require('../../src/scoring/riskScorer');

describe('Risk Scorer', () => {
  let scorer;

  beforeEach(() => {
    scorer = new RiskScorer();
  });

  describe('Risk Score Calculation', () => {
    test('should calculate HIGH severity with 0.9 confidence', () => {
      const score = scorer.calculateRiskScore('HIGH', 0.9);
      
      expect(score).toBeGreaterThan(0);
      expect(score).toBeLessThanOrEqual(10);
    });

    test('should calculate CRITICAL severity with 0.95 confidence', () => {
      const score = scorer.calculateRiskScore('CRITICAL', 0.95);
      
      expect(score).toBeGreaterThan(8);
      expect(score).toBeLessThanOrEqual(10);
    });

    test('should calculate LOW severity with 0.7 confidence', () => {
      const score = scorer.calculateRiskScore('LOW', 0.7);
      
      expect(score).toBeLessThan(5);
    });

    test('should cap score at 10', () => {
      const score = scorer.calculateRiskScore('CRITICAL', 1.0);
      
      expect(score).toBeLessThanOrEqual(10);
    });
  });

  describe('Confidence Calculation', () => {
    test('should assign base confidence for regex detection', () => {
      const confidence = scorer.calculateConfidence('regex');
      
      expect(confidence).toBeGreaterThan(0.5);
      expect(confidence).toBeLessThan(0.8);
    });

    test('should assign higher confidence for taint analysis', () => {
      const confidence = scorer.calculateConfidence('taint');
      
      expect(confidence).toBeGreaterThan(0.8);
    });

    test('should boost confidence with multiple detections', () => {
      const baseConfidence = scorer.calculateConfidence('regex');
      const boostedConfidence = scorer.calculateConfidence('regex', {
        multipleDetections: true,
      });
      
      expect(boostedConfidence).toBeGreaterThan(baseConfidence);
    });

    test('should not exceed 0.99', () => {
      const confidence = scorer.calculateConfidence('ast', {
        multipleDetections: true,
        isSensitiveSink: true,
        directFlow: true,
      });
      
      expect(confidence).toBeLessThanOrEqual(0.99);
    });
  });

  describe('Exploitability Calculation', () => {
    test('should assign high exploitability for CRITICAL severity', () => {
      const exploitability = scorer.calculateExploitability('CRITICAL', 0.95);
      
      expect(exploitability).toBeGreaterThan(7);
    });

    test('should assign moderate exploitability for MEDIUM severity', () => {
      const exploitability = scorer.calculateExploitability('MEDIUM', 0.75);
      
      expect(exploitability).toBeGreaterThan(3);
      expect(exploitability).toBeLessThan(8);
    });
  });

  describe('Impact Level Assessment', () => {
    test('should identify CRITICAL severity as data breach potential', () => {
      const impact = scorer.getImpactLevel('CRITICAL');
      
      expect(impact).toContain('Data Breach');
    });

    test('should identify HIGH severity as significant risk', () => {
      const impact = scorer.getImpactLevel('HIGH');
      
      expect(impact).toContain('Significant');
    });

    test('should identify MEDIUM severity as moderate risk', () => {
      const impact = scorer.getImpactLevel('MEDIUM');
      
      expect(impact).toContain('Moderate');
    });
  });
});
