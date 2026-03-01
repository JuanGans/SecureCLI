/**
 * LAYER 3: SCORING - Risk Scoring System
 */

const config = require('../config/config');

class RiskScorer {
  constructor() {
    this.baseWeights = config.scoring.baseSeverityWeight;
  }

  /**
   * Calculate risk score based on severity and confidence
   */
  calculateRiskScore(severity, confidence) {
    const baseScore = this.baseWeights[severity] || 5;
    const score = Math.min(10, Math.round(baseScore * confidence * 1.2));
    return score;
  }

  /**
   * Calculate confidence based on source and sink depth
   */
  calculateConfidence(detectionMethod, additionalFactors = {}) {
    let confidence = 0;

    // Base confidence by detection method
    if (detectionMethod === 'regex') {
      confidence = 0.7;
    } else if (detectionMethod === 'taint') {
      confidence = 0.85;
    } else if (detectionMethod === 'ast') {
      confidence = 0.9;
    } else if (detectionMethod === 'taint+regex' || detectionMethod === 'TAINT_ANALYSIS') {
      // Multi-engine or proven taint analysis
      confidence = 0.92;
    } else if (detectionMethod === 'hybrid') {
      confidence = 0.88;
    } else {
      // Default for unknown engines (shouldn't happen but safe fallback)
      confidence = 0.6;
    }

    // Adjust by additional factors
    if (additionalFactors.multipleDetections) {
      confidence = Math.min(0.99, confidence + 0.1);
    }

    if (additionalFactors.isSensitiveSink) {
      confidence = Math.min(0.99, confidence + 0.05);
    }

    if (additionalFactors.directFlow) {
      confidence += 0.05;
    }

    return Math.min(0.99, confidence);
  }

  /**
   * Calculate exploitability level
   */
  calculateExploitability(severity, confidence) {
    const exploitScore = Math.round(severity === 'CRITICAL' ? 9 : severity === 'HIGH' ? 7 : 5);
    const confidenceBoost = Math.round(confidence * 10);
    return Math.min(10, Math.round((exploitScore + confidenceBoost) / 2));
  }

  /**
   * Determine impact level
   */
  getImpactLevel(severity) {
    const impacts = {
      CRITICAL: 'Data Breach Potential',
      HIGH: 'Significant Security Risk',
      MEDIUM: 'Moderate Risk',
      LOW: 'Low Risk / Info Disclosure',
    };

    return impacts[severity] || 'Unknown Impact';
  }
}

module.exports = RiskScorer;
