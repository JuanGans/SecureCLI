/**
 * LAYER 1: DETECTION - Regex Pattern Definitions
 */

const SQL_PATTERNS = [
  {
    type: 'SQLI_UNION',
    name: 'UNION-Based SQL Injection',
    regex: /union\s+select/i,
    severity: 'CRITICAL',
    confidence: 0.95,
    description: 'Detected UNION SELECT pattern in query',
  },
  {
    type: 'SQLI_TIME',
    name: 'Time-Based SQL Injection',
    regex: /(sleep\(|benchmark\(|pg_sleep\(|waitfor\s+delay)/i,
    severity: 'CRITICAL',
    confidence: 0.95,
    description: 'Detected time-based delay functions',
  },
  {
    type: 'SQLI_BOOLEAN',
    name: 'Boolean-Based SQL Injection',
    regex: /or\s+1\s*=\s*1|or\s+true/i,
    severity: 'HIGH',
    confidence: 0.9,
    description: 'Detected boolean-based logic manipulation',
  },
  {
    type: 'SQLI_ERROR',
    name: 'Error-Based SQL Injection',
    regex: /(extractvalue|updatexml|json_extract|cast\s+as)/i,
    severity: 'HIGH',
    confidence: 0.85,
    description: 'Detected error-based injection techniques',
  },
  {
    type: 'SQLI_STACKED',
    name: 'Stacked Queries SQL Injection',
    regex: /;\s*(drop|delete|update|insert|create|alter)/i,
    severity: 'CRITICAL',
    confidence: 0.88,
    description: 'Detected stacked query pattern',
  },
];

const XSS_PATTERNS = [
  {
    type: 'XSS_REFLECTED',
    name: 'Reflected XSS',
    regex: /<script[^>]*>|javascript:|onerror\s*=|onload\s*=/i,
    severity: 'HIGH',
    confidence: 0.85,
    description: 'Detected script injection or event handler',
  },
  {
    type: 'XSS_STORED',
    name: 'Stored XSS',
    regex: /innerHTML\s*=|innerText\s*=|\.html\(|document\.write/i,
    severity: 'HIGH',
    confidence: 0.88,
    description: 'Detected DOM manipulation with user input',
  },
  {
    type: 'XSS_DOM',
    name: 'DOM-Based XSS',
    regex: /<|>|<html|<body|<div|<h[1-6]|<p|<img|<iframe/i,
    severity: 'MEDIUM',
    confidence: 0.75,
    description: 'Detected HTML tag injection',
  },
];

module.exports = {
  SQL_PATTERNS,
  XSS_PATTERNS,
};
