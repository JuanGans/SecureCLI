/**
 * XSS Pattern Definitions
 */

const XSS_PATTERNS = [
  {
    type: 'XSS_SCRIPT_TAG',
    name: 'Script Tag Injection',
    regex: /<script[^>]*>[^<]*<\/script>/i,
    severity: 'CRITICAL',
    confidence: 0.95,
    description: 'Detected <script> tag pattern',
  },
  {
    type: 'XSS_EVENT_HANDLER',
    name: 'Event Handler Injection',
    regex: /on(error|load|click|mouseover|focus)\s*=/i,
    severity: 'HIGH',
    confidence: 0.9,
    description: 'Detected inline event handler',
  },
  {
    type: 'XSS_JAVASCRIPT_PROTOCOL',
    name: 'JavaScript Protocol',
    regex: /javascript:/i,
    severity: 'HIGH',
    confidence: 0.88,
    description: 'Detected javascript: protocol URL',
  },
  {
    type: 'XSS_DOM_ASSIGNMENT',
    name: 'DOM Assignment',
    regex: /(innerHTML|innerText|textContent|outerHTML)\s*=/i,
    severity: 'HIGH',
    confidence: 0.85,
    description: 'Detected direct DOM property assignment',
  },
  {
    type: 'XSS_HTML_TAGS',
    name: 'HTML Tag Injection',
    regex: /<(img|iframe|embed|object|svg|input)[^>]*>/i,
    severity: 'MEDIUM',
    confidence: 0.8,
    description: 'Detected potentially dangerous HTML tags',
  },
];

module.exports = {
  XSS_PATTERNS,
};
