/**
 * OWASP Top 10 Mapping
 */

const owaspMapping = {
  SQLI_UNION: {
    category: 'A03:2021 – Injection',
    top10: 'SQL Injection - UNION Based',
    description: 'Attackers extract data from other tables using UNION queries',
    cwe: 'CWE-89: SQL Injection',
  },
  SQLI_TIME: {
    category: 'A03:2021 – Injection',
    top10: 'SQL Injection - Time Based',
    description: 'Use of time-based functions to infer database content',
    cwe: 'CWE-89: SQL Injection',
  },
  SQLI_BOOLEAN: {
    category: 'A03:2021 – Injection',
    top10: 'SQL Injection - Boolean Based',
    description: 'Manipulation of SQL logic using true/false conditions',
    cwe: 'CWE-89: SQL Injection',
  },
  SQLI_ERROR: {
    category: 'A03:2021 – Injection',
    top10: 'SQL Injection - Error Based',
    description: 'Extracting data through database error messages',
    cwe: 'CWE-89: SQL Injection',
  },
  SQLI_STACKED: {
    category: 'A03:2021 – Injection',
    top10: 'SQL Injection - Stacked Queries',
    description: 'Executing multiple SQL statements in one query',
    cwe: 'CWE-89: SQL Injection',
  },
  XSS_REFLECTED: {
    category: 'A03:2021 – Injection',
    top10: 'Cross-Site Scripting - Reflected',
    description: 'Malicious script sent via HTTP response',
    cwe: 'CWE-79: Improper Neutralization of Input During Web Page Generation',
  },
  XSS_STORED: {
    category: 'A03:2021 – Injection',
    top10: 'Cross-Site Scripting - Stored',
    description: 'Malicious script saved in database',
    cwe: 'CWE-79: Improper Neutralization of Input During Web Page Generation',
  },
  XSS_DOM: {
    category: 'A03:2021 – Injection',
    top10: 'Cross-Site Scripting - DOM Based',
    description: 'Manipulation of DOM elements with untrusted data',
    cwe: 'CWE-79: Improper Neutralization of Input During Web Page Generation',
  },
};

/**
 * Get OWASP mapping for vulnerability type
 */
function getOWASPMapping(type) {
  return owaspMapping[type] || {
    category: 'A03:2021 – Injection',
    top10: 'Unknown Vulnerability',
    description: 'Unable to categorize this vulnerability',
    cwe: 'Unknown',
  };
}

/**
 * Get all OWASP categories
 */
function getAllCategories() {
  const categories = new Set();
  Object.values(owaspMapping).forEach(mapping => {
    categories.add(mapping.category);
  });
  return Array.from(categories);
}

module.exports = {
  owaspMapping,
  getOWASPMapping,
  getAllCategories,
};
