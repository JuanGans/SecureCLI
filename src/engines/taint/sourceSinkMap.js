/**
 * LAYER 1: DETECTION - Source/Sink Mapping for Taint Analysis
 */

const SOURCE_DEFINITIONS = {
  javascript: [
    'req.body',
    'req.query',
    'req.params',
    'req.headers',
    'req.cookies',
    'location.href',
    'location.search',
    'document.location',
    'window.location',
    'location.hash',
    'document.referrer',
    'navigator.userAgent',
  ],
  php: [
    '$_GET',
    '$_POST',
    '$_REQUEST',
    '$_COOKIE',
    '$_SERVER',
    'input()',
  ],
};

const SINK_DEFINITIONS = {
  sql: [
    'query',
    'db.query',
    'connection.query',
    'pool.query',
    'mysqli_query',
    'mysql_query',
    'PDO',
    'prepare',
    'execute',
  ],
  xss: [
    'res.send',
    'res.write',
    'document.write',
    'innerHTML',
    'innerText',
    'textContent',
    'eval',
    'setTimeout',
    'setInterval',
  ],
};

/**
 * Check if identifier is a source
 */
function isSource(identifier, language = 'javascript') {
  const sources = SOURCE_DEFINITIONS[language] || SOURCE_DEFINITIONS.javascript;
  return sources.some(source => identifier.includes(source));
}

/**
 * Check if identifier is a sink
 */
function isSink(identifier, type = 'all') {
  if (type === 'sql' || type === 'all') {
    if (SINK_DEFINITIONS.sql.some(sink => identifier.includes(sink))) {
      return true;
    }
  }

  if (type === 'xss' || type === 'all') {
    if (SINK_DEFINITIONS.xss.some(sink => identifier.includes(sink))) {
      return true;
    }
  }

  return false;
}

/**
 * Get source category
 */
function getSourceCategory(identifier) {
  for (const [category, sources] of Object.entries(SOURCE_DEFINITIONS)) {
    if (sources.some(source => identifier.includes(source))) {
      return category;
    }
  }
  return null;
}

module.exports = {
  SOURCE_DEFINITIONS,
  SINK_DEFINITIONS,
  isSource,
  isSink,
  getSourceCategory,
};
