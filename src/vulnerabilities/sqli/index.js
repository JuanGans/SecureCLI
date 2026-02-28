/**
 * LAYER 2: CLASSIFICATION - SQL Injection Detectors
 */

class SQLiBoolean {
  static detect(taintFindings) {
    return taintFindings.filter(f => f.type === 'SQLI_BOOLEAN');
  }
}

class SQLiUnion {
  static detect(taintFindings) {
    return taintFindings.filter(f => f.type === 'SQLI_UNION');
  }
}

class SQLiTime {
  static detect(taintFindings) {
    return taintFindings.filter(f => f.type === 'SQLI_TIME');
  }
}

class SQLiError {
  static detect(taintFindings) {
    return taintFindings.filter(f => f.type === 'SQLI_ERROR');
  }
}

class SQLiStacked {
  static detect(taintFindings) {
    return taintFindings.filter(f => f.type === 'SQLI_STACKED');
  }
}

module.exports = {
  SQLiBoolean,
  SQLiUnion,
  SQLiTime,
  SQLiError,
  SQLiStacked,
};
