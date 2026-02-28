/**
 * LAYER 2: CLASSIFICATION - XSS Detectors
 */

class XSSReflected {
  static detect(taintFindings) {
    return taintFindings.filter(f => f.type === 'XSS_REFLECTED' || f.type === 'XSS_SCRIPT_TAG');
  }
}

class XSSStored {
  static detect(taintFindings) {
    return taintFindings.filter(f => f.type === 'XSS_STORED' || f.type === 'XSS_DOM_ASSIGNMENT');
  }
}

class XSSDoM {
  static detect(taintFindings) {
    return taintFindings.filter(f => f.type === 'XSS_DOM');
  }
}

module.exports = {
  XSSReflected,
  XSSStored,
  XSSDoM,
};
