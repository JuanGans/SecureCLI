/**
 * Structured logging system
 */

const { log } = require('./colors');

class Logger {
  constructor(verbose = false) {
    this.verbose = verbose;
    this.logs = [];
  }

  error(message, data = {}) {
    log.error(message);
    this.logs.push({ level: 'error', message, data, timestamp: new Date() });
  }

  warn(message, data = {}) {
    log.warn(message);
    this.logs.push({ level: 'warn', message, data, timestamp: new Date() });
  }

  info(message, data = {}) {
    log.info(message);
    this.logs.push({ level: 'info', message, data, timestamp: new Date() });
  }

  success(message, data = {}) {
    log.success(message);
    this.logs.push({ level: 'success', message, data, timestamp: new Date() });
  }

  debug(message, data = {}) {
    if (this.verbose) {
      log.debug(message);
    }
    this.logs.push({ level: 'debug', message, data, timestamp: new Date() });
  }

  getLogs() {
    return this.logs;
  }

  clear() {
    this.logs = [];
  }
}

module.exports = Logger;
